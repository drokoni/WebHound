use anyhow::{anyhow, Result};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use storage::{NewScreenshotAnnotation, SqliteStorage};

pub fn server(out_dir: &Path, port: u16) -> Result<()> {
    server_with_bind(out_dir, "0.0.0.0", port)
}

pub fn server_with_bind(out_dir: &Path, bind_host: &str, port: u16) -> Result<()> {
    use tiny_http::{Header, Method, Response, Server};

    let server = Server::http(format!("{bind_host}:{port}"))
        .map_err(|e| anyhow!("Server::http: {e}"))?;

    println!("Report available at: http://{bind_host}:{port}/");
    println!("Serving report from: {}", out_dir.display());

    let mut roots: Vec<PathBuf> = vec![out_dir.to_path_buf()];
    if let Some(p) = out_dir.parent() {
        roots.push(p.to_path_buf());
        if let Some(gp) = p.parent() {
            roots.push(gp.to_path_buf());
        }
    }

    println!("File roots:");
    for (i, r) in roots.iter().enumerate() {
        println!("  {i}: {}", r.display());
    }

    let sqlite = find_sqlite_in_roots(&roots)
        .map(SqliteStorage::open)
        .transpose()?;

    if let Some(sqlite) = &sqlite {
        let ann_path = out_dir.join("annotations.csv");
        if ann_path.is_file() {
            if let Err(e) = sync_annotations_csv_to_db(&ann_path, sqlite) {
                eprintln!("[!] sync annotations.csv -> sqlite on startup failed: {e}");
            }
        }
    }

    fn add_header(resp: &mut Response<std::io::Cursor<Vec<u8>>>, k: &str, v: &str) {
        if let Ok(h) = Header::from_bytes(k, v) {
            resp.add_header(h);
        }
    }

    fn add_cors(resp: &mut Response<std::io::Cursor<Vec<u8>>>) {
        add_header(resp, "Access-Control-Allow-Origin", "*");
        add_header(resp, "Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        add_header(resp, "Access-Control-Allow-Headers", "Content-Type");
    }

    fn resp_text(code: u16, s: impl Into<String>) -> Response<std::io::Cursor<Vec<u8>>> {
        Response::from_data(s.into().into_bytes()).with_status_code(code)
    }

    fn resp_json<T: serde::Serialize>(
        code: u16,
        value: &T,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>> {
        Ok(Response::from_data(serde_json::to_vec(value)?).with_status_code(code))
    }

    fn sanitize_rel(mut s: &str) -> String {
        if let Some(p) = s.find('?') {
            s = &s[..p];
        }
        if let Some(p) = s.find('#') {
            s = &s[..p];
        }
        let mut s = s.trim_start_matches('/');

        while s.starts_with("../") {
            s = &s[3..];
        }

        if s.contains('\\') {
            return String::new();
        }
        if s.split('/').any(|seg| seg == ".." || seg.is_empty()) {
            return String::new();
        }

        s.to_string()
    }

    fn find_in_roots(rel: &str, roots: &[PathBuf]) -> Option<PathBuf> {
        for r in roots {
            let p = r.join(rel);
            if p.is_file() {
                return Some(p);
            }
        }
        None
    }

    fn find_fs_path(req_path: &str, roots: &[PathBuf]) -> Option<PathBuf> {
        if let Some(p) = find_in_roots(req_path, roots) {
            return Some(p);
        }

        let direct = PathBuf::from(req_path);
        if direct.is_file() {
            return Some(direct);
        }

        let abs_candidate = PathBuf::from(format!("/{}", req_path.trim_start_matches('/')));
        if abs_candidate.is_file() {
            return Some(abs_candidate);
        }

        None
    }

    fn get_query_param(url: &str, key: &str) -> Option<String> {
        let q = url.split('?').nth(1)?;
        for part in q.split('&') {
            if part.is_empty() {
                continue;
            }
            let mut it = part.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == key {
                let dec = urlencoding::decode(v).ok()?.into_owned();
                return Some(dec);
            }
        }
        None
    }

    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 8);
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c => out.push(c),
            }
        }
        out
    }

    fn rel_from_abs(abs: &Path, roots: &[PathBuf]) -> Option<String> {
        let abs_can = abs.canonicalize().unwrap_or_else(|_| abs.to_path_buf());

        for root in roots {
            let root_can = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            if let Ok(stripped) = abs_can.strip_prefix(&root_can) {
                let rel = stripped
                    .to_string_lossy()
                    .replace('\\', "/")
                    .trim_start_matches('/')
                    .to_string();
                if !rel.is_empty() {
                    return Some(rel);
                }
            }
        }

        if abs_can.is_file() {
            return Some(abs_can.to_string_lossy().replace('\\', "/"));
        }

        None
    }

    for mut rq in server.incoming_requests() {
        let url = rq.url().to_string();
        let path_only = url.split('?').next().unwrap_or(&url);

        if rq.method() == &Method::Options && path_only.starts_with("/api/") {
            let mut resp = Response::from_data(Vec::<u8>::new()).with_status_code(204);
            add_cors(&mut resp);
            add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
            let _ = rq.respond(resp);
            continue;
        }

        if path_only == "/api/db/runs" && rq.method() == &Method::Get {
            let Some(sqlite) = &sqlite else {
                let mut resp = resp_text(404, "sqlite not found\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            };

            match sqlite.list_scan_runs() {
                Ok(rows) => {
                    let mut resp = resp_json(200, &rows)?;
                    add_cors(&mut resp);
                    add_header(&mut resp, "Content-Type", "application/json; charset=utf-8");
                    let _ = rq.respond(resp);
                }
                Err(e) => {
                    let mut resp = resp_text(500, format!("500: {e}\n"));
                    add_cors(&mut resp);
                    let _ = rq.respond(resp);
                }
            }
            continue;
        }

        if path_only == "/api/db/raw_findings" && rq.method() == &Method::Get {
            let Some(sqlite) = &sqlite else {
                let mut resp = resp_text(404, "sqlite not found\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            };

            let Some(run_id) = get_query_param(&url, "run_id").and_then(|v| v.parse::<i64>().ok()) else {
                let mut resp = resp_text(400, "missing ?run_id=\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            };

            match sqlite.list_raw_findings_simple(run_id) {
                Ok(rows) => {
                    let mut resp = resp_json(200, &rows)?;
                    add_cors(&mut resp);
                    add_header(&mut resp, "Content-Type", "application/json; charset=utf-8");
                    let _ = rq.respond(resp);
                }
                Err(e) => {
                    let mut resp = resp_text(500, format!("500: {e}\n"));
                    add_cors(&mut resp);
                    let _ = rq.respond(resp);
                }
            }
            continue;
        }

        if path_only == "/api/db/analysis_findings" && rq.method() == &Method::Get {
            let Some(sqlite) = &sqlite else {
                let mut resp = resp_text(404, "sqlite not found\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            };

            let Some(run_id) = get_query_param(&url, "run_id").and_then(|v| v.parse::<i64>().ok()) else {
                let mut resp = resp_text(400, "missing ?run_id=\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            };

            match sqlite.list_analysis_findings_simple(run_id) {
                Ok(rows) => {
                    let mut resp = resp_json(200, &rows)?;
                    add_cors(&mut resp);
                    add_header(&mut resp, "Content-Type", "application/json; charset=utf-8");
                    let _ = rq.respond(resp);
                }
                Err(e) => {
                    let mut resp = resp_text(500, format!("500: {e}\n"));
                    add_cors(&mut resp);
                    let _ = rq.respond(resp);
                }
            }
            continue;
        }

if path_only == "/api/db/screenshots" && rq.method() == &Method::Get {
    let Some(sqlite) = &sqlite else {
        let mut resp = resp_text(404, "sqlite not found\n");
        add_cors(&mut resp);
        let _ = rq.respond(resp);
        continue;
    };

    let Some(run_id) = get_query_param(&url, "run_id").and_then(|v| v.parse::<i64>().ok()) else {
        let mut resp = resp_text(400, "missing ?run_id=\n");
        add_cors(&mut resp);
        let _ = rq.respond(resp);
        continue;
    };

    match sqlite.list_screenshots_simple(run_id) {
        Ok(rows) => {
            let data: Vec<serde_json::Value> = rows.into_iter().map(
                |(id, page_url, local_path, ml_label, ml_score, user_label)| {
                    serde_json::json!({
                        "id": id,
                        "page_url": page_url,
                        "file": local_path,
                        "top_label": ml_label,
                        "top_prob": ml_score,
                        "user_label": user_label
                    })
                }
            ).collect();

            let mut resp = resp_json(200, &data)?;
            add_cors(&mut resp);
            add_header(&mut resp, "Content-Type", "application/json; charset=utf-8");
            let _ = rq.respond(resp);
        }
        Err(e) => {
            let mut resp = resp_text(500, format!("500: {e}\n"));
            add_cors(&mut resp);
            let _ = rq.respond(resp);
        }
    }
    continue;
}
if path_only == "/api/db/latest_run" && rq.method() == &Method::Get {
    let Some(sqlite) = &sqlite else {
        let mut resp = resp_text(404, "sqlite not found\n");
        add_cors(&mut resp);
        let _ = rq.respond(resp);
        continue;
    };

    match sqlite.list_scan_runs() {
        Ok(rows) => {
            let mut latest_with_screens = None;

            for r in rows {
                let run_id = r.0;
                let mode = &r.2;
                let status = &r.3;

                if mode != "images" || status != "success" {
                    continue;
                }

                match sqlite.list_screenshots_simple(run_id) {
                    Ok(shots) if !shots.is_empty() => {
                        latest_with_screens = Some(serde_json::json!({
                            "id": r.0,
                            "target": r.1,
                            "mode": r.2,
                            "status": r.3
                        }));
                        break;
                    }
                    _ => {}
                }
            }

            let mut resp = resp_json(200, &latest_with_screens)?;
            add_cors(&mut resp);
            add_header(&mut resp, "Content-Type", "application/json; charset=utf-8");
            let _ = rq.respond(resp);
        }
        Err(e) => {
            let mut resp = resp_text(500, format!("500: {e}\n"));
            add_cors(&mut resp);
            let _ = rq.respond(resp);
        }
    }
    continue;
}
        if path_only.starts_with("/api/db/screenshots/")
            && path_only.ends_with("/label")
            && rq.method() == &Method::Post
        {
            let Some(sqlite) = &sqlite else {
                let mut resp = resp_text(404, "sqlite not found\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            };

            let id_part = path_only
                .trim_start_matches("/api/db/screenshots/")
                .trim_end_matches("/label");

            let screenshot_id = match id_part.parse::<i64>() {
                Ok(v) => v,
                Err(_) => {
                    let mut resp = resp_text(400, "bad screenshot id\n");
                    add_cors(&mut resp);
                    let _ = rq.respond(resp);
                    continue;
                }
            };

            let mut body = String::new();
            rq.as_reader().read_to_string(&mut body).ok();

            let parsed: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => {
                    let mut resp = resp_text(400, format!("bad json: {e}\n"));
                    add_cors(&mut resp);
                    let _ = rq.respond(resp);
                    continue;
                }
            };

            let user_label = parsed
                .get("user_label")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();

            let analyst_note = parsed
                .get("analyst_note")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let updated_by = parsed
                .get("updated_by")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let local_path = parsed
                .get("local_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if user_label.is_empty() {
                let mut resp = resp_text(400, "missing user_label\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            }

            sqlite.update_screenshot_user_label(
                screenshot_id,
                &user_label,
                analyst_note.as_deref(),
                updated_by.as_deref(),
            )?;

            if !local_path.trim().is_empty() {
                let shot = sqlite.find_screenshot_by_local_path(&local_path)?;
                sqlite.insert_screenshot_annotation(&NewScreenshotAnnotation {
                    screenshot_id: shot.as_ref().map(|s| s.id),
                    local_path: local_path.clone(),
                    user_label: user_label.clone(),
                    analyst_note: analyst_note.clone(),
                    updated_by: updated_by.clone(),
                })?;
            }

            let ann_path = out_dir.join("annotations.csv");
            export_annotations_csv_from_db(sqlite, &ann_path)?;

            let mut resp = resp_text(200, "ok\n");
            add_cors(&mut resp);
            let _ = rq.respond(resp);
            continue;
        }

        if path_only == "/api/annotations" && rq.method() == &Method::Post {
            let mut body = String::new();
            rq.as_reader().read_to_string(&mut body).ok();

            if body.len() > 20 * 1024 * 1024 {
                let mut resp = resp_text(413, "413\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            }

            let ann_path = out_dir.join("annotations.csv");
            let tmp_path = out_dir.join("annotations.csv.tmp");

            fs::write(&tmp_path, body.as_bytes()).and_then(|_| fs::rename(&tmp_path, &ann_path))?;

            if let Some(sqlite) = &sqlite {
                sync_annotations_csv_to_db(&ann_path, sqlite)?;
                export_annotations_csv_from_db(sqlite, &ann_path)?;
            }

            let mut resp = resp_text(200, "ok\n");
            add_cors(&mut resp);
            let _ = rq.respond(resp);
            continue;
        }

        if path_only == "/api/jsonl" && rq.method() == &Method::Get {
            let file = get_query_param(&url, "file")
                .or_else(|| get_query_param(&url, "path"))
                .unwrap_or_default();

            if file.trim().is_empty() {
                let mut resp = resp_text(400, "missing ?file=\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            }

            let rel = sanitize_rel(file.trim());
            if rel.is_empty() {
                let mut resp = resp_text(400, "bad file path\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            }

            let Some(fs_path) = find_fs_path(&rel, &roots) else {
                let mut resp = resp_text(404, "not found\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            };

            let bytes = fs::read(&fs_path)?;

            let mut resp = Response::from_data(bytes).with_status_code(200);
            add_cors(&mut resp);
            add_header(
                &mut resp,
                "Content-Type",
                "application/x-ndjson; charset=utf-8",
            );
            let _ = rq.respond(resp);
            continue;
        }

        if path_only == "/api/relpath" && rq.method() == &Method::Get {
            let abs_raw = get_query_param(&url, "abs").unwrap_or_default();
            if abs_raw.trim().is_empty() {
                let mut resp = resp_text(400, "missing ?abs=\n");
                add_cors(&mut resp);
                let _ = rq.respond(resp);
                continue;
            }

            let mut abs_s = abs_raw.trim().to_string();
            if let Some(rest) = abs_s.strip_prefix("file://") {
                abs_s = rest.to_string();
            }

            let abs_path = PathBuf::from(abs_s);

            let out_json = if let Some(rel) = rel_from_abs(&abs_path, &roots) {
                format!("{{\"ok\":true,\"rel\":\"{}\"}}", json_escape(&rel))
            } else {
                format!("{{\"ok\":false}}")
            };

            let mut resp = resp_text(200, out_json);
            add_cors(&mut resp);
            add_header(&mut resp, "Content-Type", "application/json; charset=utf-8");
            let _ = rq.respond(resp);
            continue;
        }

        let mut req_path = path_only.trim_start_matches('/').to_string();
        if req_path.is_empty() || req_path.ends_with('/') {
            req_path.push_str("index.html");
        }

        let req_path = sanitize_rel(&req_path);
        if req_path.is_empty() {
            let resp = resp_text(400, "400\n");
            let _ = rq.respond(resp);
            continue;
        }

        let chosen = find_fs_path(&req_path, &roots);

        let mut resp = if let Some(fs_path) = &chosen {
            match fs::read(fs_path) {
                Ok(bytes) => Response::from_data(bytes).with_status_code(200),
                Err(e) => resp_text(500, format!("500: {e}\n")),
            }
        } else {
            resp_text(404, "404\n")
        };

        let mime = if req_path.ends_with(".html") {
            Some("text/html; charset=utf-8")
        } else if req_path.ends_with(".csv") {
            Some("text/csv; charset=utf-8")
        } else if req_path.ends_with(".json") {
            Some("application/json; charset=utf-8")
        } else if req_path.ends_with(".jsonl") || req_path.ends_with(".ndjson") {
            Some("application/x-ndjson; charset=utf-8")
        } else if req_path.ends_with(".js") {
            Some("application/javascript; charset=utf-8")
        } else if req_path.ends_with(".css") {
            Some("text/css; charset=utf-8")
        } else if req_path.ends_with(".png") {
            Some("image/png")
        } else if req_path.ends_with(".jpg") || req_path.ends_with(".jpeg") {
            Some("image/jpeg")
        } else if req_path.ends_with(".webp") {
            Some("image/webp")
        } else {
            None
        };

        if let Some(m) = mime {
            add_header(&mut resp, "Content-Type", m);
        }

        let _ = rq.respond(resp);
    }

    Ok(())
}

fn find_sqlite_in_roots(roots: &[PathBuf]) -> Option<PathBuf> {
    for r in roots {
        let p = r.join("webhound.db");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn sync_annotations_csv_to_db(path: &Path, sqlite: &SqliteStorage) -> Result<()> {
    let mut rdr = csv::Reader::from_path(path)?;
    let headers = rdr.headers()?.clone();

    let path_idx = headers
        .iter()
        .position(|h| matches!(h, "file" | "path" | "image" | "local_path"))
        .ok_or_else(|| anyhow!("annotations.csv: no file/path/local_path column"))?;

    let label_idx = headers
        .iter()
        .position(|h| matches!(h, "label" | "user_label" | "class"))
        .ok_or_else(|| anyhow!("annotations.csv: no label column"))?;

    let note_idx = headers.iter().position(|h| matches!(h, "note" | "analyst_note"));
    let updated_by_idx = headers.iter().position(|h| matches!(h, "updated_by" | "user" | "who"));

    for rec in rdr.records() {
        let rec = rec?;
        let local_path = rec.get(path_idx).unwrap_or("").to_string();
        let user_label = rec.get(label_idx).unwrap_or("").trim().to_string();

        if local_path.is_empty() || user_label.is_empty() {
            continue;
        }

        let analyst_note = note_idx.and_then(|i| rec.get(i)).map(|s| s.to_string());
        let updated_by = updated_by_idx.and_then(|i| rec.get(i)).map(|s| s.to_string());

        if let Some(shot) = sqlite.find_screenshot_by_local_path(&local_path)? {
            sqlite.update_screenshot_user_label(
                shot.id,
                &user_label,
                analyst_note.as_deref(),
                updated_by.as_deref(),
            )?;
        }

        let shot = sqlite.find_screenshot_by_local_path(&local_path)?;
        sqlite.insert_screenshot_annotation(&NewScreenshotAnnotation {
            screenshot_id: shot.as_ref().map(|s| s.id),
            local_path: local_path.clone(),
            user_label: user_label.clone(),
            analyst_note: analyst_note.clone(),
            updated_by: updated_by.clone(),
        })?;
    }

    Ok(())
}

fn export_annotations_csv_from_db(sqlite: &SqliteStorage, out_csv: &Path) -> Result<()> {
    let runs = sqlite.list_scan_runs()?;
    let latest_run = runs.into_iter().next().map(|r| r.0);

    let Some(run_id) = latest_run else {
        if let Some(parent) = out_csv.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut wtr = csv::Writer::from_path(out_csv)?;
        wtr.write_record(["local_path", "user_label", "analyst_note"])?;
        wtr.flush()?;
        return Ok(());
    };

    let rows = sqlite.list_screenshots_simple(run_id)?;

    if let Some(parent) = out_csv.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut wtr = csv::Writer::from_path(out_csv)?;
    wtr.write_record(["local_path", "user_label"])?;

    for (_id, _page_url, local_path, _ml_label, _ml_score, user_label) in rows {
        if let Some(label) = user_label {
            if !label.trim().is_empty() {
                wtr.write_record([local_path, label])?;
            }
        }
    }

    wtr.flush()?;
    Ok(())
}
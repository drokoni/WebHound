use anyhow::{anyhow, Result};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub fn server(out_dir: &Path, port: u16) -> Result<()> {
    use tiny_http::{Header, Method, Response, Server};

    let server =
        Server::http(format!("127.0.0.1:{port}")).map_err(|e| anyhow!("Server::http: {e}"))?;

    println!("Report available at: http://127.0.0.1:{port}/");
    println!("Serving report from: {}", out_dir.display());

    // roots = report/, parent/, grandparent/
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

    fn sanitize_rel(mut s: &str) -> String {
        // strip query/hash, leading '/'
        if let Some(p) = s.find('?') {
            s = &s[..p];
        }
        if let Some(p) = s.find('#') {
            s = &s[..p];
        }
        let mut s = s.trim_start_matches('/');

        // IMPORTANT: remove any leading ../ (any count)
        while s.starts_with("../") {
            s = &s[3..];
        }

        // disallow backslashes and ".." segments inside
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
                // percent decode
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

    // Try to convert abs path to rel path under roots
    fn rel_from_abs(abs: &Path, roots: &[PathBuf]) -> Option<String> {
        // try canonical (if exists), else raw
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
        None
    }

    for mut rq in server.incoming_requests() {
        let url = rq.url().to_string();
        let path_only = url.split('?').next().unwrap_or(&url);

        // OPTIONS preflight for API
        if rq.method() == &Method::Options && path_only.starts_with("/api/") {
            let mut resp = Response::from_data(Vec::<u8>::new()).with_status_code(204);
            add_cors(&mut resp);
            add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
            let _ = rq.respond(resp);
            continue;
        }

        // API: save annotations.csv
        if path_only == "/api/annotations" && rq.method() == &Method::Post {
            let mut body = String::new();
            rq.as_reader().read_to_string(&mut body).ok();

            if body.len() > 20 * 1024 * 1024 {
                let mut resp = resp_text(413, "413\n");
                add_cors(&mut resp);
                add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
                let _ = rq.respond(resp);
                continue;
            }

            let ann_path = out_dir.join("annotations.csv");
            let tmp_path = out_dir.join("annotations.csv.tmp");

            if let Err(e) =
                fs::write(&tmp_path, body.as_bytes()).and_then(|_| fs::rename(&tmp_path, &ann_path))
            {
                let mut resp = resp_text(500, format!("500: {e}\n"));
                add_cors(&mut resp);
                add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
                let _ = rq.respond(resp);
                continue;
            }

            let mut resp = resp_text(200, "ok\n");
            add_cors(&mut resp);
            add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
            let _ = rq.respond(resp);
            continue;
        }

        // API: serve jsonl (ndjson)
        // GET /api/jsonl?file=../../sensitive_info.post.jsonl
        if path_only == "/api/jsonl" && rq.method() == &Method::Get {
            let file = get_query_param(&url, "file")
                .or_else(|| get_query_param(&url, "path"))
                .unwrap_or_default();

            if file.trim().is_empty() {
                let mut resp = resp_text(400, "missing ?file=\n");
                add_cors(&mut resp);
                add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
                let _ = rq.respond(resp);
                continue;
            }

            // allow ../.. in UI, but we sanitize and search in roots
            let rel = sanitize_rel(file.trim());
            if rel.is_empty() {
                let mut resp = resp_text(400, "bad file path\n");
                add_cors(&mut resp);
                add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
                let _ = rq.respond(resp);
                continue;
            }

            let Some(fs_path) = find_in_roots(&rel, &roots) else {
                let mut resp = resp_text(404, "not found\n");
                add_cors(&mut resp);
                add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
                let _ = rq.respond(resp);
                continue;
            };

            let bytes = match fs::read(&fs_path) {
                Ok(b) => b,
                Err(e) => {
                    let mut resp = resp_text(500, format!("500: {e}\n"));
                    add_cors(&mut resp);
                    add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
                    let _ = rq.respond(resp);
                    continue;
                }
            };

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

        // API: map abs file path -> rel url under roots (best-effort)
        // GET /api/relpath?abs=file:///home/user/work/ml/dataset/html/a.html
        if path_only == "/api/relpath" && rq.method() == &Method::Get {
            let abs_raw = get_query_param(&url, "abs").unwrap_or_default();
            if abs_raw.trim().is_empty() {
                let mut resp = resp_text(400, "missing ?abs=\n");
                add_cors(&mut resp);
                add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
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

        // -------- static files --------
        let mut req_path = path_only.trim_start_matches('/').to_string();
        if req_path.is_empty() || req_path.ends_with('/') {
            req_path.push_str("index.html");
        }

        let req_path = sanitize_rel(&req_path);
        if req_path.is_empty() {
            let mut resp = resp_text(400, "400\n");
            add_header(&mut resp, "Content-Type", "text/plain; charset=utf-8");
            let _ = rq.respond(resp);
            continue;
        }

        let chosen = find_in_roots(&req_path, &roots);

        let mut resp = if let Some(fs_path) = &chosen {
            match fs::read(fs_path) {
                Ok(bytes) => Response::from_data(bytes).with_status_code(200),
                Err(e) => resp_text(500, format!("500: {e}\n")),
            }
        } else {
            resp_text(404, "404\n")
        };

        // mime
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

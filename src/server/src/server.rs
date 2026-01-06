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

    let parent = out_dir.parent().map(Path::to_path_buf);
    if let Some(p) = &parent {
        println!("Also serving files from parent: {}", p.display());
    }

    for mut rq in server.incoming_requests() {
        // API: сохранить annotations.csv
        if rq.method() == &Method::Post && rq.url().split('?').next() == Some("/api/annotations") {
            let mut body = String::new();
            rq.as_reader().read_to_string(&mut body).ok();

            // простой лимит, чтобы не улететь в память случайно
            if body.len() > 20 * 1024 * 1024 {
                let resp = Response::from_string("413\n").with_status_code(413);
                let _ = rq.respond(resp);
                continue;
            }

            let ann_path = out_dir.join("annotations.csv");
            let tmp_path = out_dir.join("annotations.csv.tmp");

            if let Err(e) =
                fs::write(&tmp_path, body.as_bytes()).and_then(|_| fs::rename(&tmp_path, &ann_path))
            {
                let resp = Response::from_string(format!("500: {e}\n")).with_status_code(500);
                let _ = rq.respond(resp);
                continue;
            }

            let mut resp = Response::from_string("ok\n").with_status_code(200);
            if let Ok(h) = Header::from_bytes("Content-Type", "text/plain") {
                resp.add_header(h);
            }
            let _ = rq.respond(resp);
            continue;
        }

        // обычная раздача файлов
        let raw = rq.url();
        let raw = raw.split('?').next().unwrap_or(raw);
        let raw = raw.split('#').next().unwrap_or(raw);

        let mut req_path = raw.trim_start_matches('/').to_string();
        if req_path.is_empty() || req_path.ends_with('/') {
            req_path.push_str("index.html");
        }

        while req_path.starts_with("../") {
            req_path = req_path[3..].to_string();
        }

        if req_path
            .split('/')
            .any(|seg| seg == ".." || seg.contains('\\') || seg.is_empty())
        {
            let resp = Response::from_string("400\n").with_status_code(400);
            let _ = rq.respond(resp);
            continue;
        }

        let mut chosen: Option<PathBuf> = None;

        let cand1 = out_dir.join(&req_path);
        if cand1.is_file() {
            chosen = Some(cand1);
        } else if let Some(parent_dir) = &parent {
            let cand2 = parent_dir.join(&req_path);
            if cand2.is_file() {
                chosen = Some(cand2);
            }
        }

        let mut resp = if let Some(fs_path) = &chosen {
            match fs::read(fs_path) {
                Ok(bytes) => Response::from_data(bytes),
                Err(e) => Response::from_string(format!("500: {e}\n")).with_status_code(500),
            }
        } else {
            Response::from_string("404\n").with_status_code(404)
        };

        let mime = if req_path.ends_with(".html") {
            Some("text/html")
        } else if req_path.ends_with(".csv") {
            Some("text/csv")
        } else if req_path.ends_with(".js") {
            Some("application/javascript")
        } else if req_path.ends_with(".css") {
            Some("text/css")
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
            if let Ok(h) = Header::from_bytes("Content-Type", m) {
                resp.add_header(h);
            }
        }

        let _ = rq.respond(resp);
    }

    Ok(())
}

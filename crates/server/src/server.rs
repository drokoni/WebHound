use anyhow::{Result, anyhow};
use std::{
    fs,
    path::{Path},
};

pub fn server(out_dir: &Path, port: u16) -> Result<()> {
    use tiny_http::{Header, Response, Server};

    let server =
        Server::http(format!("127.0.0.1:{port}")).map_err(|e| anyhow!("Server::http: {e}"))?;
    println!("Report available at: http://127.0.0.1:{port}/");
    println!("Serving from: {}", out_dir.display());
    let parent = out_dir.parent().map(Path::to_path_buf);

    for rq in server.incoming_requests() {
        let raw = rq.url();
        let raw = raw.split('?').next().unwrap_or(raw);
        let raw = raw.split('#').next().unwrap_or(raw);

        let mut req_path = raw.trim_start_matches('/').to_string();
        if req_path.is_empty() || req_path.ends_with('/') {
            req_path.push_str("index.html");
        }

        while let Some(pos) = req_path.find("/../") {
            if let Some(prev) = req_path[..pos].rfind('/') {
                req_path.replace_range(prev..pos + 4, "");
            } else {
                req_path.replace_range(0..pos + 4, "");
            }
        }

        let fs_path = if req_path.starts_with("../") {
            let mut rest = req_path.as_str();
            while rest.starts_with("../") {
                rest = &rest[3..];
            }
            if let Some(ref parent_dir) = parent {
                parent_dir.join(rest)
            } else {
                out_dir.join(rest)
            }
        } else {
            out_dir.join(&req_path)
        };

        let mut resp = if fs_path.is_file() {
            match fs::read(&fs_path) {
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

        eprintln!("[{}] {} -> {}", rq.method(), raw, fs_path.display());
        let _ = rq.respond(resp);
    }

    Ok(())
}

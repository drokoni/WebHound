use anyhow::Result as AnyResult;
use crate::sensitive_jsonl::{write_analysis_samples_from_text, SensitiveSink};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

pub async fn postfilter_assets_dir(
    assets_dir: &Path,
    sink: &SensitiveSink,
) -> AnyResult<()> {
    let files = collect_files_recursive(assets_dir)?;

    for p in files {
        let data = match read_file_limited(&p, 2 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if !is_probably_text(&data) {
            continue;
        }

        let text = String::from_utf8_lossy(&data).to_string();

        let abs = p.canonicalize().unwrap_or_else(|_| p.clone());
        let path_str = format!("file://{}", abs.display());

        write_analysis_samples_from_text(sink, &path_str, &text, "postfilter").await?;
    }

    Ok(())
}

/// Удобная обёртка: постфильтрация assets_dir и запись результата в out_file.
pub async fn postfilter_assets_dir_to_file(assets_dir: &Path, out_file: &Path) -> AnyResult<()> {
    if let Some(parent) = out_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let f = File::create(out_file)?;
    let info_file = std::sync::Arc::new(tokio::sync::Mutex::new(f));
    let sink = SensitiveSink::new(Some(info_file), None, None);

    postfilter_assets_dir(assets_dir, &sink).await
}

fn collect_files_recursive(root: &Path) -> AnyResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    visit_dir(root, &mut out)?;
    Ok(out)
}

fn visit_dir(dir: &Path, out: &mut Vec<PathBuf>) -> AnyResult<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };

    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };

        let p = ent.path();
        let md = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if md.is_dir() {
            let _ = visit_dir(&p, out);
        } else if md.is_file() {
            out.push(p);
        }
    }

    Ok(())
}

fn read_file_limited(path: &Path, limit: usize) -> AnyResult<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    buf.reserve(limit.min(64 * 1024));

    let mut chunk = [0u8; 64 * 1024];
    let mut read_total = 0usize;

    loop {
        if read_total >= limit {
            break;
        }

        let to_read = (limit - read_total).min(chunk.len());
        let n = f.read(&mut chunk[..to_read])?;
        if n == 0 {
            break;
        }

        buf.extend_from_slice(&chunk[..n]);
        read_total += n;
    }

    Ok(buf)
}

fn is_probably_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    let sample_len = data.len().min(2048);
    let mut weird = 0usize;

    for &b in &data[..sample_len] {
        if b == b'\n' || b == b'\r' || b == b'\t' {
            continue;
        }
        if !(0x20..=0x7E).contains(&b) {
            weird += 1;
        }
    }

    weird * 20 < sample_len
}
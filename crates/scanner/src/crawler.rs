use core::patterns::{PATTERNS, should_ignore_path, should_ignore_value};
use core::utils::{sanitize_filename, save_bytes};

use crate::analysis::PathsLike;
use crate::net::fetch_live_or_wayback;
use crate::screenshot::make_screenshot_task;

use anyhow::Result as AnyResult;
use reqwest::Client;
use select::{document::Document, predicate::Attr};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{sync::Mutex, task};
use url::Url;

const TEXT_EXTS: &[&str] = &[
    "html", "htm", "shtml", "xhtml", "php", "asp", "aspx", "jsp",
    "txt", "js", "json", "xml", "csv", "ini", "conf", "config",
    "env", "yaml", "yml", "log", "bak", "old", "sql",
];

const INTERESTING_NAMES: &[&str] = &["robots.txt", "sitemap.xml"];

const ARCHIVE_EXTS: &[&str] = &["zip", "tar", "tgz", "gz", "bz2", "xz"];


pub async fn process_single_url(
    client: &Client,
    url: &str,
    paths: &impl PathsLike,
    info_file: &Arc<Mutex<File>>,
) -> AnyResult<()> {
    if should_ignore_path(url) {
        return Ok(());
    }

    let (body, final_url, _from_wayback) = match fetch_live_or_wayback(client, url).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Ошибка загрузки {url}: {e}");
            return Ok(());
        }
    };

    let main_ext = detect_ext(&final_url).unwrap_or_else(|| "bin".to_string());
    let main_path = asset_path_for(&final_url, &main_ext, paths);
    save_bytes(&main_path, &body)?;
    analyze_bytes_with_rules(&body, &final_url, info_file).await?;

    if ARCHIVE_EXTS.contains(&main_ext.as_str()) {
        analyze_archive_file(&main_path, &final_url, paths, info_file).await?;
    }

    if is_html_ext(&main_ext) {
        if let Ok(text) = std::str::from_utf8(&body) {
            let mut to_visit = extract_links(text, &final_url);

            if let Some(root) = root_of(&final_url) {
                for name in INTERESTING_NAMES {
                    to_visit.insert(format!("{}/{}", root.trim_end_matches('/'), name));
                }
            }

            let mut seen = HashSet::new();

            for u in to_visit.into_iter() {
                if !seen.insert(u.clone()) {
                    continue;
                }
                if should_ignore_path(&u) {
                    continue;
                }

                if let Ok((data, used_u, _)) = fetch_live_or_wayback(client, &u).await {
                    let ext = detect_ext(&used_u).unwrap_or_else(|| "bin".to_string());
                    let path = asset_path_for(&used_u, &ext, paths);
                    save_bytes(&path, &data)?;
                    analyze_bytes_with_rules(&data, &used_u, info_file).await?;

                    if ARCHIVE_EXTS.contains(&ext.as_str()) {
                        analyze_archive_file(&path, &used_u, paths, info_file).await?;
                    }

                    spawn_screenshot(&used_u, paths);
                }
            }
        }
    }

    spawn_screenshot(&final_url, paths);

    Ok(())
}



fn spawn_screenshot(url: &str, paths: &impl PathsLike) {
    let url = url.to_string();
    let screenshots_dir = paths.screenshots_dir().to_path_buf();

    task::spawn(async move {
        if let Err(e) = make_screenshot_task(&url, &screenshots_dir).await {
            eprintln!("Ошибка скриншота {url}: {e}");
        }
    });
}



fn detect_ext(u: &str) -> Option<String> {
    Url::parse(u)
        .ok()
        .and_then(|url| {
            let path = url.path();
            let name = path.rsplit('/').next().unwrap_or("");
            if let Some((_, ext)) = name.rsplit_once('.') {
                Some(ext.to_ascii_lowercase())
            } else {
                None
            }
        })
}

fn is_html_ext(ext: &str) -> bool {
    matches!(
        ext,
        "html" | "htm" | "shtml" | "xhtml" | "php" | "asp" | "aspx" | "jsp"
    )
}

fn asset_path_for(url: &str, ext: &str, paths: &impl PathsLike) -> PathBuf {
    let safe = sanitize_filename(url);

    // JS как и раньше — отдельная директория
    if ext == "js" {
        return paths.jsscripts_dir().join(format!("{safe}.js"));
    }

    let subdir = if TEXT_EXTS.contains(&ext) || ARCHIVE_EXTS.contains(&ext) {
        ext
    } else {
        "bin"
    };

    paths
        .assets_dir()
        .join(subdir)
        .join(format!("{safe}.{ext}"))
}

fn root_of(url: &str) -> Option<String> {
    let u = Url::parse(url).ok()?;
    let scheme = u.scheme();
    let host = u.host_str()?;
    Ok(format!("{scheme}://{host}"))
}



fn extract_links(html: &str, base_url: &str) -> HashSet<String> {
    let base = match Url::parse(base_url) {
        Ok(b) => b,
        Err(_) => return HashSet::new(),
    };

    let doc = Document::from(html);
    let mut out = HashSet::new();

    for node in doc.find(Attr("href", ())) {
        if let Some(href) = node.attr("href") {
            if let Some(u) = normalize_url(&base, href) {
                out.insert(u);
            }
        }
    }

    for node in doc.find(Attr("src", ())) {
        if let Some(src) = node.attr("src") {
            if let Some(u) = normalize_url(&base, src) {
                out.insert(u);
            }
        }
    }

    out
}

fn normalize_url(base: &Url, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('#')
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("data:")
    {
        return None;
    }

    let u = if let Ok(abs) = Url::parse(trimmed) {
        abs
    } else if let Ok(joined) = base.join(trimmed) {
        joined
    } else {
        return None;
    };

    Some(u.to_string())
}



async fn analyze_bytes_with_rules(
    bytes: &[u8],
    url: &str,
    info_file: &Arc<Mutex<File>>,
) -> AnyResult<()> {
    if !is_probably_text(bytes) {
        return Ok(());
    }

    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };

    let hits = scan_patterns(text, url);

    if hits.is_empty() {
        return Ok(());
    }

    use std::io::Write;
    let mut f = info_file.lock().await;

    writeln!(f, "{url}")?;
    for (k, v) in hits {
        let (h, total_bits, len) = shannon_entropy(v.as_bytes());
        let h_r = (h * 100.0).round() / 100.0;
        let total_r = (total_bits * 100.0).round() / 100.0;
        writeln!(
            f,
            "  - [{}] Найдено: {} | len={} | H≈{} bits/char | total≈{} bits",
            k, v, len, h_r, total_r
        )?;
    }

    Ok(())
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

    weird * 10 < sample_len
}

fn scan_patterns(text: &str, url: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for spec in PATTERNS.iter() {
        for m in spec.re.captures_iter(text) {
            let m0 = match m.get(0) {
                Some(v) => v.as_str(),
                None => continue,
            };

            if should_ignore_value(m0) {
                continue;
            }

            let key = spec.name.clone();
            result.push((key, m0.to_string()));
        }
    }

    if result.is_empty() {
        let _ = url;
    }

    result
}

fn shannon_entropy(bytes: &[u8]) -> (f64, f64, usize) {
    if bytes.is_empty() {
        return (0.0, 0.0, 0);
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in bytes {
        *freq.entry(b).or_insert(0) += 1;
    }

    let n = bytes.len() as f64;
    let mut h = 0.0f64;

    for &count in freq.values() {
        let p = (count as f64) / n;
        h -= p * p.log2();
    }

    let total_bits = h * n;
    (h, total_bits, bytes.len())
}



async fn analyze_archive_file(
    archive_path: &Path,
    base_url: &str,
    paths: &impl PathsLike,
    info_file: &Arc<Mutex<File>>,
) -> AnyResult<()> {
    let archive_path = archive_path.to_path_buf();
    let base_url = base_url.to_string();
    let assets_root = paths.assets_dir().to_path_buf();

    let extracted_hits = task::spawn_blocking(move || -> AnyResult<Vec<(String, String)>> {
        let ext = archive_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut all_hits = Vec::new();

        match ext.as_str() {
            "zip" => analyze_zip(&archive_path, &base_url, &assets_root, &mut all_hits)?,
            "tar" | "tgz" | "gz" | "bz2" | "xz" => {
                analyze_tar_like(&archive_path, &base_url, &assets_root, &ext, &mut all_hits)?
            }
            _ => {}
        }

        Ok(all_hits)
    })
    .await??;

    if !extracted_hits.is_empty() {
        use std::io::Write;
        let mut f = info_file.lock().await;

        writeln!(f, "{base_url} (архив)")?;
        for (k, v) in extracted_hits {
            let (h, total_bits, len) = shannon_entropy(v.as_bytes());
            let h_r = (h * 100.0).round() / 100.0;
            let total_r = (total_bits * 100.0).round() / 100.0;
            writeln!(
                f,
                "  - [{}] Найдено: {} | len={} | H≈{} bits/char | total≈{} bits",
                k, v, len, h_r, total_r
            )?;
        }
    }

    Ok(())
}

fn analyze_zip(
    path: &Path,
    base_url: &str,
    assets_root: &Path,
    all_hits: &mut Vec<(String, String)>,
) -> AnyResult<()> {
    let file = File::open(path)?;
    let mut zip = zip::ZipArchive::new(file)?;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if !entry.is_file() {
            continue;
        }

        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;

        let name = entry.name().to_string();
        let ext = name
            .rsplit('.')
            .next()
            .unwrap_or("bin")
            .to_ascii_lowercase();

        let virt_url = format!("{base_url}!{name}");
        let save_path = build_asset_path_from_parts(&virt_url, &ext, assets_root);
        save_bytes(&save_path, &data)?;

        if is_probably_text(&data) {
            if let Ok(text) = std::str::from_utf8(&data) {
                let hits = scan_patterns(text, &virt_url);
                all_hits.extend(hits);
            }
        }
    }

    Ok(())
}

fn analyze_tar_like(
    path: &Path,
    base_url: &str,
    assets_root: &Path,
    ext: &str,
    all_hits: &mut Vec<(String, String)>,
) -> AnyResult<()> {
    use bzip2::read::BzDecoder;
    use flate2::read::GzDecoder;
    use tar::Archive;
    use xz2::read::XzDecoder;

    let file = File::open(path)?;
    let reader: Box<dyn Read> = match ext {
        "tar" => Box::new(file),
        "gz" | "tgz" => Box::new(GzDecoder::new(file)),
        "bz2" => Box::new(BzDecoder::new(file)),
        "xz" => Box::new(XzDecoder::new(file)),
        _ => Box::new(file),
    };

    let mut ar = Archive::new(reader);

    for entry in ar.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let path = match entry.path() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let name = path.to_string_lossy().to_string();
        let ext = name
            .rsplit('.')
            .next()
            .unwrap_or("bin")
            .to_ascii_lowercase();

        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;

        let virt_url = format!("{base_url}!{name}");
        let save_path = build_asset_path_from_parts(&virt_url, &ext, assets_root);
        save_bytes(&save_path, &data)?;

        if is_probably_text(&data) {
            if let Ok(text) = std::str::from_utf8(&data) {
                let hits = scan_patterns(text, &virt_url);
                all_hits.extend(hits);
            }
        }
    }

    Ok(())
}

fn build_asset_path_from_parts(url: &str, ext: &str, assets_root: &Path) -> PathBuf {
    let safe = sanitize_filename(url);
    let subdir = if TEXT_EXTS.contains(&ext) || ARCHIVE_EXTS.contains(&ext) {
        ext
    } else {
        "bin"
    };

    assets_root.join(subdir).join(format!("{safe}.{ext}"))
}


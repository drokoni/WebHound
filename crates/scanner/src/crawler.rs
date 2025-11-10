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

const ARCHIVE_EXTS: &[&str] = &["zip", "tar", "tgz", "gz", "bz2", "xz"];
const INTERESTING_NAMES: &[&str] = &["robots.txt", "sitemap.xml"];

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
            eprintln!("[!] Ошибка загрузки {url}: {e}");
            return Ok(());     
        }
    };

    handle_response_for_url(client, &final_url, body, paths, info_file).await;

    Ok(())
}

async fn handle_response_for_url(
    client: &Client,
    final_url: &str,
    body: Vec<u8>,
    paths: &impl PathsLike,
    info_file: &Arc<Mutex<File>>,
) {
    let ext = detect_ext(final_url).unwrap_or_else(|| "bin".to_string());

    if let Err(e) = save_bytes_safe(&asset_path_for(final_url, &ext, paths), &body) {
        eprintln!("[!] Ошибка сохранения {final_url}: {e}");
    }

    if let Err(e) = analyze_bytes_with_rules(&body, final_url, info_file).await {
        eprintln!("[!] Ошибка анализа содержимого {final_url}: {e}");
    }

    if ARCHIVE_EXTS.contains(&ext.as_str()) {
        if let Err(e) = analyze_archive_file(
            &asset_path_for(final_url, &ext, paths),
            final_url,
            paths,
            info_file,
        )
        .await
        {
            eprintln!("[!] Ошибка анализа архива {final_url}: {e}");
        }
    }

    if is_html_ext(&ext) {
        if let Ok(text) = std::str::from_utf8(&body) {
            handle_html_links(client, final_url, text, paths, info_file).await;
        }
    }

    spawn_screenshot(final_url, paths);
}

async fn handle_html_links(
    client: &Client,
    base_url: &str,
    html: &str,
    paths: &impl PathsLike,
    info_file: &Arc<Mutex<File>>,
) {
    let mut urls = extract_links(html, base_url);

    if let Some(root) = root_of(base_url) {
        for name in INTERESTING_NAMES {
            urls.insert(format!("{}/{}", root.trim_end_matches('/'), name));
        }
    }

    let mut seen = HashSet::new();

    for u in urls.into_iter() {
        if !seen.insert(u.clone()) {
            continue;
        }
        if should_ignore_path(&u) {
            continue;
        }

        match fetch_live_or_wayback(client, &u).await {
            Ok((data, real_u, _)) => {
                let ext = detect_ext(&real_u).unwrap_or_else(|| "bin".to_string());
                let path = asset_path_for(&real_u, &ext, paths);

                if let Err(e) = save_bytes_safe(&path, &data) {
                    eprintln!("[!] Ошибка сохранения {real_u}: {e}");
                }

                if let Err(e) = analyze_bytes_with_rules(&data, &real_u, info_file).await {
                    eprintln!("[!] Ошибка анализа содержимого {real_u}: {e}");
                }

                if ARCHIVE_EXTS.contains(&ext.as_str()) {
                    if let Err(e) =
                        analyze_archive_file(&path, &real_u, paths, info_file).await
                    {
                        eprintln!("[!] Ошибка анализа архива {real_u}: {e}");
                    }
                }

                spawn_screenshot(&real_u, paths);
            }
            Err(e) => {
                eprintln!("[!] Ошибка загрузки ресурса {u}: {e}");
            }
        }
    }
}



fn spawn_screenshot(url: &str, paths: &impl PathsLike) {
    let url = url.to_string();
    let dir = paths.screenshots_dir().to_path_buf();

    task::spawn(async move {
        if let Err(e) = make_screenshot_task(&url, &dir).await {
            eprintln!("[!] Ошибка скриншота {url}: {e}");
        }
    });
}


fn save_bytes_safe(path: &Path, data: &[u8]) -> AnyResult<()> {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Err(e.into());
        }
    }
    save_bytes(path, data)
}



fn detect_ext(u: &str) -> Option<String> {
    Url::parse(u).ok().and_then(|url| {
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
    Some(format!("{scheme}://{host}"))
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
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with('#')
        || s.starts_with("mailto:")
        || s.starts_with("javascript:")
        || s.starts_with("data:")
    {
        return None;
    }

    let u = if let Ok(abs) = Url::parse(s) {
        abs
    } else if let Ok(j) = base.join(s) {
        j
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

    let hits = scan_patterns(text);

    if hits.is_empty() {
        return Ok(());
    }

    use std::io::Write;
    let mut f = info_file.lock().await;
    writeln!(f, "{url}")?;
    for (rule_name, value) in hits {
        let (h, total_bits, len) = shannon_entropy(value.as_bytes());
        let h_r = (h * 100.0).round() / 100.0;
        let total_r = (total_bits * 100.0).round() / 100.0;
        writeln!(
            f,
            "  - [{}] Найдено: {} | len={} | H≈{} bits/char | total≈{} bits",
            rule_name, value, len, h_r, total_r
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

fn scan_patterns(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();

    for spec in PATTERNS.iter() {
        for cap in spec.re.captures_iter(text) {
            let m = match cap.get(0) {
                Some(v) => v.as_str(),
                None => continue,
            };

            if should_ignore_value(m) {
                continue;
            }

            out.push((spec.name.clone(), m.to_string()));
        }
    }

    out
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
    let mut h = 0.0;

    for &count in freq.values() {
        let p = count as f64 / n;
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

    let hits = task::spawn_blocking(move || -> AnyResult<Vec<(String, String)>> {
        let ext = archive_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut all_hits = Vec::new();

        match ext.as_str() {
            "zip" => analyze_zip(&archive_path, &base_url, &assets_root, &mut all_hits)?,
            "tar" | "gz" | "tgz" | "bz2" | "xz" => {
                analyze_tar_like(&archive_path, &base_url, &assets_root, &ext, &mut all_hits)?
            }
            _ => {}
        }

        Ok(all_hits)
    })
    .await??;

    if hits.is_empty() {
        return Ok(());
    }

    use std::io::Write;
    let mut f = info_file.lock().await;
    writeln!(f, "{base_url} (архив)")?;
    for (rule_name, value) in hits {
        let (h, total_bits, len) = shannon_entropy(value.as_bytes());
        let h_r = (h * 100.0).round() / 100.0;
        let total_r = (total_bits * 100.0).round() / 100.0;
        writeln!(
            f,
            "  - [{}] Найдено: {} | len={} | H≈{} bits/char | total≈{} bits",
            rule_name, value, len, h_r, total_r
        )?;
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
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.is_file() {
            continue;
        }

        let mut data = Vec::new();
        if entry.read_to_end(&mut data).is_err() {
            continue;
        }

        let name = entry.name().to_string();
        let ext = name
            .rsplit('.')
            .next()
            .unwrap_or("bin")
            .to_ascii_lowercase();

        let virt_url = format!("{base_url}!{name}");
        let save_path = build_asset_path_from_parts(&virt_url, &ext, assets_root);
        let _ = save_bytes_safe(&save_path, &data);

        if is_probably_text(&data) {
            if let Ok(text) = std::str::from_utf8(&data) {
                let hits = scan_patterns(text);
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
        let mut entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
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
        if entry.read_to_end(&mut data).is_err() {
            continue;
        }

        let virt_url = format!("{base_url}!{name}");
        let save_path = build_asset_path_from_parts(&virt_url, &ext, assets_root);
        let _ = save_bytes_safe(&save_path, &data);

        if is_probably_text(&data) {
            if let Ok(text) = std::str::from_utf8(&data) {
                let hits = scan_patterns(text);
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


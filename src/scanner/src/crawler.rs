use crate::net::fetch_live_or_wayback;
use crate::screenshot::make_screenshot_task;
use crate::sensitive_jsonl::{write_samples_from_text_jsonl, SensitiveSink};

use core::analysis::PathsLike;
use core::patterns::{scan_patterns, should_ignore_path, ScanHit};
use core::utils::{sanitize_filename, save_bytes};


use storage::NewScreenshot;
use sha2::{Digest, Sha256};
use anyhow::Result as AnyResult;
use reqwest::Client;
use select::{document::Document, predicate::Attr};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use tokio::task;
use url::Url;

/// Текстовые расширения (то, что имеет смысл гонять через PATTERNS/regex).
const TEXT_EXTS: &[&str] = &[
    "html", "htm", "shtml", "xhtml", "php", "asp", "aspx", "jsp", "txt", "js", "json", "xml",
    "csv", "ini", "conf", "config", "env", "yaml", "yml", "log", "bak", "old", "sql", "css",
];

const ARCHIVE_EXTS: &[&str] = &["zip", "tar", "tgz", "gz", "bz2", "xz"];
const INTERESTING_NAMES: &[&str] = &["robots.txt", "sitemap.xml"];

pub async fn process_single_url(
    client: &Client,
    url: &str,
    paths: &impl PathsLike,
    sink: &SensitiveSink,
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

    handle_response_for_url(client, &final_url, body, paths, sink).await;
    Ok(())
}

async fn handle_response_for_url(
    client: &Client,
    final_url: &str,
    body: Vec<u8>,
    paths: &impl PathsLike,
    sink: &SensitiveSink,
) {
    let ext = detect_ext(final_url)
        .or_else(|| {
            if looks_like_html(&body) {
                Some("html".to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "bin".to_string());

    let save_path = asset_path_for(final_url, &ext, paths);
    if let Err(e) = save_bytes_safe(&save_path, &body) {
        eprintln!("[!] Ошибка сохранения {final_url}: {e}");
    }

    if let Err(e) = analyze_bytes_with_rules(&body, final_url, &ext, sink).await {
        eprintln!("[!] Ошибка анализа содержимого {final_url}: {e}");
    }

    if ARCHIVE_EXTS.contains(&ext.as_str()) {
        if let Err(e) = analyze_archive_file(&save_path, final_url, paths, sink).await {
            eprintln!("[!] Ошибка анализа архива {final_url}: {e}");
        }
    }

    if is_html_ext(&ext) || looks_like_html(&body) {
        let text = String::from_utf8_lossy(&body);
        handle_html_links(client, final_url, &text, paths, sink).await;
    }

    spawn_screenshot(final_url, paths, sink);
}

async fn handle_html_links(
    client: &Client,
    base_url: &str,
    html: &str,
    paths: &impl PathsLike,
    sink: &SensitiveSink,
) {
    let mut urls = extract_links(html, base_url);

    // добавляем robots/sitemap для корня (с портом)
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
                let ext = detect_ext(&real_u)
                    .or_else(|| {
                        if looks_like_html(&data) {
                            Some("html".to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "bin".to_string());

                let path = asset_path_for(&real_u, &ext, paths);

                if let Err(e) = save_bytes_safe(&path, &data) {
                    eprintln!("[!] Ошибка сохранения {real_u}: {e}");
                }

                if let Err(e) = analyze_bytes_with_rules(&data, &real_u, &ext, sink).await {
                    eprintln!("[!] Ошибка анализа содержимого {real_u}: {e}");
                }

                if ARCHIVE_EXTS.contains(&ext.as_str()) {
                    if let Err(e) = analyze_archive_file(&path, &real_u, paths, sink).await {
                        eprintln!("[!] Ошибка анализа архива {real_u}: {e}");
                    }
                }

                spawn_screenshot(&real_u, paths, sink);
            }
            Err(e) => {
                eprintln!("[!] Ошибка загрузки ресурса {u}: {e}");
            }
        }
    }
}

fn spawn_screenshot(
    url: &str,
    paths: &impl PathsLike,
    sink: &crate::sensitive_jsonl::SensitiveSink,
) {
    let url = url.to_string();
    let dir = paths.screenshots_dir().to_path_buf();
    let sqlite = sink.sqlite.clone();
    let scan_run_id = sink.scan_run_id;

    tokio::task::spawn(async move {
        if let Err(e) = make_screenshot_task(&url, &dir).await {
            eprintln!("[!] Ошибка скриншота {url}: {e}");
            return;
        }

        let png_path = dir.join(format!("{}.png", core::utils::sanitize_filename(&url)));
        if !png_path.exists() {
            return;
        }

        if let (Some(sqlite), Some(scan_run_id)) = (sqlite, scan_run_id) {
            let meta = std::fs::metadata(&png_path).ok();
            let _ = sqlite.insert_screenshot(&NewScreenshot {
                scan_run_id,
                page_url: url.clone(),
                local_path: png_path.display().to_string(),
                image_sha256: sha256_hex_file(&png_path).ok(),
                width: None,
                height: None,
                file_size: meta.map(|m| m.len()),
                ml_model_name: None,
                ml_model_version: None,
                ml_label: None,
                ml_score: None,
                ml_scores_json: None,
                user_label: None,
                user_label_updated_at: None,
                user_label_updated_by: None,
                analyst_note: None,
            });
        }
    });
}

fn sha256_hex_file(path: &Path) -> anyhow::Result<String> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

fn save_bytes_safe(path: &Path, data: &[u8]) -> AnyResult<()> {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Err(e.into());
        }
    }
    save_bytes(path, data)
}

/// Берём ext только из path (без query) через url::Url
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

/// sniff: если начало похоже на HTML — считаем HTML даже без расширения
fn looks_like_html(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let n = body.len().min(2048);
    let s = String::from_utf8_lossy(&body[..n]).to_ascii_lowercase();

    s.contains("<!doctype html")
        || s.contains("<html")
        || s.contains("<head")
        || s.contains("<body")
}

/// Папка под каждое расширение: assets/<ext>/... (bin для неизвестного)
fn asset_path_for(url: &str, ext: &str, paths: &impl PathsLike) -> PathBuf {
    let safe = sanitize_filename(url);
    let dir = ext.to_ascii_lowercase();
    paths.assets_dir().join(dir).join(format!("{safe}.{ext}"))
}

/// root с учётом порта (важно для IP:PORT)
fn root_of(url: &str) -> Option<String> {
    let u = Url::parse(url).ok()?;
    let scheme = u.scheme();
    let host = u.host_str()?;
    let port = u.port();

    Some(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
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

/* ===========================
JSONL output (dataset-ready)
=========================== */

#[derive(Debug, Clone, Serialize)]
struct JsonlSpan {
    start: usize,  // char offset in "text"
    end: usize,    // char offset in "text"
    label: String, // PASSWORD/API_KEY/TOKEN/JWT/PRIVATE_KEY
    rule_name: String,
    value: String,
    len: usize,
    entropy_h: f64,
    entropy_total_bits: f64,
}

#[derive(Debug, Clone, Serialize)]
struct JsonlRecord {
    schema: u8,
    kind: String, // "line" | "block"
    path: String, // url или file://... или base_url!entry
    line: Option<u32>,
    text: String,
    spans: Vec<JsonlSpan>,
}

fn label_from_rule(rule_name: &str) -> Option<&'static str> {
    let r = rule_name.to_ascii_lowercase();

    if r.contains("private key") {
        return Some("PRIVATE_KEY");
    }
    if r.contains("json web token") || r.contains("jwt") {
        return Some("JWT");
    }
    if r.contains("password") || r.contains("passphrase") || r.contains("парол") {
        return Some("PASSWORD");
    }
    if r.contains("api key")
        || r.contains("apikey")
        || r.contains("client secret")
        || r.contains("secret key")
        || r.contains("access key")
        || r.contains("credentials")
    {
        return Some("API_KEY");
    }
    if r.contains("token") || r.contains("bearer") {
        return Some("TOKEN");
    }

    None
}

fn byte_to_char_idx(s: &str, byte_idx: usize) -> usize {
    // byte_idx должен быть на границе UTF-8 (у нас так и есть, т.к. ищем подстроки в str)
    s[..byte_idx].chars().count()
}

fn candidates_for_search(value: &str) -> Vec<String> {
    vec![
        value.to_string(),
        format!("\"{}\"", value),
        format!("'{}'", value),
        format!("`{}`", value),
    ]
}

/// Найти needle в text, начиная с `from`, не пересекась с used.
fn find_next_nonoverlapping(
    text: &str,
    needle: &str,
    mut from: usize,
    used: &mut Vec<(usize, usize)>,
) -> Option<(usize, usize)> {
    if needle.is_empty() {
        return None;
    }

    // ensure from is char boundary
    if from > text.len() {
        return None;
    }
    while from < text.len() && !text.is_char_boundary(from) {
        from += 1;
    }

    while from <= text.len() {
        let pos = text[from..].find(needle)?;
        let s = from + pos;
        let e = s + needle.len();

        let overlaps = used.iter().any(|(us, ue)| s < *ue && e > *us);
        if !overlaps {
            used.push((s, e));
            return Some((s, e));
        }

        from = s + 1;
        while from < text.len() && !text.is_char_boundary(from) {
            from += 1;
        }
    }
    None
}

fn line_context(text: &str, start_b: usize, end_b: usize) -> (u32, &str, usize, usize) {
    let line_start = text[..start_b].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = text[end_b..]
        .find('\n')
        .map(|i| end_b + i)
        .unwrap_or(text.len());

    let line_str = &text[line_start..line_end];
    let line_no = (text[..line_start].bytes().filter(|&b| b == b'\n').count() as u32) + 1;

    let rel_s_b = start_b - line_start;
    let rel_e_b = end_b - line_start;

    let rel_s_c = byte_to_char_idx(line_str, rel_s_b);
    let rel_e_c = byte_to_char_idx(line_str, rel_e_b);

    (line_no, line_str, rel_s_c, rel_e_c)
}

/// Превращает hits в JSONL записи:
/// - block для PRIVATE_KEY (если value содержит BEGIN/END)
/// - line для остальных (ищем value в тексте и вычисляем start/end)
fn hits_to_jsonl_lines(path: &str, full_text: &str, hits: &[ScanHit]) -> Vec<String> {
    let mut used_ranges: Vec<(usize, usize)> = Vec::new();

    let mut by_line: HashMap<u32, (String, Vec<JsonlSpan>)> = HashMap::new();
    let mut out_lines: Vec<String> = Vec::new();

    for hit in hits {
        let label = match label_from_rule(&hit.rule_name) {
            Some(l) => l,
            None => continue,
        };

        let h_r = (hit.entropy * 100.0).round() / 100.0;
        let total_r = (hit.total_bits * 100.0).round() / 100.0;

        // PRIVATE_KEY: часто многострочный — сохраняем block отдельно
        if label == "PRIVATE_KEY" && hit.value.contains("BEGIN") && hit.value.contains("END") {
            let text = hit.value.clone();
            let text_len_chars = text.chars().count();

            let span = JsonlSpan {
                start: 0,
                end: text_len_chars,
                label: label.to_string(),
                rule_name: hit.rule_name.clone(),
                value: hit.value.clone(),
                len: hit.len,
                entropy_h: h_r,
                entropy_total_bits: total_r,
            };

            let rec = JsonlRecord {
                schema: 1,
                kind: "block".to_string(),
                path: path.to_string(),
                line: None,
                text,
                spans: vec![span],
            };

            if let Ok(s) = serde_json::to_string(&rec) {
                out_lines.push(s);
            }
            continue;
        }

        // line-level: ищем value в full_text
        let mut found: Option<(usize, usize)> = None;
        for cand in candidates_for_search(&hit.value) {
            if let Some(r) = find_next_nonoverlapping(full_text, &cand, 0, &mut used_ranges) {
                found = Some(r);
                break;
            }
        }

        let (s_b, e_b) = match found {
            Some(v) => v,
            None => continue,
        };

        let (line_no, line_str, s_c, e_c) = line_context(full_text, s_b, e_b);

        let span = JsonlSpan {
            start: s_c,
            end: e_c,
            label: label.to_string(),
            rule_name: hit.rule_name.clone(),
            value: hit.value.clone(),
            len: hit.len,
            entropy_h: h_r,
            entropy_total_bits: total_r,
        };

        by_line
            .entry(line_no)
            .and_modify(|(_, spans)| spans.push(span.clone()))
            .or_insert((line_str.to_string(), vec![span]));
    }

    // запись line-записей
    for (line_no, (line_text, mut spans)) in by_line {
        spans.sort_by_key(|s| s.start);

        let rec = JsonlRecord {
            schema: 1,
            kind: "line".to_string(),
            path: path.to_string(),
            line: Some(line_no),
            text: line_text,
            spans,
        };
        if let Ok(s) = serde_json::to_string(&rec) {
            out_lines.push(s);
        }
    }

    out_lines
}

async fn analyze_bytes_with_rules(
    bytes: &[u8],
    url: &str,
    ext: &str,
    sink: &SensitiveSink,
) -> AnyResult<()> {
    let ext_lc = ext.to_ascii_lowercase();
    let should_try_text =
        TEXT_EXTS.contains(&ext_lc.as_str()) || looks_like_html(bytes) || is_probably_text(bytes);

    if !should_try_text {
        return Ok(());
    }

    let text = String::from_utf8_lossy(bytes).to_string();

    let hits = scan_patterns(&text);
    if hits.is_empty() {
        return Ok(());
    }

    write_samples_from_text_jsonl(sink, url, &text).await?;
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

    weird * 20 < sample_len
}

async fn analyze_archive_file(
    archive_path: &Path,
    base_url: &str,
    paths: &impl PathsLike,
    sink: &SensitiveSink,
) -> AnyResult<()> {
    let archive_path = archive_path.to_path_buf();
    let assets_root = paths.assets_dir().to_path_buf();
    let base_for_spawn = base_url.to_string();

    let json_lines = task::spawn_blocking(move || -> AnyResult<Vec<String>> {
        let ext = archive_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut out_json: Vec<String> = Vec::new();

        match ext.as_str() {
            "zip" => analyze_zip(&archive_path, &base_for_spawn, &assets_root, &mut out_json)?,
            "tar" | "gz" | "tgz" | "bz2" | "xz" => analyze_tar_like(
                &archive_path,
                &base_for_spawn,
                &assets_root,
                &ext,
                &mut out_json,
            )?,
            _ => {}
        }

        Ok(out_json)
    })
    .await??;

    if json_lines.is_empty() {
        return Ok(());
    }

    for jl in json_lines {
        let sample: crate::sensitive_jsonl::Sample = serde_json::from_str(&jl)?;
        sink.write_sample(&sample).await?;
    }

    Ok(())
}

fn analyze_zip(
    path: &Path,
    base_url: &str,
    assets_root: &Path,
    out_json: &mut Vec<String>,
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
            let text = String::from_utf8_lossy(&data);
            let hits = scan_patterns(&text);
            if !hits.is_empty() {
                out_json.extend(hits_to_jsonl_lines(&virt_url, &text, &hits));
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
    out_json: &mut Vec<String>,
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
            let text = String::from_utf8_lossy(&data);
            let hits = scan_patterns(&text);
            if !hits.is_empty() {
                out_json.extend(hits_to_jsonl_lines(&virt_url, &text, &hits));
            }
        }
    }

    Ok(())
}

/// Для файлов внутри архива: тоже кладём в assets/<ext>/...
fn build_asset_path_from_parts(virt_url: &str, ext: &str, assets_root: &Path) -> PathBuf {
    let safe = sanitize_filename(virt_url);
    let dir = ext.to_ascii_lowercase();
    assets_root.join(dir).join(format!("{safe}.{ext}"))
}

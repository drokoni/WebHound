use core::patterns::{PATTERNS, should_ignore_path, should_ignore_value};
use core::utils::{sanitize_filename, save_bytes};

use crate::net::fetch_live_or_wayback;
use crate::screenshot::make_screenshot_task;

use anyhow::Result as AnyResult;
use reqwest::Client;
use select::{document::Document, predicate::Predicate};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs::File, path::Path, sync::Arc};
use tokio::sync::Mutex;
use url::Url;

// какие текстовые форматы дополнительно скачивать из HTML
const INTERESTING_EXTS: &[&str] = &[
    "js", "php", "txt", "json", "xml", "csv", "ini", "conf", "config", "env", "yaml", "yml", "log",
    "bak", "old", "sql",
];

// спец-файлы по имени
const INTERESTING_NAMES: &[&str] = &["robots.txt", "sitemap.xml"];

pub async fn process_single_url(
    client: &Client,
    url: &str,
    paths: &impl PathsLike,
    info_file: &Arc<Mutex<File>>,
) -> AnyResult<()> {
    // 1) попробуем получить сам ресурс (live → wayback)
    if let Ok((bytes, used_url, _is_wayback)) = fetch_live_or_wayback(client, url).await {
        // определим «тип» грубо по расширению / content sniffing по URL
        let is_html = url_looks_html(url);

        // сохраняем оригинальную «страницу/файл»
        let filename = sanitize_filename(&used_url);
        let (save_dir, ext) = if is_html {
            (paths.assets_dir(), "html")
        } else {
            (paths.assets_dir(), guess_ext_from_url(url).unwrap_or("bin"))
        };
        let save_path = save_dir.join(format!("{filename}.{ext}"));
        save_bytes(&save_path, &bytes)?;
        // анализ содержимого на секреты (как текст)
        if let Ok(text) = String::from_utf8(bytes.clone()) {
            analyze_info(&text, url, info_file).await?;
        }

        // 2) если это HTML — парсим и вытягиваем «интересные» ссылки
        if is_html {
            let body = String::from_utf8_lossy(&bytes).to_string();
            let mut to_fetch = extract_interesting_links(&body, url);
            // добавим robots / sitemap для корня
            if let Some(root) = root_of(url) {
                for name in INTERESTING_NAMES {
                    to_fetch.insert(format!("{}/{}", root.trim_end_matches('/'), name));
                }
            }

            // скачиваем с дедупом и фильтрами
            let mut seen = HashSet::new();
            for u in to_fetch.into_iter() {
                if !seen.insert(u.clone()) {
                    continue;
                }
                if should_ignore_path(&u) {
                    eprintln!("skip by allowlist (path): {}", u);
                    continue;
                }

                match fetch_live_or_wayback(client, &u).await {
                    Ok((data, used_u, _wb)) => {
                        // где сохраняем
                        let (dir, base) = if url_has_ext(&u, "js") {
                            (paths.jsscripts_dir(), make_script_filename(&u))
                        } else {
                            (paths.assets_dir(), sanitize_filename(&used_u))
                        };
                        let ext = guess_ext_from_url(&u).unwrap_or("txt");
                        let path = dir.join(format!("{}.{}", base, ext));
                        save_bytes(&path, &data)?;
                        println!("Сохранён ресурс: {}", path.display());

                        if let Ok(text) = String::from_utf8(data) {
                            analyze_info(&text, &u, info_file).await?;
                        }
                    }
                    Err(e) => eprintln!("Не удалось скачать {}: {}", u, e),
                }
            }

            // 3) Скриншот только «живого» HTML (для wayback тоже можно, но оставим как есть)
            if let Err(e) = make_screenshot_task(url, paths.screenshots_dir()).await {
                eprintln!("Ошибка скриншота {}: {}", url, e);
            }
        }
    } else {
        eprintln!("Не получилось получить ни live, ни wayback: {}", url);
    }

    Ok(())
}

// --- Вспомогательные для process_single_url ---

pub trait PathsLike: Send + Sync {
    fn screenshots_dir(&self) -> &Path;
    fn jsscripts_dir(&self) -> &Path;
    fn assets_dir(&self) -> &Path;
}

fn url_looks_html(u: &str) -> bool {
    if let Some(ext) = guess_ext_from_url(u) {
        return matches!(
            ext,
            "html" | "htm" | "shtml" | "php" | "asp" | "aspx" | "jsp"
        );
    }
    // без расширения — считаем HTML
    true
}

fn guess_ext_from_url(u: &str) -> Option<&'static str> {
    Url::parse(u)
        .ok()?
        .path()
        .rsplit('/')
        .next()
        .and_then(|name| {
            if let Some((_, ext)) = name.rsplit_once('.') {
                let e = ext.to_ascii_lowercase();
                // нормализуем известные
                match e.as_str() {
                    "js" => Some("js"),
                    "php" => Some("php"),
                    "txt" => Some("txt"),
                    "json" => Some("json"),
                    "xml" => Some("xml"),
                    "csv" => Some("csv"),
                    "ini" => Some("ini"),
                    "conf" | "config" => Some("conf"),
                    "env" => Some("env"),
                    "yaml" => Some("yaml"),
                    "yml" => Some("yml"),
                    "log" => Some("log"),
                    "bak" => Some("bak"),
                    "old" => Some("old"),
                    "sql" => Some("sql"),
                    "html" => Some("html"),
                    "htm" => Some("htm"),
                    "asp" => Some("asp"),
                    "aspx" => Some("aspx"),
                    "jsp" => Some("jsp"),
                    _ => Some(Box::leak(e.into_boxed_str())),
                }
            } else {
                None
            }
        })
}

fn url_has_ext(u: &str, ext: &str) -> bool {
    guess_ext_from_url(u)
        .map(|e| e.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

fn root_of(u: &str) -> Option<String> {
    let p = Url::parse(u).ok()?;
    Some(format!("{}://{}", p.scheme(), p.host_str()?))
}

fn extract_interesting_links(body_html: &str, base_url: &str) -> HashSet<String> {
    let doc = Document::from(body_html);
    let mut out = HashSet::new();

    // script[src]
    for el in doc.find(select::predicate::Name("script").and(select::predicate::Attr("src", ()))) {
        if let Some(src) = el.attr("src") {
            if let Some(u) = join_url(base_url, src) {
                if url_has_any_interesting_ext(&u) && !should_ignore_path(&u) {
                    out.insert(u);
                }
            }
        }
    }
    // a[href], link[href]
    for el in doc.find(
        select::predicate::Or(
            select::predicate::Name("a"),
            select::predicate::Name("link"),
        )
        .and(select::predicate::Attr("href", ())),
    ) {
        if let Some(href) = el.attr("href") {
            if let Some(u) = join_url(base_url, href) {
                if url_has_any_interesting_ext(&u) && !should_ignore_path(&u) {
                    out.insert(u);
                }
            }
        }
    }

    out
}

fn url_has_any_interesting_ext(u: &str) -> bool {
    if let Some(ext) = guess_ext_from_url(u) {
        return INTERESTING_EXTS.iter().any(|e| e.eq_ignore_ascii_case(ext));
    }
    false
}

pub fn join_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("//") {
        let b = Url::parse(base).ok()?;
        let scheme = b.scheme();
        return Some(format!("{}:{}", scheme, href));
    }
    let base = Url::parse(base).ok()?;
    base.join(href).ok().map(|u| u.to_string())
}

fn make_script_filename(full_url: &str) -> String {
    // короткое, читаемое имя для js
    let mut hasher = Sha256::new();
    hasher.update(full_url.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    let short = &hex[..8];

    let name = Url::parse(full_url)
        .ok()
        .and_then(|u| u.path_segments()?.last().map(|s| s.to_string()))
        .unwrap_or_else(|| "script.js".to_string());
    let base = sanitize_basename(&name);
    format!("{}_{}", short, base)
}

fn sanitize_basename(s: &str) -> String {
    let mut out = s.replace(|c: char| r#"/\:?*"<>| "#.contains(c), "_");
    if out.len() > 80 {
        out.truncate(80);
    }
    out
}

// -------- Энтропия / анализ секретов --------

pub fn shannon_entropy(s: &str) -> (f64, f64, usize) {
    use std::collections::HashMap;

    let bytes = s.as_bytes();
    let n = bytes.len();
    if n == 0 {
        return (0.0, 0.0, 0);
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in bytes {
        *freq.entry(b).or_insert(0) += 1;
    }

    let n_f = n as f64;
    let mut h = 0.0f64;
    for &count in freq.values() {
        let p = (count as f64) / n_f;
        h -= p * p.log2();
    }

    let total_bits = h * n_f;
    (h, total_bits, n)
}

pub async fn analyze_info(
    content: &str,
    url: &str,
    file_mutex: &Arc<Mutex<File>>,
) -> AnyResult<()> {
    if should_ignore_path(url) {
        return Ok(());
    }

    let mut found_any = false;
    let mut buffer: Vec<(String, String)> = Vec::new();

    for spec in PATTERNS.iter() {
        for cap in spec.re.captures_iter(content) {
            // выбираем значение секрета
            let matched = cap.get(0).map(|m| m.as_str()).unwrap_or_default();
            let value = match spec.secret_group {
                Some(g) => cap.get(g),
                None => {
                    let mut v = None;
                    for i in 1..cap.len() {
                        if let Some(m) = cap.get(i) {
                            if !m.as_str().is_empty() {
                                v = Some(m);
                                break;
                            }
                        }
                    }
                    v.or_else(|| cap.get(0))
                }
            }
            .map(|m| m.as_str())
            .unwrap_or(matched);

            if should_ignore_value(value) {
                continue;
            }

            if !found_any {
                buffer.push(("URL".to_string(), url.to_string()));
                found_any = true;
            }
            buffer.push((spec.name.clone(), value.to_string()));
        }
    }

    if found_any {
        use std::io::Write;
        let mut f = file_mutex.lock().await;
        writeln!(f, "{url}")?;
        for (k, v) in buffer.into_iter().filter(|(k, _)| k != "URL") {
            let (h, total_bits, len) = shannon_entropy(&v);
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

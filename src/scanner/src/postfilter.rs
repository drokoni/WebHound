use anyhow::Result as AnyResult;
use core::patterns::{scan_patterns, ScanHit};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

/// Пост-фильтрация: рекурсивно пройти по assets_dir и прогнать ВСЕ текстовые файлы через правила.
/// Пишет найденное в info_file в формате JSONL (dataset-ready).
pub async fn postfilter_assets_dir(
    assets_dir: &Path,
    info_file: &Arc<Mutex<File>>,
) -> AnyResult<()> {
    let files = collect_files_recursive(assets_dir)?;

    for p in files {
        // читаем ограниченно, чтобы не убиваться на огромных файлах
        let data = match read_file_limited(&p, 2 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if !is_probably_text(&data) {
            continue;
        }

        // lossy decode как в crawler (чтобы не пропускать из-за битых байт)
        let text = String::from_utf8_lossy(&data).to_string();

        let hits = scan_patterns(&text);
        if hits.is_empty() {
            continue;
        }

        let abs = p.canonicalize().unwrap_or_else(|_| p.clone());
        let path_str = format!("file://{}", abs.display());

        let json_lines = hits_to_jsonl_lines(&path_str, &text, &hits);
        if json_lines.is_empty() {
            continue;
        }

        let mut f = info_file.lock().await;
        for jl in json_lines {
            writeln!(f, "{jl}")?;
        }
    }

    Ok(())
}

/// Удобная обёртка: постфильтрация assets_dir и запись результата в out_file (создаст файл).
pub async fn postfilter_assets_dir_to_file(assets_dir: &Path, out_file: &Path) -> AnyResult<()> {
    if let Some(parent) = out_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let f = File::create(out_file)?;
    let info = Arc::new(Mutex::new(f));
    postfilter_assets_dir(assets_dir, &info).await
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

//JSONL output (dataset-ready)

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
    path: String, // file://...
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

/// Найти needle в text начиная с `from`, не пересекаясь с already used диапазонами (в байтах).
fn find_next_nonoverlapping(
    text: &str,
    needle: &str,
    mut from: usize,
    used: &mut Vec<(usize, usize)>,
) -> Option<(usize, usize)> {
    if needle.is_empty() {
        return None;
    }

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

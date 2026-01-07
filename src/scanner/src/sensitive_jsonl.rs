use anyhow::Result;
use core::patterns::{should_ignore_value, PATTERNS};
use regex::Match;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct Span {
    pub start: usize,  // char offset in text
    pub end: usize,    // char offset in text
    pub label: String, // PASSWORD/API_KEY/TOKEN/JWT/PRIVATE_KEY
    pub rule_id: String,
    pub rule: String,
    pub value: String,
    pub entropy_h: f64,
    pub entropy_total_bits: f64,
    pub len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub schema: u8,
    pub kind: String, // "line" | "block"
    pub path: String, // file://... or url
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub text: String,
    pub spans: Vec<Span>,
}

fn byte_to_char_idx(s: &str, byte_idx: usize) -> usize {
    s[..byte_idx].chars().count()
}

fn map_to_label(rule_id: &str, rule_desc: &str) -> Option<&'static str> {
    let id = rule_id.to_ascii_lowercase();
    let d = rule_desc.to_ascii_lowercase();

    if id.contains("private-key") || d.contains("private key") {
        return Some("PRIVATE_KEY");
    }
    if id.contains("jwt") || d.contains("json web token") {
        return Some("JWT");
    }
    if d.contains("password") || d.contains("passphrase") {
        return Some("PASSWORD");
    }
    // "api key" и подобное — в API_KEY
    if d.contains("api key")
        || d.contains("client secret")
        || d.contains("secret key")
        || d.contains("access key")
    {
        return Some("API_KEY");
    }
    // токены (Bearer/Access token и т.п.)
    if d.contains(" token") || d.ends_with("token") {
        return Some("TOKEN");
    }
    None
}

fn shannon_entropy(bytes: &[u8]) -> (f64, f64, usize) {
    use std::collections::HashMap;
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

fn line_context(text: &str, start_b: usize, end_b: usize) -> (u32, String, usize, usize) {
    // границы строки (байты)
    let lb = text[..start_b].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let rb = text[end_b..]
        .find('\n')
        .map(|i| end_b + i)
        .unwrap_or(text.len());
    let line = &text[lb..rb];

    // номер строки (1-based)
    let line_no = (text[..lb].bytes().filter(|&b| b == b'\n').count() as u32) + 1;

    // start/end в char относительно строки
    let start_c = byte_to_char_idx(line, start_b - lb);
    let end_c = byte_to_char_idx(line, end_b - lb);

    (line_no, line.to_string(), start_c, end_c)
}

pub async fn write_samples_from_text_jsonl(
    info_file: &Arc<Mutex<File>>,
    path: &str,
    text: &str,
) -> Result<()> {
    use std::collections::HashMap;

    // 1) PRIVATE_KEY как block (многострочный)
    for spec in PATTERNS.iter() {
        let label = match map_to_label(&spec.id, &spec.name) {
            Some("PRIVATE_KEY") => "PRIVATE_KEY",
            _ => continue,
        };

        for cap in spec.re.captures_iter(text) {
            let m = cap.get(0).unwrap();
            let chunk = m.as_str();
            if should_ignore_value(chunk) {
                continue;
            }

            let (h, total, len) = shannon_entropy(chunk.as_bytes());

            let spans = vec![Span {
                start: 0,
                end: chunk.chars().count(),
                label: label.to_string(),
                rule_id: spec.id.clone(),
                rule: spec.name.clone(),
                value: chunk.to_string(),
                entropy_h: (h * 100.0).round() / 100.0,
                entropy_total_bits: (total * 100.0).round() / 100.0,
                len,
            }];

            let sample = Sample {
                schema: 1,
                kind: "block".to_string(),
                path: path.to_string(),
                line: None,
                text: chunk.to_string(),
                spans,
            };

            let mut f = info_file.lock().await;
            writeln!(f, "{}", serde_json::to_string(&sample)?)?;
        }
    }

    // 2) Всё остальное — line samples с группировкой spans по строке
    let mut by_line: HashMap<u32, (String, Vec<Span>)> = HashMap::new();

    for spec in PATTERNS.iter() {
        let label = match map_to_label(&spec.id, &spec.name) {
            Some(l) if l != "PRIVATE_KEY" => l,
            _ => continue,
        };

        for cap in spec.re.captures_iter(text) {
            let m: Option<Match> = spec
                .secret_group
                .and_then(|g| cap.get(g))
                .or_else(|| cap.get(1))
                .or_else(|| cap.get(0));

            let m = match m {
                Some(v) => v,
                None => continue,
            };

            let value = m.as_str();
            if value.is_empty() || should_ignore_value(value) {
                continue;
            }

            let (line_no, line_text, s_c, e_c) = line_context(text, m.start(), m.end());
            let (h, total, len) = shannon_entropy(value.as_bytes());

            let sp = Span {
                start: s_c,
                end: e_c,
                label: label.to_string(),
                rule_id: spec.id.clone(),
                rule: spec.name.clone(),
                value: value.to_string(),
                entropy_h: (h * 100.0).round() / 100.0,
                entropy_total_bits: (total * 100.0).round() / 100.0,
                len,
            };

            by_line
                .entry(line_no)
                .and_modify(|(_, spans)| spans.push(sp.clone()))
                .or_insert((line_text, vec![sp]));
        }
    }

    // запись line-samples
    for (line_no, (line_text, mut spans)) in by_line {
        // немного чистим пересечения: сортируем и оставляем “длиннее”
        spans.sort_by_key(|sp| (sp.start, usize::MAX - (sp.end - sp.start)));

        let sample = Sample {
            schema: 1,
            kind: "line".to_string(),
            path: path.to_string(),
            line: Some(line_no),
            text: line_text,
            spans,
        };

        let mut f = info_file.lock().await;
        writeln!(f, "{}", serde_json::to_string(&sample)?)?;
    }

    Ok(())
}

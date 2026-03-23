use anyhow::Result;
use core::patterns::{should_ignore_value, PATTERNS};
use regex::Match;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use storage::{NewAnalysisFinding, NewRawFinding, SqliteStorage};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub rule_id: String,
    pub rule: String,
    pub value: String,
    pub entropy_h: f64,
    pub entropy_total_bits: f64,
    pub len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub schema: u8,
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub text: String,
    pub spans: Vec<Span>,
}

#[derive(Clone)]
pub struct SensitiveSink {
    pub info_file: Option<Arc<Mutex<File>>>,
    pub sqlite: Option<SqliteStorage>,
    pub scan_run_id: Option<i64>,
}

impl SensitiveSink {
    pub fn new(
        info_file: Option<Arc<Mutex<File>>>,
        sqlite: Option<SqliteStorage>,
        scan_run_id: Option<i64>,
    ) -> Self {
        Self {
            info_file,
            sqlite,
            scan_run_id,
        }
    }

    pub async fn write_jsonl_sample(&self, sample: &Sample) -> Result<()> {
        if let Some(info_file) = &self.info_file {
            let mut f = info_file.lock().await;
            writeln!(f, "{}", serde_json::to_string(sample)?)?;
        }
        Ok(())
    }

    pub fn write_sqlite_raw_sample(&self, sample: &Sample) -> Result<()> {
        let Some(sqlite) = &self.sqlite else {
            return Ok(());
        };
        let Some(scan_run_id) = self.scan_run_id else {
            return Ok(());
        };

        let text_hash = sha256_hex(sample.text.as_bytes());

        for sp in &sample.spans {
            let row = NewRawFinding {
                scan_run_id,
                source_path: sample.path.clone(),
                source_kind: classify_source_kind(&sample.path),
                line: sample.line,
                sample_kind: sample.kind.clone(),
                finding_type: sp.label.clone(),
                rule_id: sp.rule_id.clone(),
                rule_name: sp.rule.clone(),
                match_text: sp.value.clone(),
                context_text: sample.text.clone(),
                start_offset: sp.start,
                end_offset: sp.end,
                entropy_h: sp.entropy_h,
                entropy_total_bits: sp.entropy_total_bits,
                value_len: sp.len,
                source_text_hash: Some(text_hash.clone()),
            };
            sqlite.insert_raw_finding(&row)?;
        }

        Ok(())
    }

    pub fn write_sqlite_analysis_sample(&self, sample: &Sample, stage: &str) -> Result<()> {
        let Some(sqlite) = &self.sqlite else {
            return Ok(());
        };
        let Some(scan_run_id) = self.scan_run_id else {
            return Ok(());
        };

        for sp in &sample.spans {
            let row = NewAnalysisFinding {
                scan_run_id,
                raw_finding_id: None,
                source_path: sample.path.clone(),
                source_kind: classify_source_kind(&sample.path),
                analysis_stage: stage.to_string(),
                line: sample.line,
                sample_kind: sample.kind.clone(),
                finding_type: sp.label.clone(),
                rule_id: Some(sp.rule_id.clone()),
                rule_name: Some(sp.rule.clone()),
                match_text: sp.value.clone(),
                context_text: sample.text.clone(),
                start_offset: Some(sp.start),
                end_offset: Some(sp.end),
                entropy_h: Some(sp.entropy_h),
                entropy_total_bits: Some(sp.entropy_total_bits),
                value_len: Some(sp.len),
                ml_model_name: None,
                ml_model_version: None,
                ml_label: None,
                ml_score: None,
                ml_scores_json: None,
                final_label: None,
                final_confidence: None,
                analyst_note: None,
                is_false_positive: false,
            };
            sqlite.insert_analysis_finding(&row)?;
        }

        Ok(())
    }

    pub async fn write_sample(&self, sample: &Sample) -> Result<()> {
        self.write_jsonl_sample(sample).await?;
        self.write_sqlite_raw_sample(sample)?;
        Ok(())
    }

    pub async fn write_analysis_sample(&self, sample: &Sample, stage: &str) -> Result<()> {
        self.write_jsonl_sample(sample).await?;
        self.write_sqlite_analysis_sample(sample, stage)?;
        Ok(())
    }
}

fn classify_source_kind(path: &str) -> String {
    if path.contains('!') {
        "archive_entry".to_string()
    } else if path.starts_with("http://") || path.starts_with("https://") {
        "url".to_string()
    } else {
        "file".to_string()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
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
    if d.contains("api key")
        || d.contains("client secret")
        || d.contains("secret key")
        || d.contains("access key")
    {
        return Some("API_KEY");
    }
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
    let lb = text[..start_b].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let rb = text[end_b..]
        .find('\n')
        .map(|i| end_b + i)
        .unwrap_or(text.len());

    let line = &text[lb..rb];
    let line_no = (text[..lb].bytes().filter(|&b| b == b'\n').count() as u32) + 1;

    let start_c = byte_to_char_idx(line, start_b - lb);
    let end_c = byte_to_char_idx(line, end_b - lb);

    (line_no, line.to_string(), start_c, end_c)
}

pub async fn write_samples_from_text_jsonl(
    sink: &SensitiveSink,
    path: &str,
    text: &str,
) -> Result<()> {
    use std::collections::HashMap;

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

            sink.write_sample(&sample).await?;
        }
    }

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

    for (line_no, (line_text, mut spans)) in by_line {
        spans.sort_by_key(|sp| (sp.start, usize::MAX - (sp.end - sp.start)));

        let sample = Sample {
            schema: 1,
            kind: "line".to_string(),
            path: path.to_string(),
            line: Some(line_no),
            text: line_text,
            spans,
        };

        sink.write_sample(&sample).await?;
    }

    Ok(())
}

pub async fn write_analysis_samples_from_text(
    sink: &SensitiveSink,
    path: &str,
    text: &str,
    stage: &str,
) -> Result<()> {
    use std::collections::HashMap;

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
            let sample = Sample {
                schema: 1,
                kind: "block".to_string(),
                path: path.to_string(),
                line: None,
                text: chunk.to_string(),
                spans: vec![Span {
                    start: 0,
                    end: chunk.chars().count(),
                    label: label.to_string(),
                    rule_id: spec.id.clone(),
                    rule: spec.name.clone(),
                    value: chunk.to_string(),
                    entropy_h: (h * 100.0).round() / 100.0,
                    entropy_total_bits: (total * 100.0).round() / 100.0,
                    len,
                }],
            };

            sink.write_analysis_sample(&sample, stage).await?;
        }
    }

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

            let Some(m) = m else {
                continue;
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

    for (line_no, (line_text, mut spans)) in by_line {
        spans.sort_by_key(|sp| (sp.start, usize::MAX - (sp.end - sp.start)));

        let sample = Sample {
            schema: 1,
            kind: "line".to_string(),
            path: path.to_string(),
            line: Some(line_no),
            text: line_text,
            spans,
        };

        sink.write_analysis_sample(&sample, stage).await?;
    }

    Ok(())
}
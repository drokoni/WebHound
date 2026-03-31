use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewScanRun {
    pub target: String,
    pub mode: String,
    pub status: String,
    pub config_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOutUrl {
    pub scan_run_id: i64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSubdomain {
    pub scan_run_id: i64,
    pub subdomain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRawFinding {
    pub scan_run_id: i64,
    pub source_path: String,
    pub source_kind: String, // url | file | archive_entry
    pub line: Option<u32>,
    pub sample_kind: String, // line | block
    pub finding_type: String,
    pub rule_id: String,
    pub rule_name: String,
    pub match_text: String,   // ПОЛНЫЙ секрет
    pub context_text: String, // строка/блок
    pub start_offset: usize,
    pub end_offset: usize,
    pub entropy_h: f64,
    pub entropy_total_bits: f64,
    pub value_len: usize,
    pub source_text_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAnalysisFinding {
    pub scan_run_id: i64,
    pub raw_finding_id: Option<i64>,
    pub source_path: String,
    pub source_kind: String,
    pub analysis_stage: String, // postfilter | text_ml | manual
    pub line: Option<u32>,
    pub sample_kind: String,
    pub finding_type: String,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub match_text: String,
    pub context_text: String,
    pub start_offset: Option<usize>,
    pub end_offset: Option<usize>,
    pub entropy_h: Option<f64>,
    pub entropy_total_bits: Option<f64>,
    pub value_len: Option<usize>,
    pub ml_model_name: Option<String>,
    pub ml_model_version: Option<String>,
    pub ml_label: Option<String>,
    pub ml_score: Option<f64>,
    pub ml_scores_json: Option<String>,
    pub final_label: Option<String>,
    pub final_confidence: Option<f64>,
    pub analyst_note: Option<String>,
    pub is_false_positive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewScreenshot {
    pub scan_run_id: i64,
    pub page_url: String,
    pub local_path: String,
    pub image_sha256: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub file_size: Option<u64>,
    pub ml_model_name: Option<String>,
    pub ml_model_version: Option<String>,
    pub ml_label: Option<String>,
    pub ml_score: Option<f64>,
    pub ml_scores_json: Option<String>,
    pub user_label: Option<String>,
    pub user_label_updated_at: Option<String>,
    pub user_label_updated_by: Option<String>,
    pub analyst_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEvent {
    pub scan_run_id: Option<i64>,
    pub level: String,
    pub component: String,
    pub message: String,
    pub details_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawFindingRow {
    pub id: i64,
    pub scan_run_id: i64,
    pub source_path: String,
    pub source_kind: String,
    pub line: Option<u32>,
    pub sample_kind: String,
    pub finding_type: String,
    pub rule_id: String,
    pub rule_name: String,
    pub match_text: String,
    pub context_text: String,
    pub start_offset: usize,
    pub end_offset: usize,
    pub entropy_h: f64,
    pub entropy_total_bits: f64,
    pub value_len: usize,
    pub source_text_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotRow {
    pub id: i64,
    pub scan_run_id: i64,
    pub page_url: String,
    pub local_path: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewVisionPrediction {
    pub scan_run_id: i64,
    pub screenshot_id: Option<i64>,
    pub local_path: String,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub top_label: String,
    pub top_prob: f64,
    pub probs_json: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewScreenshotAnnotation {
    pub screenshot_id: Option<i64>,
    pub local_path: String,
    pub user_label: String,
    pub analyst_note: Option<String>,
    pub updated_by: Option<String>,
}

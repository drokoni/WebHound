use anyhow::{anyhow, bail, Context, Result};
use ndarray::{Array2, ArrayView2, CowArray, Ix2, IxDyn};
use ort::{
    environment::Environment,
    session::{Session, SessionBuilder},
    value::Value,
    LoggingLevel,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokenizers::{PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

const DEFAULT_MAX_LENGTH: usize = 192;
const DEFAULT_USE_PATH_PREFIX: bool = false;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextAnalyzerConfig {
    pub model_dir: PathBuf,
    #[serde(default = "default_max_length")]
    pub max_length: usize,
    #[serde(default = "default_use_path_prefix")]
    pub use_path_prefix: bool,
}

fn default_max_length() -> usize {
    DEFAULT_MAX_LENGTH
}

fn default_use_path_prefix() -> bool {
    DEFAULT_USE_PATH_PREFIX
}

impl TextAnalyzerConfig {
    pub fn new(model_dir: impl AsRef<Path>) -> Self {
        Self {
            model_dir: model_dir.as_ref().to_path_buf(),
            max_length: DEFAULT_MAX_LENGTH,
            use_path_prefix: DEFAULT_USE_PATH_PREFIX,
        }
    }

    pub fn model_path(&self) -> PathBuf {
        self.model_dir.join("model.onnx")
    }

    pub fn tokenizer_path(&self) -> PathBuf {
        self.model_dir.join("tokenizer").join("tokenizer.json")
    }

    pub fn metadata_path(&self) -> PathBuf {
        self.model_dir.join("export_metadata.json")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextPrediction {
    pub pred_id: usize,
    pub pred_label: String,
    pub pred_score: f32,
    pub pred_probs: BTreeMap<String, f32>,
    pub model_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExportMetadata {
    #[serde(default)]
    pub model_name: Option<String>,
    #[serde(default)]
    pub num_labels: Option<usize>,
    #[serde(default)]
    pub id2label: BTreeMap<String, String>,
    #[serde(default)]
    pub max_position_embeddings: Option<usize>,
    #[serde(default)]
    pub architectures: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SensitiveSpan {
    #[serde(default)]
    pub start: usize,
    #[serde(default)]
    pub end: usize,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub rule: String,
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub entropy_h: f64,
    #[serde(default)]
    pub entropy_total_bits: f64,
    #[serde(default)]
    pub len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SensitiveSample {
    #[serde(default)]
    pub schema: Option<u8>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub spans: Vec<SensitiveSpan>,
}

pub struct TextClassifier {
    _env: Arc<Environment>,
    session: Session,
    tokenizer: Tokenizer,
    labels: Vec<String>,
    max_length: usize,
    use_path_prefix: bool,
}

impl TextClassifier {
    pub fn new(cfg: TextAnalyzerConfig) -> Result<Self> {
        if !cfg.model_path().is_file() {
            bail!("ONNX model not found: {}", cfg.model_path().display());
        }
        if !cfg.tokenizer_path().is_file() {
            bail!("tokenizer.json not found: {}", cfg.tokenizer_path().display());
        }
        if !cfg.metadata_path().is_file() {
            bail!("metadata not found: {}", cfg.metadata_path().display());
        }

        let metadata: ExportMetadata = serde_json::from_slice(
            &fs::read(cfg.metadata_path())
                .with_context(|| format!("read {}", cfg.metadata_path().display()))?,
        )
        .with_context(|| format!("parse {}", cfg.metadata_path().display()))?;

        let labels = labels_from_metadata(&metadata)?;

        let env = Environment::builder()
            .with_name("webhound-text")
            .with_log_level(LoggingLevel::Warning)
            .build()
            .map_err(|e| anyhow!("Environment::build: {e}"))?;
        let env = Arc::new(env);

        let sb: SessionBuilder =
            SessionBuilder::new(&env).map_err(|e| anyhow!("SessionBuilder::new: {e}"))?;
        let session = sb
            .with_model_from_file(cfg.model_path())
            .map_err(|e| anyhow!("with_model_from_file: {e}"))?;

        let mut tokenizer = Tokenizer::from_file(cfg.tokenizer_path())
            .map_err(|e| anyhow!("Tokenizer::from_file: {e}"))?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: cfg.max_length,
                ..Default::default()
            }))
            .map_err(|e| anyhow!("tokenizer truncation: {e}"))?;
        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::Fixed(cfg.max_length),
            ..Default::default()
        }));

        Ok(Self {
            _env: env,
            session,
            tokenizer,
            labels,
            max_length: cfg.max_length,
            use_path_prefix: cfg.use_path_prefix,
        })
    }

    pub fn predict_text(&self, text: &str, path: Option<&str>) -> Result<TextPrediction> {
    let model_text = build_model_text(text, path, self.use_path_prefix);

    let enc = self
        .tokenizer
        .encode(model_text.clone(), true)
        .map_err(|e| anyhow!("tokenizer.encode: {e}"))?;

    let ids: Vec<i64> = enc.get_ids().iter().map(|&v| v as i64).collect();
    let mask: Vec<i64> = enc.get_attention_mask().iter().map(|&v| v as i64).collect();

    if ids.is_empty() || mask.is_empty() {
        bail!("tokenizer produced empty input");
    }
    if ids.len() != mask.len() {
        bail!(
            "tokenizer mismatch: input_ids={} attention_mask={}",
            ids.len(),
            mask.len()
        );
    }

    let seq_len = ids.len();

    let ids_arr = Array2::from_shape_vec((1, seq_len), ids)
        .context("build input_ids ndarray")?
        .into_dyn();

    let mask_arr = Array2::from_shape_vec((1, seq_len), mask)
        .context("build attention_mask ndarray")?
        .into_dyn();

    let ids_cow: CowArray<'_, i64, IxDyn> = CowArray::from(ids_arr.view());
    let mask_cow: CowArray<'_, i64, IxDyn> = CowArray::from(mask_arr.view());

    let ids_tensor = Value::from_array(self.session.allocator(), &ids_cow)
        .map_err(|e| anyhow!("Value::from_array(input_ids): {e}"))?;
    let mask_tensor = Value::from_array(self.session.allocator(), &mask_cow)
        .map_err(|e| anyhow!("Value::from_array(attention_mask): {e}"))?;

    let outputs = self
        .session
        .run(vec![ids_tensor, mask_tensor])
        .map_err(|e| anyhow!("session.run: {e}"))?;

    let out = outputs
        .get(0)
        .ok_or_else(|| anyhow!("ONNX returned no outputs"))?
        .try_extract::<f32>()
        .map_err(|e| anyhow!("extract logits: {e}"))?;

    let out_view = out.view();
    let logits2: ArrayView2<'_, f32> = out_view
        .clone()
        .into_dimensionality::<Ix2>()
        .context("bad logits rank, expected [batch, num_labels]")?;

    if logits2.nrows() != 1 {
        bail!("expected batch=1, got {}", logits2.nrows());
    }

    let logits = logits2.row(0).to_vec();
    if logits.len() != self.labels.len() {
        bail!(
            "label mismatch: model produced {} logits, metadata has {} labels",
            logits.len(),
            self.labels.len()
        );
    }

    Ok(prediction_from_logits(&self.labels, logits, model_text))
}

    pub fn annotate_jsonl(
        &self,
        input_jsonl: impl AsRef<Path>,
        output_jsonl: impl AsRef<Path>,
    ) -> Result<TextAnnotateStats> {
        let input_jsonl = input_jsonl.as_ref();
        let output_jsonl = output_jsonl.as_ref();

        let input = File::open(input_jsonl)
            .with_context(|| format!("open {}", input_jsonl.display()))?;
        if let Some(parent) = output_jsonl.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("mkdir -p {}", parent.display()))?;
        }
        let output = File::create(output_jsonl)
            .with_context(|| format!("create {}", output_jsonl.display()))?;

        let reader = BufReader::new(input);
        let mut writer = BufWriter::new(output);

        let mut stats = TextAnnotateStats::default();

        for (idx, line_res) in reader.lines().enumerate() {
            let line_no = idx + 1;
            let line = line_res
                .with_context(|| format!("read line {} from {}", line_no, input_jsonl.display()))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut obj: JsonValue = serde_json::from_str(trimmed).with_context(|| {
                format!("parse JSON at {}:{}", input_jsonl.display(), line_no)
            })?;

            let path = obj
    .get("path")
    .and_then(|v| v.as_str())
    .unwrap_or("")
    .to_string();

let text = obj
    .get("text")
    .and_then(|v| v.as_str())
    .unwrap_or("")
    .to_string();

if text.trim().is_empty() {
    continue;
}

let pred = self.predict_text(&text, Some(&path)).with_context(|| {
    format!(
        "predict sample at {}:{} ({})",
        input_jsonl.display(),
        line_no,
        path
    )
})?;

            attach_prediction(&mut obj, &pred)?;
            serde_json::to_writer(&mut writer, &obj)?;
            writer.write_all(b"\n")?;

            stats.total += 1;
            *stats.by_label.entry(pred.pred_label.clone()).or_insert(0usize) += 1;
        }

        writer.flush()?;
        Ok(stats)
    }

    pub fn max_length(&self) -> usize {
        self.max_length
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TextAnnotateStats {
    pub total: usize,
    pub by_label: BTreeMap<String, usize>,
}

fn labels_from_metadata(meta: &ExportMetadata) -> Result<Vec<String>> {
    if meta.id2label.is_empty() {
        bail!("export_metadata.json has empty id2label");
    }

    let mut pairs: Vec<(usize, String)> = Vec::new();
    for (k, v) in &meta.id2label {
        let idx: usize = k
            .parse()
            .with_context(|| format!("bad id2label key: {k}"))?;
        pairs.push((idx, v.clone()));
    }
    pairs.sort_by_key(|(idx, _)| *idx);

    if let Some(expected) = meta.num_labels {
        if pairs.len() != expected {
            bail!(
                "metadata mismatch: id2label has {} items but num_labels={expected}",
                pairs.len()
            );
        }
    }

    Ok(pairs.into_iter().map(|(_, v)| v).collect())
}

fn build_model_text(text: &str, path: Option<&str>, use_path_prefix: bool) -> String {
    if use_path_prefix {
        if let Some(path) = path.filter(|p| !p.trim().is_empty()) {
            return format!("[PATH] {path} [TEXT] {text}");
        }
    }
    text.to_string()
}

fn prediction_from_logits(
    labels: &[String],
    logits: Vec<f32>,
    model_text: String,
) -> TextPrediction {
    let probs = softmax(logits);
    let mut pred_id = 0usize;
    let mut pred_score = f32::MIN;
    for (i, &p) in probs.iter().enumerate() {
        if p > pred_score {
            pred_score = p;
            pred_id = i;
        }
    }

    let mut pred_probs = BTreeMap::new();
    for (label, prob) in labels.iter().zip(probs.iter().copied()) {
        pred_probs.insert(label.clone(), prob);
    }

    let pred_label = labels
        .get(pred_id)
        .cloned()
        .unwrap_or_else(|| pred_id.to_string());

    TextPrediction {
        pred_id,
        pred_label,
        pred_score,
        pred_probs,
        model_text,
    }
}

fn softmax(mut xs: Vec<f32>) -> Vec<f32> {
    if xs.is_empty() {
        return xs;
    }
    let max = xs.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0_f32;
    for x in &mut xs {
        *x = (*x - max).exp();
        sum += *x;
    }
    if sum > 0.0 {
        for x in &mut xs {
            *x /= sum;
        }
    }
    xs
}

fn attach_prediction(obj: &mut JsonValue, pred: &TextPrediction) -> Result<()> {
    let map = obj
        .as_object_mut()
        .ok_or_else(|| anyhow!("expected JSON object in sensitive_info JSONL"))?;

    let mut probs_map = Map::new();
    for (label, prob) in &pred.pred_probs {
        probs_map.insert(label.clone(), JsonValue::from(*prob));
    }

    map.insert("ml_pred_id".into(), JsonValue::from(pred.pred_id as u64));
    map.insert("ml_pred_label".into(), JsonValue::from(pred.pred_label.clone()));
    map.insert("ml_pred_score".into(), JsonValue::from(pred.pred_score));
    map.insert("ml_pred_probs".into(), JsonValue::Object(probs_map));
    map.insert("ml_model_text".into(), JsonValue::from(pred.model_text.clone()));

    Ok(())
}
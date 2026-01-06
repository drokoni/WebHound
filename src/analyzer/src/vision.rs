use anyhow::{anyhow, Context, Result};
use csv::Writer;
use image::imageops::FilterType;
use ndarray::{Array3, Array4, ArrayView2, Axis, CowArray, Ix2, IxDyn};
use ort::{
    environment::Environment,
    session::{Session, SessionBuilder},
    value::Value,
    LoggingLevel,
};
use server::write_prediction_report_html;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use walkdir::WalkDir;

const INPUT_W: usize = 224;
const INPUT_H: usize = 224;

#[derive(Clone)]
pub struct Labels(pub Vec<String>);

impl Labels {
    pub fn eyeballer_default() -> Self {
        Self(vec![
            "boring".into(),
            "interesting".into(),
            "login".into(),
            "error".into(),
            "other".into(),
        ])
    }
}

pub struct EyeballerRunner {
    _env: Arc<Environment>,
    session: Session,
    #[allow(dead_code)]
    input_name: String,
    labels: Labels,
}

impl EyeballerRunner {
    pub fn new(model_path: impl AsRef<Path>, labels: Labels) -> Result<Self> {
        let env = Environment::builder()
            .with_name("eyeballer")
            .with_log_level(LoggingLevel::Warning)
            .build()
            .map_err(|e| anyhow!("Environment::build: {e}"))?;
        let env = Arc::new(env);

        let sb: SessionBuilder =
            SessionBuilder::new(&env).map_err(|e| anyhow!("SessionBuilder::new: {e}"))?;
        let session = sb
            .with_model_from_file(model_path.as_ref())
            .map_err(|e| anyhow!("with_model_from_file: {e}"))?;

        let input_name = session
            .inputs
            .get(0)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "input".to_string());

        Ok(Self {
            _env: env,
            session,
            input_name,
            labels,
        })
    }

    fn softmax(&self, mut v: Vec<f32>) -> Vec<f32> {
        if v.is_empty() {
            return v;
        }
        let m = v.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
        let mut s = 0.0;
        for x in v.iter_mut() {
            *x = (*x - m).exp();
            s += *x;
        }
        if s > 0.0 {
            for x in v.iter_mut() {
                *x /= s;
            }
        }
        v
    }

    fn is_img_ext(ext: &str) -> bool {
        matches!(
            ext.to_ascii_lowercase().as_str(),
            "png" | "jpg" | "jpeg" | "bmp" | "webp"
        )
    }

    fn collect_images(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for e in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if !e.file_type().is_file() {
                continue;
            }
            let p = e.path();
            let ok = p
                .extension()
                .and_then(|s| s.to_str())
                .map(Self::is_img_ext)
                .unwrap_or(false);
            if ok {
                files.push(p.to_path_buf());
            }
        }
        files.sort();
        if files.is_empty() {
            return Err(anyhow!("Нет изображений в {}", dir.display()));
        }
        Ok(files)
    }

    /// Прогон папки со скриншотами → CSV + HTML отчёт.
    /// ВАЖНО: чтобы не копировать скрины, отчёт пишем прямо в images_dir,
    /// поэтому out_dir должен совпадать с images_dir.
    pub fn infer_to_csv_html(
        &self,
        images_dir: &Path,
        out_dir: &Path,
        csv_name: &str,
        html_template: Option<&str>,
    ) -> Result<(PathBuf, PathBuf)> {
        if out_dir != images_dir {
            return Err(anyhow!(
                "Чтобы не копировать скрины, out_dir должен быть равен images_dir (отчёт будет лежать рядом со скриншотами). \
                 Передано: out_dir={}, images_dir={}",
                out_dir.display(),
                images_dir.display()
            ));
        }

        fs::create_dir_all(out_dir).with_context(|| format!("mkdir -p {}", out_dir.display()))?;

        let csv_path = out_dir.join(csv_name);
        let mut w = Writer::from_path(&csv_path)
            .with_context(|| format!("open csv for write: {}", csv_path.display()))?;

        // заголовок CSV
        let mut header = vec!["file".into(), "top_label".into(), "top_prob".into()];
        for l in &self.labels.0 {
            header.push(format!("p_{}", l));
        }
        w.write_record(&header)?;

        let files = self.collect_images(images_dir)?;
        let ncls = self.labels.0.len();

        for p in files {
            let img = image::open(&p).with_context(|| format!("open image: {}", p.display()))?;
            let img = img.resize_exact(INPUT_W as u32, INPUT_H as u32, FilterType::Triangle);
            let rgb = img.to_rgb8();

            let mut hwc = Array3::<f32>::zeros((INPUT_H, INPUT_W, 3));
            for (y, x, px) in rgb.enumerate_pixels() {
                let [r, g, b] = px.0;
                hwc[(y as usize, x as usize, 0)] = r as f32 / 255.0;
                hwc[(y as usize, x as usize, 1)] = g as f32 / 255.0;
                hwc[(y as usize, x as usize, 2)] = b as f32 / 255.0;
            }

            // NHWC -> (1, H, W, C)
            let nhwc: Array4<f32> = hwc.insert_axis(Axis(0));
            let input_dyn = nhwc.into_dyn();

            let input_cow: CowArray<f32, IxDyn> = CowArray::from(input_dyn.view());
            let input_tensor = Value::from_array(self.session.allocator(), &input_cow)?;

            let outputs = self.session.run(vec![input_tensor])?;
            let out = outputs[0].try_extract::<f32>()?;

            let out2: ArrayView2<f32> = out
                .view()
                .into_dimensionality::<Ix2>()
                .context("bad output rank")?;

            let mut logits = vec![0.0_f32; ncls];
            for c in 0..ncls {
                logits[c] = out2[(0, c)];
            }
            let probs = self.softmax(logits);

            let (mut top_i, mut top_p) = (0usize, f32::MIN);
            for (j, &pv) in probs.iter().enumerate() {
                if pv > top_p {
                    top_p = pv;
                    top_i = j;
                }
            }

            // ВАЖНО: НЕ копируем файл. Пишем относительный путь внутри images_dir.
            let rel = p.strip_prefix(images_dir).unwrap_or(&p);
            let rel_str = rel.to_string_lossy().replace('\\', "/");

            let mut row = vec![
                rel_str,
                self.labels
                    .0
                    .get(top_i)
                    .cloned()
                    .unwrap_or_else(|| top_i.to_string()),
                format!("{:.6}", top_p),
            ];
            for j in 0..ncls {
                row.push(format!("{:.6}", probs[j]));
            }
            w.write_record(&row)?;
        }

        w.flush()?;

        // index.html рядом с CSV в images_dir/out_dir
        let html_path = write_prediction_report_html(
            out_dir,
            csv_name,
            images_dir,
            html_template,
            Some("Eyeballer ONNX Report"),
        )?;

        Ok((csv_path, html_path))
    }
}

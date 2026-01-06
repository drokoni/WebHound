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

    /// Прогон папки со скриншотами → predictions.csv + index.html
    /// Дополнительно создаёт annotations.csv (если его ещё нет):
    ///   file,manual_label
    /// где manual_label по умолчанию = top_label (предсказание модели).
    ///
    /// Ожидаемый layout для режима без копирования картинок:
    ///   images_dir = .../screens
    ///   out_dir    = .../screens/report
    pub fn infer_to_csv_html(
        &self,
        images_dir: &Path,
        out_dir: &Path,
        csv_name: &str,
        html_template: Option<&str>,
    ) -> Result<(PathBuf, PathBuf)> {
        fs::create_dir_all(out_dir).with_context(|| format!("mkdir -p {}", out_dir.display()))?;

        // Для текущего режима сервера: он берёт файлы из parent(out_dir) как fallback.
        if out_dir.parent() != Some(images_dir) {
            return Err(anyhow!(
                "Для режима без копирования ожидается out_dir = images_dir/report. \
Передано: out_dir={}, images_dir={}",
                out_dir.display(),
                images_dir.display()
            ));
        }

        let csv_path = out_dir.join(csv_name);
        let mut w = Writer::from_path(&csv_path)
            .with_context(|| format!("open csv for write: {}", csv_path.display()))?;

        // Заголовок predictions.csv
        let mut header = vec!["file".into(), "top_label".into(), "top_prob".into()];
        for l in &self.labels.0 {
            header.push(format!("p_{}", l));
        }
        w.write_record(&header)?;

        let files = self.collect_images(images_dir)?;
        let ncls = self.labels.0.len();

        // Стартовая разметка: file -> predicted label
        let mut initial_ann: Vec<(String, String)> = Vec::with_capacity(files.len());

        for p in files {
            let img = image::open(&p).with_context(|| format!("open image: {}", p.display()))?;
            let img = img.resize_exact(INPUT_W as u32, INPUT_H as u32, FilterType::Triangle);
            let rgb = img.to_rgb8();

            // HWC float32
            let mut hwc = Array3::<f32>::zeros((INPUT_H, INPUT_W, 3));
            for (y, x, px) in rgb.enumerate_pixels() {
                let [r, g, b] = px.0;
                hwc[(y as usize, x as usize, 0)] = r as f32 / 255.0;
                hwc[(y as usize, x as usize, 1)] = g as f32 / 255.0;
                hwc[(y as usize, x as usize, 2)] = b as f32 / 255.0;
            }

            // NHWC -> (1,H,W,C)
            let nhwc: Array4<f32> = hwc.insert_axis(Axis(0));
            let input_dyn = nhwc.into_dyn();
            let input_cow: CowArray<f32, IxDyn> = CowArray::from(input_dyn.view());
            let input_tensor = Value::from_array(self.session.allocator(), &input_cow)?;

            let outputs = self.session.run(vec![input_tensor])?;
            let out = outputs[0].try_extract::<f32>()?;

            // FIX E0507
            let out_view = out.view();
            let out2: ArrayView2<f32> = out_view
                .clone()
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

            let top_label = self
                .labels
                .0
                .get(top_i)
                .cloned()
                .unwrap_or_else(|| top_i.to_string());

            // В CSV кладём путь относительно images_dir (без ../),
            // чтобы браузер запрашивал "/file.png".
            let rel_in_images = p.strip_prefix(images_dir).unwrap_or(&p);
            let rel_str = rel_in_images.to_string_lossy().replace('\\', "/");

            // predictions row
            let mut row = vec![rel_str.clone(), top_label.clone(), format!("{:.6}", top_p)];
            for j in 0..ncls {
                row.push(format!("{:.6}", probs[j]));
            }
            w.write_record(&row)?;

            // initial annotation
            initial_ann.push((rel_str, top_label));
        }

        w.flush()?;

        // annotations.csv — создаём только если его ещё нет
        // Формат one-hot:
        // filename,<label1>,<label2>,...
        // img.png,FALSE,TRUE,...
        let ann_path = out_dir.join("annotations.csv");
        if !ann_path.is_file() {
            let mut aw = Writer::from_path(&ann_path).with_context(|| {
                format!("open annotations csv for write: {}", ann_path.display())
            })?;

            // header
            let mut header: Vec<String> = Vec::with_capacity(1 + self.labels.0.len());
            header.push("filename".to_string());
            header.extend(self.labels.0.iter().cloned());
            aw.write_record(&header)?;

            for (f, lbl) in initial_ann {
                let mut rec: Vec<String> = Vec::with_capacity(1 + self.labels.0.len());
                rec.push(f);
                for l in &self.labels.0 {
                    rec.push(if l == &lbl {
                        "TRUE".into()
                    } else {
                        "FALSE".into()
                    });
                }
                aw.write_record(&rec)?;
            }

            aw.flush()?;
        }

        let html_path = write_prediction_report_html(
            out_dir,
            csv_name,
            images_dir,
            html_template,
            Some("WebHound Report screens"),
        )?;

        Ok((csv_path, html_path))
    }
}

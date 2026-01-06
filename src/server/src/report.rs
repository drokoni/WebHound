use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::templates::PREDICTION_REPORT_HTML;

/// Рендерит HTML отчёта (ничего не пишет на диск).
/// Поддерживает плейсхолдеры:
/// - {CSV_NAME}
/// - {IMAGES_DIR}
/// - {TITLE} (если вдруг есть в кастомном шаблоне)
pub fn render_prediction_report_html(
    csv_name: &str,
    images_dir: &Path,
    html_template: Option<&str>,
    title: Option<&str>,
) -> String {
    let tpl = html_template.unwrap_or(PREDICTION_REPORT_HTML);

    let mut html = tpl
        .replace("{CSV_NAME}", csv_name)
        .replace("{IMAGES_DIR}", &images_dir.display().to_string());

    if let Some(t) = title {
        html = html.replace("{TITLE}", t);
    }

    html
}

/// Пишет index.html в out_dir.
pub fn write_prediction_report_html(
    out_dir: &Path,
    csv_name: &str,
    images_dir: &Path,
    html_template: Option<&str>,
    title: Option<&str>,
) -> Result<PathBuf> {
    fs::create_dir_all(out_dir).with_context(|| format!("mkdir -p {}", out_dir.display()))?;

    let html = render_prediction_report_html(csv_name, images_dir, html_template, title);

    let html_path = out_dir.join("index.html");
    fs::write(&html_path, html).with_context(|| format!("write {}", html_path.display()))?;

    Ok(html_path)
}

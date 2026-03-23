use analyzer::text::{TextAnalyzerConfig, TextClassifier};
use analyzer::vision::*;
use anyhow::{anyhow, Result};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use scanner::run_scan;
use std::{fs, path::PathBuf, time::Duration};
use storage::{NewAnalysisFinding, NewEvent, SqliteStorage};

#[derive(Parser, Debug)]
#[command(
    author = "McQueen",
    version = "0.1",
    about = "WebHound: scan + reports",
    long_about = None,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum MatchType {
    /// Домен + поддомены
    Domain,
    /// Только конкретный host
    Host,
}

impl MatchType {
    fn as_str(self) -> &'static str {
        match self {
            MatchType::Domain => "domain",
            MatchType::Host => "host",
        }
    }
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "CDX options")]
struct CdxArgs {
    /// Как CDX матчить адреса: domain (домен+поддомены) или host (только хост)
    #[arg(long, value_enum, default_value_t = MatchType::Domain)]
    match_type: MatchType,

    /// Ограничить число URL, возвращаемых CDX
    #[arg(long, value_name = "N")]
    limit: Option<u32>,

    /// Отключить collapse=urlkey
    #[arg(long, action = ArgAction::SetTrue)]
    no_collapse: bool,

    /// Разрешить записи со статусом не-200
    #[arg(long, action = ArgAction::SetTrue)]
    no_filter_200: bool,

    /// Разрешить не-HTML
    #[arg(long, action = ArgAction::SetTrue)]
    no_filter_html: bool,

    /// Таймаут HTTP запросов (в секундах)
    #[arg(long, default_value_t = 30, value_name = "SEC")]
    timeout_s: u64,

    /// Количество ретраев при 429/5xx/сетевых ошибках
    #[arg(long, default_value_t = 6, value_name = "N")]
    retries: u32,

    /// Включить fallback по годам
    #[arg(long, action = ArgAction::SetTrue)]
    year_fallback: bool,

    /// Год начала fallback по годам
    #[arg(long, default_value_t = 2018, value_name = "YYYY")]
    year_from: u16,

    /// Год конца fallback по годам
    #[arg(long, default_value_t = 2025, value_name = "YYYY")]
    year_to: u16,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Report / ML options")]
struct ReportArgs {
    /// Включить анализ скриншотов (ONNX) и генерацию HTML-отчёта
    #[arg(long, action = ArgAction::SetTrue)]
    analyze: bool,

    /// Путь к ONNX модели для скриншотов
    #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
    model: PathBuf,

    /// Папка отчёта
    #[arg(long, value_name = "DIR")]
    report: Option<PathBuf>,

    /// Размер batch (пока не используется)
    #[arg(long, value_name = "N", default_value_t = 32, hide = true)]
    batch: usize,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Serve options")]
struct ServeArgs {
    /// Поднять HTTP-сервер для отчёта
    #[arg(long, action = ArgAction::SetTrue)]
    serve: bool,

    /// Порт сервера
    #[arg(long, value_name = "PORT", default_value_t = 8000)]
    port: u16,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Text model options")]
struct TextAnalyzeArgs {
    /// Включить post-анализ sensitive_info.jsonl через text ONNX model
    #[arg(long, action = ArgAction::SetTrue)]
    text_analyze: bool,

    /// Папка модели:
    /// model.onnx + export_metadata.json + tokenizer/tokenizer.json
    #[arg(long, value_name = "DIR")]
    text_model_dir: Option<PathBuf>,

    /// Входной sensitive_info.jsonl
    /// По умолчанию в scan берётся paths.sensitive_jsonl
    #[arg(long, value_name = "FILE")]
    text_input: Option<PathBuf>,

    /// Выходной enriched JSONL
    #[arg(long, value_name = "FILE")]
    text_output: Option<PathBuf>,

    /// Добавлять [PATH] ... [TEXT] ...
    /// По умолчанию выключено, потому что в ноутбуке обучение шло с USE_PATH_PREFIX=false
    #[arg(long, action = ArgAction::SetTrue)]
    text_use_path_prefix: bool,

    /// Max length для токенизатора
    #[arg(long, value_name = "N", default_value_t = 192)]
    text_max_length: usize,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Поднять HTTP-сервер для готового отчёта
    #[command(
        after_help = r#"Examples:
  webhound serv ./example.com/screenshots/report
  webhound serv ./report --port 8000
"#
    )]
    Serv {
        /// Папка отчёта (где лежит index.html)
        #[arg(value_name = "REPORT_DIR")]
        dir: PathBuf,

        /// Порт (по умолчанию 8000)
        #[arg(long, value_name = "PORT", default_value_t = 8000)]
        port: u16,
    },

    /// Вывести URL'ы из Wayback CDX для домена
    #[command(
        after_help = r#"Examples:
  webhound cdx example.com
  webhound cdx example.com --match-type domain --limit 500 --out out.txt
  webhound cdx example.com --year-fallback --year-from 2015 --year-to 2025
"#
    )]
    Cdx {
        /// Домен/host
        #[arg(value_name = "DOMAIN")]
        domain: String,

        #[command(flatten)]
        cdx: CdxArgs,

        /// Сохранить вывод в файл
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Полный скан: CDX → скачивание → assets → secrets → screenshots (+ опц. ML-отчёт)
    #[command(
        after_help = r#"Examples:
  source ./.env
  WebHound scan example.com
  WebHound scan example.com --limit 500
  WebHound scan example.com --analyze --model "$WEBHOUND_VISION_MODEL" --serve
  WebHound scan example.com --text-analyze --text-model-dir "$WEBHOUND_TEXT_MODEL_DIR"
  WebHound scan example.com --analyze --model "$WEBHOUND_VISION_MODEL" --text-analyze --text-model-dir "$WEBHOUND_TEXT_MODEL_DIR" --serve
"#
    )]
    Scan {
        /// Цель скана
        #[arg(value_name = "TARGET")]
        target: String,

        #[command(flatten)]
        cdx: CdxArgs,

        #[command(flatten)]
        report: ReportArgs,

        #[command(flatten)]
        text: TextAnalyzeArgs,

        #[command(flatten)]
        serve: ServeArgs,
    },

    /// Анализ локальной папки со скриншотами (без сети)
    #[command(
        after_help = r#"Examples:
  source ./.env
  WebHound images ./example.com/screenshots
  WebHound images ./example.com/screenshots --model "$WEBHOUND_VISION_MODEL" --serve
  WebHound images ./screenshots --model "$WEBHOUND_VISION_MODEL" --report ./screenshots/report
"#
    )]
    Images {
        /// Папка со скриншотами
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        /// Устарело, в режиме images анализ всегда выполняется
        #[arg(long, action = ArgAction::SetTrue, hide = true)]
        analyze: bool,

        /// Путь к ONNX модели
        #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
        model: PathBuf,

        /// Папка отчёта
        #[arg(long, value_name = "DIR")]
        report: Option<PathBuf>,

        /// Размер batch (пока не используется)
        #[arg(long, value_name = "N", default_value_t = 32, hide = true)]
        batch: usize,

        #[command(flatten)]
        serve: ServeArgs,
    },

    /// Пост-анализ папки assets (или любой папки с файлами) по правилам PATTERNS
    #[command(
        after_help = r#"Examples:
  source ./.env
  WebHound assets ./example.com/assets
  WebHound assets ./example.com/assets --out ./example.com/sensitive_info.post.jsonl
  WebHound text-analyze ./example.com/sensitive_info.post.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR" --out ./example.com/sensitive_info.post.ml.jsonl
"#
    )]
    Assets {
        /// Папка с файлами (обычно .../assets)
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        /// Куда писать JSONL
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Прогнать existing sensitive_info.jsonl через text ONNX model
    #[command(
        after_help = r#"Examples:
  WebHound text-analyze ./example.com/sensitive_info.jsonl
  WebHound text-analyze ./example.com/sensitive_info.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR"
  WebHound text-analyze ./example.com/sensitive_info.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR" --out ./example.com/sensitive_info.ml.jsonl
  WebHound text-analyze ./example.com/sensitive_info.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR" --text-use-path-prefix
"#
    )]
    TextAnalyze {
        /// Входной sensitive_info JSONL
        #[arg(value_name = "INPUT_JSONL")]
        input: PathBuf,

        /// Папка модели
        #[arg(long, value_name = "DIR")]
        model_dir: PathBuf,

        /// Выходной enriched JSONL
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,

        /// Добавлять [PATH] ... [TEXT] ...
        #[arg(long, action = ArgAction::SetTrue)]
        text_use_path_prefix: bool,

        /// Max length для токенизатора
        #[arg(long, value_name = "N", default_value_t = 192)]
        text_max_length: usize,
    },
}

fn analyze_and_maybe_serve(
    images_dir: &PathBuf,
    out_dir: &PathBuf,
    model: &PathBuf,
    serve: bool,
    port: u16,
) -> Result<()> {
    fs::create_dir_all(out_dir).map_err(|e| anyhow!("Не создать {}: {e}", out_dir.display()))?;

    let runner = EyeballerRunner::new(model, Labels::eyeballer_default())?;
    let (_csv, html) = runner.infer_to_csv_html(images_dir, out_dir, "predictions.csv", None)?;

    println!("Отчёт: {}", html.display());

    if serve {
        println!("Сервер: http://127.0.0.1:{}/", port);
        server::server(out_dir, port)?;
    }

    Ok(())
}

fn import_vision_csv_to_db(
    sqlite: &SqliteStorage,
    scan_run_id: i64,
    report_dir: &PathBuf,
) -> Result<()> {
    let csv_path = report_dir.join("predictions.csv");
    if !csv_path.is_file() {
        return Ok(());
    }

    let mut rdr = csv::Reader::from_path(&csv_path)?;
    let headers = rdr.headers()?.clone();

    let file_idx = headers.iter().position(|h| h == "file")
        .ok_or_else(|| anyhow!("predictions.csv: no 'file' column"))?;
    let top_label_idx = headers.iter().position(|h| h == "top_label")
        .ok_or_else(|| anyhow!("predictions.csv: no 'top_label' column"))?;
    let top_prob_idx = headers.iter().position(|h| h == "top_prob")
        .ok_or_else(|| anyhow!("predictions.csv: no 'top_prob' column"))?;

    for rec in rdr.records() {
        let rec = rec?;
        let local_path = rec.get(file_idx).unwrap_or("").to_string();
        let top_label = rec.get(top_label_idx).unwrap_or("").to_string();
        let top_prob: f64 = rec.get(top_prob_idx).unwrap_or("0").parse().unwrap_or(0.0);

        let mut probs_map = serde_json::Map::new();
        for (idx, h) in headers.iter().enumerate() {
            if h != "file" && h != "top_label" && h != "top_prob" {
                if let Some(v) = rec.get(idx) {
                    if let Ok(p) = v.parse::<f64>() {
                        probs_map.insert(h.to_string(), serde_json::json!(p));
                    }
                }
            }
        }

        let ml_scores_json = serde_json::Value::Object(probs_map).to_string();

        sqlite.upsert_screenshot_ml_only(
            scan_run_id,
            "",
            &local_path,
            "vision",
            None,
            &top_label,
            top_prob,
            &ml_scores_json,
        )?;
    }

    Ok(())
}

fn annotate_sensitive_info(
    model_dir: &PathBuf,
    input_jsonl: &PathBuf,
    output_jsonl: &PathBuf,
    use_path_prefix: bool,
    max_length: usize,
) -> Result<()> {
    let mut cfg = TextAnalyzerConfig::new(model_dir);
    cfg.use_path_prefix = use_path_prefix;
    cfg.max_length = max_length;

    let classifier = TextClassifier::new(cfg)?;
    let stats = classifier.annotate_jsonl(input_jsonl, output_jsonl)?;

    println!("Text-ML annotated: {}", output_jsonl.display());
    println!("Processed samples: {}", stats.total);
    for (label, n) in stats.by_label {
        println!("  {label}: {n}");
    }

    Ok(())
}

fn annotate_text_from_db(
    sqlite: &SqliteStorage,
    scan_run_id: i64,
    model_dir: &PathBuf,
    use_path_prefix: bool,
    max_length: usize,
) -> Result<()> {
    let mut cfg = TextAnalyzerConfig::new(model_dir);
    cfg.use_path_prefix = use_path_prefix;
    cfg.max_length = max_length;

    let classifier = TextClassifier::new(cfg)?;
    let rows = sqlite.list_raw_findings_for_run(scan_run_id)?;

    for row in rows {
        let pred = classifier.predict_text(&row.context_text, Some(&row.source_path))?;
        let ml_scores_json = serde_json::to_string(&pred.pred_probs)?;

        sqlite.insert_analysis_finding(&NewAnalysisFinding {
            scan_run_id,
            raw_finding_id: Some(row.id),
            source_path: row.source_path.clone(),
            source_kind: row.source_kind.clone(),
            analysis_stage: "text_ml".to_string(),
            line: row.line,
            sample_kind: row.sample_kind.clone(),
            finding_type: row.finding_type.clone(),
            rule_id: Some(row.rule_id.clone()),
            rule_name: Some(row.rule_name.clone()),
            match_text: row.match_text.clone(),
            context_text: row.context_text.clone(),
            start_offset: Some(row.start_offset),
            end_offset: Some(row.end_offset),
            entropy_h: Some(row.entropy_h),
            entropy_total_bits: Some(row.entropy_total_bits),
            value_len: Some(row.value_len),
            ml_model_name: Some("text".to_string()),
            ml_model_version: None,
            ml_label: Some(pred.pred_label.clone()),
            ml_score: Some(pred.pred_score as f64),
            ml_scores_json: Some(ml_scores_json),
            final_label: Some(pred.pred_label.clone()),
            final_confidence: Some(pred.pred_score as f64),
            analyst_note: None,
            is_false_positive: false,
        })?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.cmd {
        Cmd::Serv { dir, port } => {
            println!(
                "Сервер отчёта: http://0.0.0.0:{}/ (dir = {})",
                port,
                dir.display()
            );
            server::server(&dir, port)?;
        }

        Cmd::Cdx { domain, cdx, out } => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(cdx.timeout_s))
                .build()?;

            let opts = scanner::net::CdxDomainOpts {
                match_type: cdx.match_type.as_str().to_string(),
                collapse_urlkey: !cdx.no_collapse,
                limit: cdx.limit,
                filter_status_200: !cdx.no_filter_200,
                filter_mimetype_html: !cdx.no_filter_html,
                timeout: Duration::from_secs(cdx.timeout_s),
                retries: cdx.retries,
                fallback_year_from: cdx.year_from,
                fallback_year_to: cdx.year_to,
                enable_year_fallback: cdx.year_fallback,
            };

            let body = scanner::net::fetch_wayback_urls_resilient(&client, &domain, opts).await?;

            if let Some(path) = out {
                fs::write(&path, body)?;
                println!("Saved: {}", path.display());
            } else {
                print!("{body}");
            }
        }

        Cmd::Scan {
            target,
            cdx,
            report,
            text,
            serve,
        } => {
            scanner::net::set_cdx_defaults(scanner::net::CdxDomainOpts {
                match_type: cdx.match_type.as_str().to_string(),
                collapse_urlkey: !cdx.no_collapse,
                limit: cdx.limit,
                filter_status_200: !cdx.no_filter_200,
                filter_mimetype_html: !cdx.no_filter_html,
                timeout: Duration::from_secs(cdx.timeout_s),
                retries: cdx.retries,
                fallback_year_from: cdx.year_from,
                fallback_year_to: cdx.year_to,
                enable_year_fallback: cdx.year_fallback,
            });

            let paths = run_scan(&target)
                .await
                .map_err(|e| anyhow!(e.to_string()))?;

            println!("Скан завершён. Результаты: {}", paths.base.display());

if text.text_analyze {
    let model_dir = text
        .text_model_dir
        .clone()
        .ok_or_else(|| anyhow!("--text-model-dir обязателен при --text-analyze"))?;

    let sqlite = SqliteStorage::open(paths.base.join("webhound.db"))?;
    let scan_run_id = sqlite.create_scan_run(storage::NewScanRun {
        target: paths.base.display().to_string(),
        mode: "text_analyze".to_string(),
        status: "running".to_string(),
        config_json: None,
    })?;

    let result = annotate_text_from_db(
        &sqlite,
        scan_run_id,
        &model_dir,
        text.text_use_path_prefix,
        text.text_max_length,
    );

    match result {
        Ok(()) => {
            let _ = sqlite.finish_scan_run(scan_run_id, "success");
        }
        Err(e) => {
            let _ = sqlite.insert_event(&NewEvent {
                scan_run_id: Some(scan_run_id),
                level: "error".to_string(),
                component: "text_ml".to_string(),
                message: "text db annotation failed".to_string(),
                details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
            });
            let _ = sqlite.finish_scan_run(scan_run_id, "failed");
            return Err(e);
        }
    }
}

            if report.analyze {
                let out_dir = report
                    .report
                    .clone()
                    .unwrap_or_else(|| paths.screenshots_dir.join("report"));

                analyze_and_maybe_serve(
                    &paths.screenshots_dir,
                    &out_dir,
                    &report.model,
                    serve.serve,
                    serve.port,
                )?;
            }
        }

        Cmd::Images {
    dir,
    analyze: _,
    model,
    report,
    batch: _,
    serve,
} => {
    let (sqlite, scan_run_id) = scanner::run_images_analysis(&dir).await?;

    let out_dir = report.clone().unwrap_or_else(|| dir.join("report"));
    let result = analyze_and_maybe_serve(&dir, &out_dir, &model, serve.serve, serve.port);

    match result {
        Ok(()) => {
            if let Err(e) = import_vision_csv_to_db(&sqlite, scan_run_id, &out_dir) {
                let _ = sqlite.insert_event(&NewEvent {
                    scan_run_id: Some(scan_run_id),
                    level: "error".to_string(),
                    component: "images".to_string(),
                    message: "import predictions.csv to sqlite failed".to_string(),
                    details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
                });
            }

            let _ = sqlite.finish_scan_run(scan_run_id, "success");
        }
        Err(e) => {
            let _ = sqlite.insert_event(&NewEvent {
                scan_run_id: Some(scan_run_id),
                level: "error".to_string(),
                component: "images".to_string(),
                message: "images analysis failed".to_string(),
                details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
            });
            let _ = sqlite.finish_scan_run(scan_run_id, "failed");
            return Err(e);
        }
    }
}

        Cmd::Assets { dir, out: _ } => {
            scanner::run_assets_analysis(&dir).await?;
            println!("Assets postfilter done.");
            println!("Assets dir: {}", dir.display());
        }

        Cmd::TextAnalyze {
            input,
            model_dir,
            out,
            text_use_path_prefix,
            text_max_length,
        } => {
            let output_jsonl = out.unwrap_or_else(|| {
                let parent = input.parent().unwrap_or_else(|| std::path::Path::new("."));
                parent.join("sensitive_info.ml.jsonl")
            });

            annotate_sensitive_info(
                &model_dir,
                &input,
                &output_jsonl,
                text_use_path_prefix,
                text_max_length,
            )?;
        }
    }

    Ok(())
}
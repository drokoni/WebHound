use analyzer::text::{TextAnalyzerConfig, TextClassifier};
use analyzer::vision::*;
use anyhow::{anyhow, Result};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use scanner::run_scan;
use std::{fs, path::PathBuf, time::Duration};
use storage::{
    NewAnalysisFinding, NewEvent, NewScreenshot, NewScanRun, NewVisionPrediction, SqliteStorage,
};

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
    Domain,
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
    #[arg(long, value_enum, default_value_t = MatchType::Domain)]
    match_type: MatchType,

    #[arg(long, value_name = "N")]
    limit: Option<u32>,

    #[arg(long, action = ArgAction::SetTrue)]
    no_collapse: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    no_filter_200: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    no_filter_html: bool,

    #[arg(long, default_value_t = 30, value_name = "SEC")]
    timeout_s: u64,

    #[arg(long, default_value_t = 6, value_name = "N")]
    retries: u32,

    #[arg(long, action = ArgAction::SetTrue)]
    year_fallback: bool,

    #[arg(long, default_value_t = 2018, value_name = "YYYY")]
    year_from: u16,

    #[arg(long, default_value_t = 2025, value_name = "YYYY")]
    year_to: u16,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Report / ML options")]
struct ReportArgs {
    #[arg(long, action = ArgAction::SetTrue)]
    analyze: bool,

    #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
    model: PathBuf,

    #[arg(long, value_name = "DIR")]
    report: Option<PathBuf>,

    #[arg(long, value_name = "N", default_value_t = 32, hide = true)]
    batch: usize,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Serve options")]
struct ServeArgs {
    #[arg(long, action = ArgAction::SetTrue)]
    serve: bool,

    #[arg(long, value_name = "PORT", default_value_t = 8000)]
    port: u16,

    #[arg(long, value_name = "HOST", default_value = "127.0.0.1")]
    host: String,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Text model options")]
struct TextAnalyzeArgs {
    #[arg(long, action = ArgAction::SetTrue)]
    text_analyze: bool,

    #[arg(long, value_name = "DIR")]
    text_model_dir: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    text_input: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    text_output: Option<PathBuf>,

    #[arg(long, action = ArgAction::SetTrue)]
    text_use_path_prefix: bool,

    #[arg(long, value_name = "N", default_value_t = 192)]
    text_max_length: usize,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    #[command(
        after_help = r#"Examples:
  webhound serv ./example.com/screenshots/report
  webhound serv ./report --host 127.0.0.1 --port 8000
"#
    )]
    Serv {
        #[arg(value_name = "REPORT_DIR")]
        dir: PathBuf,

        #[arg(long, value_name = "PORT", default_value_t = 8000)]
        port: u16,

        #[arg(long, value_name = "HOST", default_value = "127.0.0.1")]
        host: String,
    },

    #[command(
        after_help = r#"Examples:
  webhound cdx example.com
  webhound cdx example.com --match-type domain --limit 500 --out out.txt
  webhound cdx example.com --year-fallback --year-from 2015 --year-to 2025
"#
    )]
    Cdx {
        #[arg(value_name = "DOMAIN")]
        domain: String,

        #[command(flatten)]
        cdx: CdxArgs,

        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

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

    #[command(
        after_help = r#"Examples:
  source ./.env
  WebHound images ./example.com/screenshots
  WebHound images ./example.com/screenshots --model "$WEBHOUND_VISION_MODEL" --serve
  WebHound images ./screenshots --model "$WEBHOUND_VISION_MODEL" --report ./screenshots/report
"#
    )]
    Images {
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        #[arg(long, action = ArgAction::SetTrue, hide = true)]
        analyze: bool,

        #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
        model: PathBuf,

        #[arg(long, value_name = "DIR")]
        report: Option<PathBuf>,

        #[arg(long, value_name = "N", default_value_t = 32, hide = true)]
        batch: usize,

        #[command(flatten)]
        serve: ServeArgs,
    },

    #[command(
        after_help = r#"Examples:
  source ./.env
  WebHound assets ./example.com/assets
  WebHound assets ./example.com/assets --out ./example.com/sensitive_info.post.jsonl
  WebHound text-analyze ./example.com/sensitive_info.post.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR" --out ./example.com/sensitive_info.post.ml.jsonl
"#
    )]
    Assets {
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    #[command(
        after_help = r#"Examples:
  WebHound text-analyze ./example.com/sensitive_info.jsonl
  WebHound text-analyze ./example.com/sensitive_info.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR"
  WebHound text-analyze ./example.com/sensitive_info.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR" --out ./example.com/sensitive_info.ml.jsonl
  WebHound text-analyze ./example.com/sensitive_info.jsonl --model-dir "$WEBHOUND_TEXT_MODEL_DIR" --text-use-path-prefix
"#
    )]
    TextAnalyze {
        #[arg(value_name = "INPUT_JSONL")]
        input: PathBuf,

        #[arg(long, value_name = "DIR")]
        model_dir: PathBuf,

        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,

        #[arg(long, action = ArgAction::SetTrue)]
        text_use_path_prefix: bool,

        #[arg(long, value_name = "N", default_value_t = 192)]
        text_max_length: usize,
    },
}

fn analyze_and_maybe_serve(
    images_dir: &PathBuf,
    out_dir: &PathBuf,
    model: &PathBuf,
    serve: bool,
    host: &str,
    port: u16,
) -> Result<()> {
    fs::create_dir_all(out_dir).map_err(|e| anyhow!("Не создать {}: {e}", out_dir.display()))?;

    let runner = EyeballerRunner::new(model, Labels::eyeballer_default())?;
    let (_csv, html) = runner.infer_to_csv_html(images_dir, out_dir, "predictions.csv", None)?;

    println!("Отчёт: {}", html.display());

    if serve {
        println!("Сервер: http://{}:{}/", host, port);
        server::server_with_bind(out_dir, host, port)?;
    }

    Ok(())
}

fn export_predictions_csv_from_db(
    sqlite: &SqliteStorage,
    run_id: i64,
    out_csv: &PathBuf,
) -> Result<()> {
    let rows = sqlite.list_screenshots_simple(run_id)?;

    if let Some(parent) = out_csv.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut wtr = csv::Writer::from_path(out_csv)?;
    wtr.write_record(["file", "top_label", "top_prob"])?;

    for (_id, _page_url, local_path, ml_label, ml_score, _user_label) in rows {
        wtr.write_record([
            local_path,
            ml_label.unwrap_or_default(),
            ml_score.map(|v| v.to_string()).unwrap_or_default(),
        ])?;
    }

    wtr.flush()?;
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

    let file_idx = headers
        .iter()
        .position(|h| h == "file")
        .ok_or_else(|| anyhow!("predictions.csv: no 'file' column"))?;
    let top_label_idx = headers
        .iter()
        .position(|h| h == "top_label")
        .ok_or_else(|| anyhow!("predictions.csv: no 'top_label' column"))?;
    let top_prob_idx = headers
        .iter()
        .position(|h| h == "top_prob")
        .ok_or_else(|| anyhow!("predictions.csv: no 'top_prob' column"))?;

    for rec in rdr.records() {
        let rec = rec?;
        let local_path_raw = rec.get(file_idx).unwrap_or("").to_string();
        let local_path = if let Ok(canon) = std::path::PathBuf::from(&local_path_raw).canonicalize() {
            canon.to_string_lossy().to_string()
        } else {
            local_path_raw
        };

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
        let shot = sqlite.find_screenshot_by_local_path(&local_path)?;

        sqlite.insert_vision_prediction(&NewVisionPrediction {
            scan_run_id,
            screenshot_id: shot.as_ref().map(|s| s.id),
            local_path: local_path.clone(),
            model_name: Some("vision".to_string()),
            model_version: None,
            top_label: top_label.clone(),
            top_prob,
            probs_json: ml_scores_json.clone(),
        })?;

        if shot.is_some() {
            sqlite.update_screenshot_ml(
                &local_path,
                "vision",
                None,
                &top_label,
                top_prob,
                &ml_scores_json,
            )?;
        } else {
            sqlite.insert_screenshot(&NewScreenshot {
                scan_run_id,
                page_url: String::new(),
                local_path: local_path.clone(),
                image_sha256: None,
                width: None,
                height: None,
                file_size: None,
                ml_model_name: Some("vision".to_string()),
                ml_model_version: None,
                ml_label: Some(top_label.clone()),
                ml_score: Some(top_prob),
                ml_scores_json: Some(ml_scores_json.clone()),
                user_label: None,
                user_label_updated_at: None,
                user_label_updated_by: None,
                analyst_note: None,
            })?;
        }
    }

    export_predictions_csv_from_db(sqlite, scan_run_id, &csv_path)?;
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
    text_run_id: i64,
    model_dir: &PathBuf,
    use_path_prefix: bool,
    max_length: usize,
) -> Result<()> {
    let mut cfg = TextAnalyzerConfig::new(model_dir);
    cfg.use_path_prefix = use_path_prefix;
    cfg.max_length = max_length;

    let classifier = TextClassifier::new(cfg)?;

    let source_run_id = sqlite
        .latest_scan_run_id()?
        .ok_or_else(|| anyhow!("Не найден scan run с raw_findings для text ML"))?;

    let rows = sqlite.list_raw_findings_for_run(source_run_id)?;

    for row in rows {
        let pred = classifier.predict_text(&row.context_text, Some(&row.source_path))?;
        let ml_scores_json = serde_json::to_string(&pred.pred_probs)?;

        sqlite.insert_analysis_finding(&NewAnalysisFinding {
            scan_run_id: text_run_id,
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
        Cmd::Serv { dir, port, host } => {
            println!(
                "Сервер отчёта: http://{}:{}/ (dir = {})",
                host,
                port,
                dir.display()
            );
            server::server_with_bind(&dir, &host, port)?;
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
                let text_run_id = sqlite.create_scan_run(NewScanRun {
                    target: paths.base.display().to_string(),
                    mode: "text_analyze".to_string(),
                    status: "running".to_string(),
                    config_json: None,
                })?;

                let result = annotate_text_from_db(
                    &sqlite,
                    text_run_id,
                    &model_dir,
                    text.text_use_path_prefix,
                    text.text_max_length,
                );

                match result {
                    Ok(()) => {
                        let _ = sqlite.finish_scan_run(text_run_id, "success");
                    }
                    Err(e) => {
                        let _ = sqlite.insert_event(&NewEvent {
                            scan_run_id: Some(text_run_id),
                            level: "error".to_string(),
                            component: "text_ml".to_string(),
                            message: "text db annotation failed".to_string(),
                            details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
                        });
                        let _ = sqlite.finish_scan_run(text_run_id, "failed");
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
                    &serve.host,
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
            let result = analyze_and_maybe_serve(
                &dir,
                &out_dir,
                &model,
                serve.serve,
                &serve.host,
                serve.port,
            );

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
            let sqlite = SqliteStorage::open("webhound.db")?;

            let text_run_id = sqlite.create_scan_run(NewScanRun {
                target: ".".to_string(),
                mode: "text_analyze".to_string(),
                status: "running".to_string(),
                config_json: None,
            })?;

            let result = annotate_text_from_db(
                &sqlite,
                text_run_id,
                &model_dir,
                text_use_path_prefix,
                text_max_length,
            );

            match result {
                Ok(()) => {
                    let _ = sqlite.finish_scan_run(text_run_id, "success");

                    if let Some(output_jsonl) = out {
                        annotate_sensitive_info(
                            &model_dir,
                            &input,
                            &output_jsonl,
                            text_use_path_prefix,
                            text_max_length,
                        )?;
                    }
                }
                Err(e) => {
                    let _ = sqlite.insert_event(&NewEvent {
                        scan_run_id: Some(text_run_id),
                        level: "error".to_string(),
                        component: "text_ml".to_string(),
                        message: "text db annotation failed".to_string(),
                        details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
                    });
                    let _ = sqlite.finish_scan_run(text_run_id, "failed");
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}
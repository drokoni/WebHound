use analyzer::vision::*;
use anyhow::{anyhow, Result};
use clap::{ArgAction, Parser, Subcommand};
use scanner::run_scan;
use std::{fs, path::PathBuf, time::Duration};

#[derive(Parser, Debug)]
#[command(
    author = "McQueen",
    version = "0.1",
    about = "WebHound: scan + reports",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Поднять HTTP-сервер для готового отчёта (index.html + CSV внутри DIR)
    Serv {
        /// Папка отчёта
        #[arg(value_name = "REPORT_DIR")]
        dir: PathBuf,
        /// Порт (по умолчанию 8000)
        #[arg(long, value_name = "PORT", default_value_t = 8000)]
        port: u16,
    },

    /// Вывести URL’ы из Wayback CDX для домена (stdout или в файл)
    Cdx {
        /// Домен/host (например www.wildberries.ru)
        #[arg(value_name = "DOMAIN")]
        domain: String,

        #[arg(long, default_value = "domain")]
        match_type: String,

        #[arg(long)]
        limit: Option<u32>,

        #[arg(long, action = ArgAction::SetTrue)]
        no_collapse: bool,

        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_200: bool,

        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_html: bool,

        #[arg(long, default_value_t = 30)]
        timeout_s: u64,

        #[arg(long, default_value_t = 6)]
        retries: u32,

        #[arg(long, action = ArgAction::SetTrue)]
        year_fallback: bool,

        #[arg(long, default_value_t = 2018)]
        year_from: u16,

        #[arg(long, default_value_t = 2025)]
        year_to: u16,

        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Запустить скан 
    Scan {
        #[arg(value_name = "TARGET")]
        target: String,

        // CDX opts
        #[arg(long, default_value = "domain")]
        match_type: String,

        #[arg(long)]
        limit: Option<u32>,

        #[arg(long, action = ArgAction::SetTrue)]
        no_collapse: bool,

        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_200: bool,

        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_html: bool,

        #[arg(long, default_value_t = 30)]
        timeout_s: u64,

        #[arg(long, default_value_t = 6)]
        retries: u32,

        #[arg(long, action = ArgAction::SetTrue)]
        year_fallback: bool,

        #[arg(long, default_value_t = 2018)]
        year_from: u16,

        #[arg(long, default_value_t = 2025)]
        year_to: u16,

        // analyze opts
        #[arg(long, action = ArgAction::SetTrue)]
        analyze: bool,

        #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
        model: PathBuf,

        #[arg(long, value_name = "DIR")]
        report: Option<PathBuf>,

        #[arg(long, value_name = "N", default_value_t = 32)]
        batch: usize,

        #[arg(long, action = ArgAction::SetTrue)]
        serve: bool,

        #[arg(long, value_name = "PORT", default_value_t = 8000)]
        port: u16,
    },

    /// Анализ локальной папки со скриншотами (без сети)
    Images {
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        #[arg(long, action = ArgAction::SetTrue)]
        analyze: bool,

        #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
        model: PathBuf,

        #[arg(long, value_name = "DIR")]
        report: Option<PathBuf>,

        #[arg(long, value_name = "N", default_value_t = 32)]
        batch: usize,

        #[arg(long, action = ArgAction::SetTrue)]
        serve: bool,

        #[arg(long, value_name = "PORT", default_value_t = 8000)]
        port: u16,
    },

    /// Пост-анализ папки assets (или любой папки с файлами) по правилам PATTERNS
    Assets {
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

fn base_dir_name(target: &str) -> String {
    if let Ok(u) = url::Url::parse(target) {
        let host = u.host_str().unwrap_or("site");
        if let Some(port) = u.port() {
            return format!("{}_{}", host, port);
        }
        return host.to_string();
    }
    target.replace(':', "_")
}

fn report_dir_for_target(target: &str, report: &Option<PathBuf>) -> PathBuf {
    report
        .clone()
        .unwrap_or_else(|| PathBuf::from(base_dir_name(target)).join("report"))
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.cmd {
        Cmd::Serv { dir, port } => {
            println!(
                "Сервер отчёта: http://127.0.0.1:{}/  (dir = {})",
                port,
                dir.display()
            );
            server::server(&dir, port)?;
        }

        Cmd::Cdx {
            domain,
            match_type,
            limit,
            no_collapse,
            no_filter_200,
            no_filter_html,
            timeout_s,
            retries,
            year_fallback,
            year_from,
            year_to,
            out,
        } => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_s))
                .build()?;

            let opts = scanner::net::CdxDomainOpts {
                match_type,
                collapse_urlkey: !no_collapse,
                limit,
                filter_status_200: !no_filter_200,
                filter_mimetype_html: !no_filter_html,
                timeout: Duration::from_secs(timeout_s),
                retries,
                fallback_year_from: year_from,
                fallback_year_to: year_to,
                enable_year_fallback: year_fallback,
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
            match_type,
            limit,
            no_collapse,
            no_filter_200,
            no_filter_html,
            timeout_s,
            retries,
            year_fallback,
            year_from,
            year_to,
            analyze,
            model,
            report,
            batch: _batch,
            serve,
            port,
        } => {
            scanner::net::set_cdx_defaults(scanner::net::CdxDomainOpts {
                match_type,
                collapse_urlkey: !no_collapse,
                limit,
                filter_status_200: !no_filter_200,
                filter_mimetype_html: !no_filter_html,
                timeout: Duration::from_secs(timeout_s),
                retries,
                fallback_year_from: year_from,
                fallback_year_to: year_to,
                enable_year_fallback: year_fallback,
            });

            let paths = run_scan(&target)
                .await
                .map_err(|e| anyhow!(e.to_string()))?;
            println!("Скан завершён. Результаты: {}", paths.base.display());

            if analyze {
                let out_dir = report_dir_for_target(&target, &report);
                analyze_and_maybe_serve(&paths.screenshots_dir, &out_dir, &model, serve, port)?;
            }
        }

        Cmd::Images {
            dir,
            analyze: _,
            model,
            report,
            batch: _batch,
            serve,
            port,
        } => {
            // В режиме images анализ всегда выполняем (это и есть смысл режима)
            let out_dir = report.clone().unwrap_or_else(|| dir.join("report"));
            analyze_and_maybe_serve(&dir, &out_dir, &model, serve, port)?;
        }

        Cmd::Assets { dir, out } => {
            let out_file = out.unwrap_or_else(|| {
                if dir.file_name().and_then(|s| s.to_str()) == Some("assets") {
                    dir.parent()
                        .unwrap_or(&dir)
                        .join("sensitive_info.post.jsonl")
                } else {
                    dir.join("sensitive_info.post.jsonl")
                }
            });

            scanner::postfilter::postfilter_assets_dir_to_file(&dir, &out_file).await?;
            println!("Assets postfilter done.");
            println!("Assets dir: {}", dir.display());
            println!("Output: {}", out_file.display());
        }
    }

    Ok(())
}

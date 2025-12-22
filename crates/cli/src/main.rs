use analyzer::vision::*;
use anyhow::{anyhow, Result};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use scanner::run_scan;
use std::{fs, path::PathBuf, time::Duration};

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

        /// matchType (обычно "domain")
        #[arg(long, default_value = "domain")]
        match_type: String,

        /// limit=...
        #[arg(long)]
        limit: Option<u32>,

        /// Не делать collapse=urlkey
        #[arg(long, action = ArgAction::SetTrue)]
        no_collapse: bool,

        /// Не ставить filter=statuscode:200
        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_200: bool,

        /// Не ставить filter=mimetype:text/html
        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_html: bool,

        /// Таймаут на один запрос (сек)
        #[arg(long, default_value_t = 30)]
        timeout_s: u64,

        /// Ретраи на 429/5xx/timeout
        #[arg(long, default_value_t = 6)]
        retries: u32,

        /// Включить fallback по годам
        #[arg(long, action = ArgAction::SetTrue)]
        year_fallback: bool,

        /// Год начала fallback (включительно)
        #[arg(long, default_value_t = 2018)]
        year_from: u16,

        /// Год конца fallback (включительно)
        #[arg(long, default_value_t = 2025)]
        year_to: u16,

        /// Куда сохранить список (иначе stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Запустить скан с настройками CDX (без изменения run_scan сигнатуры)
    Scan {
        /// TARGET (домен или URL)
        #[arg(value_name = "TARGET")]
        target: String,

        /// matchType (обычно "domain")
        #[arg(long, default_value = "domain")]
        match_type: String,

        /// limit=...
        #[arg(long)]
        limit: Option<u32>,

        /// Не делать collapse=urlkey
        #[arg(long, action = ArgAction::SetTrue)]
        no_collapse: bool,

        /// Не ставить filter=statuscode:200
        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_200: bool,

        /// Не ставить filter=mimetype:text/html
        #[arg(long, action = ArgAction::SetTrue)]
        no_filter_html: bool,

        /// Таймаут на один запрос (сек)
        #[arg(long, default_value_t = 30)]
        timeout_s: u64,

        /// Ретраи на 429/5xx/timeout
        #[arg(long, default_value_t = 6)]
        retries: u32,

        /// Включить fallback по годам
        #[arg(long, action = ArgAction::SetTrue)]
        year_fallback: bool,

        /// Год начала fallback (включительно)
        #[arg(long, default_value_t = 2018)]
        year_from: u16,

        /// Год конца fallback (включительно)
        #[arg(long, default_value_t = 2025)]
        year_to: u16,

        /// Анализировать скриншоты после скана
        #[arg(long, action = ArgAction::SetTrue)]
        analyze: bool,

        /// Путь к .onnx модели
        #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
        model: PathBuf,

        /// Папка для отчёта
        #[arg(long, value_name = "DIR")]
        report: Option<PathBuf>,

        /// Размер батча
        #[arg(long, value_name = "N", default_value_t = 32)]
        batch: usize,

        /// Поднять локальный HTTP-сервер (для основного режима)
        #[arg(long, action = ArgAction::SetTrue)]
        serve: bool,

        /// Порт сервера (для основного режима)
        #[arg(long, value_name = "PORT", default_value_t = 8000)]
        port: u16,
    },
}

#[derive(Parser, Debug)]
#[command(
    author = "McQueen",
    version = "0.1",
    about = "Сканер + Eyeballer ONNX-анализ",
    long_about = None
)]
struct Cli {
    /// Подкоманды (например, `serv`, `cdx`, `scan`). Если не указана — работает основной режим (скан/анализ).
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Цель для скана: домен (example.com) или URL (http://127.0.0.1:8080/...)
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Папка с изображениями. Если указана — скан НЕ выполняется.
    #[arg(long, value_name = "DIR")]
    images: Option<PathBuf>,

    /// Выполнить анализ скриншотов (если задан --images, включается автоматически)
    #[arg(long, action = ArgAction::SetTrue)]
    analyze: bool,

    /// Путь к .onnx модели
    #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
    model: PathBuf,

    /// Папка для отчёта
    #[arg(long, value_name = "DIR")]
    report: Option<PathBuf>,

    /// Размер батча
    #[arg(long, value_name = "N", default_value_t = 32)]
    batch: usize,

    /// Поднять локальный HTTP-сервер (для основного режима)
    #[arg(long, action = ArgAction::SetTrue)]
    serve: bool,

    /// Порт сервера (для основного режима)
    #[arg(long, value_name = "PORT", default_value_t = 8000)]
    port: u16,

    /// Пост-анализ папки assets (или любой папки с файлами) по правилам PATTERNS.
    /// В этом режиме сеть/скан НЕ запускается.
    #[arg(long, value_name = "DIR")]
    assets: Option<PathBuf>,

    /// Куда писать результаты пост-анализа assets.
    /// По умолчанию: если DIR заканчивается на ".../assets" -> "../sensitive_info.post.txt",
    /// иначе -> "DIR/sensitive_info.post.txt"
    #[arg(long, value_name = "FILE")]
    assets_out: Option<PathBuf>,
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

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Cli::parse();

    // --- Подкоманды ---
    if let Some(cmd) = args.cmd.take() {
        match cmd {
            Cmd::Serv { dir, port } => {
                println!(
                    "Сервер отчёта: http://127.0.0.1:{}/  (dir = {})",
                    port,
                    dir.display()
                );
                server::server(&dir, port)?;
                return Ok(());
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
                return Ok(());
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
                batch,
                serve,
                port,
            } => {
                // Устанавливаем CDX дефолты, которые будет использовать net.rs внутри run_scan
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

                let paths = run_scan(&target).await.map_err(|e| anyhow!(e.to_string()))?;
                println!("Скан завершён. Результаты: {}", paths.base.display());

                if analyze {
                    let images_dir = paths.screenshots_dir.clone();
                    let out_dir = report
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(base_dir_name(&target)).join("report"));

                    fs::create_dir_all(&out_dir)
                        .map_err(|e| anyhow!("Не создать {}: {e}", out_dir.display()))?;

                    let runner = EyeballerRunner::new(&model, Labels::eyeballer_default())?;
                    let (_csv, html) =
                        runner.infer_to_csv_html(&images_dir, &out_dir, "predictions.csv", None)?;
                    println!("Отчёт: {}", html.display());

                    if serve {
                        println!("Сервер: http://127.0.0.1:{}/", port);
                        server::server(&out_dir, port)?;
                    }
                }

                return Ok(());
            }
        }
    }

    // --- Assets postfilter режим ---
    if let Some(assets_dir) = args.assets.clone() {
        let out_file = args.assets_out.clone().unwrap_or_else(|| {
            if assets_dir.file_name().and_then(|s| s.to_str()) == Some("assets") {
                assets_dir
                    .parent()
                    .unwrap_or(&assets_dir)
                    .join("sensitive_info.post.txt")
            } else {
                assets_dir.join("sensitive_info.post.txt")
            }
        });

        scanner::postfilter::postfilter_assets_dir_to_file(&assets_dir, &out_file).await?;

        println!("Assets postfilter done.");
        println!("Assets dir: {}", assets_dir.display());
        println!("Output: {}", out_file.display());
        return Ok(());
    }

    // --- Валидация для основного режима ---
    if args.images.is_none() && args.target.is_none() {
        let mut cmd = Cli::command();
        cmd.print_help().ok();
        eprintln!("\n\nОшибка: укажи TARGET или --images DIR (или используй подкоманду `serv`).");
        return Ok(());
    }

    // --- Режим 1: только инференс по папке (--images) ---
    if let Some(images_dir) = args.images.clone() {
        let out_dir = args.report.clone().unwrap_or_else(|| images_dir.join("report"));

        fs::create_dir_all(&out_dir)
            .map_err(|e| anyhow!("Не создать {}: {e}", out_dir.display()))?;

        args.analyze = true;

        let runner = EyeballerRunner::new(&args.model, Labels::eyeballer_default())?;
        let (_csv, html) = runner.infer_to_csv_html(&images_dir, &out_dir, "predictions.csv", None)?;
        println!("Отчёт: {}", html.display());

        if args.serve {
            println!("Сервер: http://127.0.0.1:{}/", args.port);
            server::server(&out_dir, args.port)?;
        }
        return Ok(());
    }

    // --- Режим 2: полный цикл — скан → (опц.) анализ ---
    let target = args.target.as_deref().unwrap();
    let paths = run_scan(target).await.map_err(|e| anyhow!(e.to_string()))?;
    println!("Скан завершён. Результаты: {}", paths.base.display());

    if args.analyze {
        let images_dir = paths.screenshots_dir.clone();
        let out_dir = args
            .report
            .clone()
            .unwrap_or_else(|| PathBuf::from(base_dir_name(target)).join("report"));

        fs::create_dir_all(&out_dir)
            .map_err(|e| anyhow!("Не создать {}: {e}", out_dir.display()))?;

        let runner = EyeballerRunner::new(&args.model, Labels::eyeballer_default())?;
        let (_csv, html) =
            runner.infer_to_csv_html(&images_dir, &out_dir, "predictions.csv", None)?;
        println!("Отчёт: {}", html.display());

        if args.serve {
            println!("Сервер: http://127.0.0.1:{}/", args.port);
            server::server(&out_dir, args.port)?;
        }
    }

    Ok(())
}


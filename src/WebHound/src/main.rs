use analyzer::vision::*;
use anyhow::{anyhow, Result};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use scanner::run_scan;
use std::{fs, path::PathBuf, time::Duration};

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
    /// Домен + поддомены (обычно нужно это)
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

    /// Отключить collapse=urlkey (иначе CDX склеивает дубли)
    #[arg(long, action = ArgAction::SetTrue)]
    no_collapse: bool,

    /// Разрешить записи со статусом не-200 (по умолчанию фильтруется только 200)
    #[arg(long, action = ArgAction::SetTrue)]
    no_filter_200: bool,

    /// Разрешить не-HTML (JS/CSS/PDF и т.д.), по умолчанию только HTML
    #[arg(long, action = ArgAction::SetTrue)]
    no_filter_html: bool,

    /// Таймаут HTTP запросов (в секундах)
    #[arg(long, default_value_t = 30, value_name = "SEC")]
    timeout_s: u64,

    /// Количество ретраев при 429/5xx/сетевых ошибках
    #[arg(long, default_value_t = 6, value_name = "N")]
    retries: u32,

    /// Включить fallback по годам (если доменный CDX-запрос “плохой”)
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

    /// Путь к ONNX модели
    #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
    model: PathBuf,

    /// Папка отчёта.
    /// Важно: для scan по умолчанию будет <screenshots>/report (правильный layout для HTML).
    #[arg(long, value_name = "DIR")]
    report: Option<PathBuf>,

    /// Размер batch (сейчас параметр зарезервирован и не используется)
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

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Поднять HTTP-сервер для готового отчёта (index.html + CSV внутри DIR)
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

    /// Вывести URL’ы из Wayback CDX для домена (stdout или в файл)
    #[command(
        after_help = r#"Examples:
  webhound cdx example.com
  webhound cdx example.com --match-type domain --limit 500 --out out.txt
  webhound cdx example.com --year-fallback --year-from 2015 --year-to 2025
"#
    )]
    Cdx {
        /// Домен/host (например www.wildberries.ru)
        #[arg(value_name = "DOMAIN")]
        domain: String,

        #[command(flatten)]
        cdx: CdxArgs,

        /// Сохранить вывод в файл (иначе печатает в stdout)
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Полный скан: CDX → скачивание → assets → secrets → screenshots (+ опц. ML-отчёт)
    #[command(
        after_help = r#"Examples:
  webhound scan example.com
  webhound scan example.com --limit 500
  webhound scan example.com --analyze --serve
  webhound scan example.com --analyze --report ./example.com/screenshots/report --port 8000 --serve
"#
    )]
    Scan {
        /// Цель скана (лучше передавать домен: example.com)
        #[arg(value_name = "TARGET")]
        target: String,

        #[command(flatten)]
        cdx: CdxArgs,

        #[command(flatten)]
        report: ReportArgs,

        #[command(flatten)]
        serve: ServeArgs,
    },

    /// Анализ локальной папки со скриншотами (без сети)
    #[command(
        after_help = r#"Examples:
  webhound images ./example.com/screenshots
  webhound images ./example.com/screenshots --serve
  webhound images ./screenshots --model assets/ml/eyeballer.onnx --report ./screenshots/report
"#
    )]
    Images {
        /// Папка со скриншотами (PNG/JPG)
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        /// (устарело) — в режиме images анализ всегда выполняется
        #[arg(long, action = ArgAction::SetTrue, hide = true)]
        analyze: bool,

        /// Путь к ONNX модели
        #[arg(long, value_name = "PATH", default_value = "assets/ml/eyeballer.onnx")]
        model: PathBuf,

        /// Папка отчёта (по умолчанию: <DIR>/report)
        #[arg(long, value_name = "DIR")]
        report: Option<PathBuf>,

        /// Размер batch (сейчас параметр зарезервирован и не используется)
        #[arg(long, value_name = "N", default_value_t = 32, hide = true)]
        batch: usize,

        #[command(flatten)]
        serve: ServeArgs,
    },

    /// Пост-анализ папки assets (или любой папки с файлами) по правилам PATTERNS
    #[command(
        after_help = r#"Examples:
  webhound assets ./example.com/assets
  webhound assets ./example.com/assets --out ./example.com/sensitive_info.post.jsonl
"#
    )]
    Assets {
        /// Папка с файлами (обычно .../assets)
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        /// Куда писать JSONL (по умолчанию: sensitive_info.post.jsonl рядом)
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
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
            serve,
        } => {
            // Устанавливаем defaults для net слоя (scan потом их использует)
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

            if report.analyze {
                // Самый “правильный” дефолт: отчёт рядом со скриншотами -> <screenshots>/report
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
            // В режиме images анализ всегда выполняем (это и есть смысл режима)
            let out_dir = report.clone().unwrap_or_else(|| dir.join("report"));
            analyze_and_maybe_serve(&dir, &out_dir, &model, serve.serve, serve.port)?;
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


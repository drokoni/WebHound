use analyzer::vision::*;
use anyhow::{anyhow, Result};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use scanner::run_scan;
use server::server;
use std::{fs, path::PathBuf};

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
}

#[derive(Parser, Debug)]
#[command(
    author = "McQueen",
    version = "0.1",
    about = "Сканер + Eyeballer ONNX-анализ",
    long_about = None
)]
struct Cli {
    /// Подкоманды (например, `serv`). Если не указана — работает основной режим (скан/анализ).
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
    // Если это URL — берём host[:port], иначе оставляем как есть (домен/host)
    if let Ok(u) = url::Url::parse(target) {
        let host = u.host_str().unwrap_or("site");
        if let Some(port) = u.port() {
            return format!("{}_{}", host, port); // ':' в имени папки не нужен
        }
        return host.to_string();
    }

    // target без схемы: example.com или 127.0.0.1:8080
    target.replace(':', "_")
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Cli::parse();

    // --- Подкоманда: только сервер ---
    if let Some(Cmd::Serv { dir, port }) = args.cmd {
        println!(
            "Сервер отчёта: http://127.0.0.1:{}/  (dir = {})",
            port,
            dir.display()
        );
        server::server(&dir, port)?;
        return Ok(());
    }
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
    // допускаются два пути:
    //   1) --images DIR (тогда target не обязателен)
    //   2) TARGET (тогда --images не нужен)
    if args.images.is_none() && args.target.is_none() {
        let mut cmd = Cli::command();
        cmd.print_help().ok();
        eprintln!("\n\nОшибка: укажи TARGET или --images DIR (или используй подкоманду `serv`).");
        return Ok(());
    }

    // --- Режим 1: только инференс по папке (--images) ---
    if let Some(images_dir) = args.images.clone() {
        let out_dir = args
            .report
            .clone()
            .unwrap_or_else(|| images_dir.join("report"));

        fs::create_dir_all(&out_dir)
            .map_err(|e| anyhow!("Не создать {}: {e}", out_dir.display()))?;

        // включаем analyze автоматически в этом режиме
        args.analyze = true;

        let runner = EyeballerRunner::new(&args.model, Labels::eyeballer_default())?;
        let (_csv, html) =
            runner.infer_to_csv_html(&images_dir, &out_dir, "predictions.csv", None)?;
        println!("Отчёт: {}", html.display());

        if args.serve {
            println!("Сервер: http://127.0.0.1:{}/", args.port);
            server::server(&out_dir, args.port)?;
        }
        return Ok(());
    }

    // --- Режим 2: полный цикл — скан → (опц.) анализ ---
    let target = args.target.as_deref().unwrap(); // к этому месту гарантированно Some
    let base = base_dir_name(target);

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

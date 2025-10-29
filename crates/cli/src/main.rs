use anyhow::{Result, anyhow};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use std::{fs, path::PathBuf};
use analyzer::vision::*;
use server::server;

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

    /// Домен для скана (если НЕ указан --images и НЕ задана подкоманда)
    #[arg(value_name = "DOMAIN")]
    domain: Option<String>,

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

    // --- Валидация для основного режима ---
    // допускаются два пути:
    //   1) --images DIR (тогда domain не обязателен)
    //   2) DOMAIN (тогда --images не нужен)
    if args.images.is_none() && args.domain.is_none() {
        let mut cmd = Cli::command();
        cmd.print_help().ok();
        eprintln!("\n\nОшибка: укажи DOMAIN или --images DIR (или используй подкоманду `serv`).");
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
    let domain = args.domain.as_deref().unwrap(); // к этому месту гарантированно Some

    let paths = run_scan(domain).await.map_err(|e| anyhow!(e.to_string()))?;
    println!("Скан завершён. Результаты: {}", paths.base.display());

    if args.analyze {
        let images_dir = paths.screenshots_dir.clone();
        let out_dir = args
            .report
            .clone()
            .unwrap_or_else(|| PathBuf::from(domain).join("report"));

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

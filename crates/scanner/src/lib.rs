pub mod browser_manager;
pub mod crawler;
pub mod net;
pub mod screenshot;

pub use crawler::{PathsLike, process_single_url};
pub use net::{fetch_live_or_wayback, fetch_wayback_urls};
pub use screenshot::make_screenshot_task;
use anyhow::Result;
use futures::{stream, StreamExt};
use reqwest::Client;
use std::{
    collections::HashSet,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use core::utils::{extract_subdomains, read_urls};

// =====================================================================
// 4) Paths + адаптер под crawler::PathsLike
// =====================================================================
#[derive(Clone)]
pub struct Paths {
    pub base: PathBuf,
    pub out_txt: PathBuf,
    pub subdomains_txt: PathBuf,
    pub screenshots_dir: PathBuf,
    pub jsscripts_dir: PathBuf,
    pub sensitive_info_txt: PathBuf,
    pub assets_dir: PathBuf,
}

impl Paths {
    pub fn new(domain: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let base = PathBuf::from(domain);
        let screenshots_dir = base.join("screenshots");
        let jsscripts_dir = base.join("JSscripts");
        let assets_dir = base.join("assets");

        fs::create_dir_all(&screenshots_dir)?;
        fs::create_dir_all(&jsscripts_dir)?;
        fs::create_dir_all(&assets_dir)?;

        Ok(Self {
            base: base.clone(),
            out_txt: base.join("out.txt"),
            subdomains_txt: base.join("subdomains.txt"),
            screenshots_dir,
            jsscripts_dir,
            sensitive_info_txt: base.join("sensitive_info.txt"),
            assets_dir,
        })
    }
}

impl PathsLike for Paths {
    fn screenshots_dir(&self) -> &Path { &self.screenshots_dir }
    fn jsscripts_dir(&self)   -> &Path { &self.jsscripts_dir }
    fn assets_dir(&self)      -> &Path { &self.assets_dir }
}

// =====================================================================
// 5) Скан как библиотечная функция
// =====================================================================
pub async fn run_scan(domain: &str) -> Result<Paths, Box<dyn std::error::Error>> {
    let paths = Paths::new(domain)?;
    let client = Client::new();

    // 1) Wayback URLs
    let body = fetch_wayback_urls(&client, domain).await?;
    fs::write(&paths.out_txt, &body)?;

    // 2) Поддомены
    let subdomains = extract_subdomains(&paths.out_txt).await?;
    if !subdomains.is_empty() {
        fs::write(&paths.subdomains_txt, subdomains.join("\n"))?;
    }

    // 3) Чувствительная информация
    let info_file = Arc::new(Mutex::new(File::create(&paths.sensitive_info_txt)?));

    // 4) URL’ы — читаем, чистим, дедуп
    let mut urls = read_urls(&paths.out_txt).await?;
    urls.retain(|u| !u.trim().is_empty());
    //let urls: Vec<String> = urls.into_iter().collect::<HashSet<_>>().into_iter().collect();
    let urls: Vec<String> = urls
        .into_iter()
        .collect::<HashSet<String>>()   // <- явно HashSet<String>
        .into_iter()
        .collect();
    
    // 5) Параллельная обработка
    let concurrency = 4usize;
    stream::iter(urls.into_iter().map(|url| {
        let client = client.clone();
        let info_file = Arc::clone(&info_file);
        let paths = paths.clone();
        async move {
            if let Err(e) = process_single_url(&client, &url, &paths, &info_file).await {
                eprintln!("Ошибка обработки {}: {}", url, e);
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;

    Ok(paths)
}

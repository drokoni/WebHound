pub mod browser_manager;
pub mod crawler;
pub mod net;
pub mod postfilter;
pub mod screenshot;
pub mod sensitive_jsonl;

use anyhow::Result;
use core::utils::{extract_subdomains, read_urls};
use core::PathsLike;
pub use crawler::process_single_url;
use futures::{stream, StreamExt};
pub use net::{fetch_live_or_wayback, fetch_wayback_urls};
use reqwest::Client;
pub use screenshot::make_screenshot_task;
use std::{
    collections::HashSet,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::Arc,
};
use storage::{NewEvent, NewOutUrl, NewScanRun, NewSubdomain, SqliteStorage};
use tokio::sync::Mutex;

use crate::sensitive_jsonl::SensitiveSink;

#[derive(Clone)]
pub struct Paths {
    pub base: PathBuf,
    pub out_txt: PathBuf,
    pub subdomains_txt: PathBuf,
    pub screenshots_dir: PathBuf,
    pub sensitive_info_txt: PathBuf,
    pub assets_dir: PathBuf,
    pub sqlite_db: PathBuf,
}

#[derive(Clone)]
pub struct ScanContext {
    pub sqlite: Option<SqliteStorage>,
    pub scan_run_id: Option<i64>,
}

impl Paths {
    pub fn new(domain: &str) -> Result<Self> {
        let base = PathBuf::from(domain);
        let screenshots_dir = base.join("screenshots");
        let assets_dir = base.join("assets");

        fs::create_dir_all(&screenshots_dir)?;
        fs::create_dir_all(&assets_dir)?;

        Ok(Self {
            base: base.clone(),
            out_txt: base.join("out.txt"),
            subdomains_txt: base.join("subdomains.txt"),
            screenshots_dir,
            sensitive_info_txt: base.join("sensitive_info.jsonl"),
            assets_dir,
            sqlite_db: base.join("webhound.db"),
        })
    }
}

impl PathsLike for Paths {
    fn screenshots_dir(&self) -> &Path {
        &self.screenshots_dir
    }

    fn assets_dir(&self) -> &Path {
        &self.assets_dir
    }
}

pub async fn run_scan(domain: &str) -> Result<Paths> {
    let paths = Paths::new(domain)?;
    let client = Client::new();

    let sqlite = SqliteStorage::open(&paths.sqlite_db)?;
    let scan_run_id = sqlite.create_scan_run(NewScanRun {
        target: domain.to_string(),
        mode: "scan".to_string(),
        status: "running".to_string(),
        config_json: None,
    })?;

    let _scan_ctx = ScanContext {
        sqlite: Some(sqlite.clone()),
        scan_run_id: Some(scan_run_id),
    };

    let result = async {
        let body = fetch_wayback_urls(&client, domain).await?;
        fs::write(&paths.out_txt, &body)?;

        for line in body.lines().map(str::trim).filter(|s| !s.is_empty()) {
            sqlite.insert_out_url(&NewOutUrl {
                scan_run_id,
                url: line.to_string(),
            })?;
        }

        let subdomains = extract_subdomains(&paths.out_txt).await?;
        if !subdomains.is_empty() {
            fs::write(&paths.subdomains_txt, subdomains.join("\n"))?;
        }

        for sub in &subdomains {
            sqlite.insert_subdomain(&NewSubdomain {
                scan_run_id,
                subdomain: sub.clone(),
            })?;
        }

        let info_file = Arc::new(Mutex::new(File::create(&paths.sensitive_info_txt)?));
        let sink = SensitiveSink::new(
            Some(Arc::clone(&info_file)),
            Some(sqlite.clone()),
            Some(scan_run_id),
        );

        let mut urls = read_urls(&paths.out_txt).await?;
        urls.retain(|u| !u.trim().is_empty());

        let urls: Vec<String> = urls
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let concurrency = 4usize;

        stream::iter(urls.into_iter().map(|url| {
            let client = client.clone();
            let sink = sink.clone();
            let paths = paths.clone();

            async move {
                if let Err(e) = process_single_url(&client, &url, &paths, &sink).await {
                    eprintln!("Ошибка обработки {}: {}", url, e);
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        }))
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

        if let Err(e) = postfilter::postfilter_assets_dir(&paths.assets_dir, &sink).await {
            eprintln!("[!] Postfilter assets failed: {e}");
            let _ = sqlite.insert_event(&NewEvent {
                scan_run_id: Some(scan_run_id),
                level: "error".to_string(),
                component: "postfilter".to_string(),
                message: "postfilter_assets_dir failed".to_string(),
                details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
            });
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    match result {
        Ok(()) => {
            let _ = sqlite.finish_scan_run(scan_run_id, "success");
            Ok(paths)
        }
        Err(e) => {
            let _ = sqlite.insert_event(&NewEvent {
                scan_run_id: Some(scan_run_id),
                level: "error".to_string(),
                component: "run_scan".to_string(),
                message: "scan run failed".to_string(),
                details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
            });
            let _ = sqlite.finish_scan_run(scan_run_id, "failed");
            Err(e)
        }
    }
}
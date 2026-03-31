pub mod browser_manager;
pub mod crawler;
pub mod net;
pub mod postfilter;
pub mod screenshot;
pub mod sensitive_jsonl;

use anyhow::Result;
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
use url::Url;

use crate::sensitive_jsonl::SensitiveSink;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StorageMode {
    Files,
    Db,
}

impl StorageMode {
    pub fn writes_files(self) -> bool {
        matches!(self, Self::Files)
    }

    pub fn writes_db(self) -> bool {
        matches!(self, Self::Db)
    }
}

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

fn extract_subdomains_from_body(body: &str) -> Vec<String> {
    let mut out = HashSet::new();

    for line in body.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(url) = Url::parse(line) {
            if let Some(host) = url.host_str() {
                out.insert(host.to_string());
            }
        }
    }

    let mut out: Vec<String> = out.into_iter().collect();
    out.sort();
    out
}

pub async fn run_scan(domain: &str, storage_mode: StorageMode) -> Result<Paths> {
    let paths = Paths::new(domain)?;
    let client = Client::new();

    let sqlite = if storage_mode.writes_db() {
        Some(SqliteStorage::open(&paths.sqlite_db)?)
    } else {
        None
    };

    let scan_run_id = if let Some(sqlite) = &sqlite {
        Some(sqlite.create_scan_run(NewScanRun {
            target: domain.to_string(),
            mode: "scan".to_string(),
            status: "running".to_string(),
            config_json: None,
        })?)
    } else {
        None
    };

    let _scan_ctx = ScanContext {
        sqlite: sqlite.clone(),
        scan_run_id,
    };

    let result = async {
        let body = fetch_wayback_urls(&client, domain).await?;

        if storage_mode.writes_files() {
            fs::write(&paths.out_txt, &body)?;
        }

        if let (Some(sqlite), Some(scan_run_id)) = (&sqlite, scan_run_id) {
            for line in body.lines().map(str::trim).filter(|s| !s.is_empty()) {
                sqlite.insert_out_url(&NewOutUrl {
                    scan_run_id,
                    url: line.to_string(),
                })?;
            }
        }

        let subdomains = extract_subdomains_from_body(&body);

        if storage_mode.writes_files() && !subdomains.is_empty() {
            fs::write(&paths.subdomains_txt, subdomains.join("\n"))?;
        }

        if let (Some(sqlite), Some(scan_run_id)) = (&sqlite, scan_run_id) {
            for sub in &subdomains {
                sqlite.insert_subdomain(&NewSubdomain {
                    scan_run_id,
                    subdomain: sub.clone(),
                })?;
            }
        }

        let info_file = if storage_mode.writes_files() {
            Some(Arc::new(Mutex::new(File::create(
                &paths.sensitive_info_txt,
            )?)))
        } else {
            None
        };

        let sink = SensitiveSink::new(info_file, sqlite.clone(), scan_run_id);

        let urls: Vec<String> = body
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
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

            if let (Some(sqlite), Some(scan_run_id)) = (&sqlite, scan_run_id) {
                let _ = sqlite.insert_event(&NewEvent {
                    scan_run_id: Some(scan_run_id),
                    level: "error".to_string(),
                    component: "postfilter".to_string(),
                    message: "postfilter_assets_dir failed".to_string(),
                    details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
                });
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    match result {
        Ok(()) => {
            if let (Some(sqlite), Some(scan_run_id)) = (&sqlite, scan_run_id) {
                let _ = sqlite.finish_scan_run(scan_run_id, "success");
            }
            Ok(paths)
        }
        Err(e) => {
            if let (Some(sqlite), Some(scan_run_id)) = (&sqlite, scan_run_id) {
                let _ = sqlite.insert_event(&NewEvent {
                    scan_run_id: Some(scan_run_id),
                    level: "error".to_string(),
                    component: "run_scan".to_string(),
                    message: "scan run failed".to_string(),
                    details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
                });
                let _ = sqlite.finish_scan_run(scan_run_id, "failed");
            }
            Err(e)
        }
    }
}

pub async fn run_assets_analysis(
    dir: &Path,
    storage_mode: StorageMode,
    out_override: Option<PathBuf>,
) -> Result<()> {
    let base = if dir.file_name().and_then(|s| s.to_str()) == Some("assets") {
        dir.parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| dir.to_path_buf())
    } else {
        dir.to_path_buf()
    };

    fs::create_dir_all(&base)?;

    let sqlite = if storage_mode.writes_db() {
        Some(SqliteStorage::open(base.join("webhound.db"))?)
    } else {
        None
    };

    let scan_run_id = if let Some(sqlite) = &sqlite {
        Some(sqlite.create_scan_run(NewScanRun {
            target: base.display().to_string(),
            mode: "assets".to_string(),
            status: "running".to_string(),
            config_json: None,
        })?)
    } else {
        None
    };

    let info_file = if storage_mode.writes_files() {
        let out_file = out_override.unwrap_or_else(|| {
            if dir.file_name().and_then(|s| s.to_str()) == Some("assets") {
                base.join("sensitive_info.post.jsonl")
            } else {
                dir.join("sensitive_info.post.jsonl")
            }
        });

        Some(Arc::new(Mutex::new(
            File::options().create(true).append(true).open(&out_file)?,
        )))
    } else {
        None
    };

    let sink = SensitiveSink::new(info_file, sqlite.clone(), scan_run_id);

    let result = postfilter::postfilter_assets_dir(dir, &sink).await;

    match result {
        Ok(()) => {
            if let (Some(sqlite), Some(scan_run_id)) = (&sqlite, scan_run_id) {
                let _ = sqlite.finish_scan_run(scan_run_id, "success");
            }
            Ok(())
        }
        Err(e) => {
            if let (Some(sqlite), Some(scan_run_id)) = (&sqlite, scan_run_id) {
                let _ = sqlite.insert_event(&NewEvent {
                    scan_run_id: Some(scan_run_id),
                    level: "error".to_string(),
                    component: "assets".to_string(),
                    message: "assets analysis failed".to_string(),
                    details_json: Some(serde_json::json!({ "error": e.to_string() }).to_string()),
                });
                let _ = sqlite.finish_scan_run(scan_run_id, "failed");
            }
            Err(e)
        }
    }
}

pub async fn run_images_analysis(dir: &Path) -> Result<(SqliteStorage, i64)> {
    let base = if dir.file_name().and_then(|s| s.to_str()) == Some("screenshots") {
        dir.parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| dir.to_path_buf())
    } else {
        dir.to_path_buf()
    };

    fs::create_dir_all(&base)?;

    let sqlite = SqliteStorage::open(base.join("webhound.db"))?;
    let scan_run_id = sqlite.create_scan_run(NewScanRun {
        target: base.display().to_string(),
        mode: "images".to_string(),
        status: "running".to_string(),
        config_json: None,
    })?;

    Ok((sqlite, scan_run_id))
}

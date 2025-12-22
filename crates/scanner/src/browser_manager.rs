use anyhow::{anyhow, Result};
use headless_chrome::{Browser, LaunchOptionsBuilder};
use portpicker::pick_unused_port;
use std::sync::{Arc, Mutex};
use std::{
    env,
    path::{Path, PathBuf},
};

pub struct BrowserManager {
    inner: Mutex<Option<Arc<Browser>>>,
}

impl BrowserManager {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub fn get(&self) -> Result<Arc<Browser>> {
        {
            let guard = self
                .inner
                .lock()
                .map_err(|e| anyhow!("mutex poisoned in BrowserManager::get: {e}"))?;
            if let Some(browser) = &*guard {
                return Ok(browser.clone());
            }
        } // guard дропается здесь

        let browser = Arc::new(Self::build_browser()?);

        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|e| anyhow!("mutex poisoned in BrowserManager::get (store): {e}"))?;
            *guard = Some(browser.clone());
        } // guard дропается здесь

        Ok(browser)
    }

    fn build_browser() -> Result<Browser> {
        let port = pick_unused_port()
            .ok_or_else(|| anyhow!("Не удалось выбрать свободный порт для Chrome"))?;

        let chrome_path = detect_chrome_binary().ok_or_else(|| {
            anyhow!("Не удалось найти бинарь Chrome/Chromium. Укажи WEBHOUND_CHROME или CHROME_BIN")
        })?;

        let options = LaunchOptionsBuilder::default()
            .path(Some(chrome_path))
            .port(Some(port)) 
            .headless(true)
            .window_size(Some((1280, 720)))
            .build()
            .map_err(|e| anyhow!("Сборка LaunchOptions: {e}"))?;

        Browser::new(options).map_err(|e| anyhow!("Запуск Chrome/Chromium: {e}"))
    }

    pub fn invalidate(&self) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow!("mutex poisoned in BrowserManager::invalidate: {e}"))?;
        *guard = None;
        Ok(())
    }
}

pub static BROWSER_MANAGER: BrowserManager = BrowserManager::new();

fn detect_chrome_binary() -> Option<PathBuf> {
    if let Ok(path) = env::var("WEBHOUND_CHROME").or_else(|_| env::var("CHROME_BIN")) {
        let pb = PathBuf::from(path);
        if pb.is_file() {
            return Some(pb);
        }
    }

    #[cfg(target_os = "linux")]
    const CANDIDATES: &[&str] = &[
            // ABS paths first (most reliable)
        "/usr/bin/google-chrome-stable",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        "google-chrome-stable",
        "google-chrome",
        "chromium",
        "chromium-browser",
    ];

    #[cfg(target_os = "windows")]
    const CANDIDATES: &[&str] = &["chrome.exe", "msedge.exe"];

    #[cfg(target_os = "macos")]
    const CANDIDATES: &[&str] = &[
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "google-chrome",
        "chrome",
    ];

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    const CANDIDATES: &[&str] = &["google-chrome", "chromium"];

    for cand in CANDIDATES {
        let path = Path::new(cand);
        if path.is_absolute() && path.is_file() {
            return Some(path.to_path_buf());
        }
        if let Some(found) = which(cand) {
            return Some(found);
        }
    }

    None
}

fn which(prog: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let full = dir.join(prog);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

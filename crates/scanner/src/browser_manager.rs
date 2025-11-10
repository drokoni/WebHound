use anyhow::{Result, anyhow};
use headless_chrome::{Browser, LaunchOptionsBuilder};
use std::sync::{Arc, Mutex};
use portpicker::pick_unused_port;

pub struct BrowserManager {
    inner: Mutex<Option<Arc<Browser>>>,
}

impl BrowserManager {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    fn launch_browser() -> Result<Arc<Browser>> {
        let port = pick_unused_port().unwrap_or(0);
        let mut builder = LaunchOptionsBuilder::default();
        builder.headless(true);
        builder.port(Some(port));

        let launch_opts = builder
            .build()
            .map_err(|e| anyhow!("building LaunchOptions: {e}"))?;

        let browser =
            Browser::new(launch_opts).map_err(|e| anyhow!("starting headless chrome: {e}"))?;
        Ok(Arc::new(browser))
    }

    pub fn get(&self) -> Result<Arc<Browser>> {
        // пробуем взять из кэша
        match self.inner.lock() {
            Ok(guard) => {
                if let Some(existing) = guard.as_ref() {
                    return Ok(existing.clone());
                }
            }
            Err(e) => return Err(anyhow!("mutex poisoned in BrowserManager::get(read): {e}")),
        }

        let fresh = Self::launch_browser()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow!("mutex poisoned in BrowserManager::get(write): {e}"))?;
        *guard = Some(fresh.clone());
        Ok(fresh)
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

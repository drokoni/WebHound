use anyhow::{anyhow, Result};
use headless_chrome::{Browser, LaunchOptionsBuilder};
use std::sync::{Arc, Mutex};

pub struct BrowserManager {
    inner: Mutex<Option<Arc<Browser>>>,
}

impl BrowserManager {
    pub const fn new() -> Self {
        Self { inner: Mutex::new(None) }
    }

    fn launch_browser() -> Result<Arc<Browser>> {
        // В 0.9 используем только доступные билдер-методы.
        let mut builder = LaunchOptionsBuilder::default();
        builder.headless(true);
        builder.port(Some(9222));
        // Если у твоей сборки есть метод sandbox(false) — можно раскомментировать:
        // builder.sandbox(false);

        let launch_opts = builder
            .build()
            .map_err(|e| anyhow!("building LaunchOptions: {e}"))?;

        let browser = Browser::new(launch_opts)
            .map_err(|e| anyhow!("starting headless chrome: {e}"))?;
        Ok(Arc::new(browser))
    }

    /// Вернёт живой экземпляр браузера; если прежний умер — поднимет новый.
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

        // запускаем новый и кладём в кэш
        let fresh = Self::launch_browser()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| anyhow!("mutex poisoned in BrowserManager::get(write): {e}"))?;
        *guard = Some(fresh.clone());
        Ok(fresh)
    }

    /// Сбрасывает кэш; при следующем get() запустится новый Chrome.
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



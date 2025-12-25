use anyhow::{anyhow, Result as AnyResult};
use headless_chrome::protocol::cdp::Page::{
    CaptureScreenshotFormatOption as ScreenshotFormat, Viewport,
};
use std::sync::{Arc, OnceLock};
use std::{path::Path, thread, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task,
};

use crate::browser_manager::BROWSER_MANAGER;
use core::utils::sanitize_filename;

static TAB_SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn tab_limit() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if cpus <= 1 {
        1
    } else {
        2
    }
}

fn sem() -> Arc<Semaphore> {
    TAB_SEM
        .get_or_init(|| Arc::new(Semaphore::new(tab_limit())))
        .clone()
}

fn is_browser_level_error_str(s: &str) -> bool {
    let s = s.to_lowercase();
    s.contains("websocket url")
        || s.contains("chrome launched, but didn't give us a websocket url")
        || s.contains("disconnected")
        || s.contains("target closed")
        || s.contains("connection reset")
}

pub async fn make_screenshot_task(url: &str, screenshots_dir: &Path) -> AnyResult<()> {
    let fixed_url = url.to_string();
    let fixed_for_name = fixed_url.clone();

    let permit: OwnedSemaphorePermit = sem()
        .acquire_owned()
        .await
        .map_err(|e| anyhow!("Semaphore acquire: {e}"))?;

    let data = task::spawn_blocking(move || -> AnyResult<Vec<u8>> {
        let _permit = permit;

        for attempt in 1..=2 {
            let browser = match BROWSER_MANAGER.get() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Ошибка получения браузера (попытка {attempt}) для {fixed_url}: {e}");
                    let _ = BROWSER_MANAGER.invalidate();
                    if attempt == 2 { return Err(e); }
                    continue;
                }
            };

            let tab = match browser.new_tab() {
                Ok(t) => t,
                Err(e) => {
                    let msg = e.to_string();
                    eprintln!("Не удалось создать вкладку (попытка {attempt}) для {fixed_url}: {msg}");
                    let _ = BROWSER_MANAGER.invalidate();
                    if attempt == 2 {
                        return Err(anyhow!("Не удалось создать вкладку для {fixed_url}: {msg}"));
                    }
                    continue;
                }
            };

            if let Err(e) = tab.navigate_to(&fixed_url) {
                let msg = e.to_string();
                eprintln!("Навигация на {fixed_url} (попытка {attempt}) ошибка: {msg}");
                if is_browser_level_error_str(&msg) {
                    let _ = BROWSER_MANAGER.invalidate();
                }
                if attempt == 2 {
                    return Err(anyhow!("Навигация на {fixed_url} провалилась: {msg}"));
                }
                continue;
            }

            match tab.wait_until_navigated() {
                Ok(_) => thread::sleep(Duration::from_secs(2)),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("The event waited for never came") {
                        eprintln!(
                            "wait_until_navigated не дождался события для {fixed_url} \
                             (попытка {attempt}): {msg} — продолжаем по таймеру"
                        );
                        thread::sleep(Duration::from_secs(8));
                    } else {
                        eprintln!("Ошибка wait_until_navigated для {fixed_url} (попытка {attempt}): {msg}");
                        if is_browser_level_error_str(&msg) {
                            let _ = BROWSER_MANAGER.invalidate();
                        }
                        if attempt == 2 {
                            return Err(anyhow!("Навигация к {fixed_url} провалилась: {msg}"));
                        }
                        continue;
                    }
                }
            }

            // 1.0.20: capture_screenshot(format, quality, viewport, from_surface)
            let viewport: Option<Viewport> = None;

            match tab.capture_screenshot(ScreenshotFormat::Png, None, viewport, true) {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    let msg = e.to_string();
                    eprintln!("Ошибка скриншота {fixed_url} (попытка {attempt}): {msg}");
                    if is_browser_level_error_str(&msg) {
                        let _ = BROWSER_MANAGER.invalidate();
                    }
                    if attempt == 2 {
                        return Err(anyhow!("Скриншот для {fixed_url} провалился: {msg}"));
                    }
                    continue;
                }
            }
        }

        Err(anyhow!("Не удалось создать скриншот для {fixed_url} после нескольких попыток"))
    })
    .await
    .map_err(|e| anyhow!("JoinError: {e}"))??;

    let name = sanitize_filename(&fixed_for_name);
    std::fs::create_dir_all(screenshots_dir)
        .map_err(|e| anyhow!("Создание папки {:?}: {e}", screenshots_dir))?;
    let path = screenshots_dir.join(format!("{name}.png"));
    std::fs::write(&path, &data).map_err(|e| anyhow!("Запись файла {:?}: {e}", path))?;

    Ok(())
}

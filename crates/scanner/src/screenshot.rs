use anyhow::{anyhow, Result as AnyResult};
use headless_chrome::protocol::page::ScreenshotFormat;
use std::path::Path;
use tokio::task;
use webhound_core::utils::sanitize_filename;

use crate::browser_manager::BROWSER_MANAGER;

/// Сделать PNG-скриншот страницы
pub async fn make_screenshot_task(url: &str, screenshots_dir: &Path) -> AnyResult<()> {
    let fixed_url = url.to_string();
    let fixed_for_name = fixed_url.clone();

    let data = task::spawn_blocking(move || -> AnyResult<Vec<u8>> {
        for attempt in 1..=2 {
            let browser = BROWSER_MANAGER
                .get()
                .map_err(|e| anyhow!("Запуск Chrome: {e}"))?;

            match browser.new_tab() {
                Ok(tab) => {
                    tab.navigate_to(&fixed_url)
                        .map_err(|e| anyhow!("navigate_to({fixed_url}): {e}"))?
                        .wait_until_navigated()
                        .map_err(|e| anyhow!("wait_until_navigated: {e}"))?;

                    let png = tab
                        .capture_screenshot(ScreenshotFormat::PNG, None, true)
                        .map_err(|e| anyhow!("capture_screenshot: {e}"))?;
                    return Ok(png);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("connection is closed") || msg.contains("WebSocket") {
                        if attempt == 1 {
                            let _ = BROWSER_MANAGER.invalidate();
                            continue;
                        }
                    }
                    return Err(anyhow!("Не удалось создать вкладку: {msg}"));
                }
            }
        }
        Err(anyhow!("Не удалось создать вкладку после повторной попытки"))
    })
    .await
    .map_err(|e| anyhow!("JoinError: {e}"))??;

    // сохраняем PNG
    let name = sanitize_filename(&fixed_for_name);
    std::fs::create_dir_all(screenshots_dir)
        .map_err(|e| anyhow!("Создание папки {:?}: {e}", screenshots_dir))?;
    let path = screenshots_dir.join(format!("{name}.png"));
    std::fs::write(&path, &data).map_err(|e| anyhow!("Запись файла {:?}: {e}", path))?;
    Ok(())
}


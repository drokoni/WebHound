use anyhow::{Result as AnyResult, anyhow};
use headless_chrome::protocol::page::ScreenshotFormat;
use tokio::task;
use std::{path::Path, thread, time::Duration};
use core::utils::sanitize_filename;

use crate::browser_manager::BROWSER_MANAGER;

pub async fn make_screenshot_task(url: &str, screenshots_dir: &Path) -> AnyResult<()> {
    let fixed_url = url.to_string();
    let fixed_for_name = fixed_url.clone();

    let data = task::spawn_blocking(move || -> AnyResult<Vec<u8>> {
        for attempt in 1..=2 {
            let browser = match BROWSER_MANAGER.get() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!(
                        "Ошибка получения браузера (попытка {attempt}) для {fixed_url}: {e}"
                    );
                    if attempt == 2 {
                        return Err(e);
                    }
                    continue;
                }
            };

            let tab = match browser.new_tab() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!(
                        "Не удалось создать вкладку (попытка {attempt}) для {fixed_url}: {e}"
                    );
                    let _ = BROWSER_MANAGER.invalidate();
                    if attempt == 2 {
                        return Err(anyhow!(
                            "Не удалось создать вкладку для {fixed_url}: {e}"
                        ));
                    }
                    continue;
                }
            };

            if let Err(e) = tab.navigate_to(&fixed_url) {
                eprintln!(
                    "Навигация на {fixed_url} (попытка {attempt}) завершилась ошибкой: {e}"
                );
                let _ = BROWSER_MANAGER.invalidate();
                if attempt == 2 {
                    return Err(anyhow!("Навигация на {fixed_url} провалилась: {e}"));
                }
                continue;
            }

            let nav_res = tab.wait_until_navigated();
            match nav_res {
                Ok(_) => {
                    thread::sleep(Duration::from_secs(2));
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("The event waited for never came") {
                        eprintln!(
                            "wait_until_navigated не дождался события для {fixed_url} \
                             (попытка {attempt}): {msg} — продолжаем по таймеру"
                        );
                        thread::sleep(Duration::from_secs(8));
                    } else {
                        eprintln!(
                            "Ошибка в wait_until_navigated для {fixed_url} (попытка {attempt}): {msg}"
                        );
                        let _ = BROWSER_MANAGER.invalidate();
                        if attempt == 2 {
                            return Err(anyhow!(
                                "Навигация к {fixed_url} провалилась (wait_until_navigated): {msg}"
                            ));
                        }
                        continue;
                    }
                }
            }

            match tab.capture_screenshot(ScreenshotFormat::PNG, None, true) {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    eprintln!(
                        "Ошибка скриншота {fixed_url} (попытка {attempt}): {e}"
                    );
                    let _ = BROWSER_MANAGER.invalidate();
                    if attempt == 2 {
                        return Err(anyhow!("Скриншот для {fixed_url} провалился: {e}"));
                    }
                    continue;
                }
            }
        }

        Err(anyhow!(
            "Не удалось создать скриншот для {fixed_url} после нескольких попыток"
        ))
    })
    .await
    .map_err(|e| anyhow!("JoinError: {e}"))??;

    let name = sanitize_filename(&fixed_for_name);
    std::fs::create_dir_all(screenshots_dir)
        .map_err(|e| anyhow!("Создание папки {:?}: {e}", screenshots_dir))?;
    let path = screenshots_dir.join(format!("{name}.png"));
    std::fs::write(&path, &data)
        .map_err(|e| anyhow!("Запись файла {:?}: {e}", path))?;

    Ok(())
}



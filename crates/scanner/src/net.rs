use anyhow::{Result as AnyResult, anyhow};
use reqwest::{Client, StatusCode, Url};
use serde_json;
use tokio::time::{Duration, timeout};


// Нормализация домена: убираем схемы и лишние /.
fn normalize_host(input: &str) -> String {
    let s = input.trim();
    let s = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")).unwrap_or(s);
    let s = s.trim_start_matches('/').trim_end_matches('/');
    s.to_string()
}

/// Получить список Wayback URL-ов по домену без лишнего URL-энкода
pub async fn fetch_wayback_urls(client: &Client, domain: &str) -> AnyResult<String> {
    let host = normalize_host(domain); 
    let ua = "curl/8.4.0";

    let mut alt = Url::parse("https://web.archive.org/cdx/search/cdx")?;
    alt.set_query(Some(&format!(
        "url={0}/*&matchType=domain&collapse=urlkey&output=txt&fl=original&limit=250",
        host
    )));
    let resp2 = client.get(alt.clone()).header("User-Agent", ua).send().await?;
    anyhow::ensure!(
        resp2.status().is_success(),
        "CDX failed: {} -> {}",
        alt, resp2.status()
    );
    Ok(resp2.text().await?)
}

/// Live или Wayback. Возвращает (bytes, использованный_url, is_wayback)
pub async fn fetch_live_or_wayback(
    client: &Client,
    original_url: &str,
) -> AnyResult<(Vec<u8>, String, bool)> {
    let ua = "curl/8.4.0";

    // 1) попробовать live
    if let Ok(Ok(ok)) = timeout(Duration::from_secs(15), client.get(original_url).header("User-Agent", ua).send()).await {
        if ok.status().is_success() {
            let data = ok.bytes().await?;
            return Ok((data.to_vec(), original_url.to_string(), false));
        }
    }

    // 2) взять последний 200 из CDX (упрощаем поля)
    let mut cdx = Url::parse("https://web.archive.org/cdx/search/cdx")?;
    cdx.set_query(Some(&format!(
        "url={url}&output=json&fl=timestamp,original&filter=statuscode:200&limit=1&sort=descending",
        url = original_url
    )));
    let cdx_resp = client.get(cdx.clone()).header("User-Agent", ua).send().await?;
    if cdx_resp.status() != StatusCode::OK {
        return Err(anyhow!("Wayback CDX status {} for {}", cdx_resp.status(), original_url));
    }

    let val: serde_json::Value = serde_json::from_slice(&cdx_resp.bytes().await?)?;
    // Ожидаем: [ ["timestamp","original"], ["20240101123456","http://..."] ]
    let ts = val.as_array()
        .and_then(|arr| arr.get(1))
        .and_then(|row| row.get(0))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Wayback: нет timestamp для {}", original_url))?;

    let archived = format!("https://web.archive.org/web/{}id_/{}", ts, original_url);
    let resp = client.get(&archived).header("User-Agent", ua).send().await?.error_for_status()?;
    let data = resp.bytes().await?;
    Ok((data.to_vec(), archived, true))
}
/*
/// Получить список Wayback URL-ов по домену
pub async fn fetch_wayback_urls(client: &Client, domain: &str) -> AnyResult<String> {
    let resp = client
        .get("https://web.archive.org/cdx/search/cdx")
        .query(&[
            ("url", format!("*.{}*",domain)),
            ("collapse", "urlkey".to_string()),
            ("output", "text".to_string()),
            ("fl", "original".to_string()),
            ("limit", "250".to_string()),
        ])
        .send()
        .await?
        .error_for_status()?;

    Ok(resp.text().await?)
}

pub async fn fetch_wayback_urls(client: &Client, domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resp = client
        .get("https://web.archive.org/cdx/search/cdx")
        .query(&[
            // охватывает domain и все поддомены, без тяжёлых фильтров
            //("url", format!("/{domain}")),
            ("matchType", "domain".to_string()),
            ("collapse", "urlkey".to_string()),
            ("output", "text".to_string()),
            ("fl", "original".to_string()),
            ("limit", "250".to_string()),
        ])
        .send()
        .await?
        .error_for_status()?;

    Ok(resp.text().await?)
}
/// Проверить доступность URL (HEAD→GET)
pub async fn check_url_200(url: &str, client: &Client) -> bool {
    match timeout(Duration::from_secs(8), client.head(url).send()).await {
        Ok(Ok(r)) if r.status().is_success() => return true,
        _ => {}
    }

    timeout(Duration::from_secs(12), client.get(url).send())
        .await
        .ok()
        .and_then(|r| r.ok())
        .map_or(false, |r| r.status().is_success())
}

/// Live или Wayback. Возвращает (bytes, использованный_url, is_wayback)
pub async fn fetch_live_or_wayback(
    client: &Client,
    original_url: &str,
) -> AnyResult<(Vec<u8>, String, bool)> {
    // 1) live
    if let Ok(resp) = timeout(Duration::from_secs(15), client.get(original_url).send()).await {
        if let Ok(ok) = resp {
            if ok.status().is_success() {
                let data = ok.bytes().await.map_err(|e| anyhow!(e.to_string()))?;
                return Ok((data.to_vec(), original_url.to_string(), false));
            }
        }
    }

    // 2) wayback CDX — последний успешный 200
    let cdx_resp = client
        .get("https://web.archive.org/cdx/search/cdx")
        .query(&[
            ("url", original_url.to_string()),
            ("output", "json".to_string()),
            ("filter", "statuscode:200".to_string()),
            ("limit", "1".to_string()),
            ("from", "20000101".to_string()),
            ("to", "20991231".to_string()),
            ("sort", "descending".to_string()),
        ])
        .send()
        .await
        .map_err(|e| anyhow!("Wayback CDX error: {e}"))?;

    if cdx_resp.status() != StatusCode::OK {
        return Err(anyhow!(
            "Wayback CDX status {} for {}",
            cdx_resp.status(),
            original_url
        ));
    }

    let json_val: serde_json::Value =
        serde_json::from_slice(&cdx_resp.bytes().await?).map_err(|e| anyhow!(e.to_string()))?;
    let ts = json_val
        .as_array()
        .and_then(|arr| arr.get(1))
        .and_then(|row| row.get(1))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Wayback: нет timestamp для {}", original_url))?;

    let archived = format!("https://web.archive.org/web/{}id_/{}", ts, original_url);
    let resp = client
        .get(&archived)
        .send()
        .await
        .map_err(|e| anyhow!(e.to_string()))?
        .error_for_status()
        .map_err(|e| anyhow!(e.to_string()))?;
    let data = resp.bytes().await.map_err(|e| anyhow!(e.to_string()))?;
    Ok((data.to_vec(), archived, true))
}
*/


use anyhow::{Result as AnyResult, anyhow};
use reqwest::{Client, StatusCode, Url};
use serde_json;
use tokio::time::{Duration, timeout};


fn normalize_host(input: &str) -> String {
    let s = input.trim();
    let s = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")).unwrap_or(s);
    let s = s.trim_start_matches('/').trim_end_matches('/');
    s.to_string()
}

pub async fn fetch_wayback_urls(client: &Client, domain: &str) -> AnyResult<String> {
    let host = normalize_host(domain); 
    let ua = "curl/8.4.0";

    let mut alt = Url::parse("https://web.archive.org/cdx/search/cdx")?;
    alt.set_query(Some(&format!(
        "url={0}/*&matchType=domain&collapse=urlkey&output=txt&fl=original",
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

pub async fn fetch_live_or_wayback(
    client: &Client,
    original_url: &str,
) -> AnyResult<(Vec<u8>, String, bool)> {
    let ua = "curl/8.4.0";

    if let Ok(Ok(ok)) = timeout(Duration::from_secs(15), client.get(original_url).header("User-Agent", ua).send()).await {
        if ok.status().is_success() {
            let data = ok.bytes().await?;
            return Ok((data.to_vec(), original_url.to_string(), false));
        }
    }

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


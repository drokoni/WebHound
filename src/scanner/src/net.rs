use anyhow::{anyhow, Context, Result as AnyResult};
use rand::{thread_rng, Rng};
use reqwest::{header, Client, StatusCode, Url};
use serde_json;
use std::sync::OnceLock;
use tokio::time::{sleep, timeout, Duration};

fn normalize_host(input: &str) -> String {
    let s = input.trim();
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);
    let s = s.trim_start_matches('/').trim_end_matches('/');
    s.to_string()
}

/// Настройки доменного CDX (url=HOST/*)
#[derive(Clone, Debug)]
pub struct CdxDomainOpts {
    pub match_type: String,         // "domain" по умолчанию
    pub collapse_urlkey: bool,      // collapse=urlkey
    pub limit: Option<u32>,         // limit=...
    pub filter_status_200: bool,    // filter=statuscode:200
    pub filter_mimetype_html: bool, // filter=mimetype:text/html

    pub timeout: Duration, // таймаут на один HTTP запрос
    pub retries: u32,      // кол-во ретраев на 429/5xx/сетевые

    /// fallback по годам (если доменный CDX валится)
    pub fallback_year_from: u16,
    pub fallback_year_to: u16,

    /// Если true — fallback по годам включён
    pub enable_year_fallback: bool,
}

impl Default for CdxDomainOpts {
    fn default() -> Self {
        Self {
            match_type: "domain".to_string(),
            collapse_urlkey: true,
            limit: Some(2000),
            filter_status_200: true,
            filter_mimetype_html: true,
            timeout: Duration::from_secs(30),
            retries: 6,
            fallback_year_from: 2018,
            fallback_year_to: 2025,
            enable_year_fallback: true,
        }
    }
}

/// Глобальные дефолты CDX (чтобы можно было настраивать из CLI без изменения run_scan сигнатуры)
static CDX_DEFAULTS: OnceLock<CdxDomainOpts> = OnceLock::new();

pub fn set_cdx_defaults(opts: CdxDomainOpts) {
    // set() возвращает Err если уже задано — нам это ок: второй раз не перезатираем
    let _ = CDX_DEFAULTS.set(opts);
}

fn cdx_defaults() -> CdxDomainOpts {
    CDX_DEFAULTS.get().cloned().unwrap_or_default()
}

fn is_retryable_status(st: StatusCode) -> bool {
    st == StatusCode::TOO_MANY_REQUESTS || st.is_server_error() || st == StatusCode::REQUEST_TIMEOUT
}

async fn get_text_with_retry(
    client: &Client,
    url: Url,
    ua: &str,
    retries: u32,
) -> AnyResult<String> {
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;

        let resp = timeout(
            Duration::from_secs(60),
            client.get(url.clone()).header("User-Agent", ua).send(),
        )
        .await;

        match resp {
            Ok(Ok(r)) => {
                let st = r.status();

                if st.is_success() {
                    return Ok(r.text().await.context("read response text")?);
                }

                // retry на 429/5xx
                if is_retryable_status(st) && attempt <= retries + 1 {
                    // base backoff: 500ms * 2^(attempt-1), clamp
                    let mut delay_ms =
                        500u64.saturating_mul(1u64 << (attempt.saturating_sub(1).min(6)));
                    delay_ms = delay_ms.min(8_000);

                    // respect Retry-After
                    if let Some(ra) = r.headers().get(header::RETRY_AFTER) {
                        if let Ok(s) = ra.to_str() {
                            if let Ok(sec) = s.parse::<u64>() {
                                delay_ms = (sec * 1000).min(8_000);
                            }
                        }
                    }

                    let jitter: u64 = thread_rng().gen_range(0..250);
                    sleep(Duration::from_millis(delay_ms + jitter)).await;
                    continue;
                }

                return Err(anyhow!("CDX failed: {} -> {}", url, st));
            }
            Ok(Err(e)) => {
                // сетевые ошибки — retry
                if attempt <= retries + 1 {
                    let mut delay_ms =
                        500u64.saturating_mul(1u64 << (attempt.saturating_sub(1).min(6)));
                    delay_ms = delay_ms.min(8_000);
                    let jitter: u64 = thread_rng().gen_range(0..250);
                    sleep(Duration::from_millis(delay_ms + jitter)).await;
                    continue;
                }
                return Err(anyhow!("CDX request error: {} -> {}", url, e));
            }
            Err(_) => {
                // timeout(...) завершился по таймауту — retry
                if attempt <= retries + 1 {
                    let mut delay_ms =
                        500u64.saturating_mul(1u64 << (attempt.saturating_sub(1).min(6)));
                    delay_ms = delay_ms.min(8_000);
                    let jitter: u64 = thread_rng().gen_range(0..250);
                    sleep(Duration::from_millis(delay_ms + jitter)).await;
                    continue;
                }
                return Err(anyhow!("CDX timeout: {}", url));
            }
        }
    }
}

fn build_cdx_domain_url(
    host: &str,
    opts: &CdxDomainOpts,
    from: Option<u16>,
    to: Option<u16>,
) -> AnyResult<Url> {
    let mut u = Url::parse("https://web.archive.org/cdx/search/cdx")?;

    // базовые поля
    let mut q = format!(
        "url={0}/*&matchType={1}&output=txt&fl=original",
        host, opts.match_type
    );

    if opts.collapse_urlkey {
        q.push_str("&collapse=urlkey");
    }
    if let Some(limit) = opts.limit {
        q.push_str(&format!("&limit={}", limit));
    }
    if let Some(f) = from {
        q.push_str(&format!("&from={}", f));
    }
    if let Some(t) = to {
        q.push_str(&format!("&to={}", t));
    }
    if opts.filter_status_200 {
        q.push_str("&filter=statuscode:200");
    }
    if opts.filter_mimetype_html {
        q.push_str("&filter=mimetype:text/html");
    }

    u.set_query(Some(&q));
    Ok(u)
}

/// Доменный список URL из CDX (сырой txt: URL per line)
pub async fn fetch_wayback_urls(client: &Client, domain: &str) -> AnyResult<String> {
    let host = normalize_host(domain);
    let ua = "curl/8.4.0";
    let opts = cdx_defaults();

    let url = build_cdx_domain_url(&host, &opts, None, None)?;
    let body = get_text_with_retry(client, url, ua, opts.retries).await?;

    // если пусто — считаем ошибкой, чтобы fallback мог сработать
    if body.lines().all(|l| l.trim().is_empty()) {
        return Err(anyhow!("CDX returned 0 urls for host={}", host));
    }

    Ok(body)
}

/// То же, но “устойчиво”: если доменный CDX падает — режем по годам.
pub async fn fetch_wayback_urls_resilient(
    client: &Client,
    domain: &str,
    opts: CdxDomainOpts,
) -> AnyResult<String> {
    let host = normalize_host(domain);
    let ua = "curl/8.4.0";

    // Сначала пробуем доменом
    let url = build_cdx_domain_url(&host, &opts, None, None)?;
    match get_text_with_retry(client, url, ua, opts.retries).await {
        Ok(body) if !body.lines().all(|l| l.trim().is_empty()) => return Ok(body),
        Ok(_) | Err(_) => {
            if !opts.enable_year_fallback {
                return Err(anyhow!(
                    "CDX failed and year fallback disabled for host={}",
                    host
                ));
            }
        }
    }

    // Fallback по годам: собираем, сортируем, dedup
    let mut all: Vec<String> = Vec::new();
    for y in opts.fallback_year_from..=opts.fallback_year_to {
        let url_y = build_cdx_domain_url(&host, &opts, Some(y), Some(y))?;
        if let Ok(body_y) = get_text_with_retry(client, url_y, ua, opts.retries).await {
            for line in body_y.lines() {
                let s = line.trim();
                if s.starts_with("http://") || s.starts_with("https://") {
                    all.push(s.to_string());
                }
            }
        }
    }

    all.sort();
    all.dedup();

    anyhow::ensure!(
        !all.is_empty(),
        "CDX year fallback returned 0 urls for host={}",
        host
    );

    Ok(all.join("\n"))
}

pub async fn fetch_live_or_wayback(
    client: &Client,
    original_url: &str,
) -> AnyResult<(Vec<u8>, String, bool)> {
    let ua = "curl/8.4.0";

    // 1) Live (быстро)
    if let Ok(Ok(ok)) = timeout(
        Duration::from_secs(15),
        client.get(original_url).header("User-Agent", ua).send(),
    )
    .await
    {
        if ok.status().is_success() {
            let data = ok.bytes().await?;
            return Ok((data.to_vec(), original_url.to_string(), false));
        }
    }

    // 2) CDX: последний snapshot
    let mut cdx = Url::parse("https://web.archive.org/cdx/search/cdx")?;
    cdx.set_query(Some(&format!(
        "url={url}&output=json&fl=timestamp,original&filter=statuscode:200&limit=1&sort=descending",
        url = original_url
    )));

    // Для этого запроса тоже делаем retry (429/5xx)
    let opts = cdx_defaults();
    let body = get_text_with_retry(client, cdx.clone(), ua, opts.retries).await?;
    let val: serde_json::Value = serde_json::from_str(&body)
        .or_else(|_| serde_json::from_slice(body.as_bytes()))
        .context("parse CDX json")?;

    let ts = val
        .as_array()
        .and_then(|arr| arr.get(1))
        .and_then(|row| row.get(0))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Wayback: нет timestamp для {}", original_url))?;

    // 3) Скачиваем архивную версию
    let archived = format!("https://web.archive.org/web/{}id_/{}", ts, original_url);

    let resp = client
        .get(&archived)
        .header("User-Agent", ua)
        .send()
        .await?
        .error_for_status()?;

    let data = resp.bytes().await?;
    Ok((data.to_vec(), archived, true))
}

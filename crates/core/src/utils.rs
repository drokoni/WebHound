use anyhow::Result as AnyResult;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    path::Path,
};
use tokio::{
    fs::File as AsyncFile,
    io::{AsyncBufReadExt, BufReader},
};
use url::Url;

/// Записать строку в файл (c созданием директорий)
pub fn write_str_to_file(path: &Path, content: &str) -> AnyResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

/// Прочитать список URL-ов (по строке на строку)
pub async fn read_urls(file_path: &Path) -> AnyResult<Vec<String>> {
    let mut urls = Vec::new();
    let file = AsyncFile::open(file_path).await?;
    let mut reader = BufReader::new(file).lines();

    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }
    Ok(urls)
}

/// Вытащить поддомены из файла со ссылками
pub async fn extract_subdomains(file_path: &Path) -> AnyResult<Vec<String>> {
    let mut subdomains = HashSet::new();
    let re = Regex::new(r"https?://([^/\s]+)")?;

    let file = AsyncFile::open(file_path).await?;
    let mut reader = BufReader::new(file).lines();

    while let Some(line) = reader.next_line().await? {
        if let Some(captures) = re.captures(&line) {
            if let Some(domain) = captures.get(1) {
                subdomains.insert(domain.as_str().to_string());
            }
        }
    }
    Ok(subdomains.into_iter().collect())
}

/// Сохранить произвольные байты
pub fn save_bytes(path: &Path, data: &[u8]) -> AnyResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

/// Сделать безопасное файловое имя на основе URL
pub fn sanitize_filename(url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    let short = &hex[..12];

    let parsed = Url::parse(url).ok();
    let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("unknown");
    let mut path = parsed
        .as_ref()
        .map(|u| u.path())
        .unwrap_or("/")
        .replace('/', "_");
    if path.len() > 40 {
        path.truncate(40);
    }
    let base = format!("{}{}", host, path);
    let base = base
        .chars()
        .map(|c| if r#"/\:?*"<>| "#.contains(c) { '_' } else { c })
        .collect::<String>();
    let mut name = format!("{}__{}", base, short);
    if name.len() > 100 {
        name.truncate(100);
    }
    name
}


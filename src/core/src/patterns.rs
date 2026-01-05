use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder, RegexSet};
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct PatternSpec {
    pub re: Regex,
    pub name: String,
    pub secret_group: Option<usize>,

    /// Минимальная Shannon entropy (bits/char) для секрета (как в gitleaks: entropy).
    pub entropy: Option<f64>,

    /// Какая capture-group участвует в подсчёте энтропии (gitleaks: entropyGroup).
    pub entropy_group: Option<usize>,
}

/// Результат срабатывания правила (уже с учётом entropy-фильтра).
#[derive(Debug, Clone)]
pub struct ScanHit {
    pub rule_name: String,
    pub value: String,
    pub entropy: f64,
    pub total_bits: f64,
    pub len: usize,
}

#[derive(Debug, Deserialize)]
struct GitleaksConfig {
    #[serde(default)]
    rules: Vec<GitleaksRule>,
}

#[derive(Debug, Deserialize)]
pub struct GitleaksRule {
    pub id: String,
    pub description: String,
    pub regex: String,

    #[serde(default)]
    pub report: Option<String>, // иногда есть короткий отчёт

    #[serde(default)]
    pub tags: Vec<String>, // например ["key", "AWS"]

    #[serde(default)]
    pub entropy: Option<f64>, // минимальная энтропия

    #[serde(rename = "entropyGroup")]
    pub entropy_group: Option<usize>,

    #[serde(rename = "secretGroup")]
    pub secret_group: Option<usize>,

    #[serde(default)]
    pub keywords: Vec<String>,

    #[serde(default)]
    pub stopwords: Vec<String>, // слова, при которых можно игнорить

    #[serde(default)]
    pub allowlists: Vec<AllowList>,
}

#[derive(Debug, Deserialize)]
pub struct AllowList {
    #[serde(default)]
    pub regexes: Vec<String>,

    #[serde(default)]
    pub paths: Vec<String>,

    #[serde(default)]
    pub commits: Vec<String>,

    #[serde(default)]
    pub files: Vec<String>,
}

const RULS_TOML: &str = config::RULS_TOML;

fn compile_with_bigger_limits(pat: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pat)
        .size_limit(64 * 1024 * 1024) // 64 MiB на таблицы
        .dfa_size_limit(64 * 1024 * 1024) // 64 MiB на DFA
        .build()
}

fn build_lightweight_regex_from_keywords(keywords: &[String]) -> Option<(Regex, usize)> {
    if keywords.is_empty() {
        return None;
    }
    let alts: String = keywords
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| regex::escape(s))
        .collect::<Vec<_>>()
        .join("|");

    if alts.is_empty() {
        return None;
    }

    // (['"]?) (SECRET) (\1) — секрет во 2-й группе
    let pat = format!(
        r#"(?i)\b(?:{})(?:\W{{0,20}}[:=]\W{{0,20}}|\W{{1,20}})?(['\"]?)([A-Za-z0-9_\-]{{20,}})(\1)?"#,
        alts
    );
    match compile_with_bigger_limits(&pat) {
        Ok(re) => Some((re, 2)),
        Err(_) => None,
    }
}

pub static PATTERNS: Lazy<Vec<PatternSpec>> = Lazy::new(|| {
    let cfg: GitleaksConfig =
        toml::from_str(RULS_TOML).expect("BUG: не удалось распарсить  ../../config/ruls.toml");

    let mut out: Vec<PatternSpec> = Vec::new();

    for r in cfg.rules {
        match compile_with_bigger_limits(&r.regex) {
            Ok(re) => {
                out.push(PatternSpec {
                    re,
                    name: r.description,
                    secret_group: r.secret_group,
                    entropy: r.entropy,
                    entropy_group: r.entropy_group,
                });
            }
            Err(e) => {
                if let Some((re, group_idx)) = build_lightweight_regex_from_keywords(&r.keywords) {
                    eprintln!(
                        " правило '{}' слишком большое: {}. Используем облегчённый regex на базе keywords (secret_group={}).",
                        r.description, e, group_idx
                    );
                    out.push(PatternSpec {
                        re,
                        name: format!("{} (lightweight)", r.description),
                        secret_group: Some(group_idx),
                        entropy: r.entropy,
                        entropy_group: Some(group_idx),
                    });
                } else {
                    eprintln!(
                        "[gitleaks]  пропустил правило '{}' — не удалось скомпилировать: {} (и нет подходящих keywords)",
                        r.description, e
                    );
                }
            }
        }
    }

    out
});

// -------- IGNORE: значения (RegexSet) --------
pub static IGNORE_VALUE_REGEXES: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(&[
        r"(?i)^(true|false|null)$",
        r"^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\*+|\.+)$",
        r#"^\$(\d+|\{\d+\})$"#,
        r#"^\$([A-Z_]+|[a-z_]+)$"#,
        r#"^\$\{([A-Z_]+|[a-z_]+)\}$"#,
        r#"^\{\{[ \t]*[\w ().|]+[ \t]*\}\}$"#,
        r#"^\$\{\{[ \t]*((env|github|secrets|vars)(\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*\}\}$"#,
        r#"^%([A-Z_]+|[a-z_]+)%$"#,
        r#"^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$"#,
        r#"^\{\d{0,2}\}$"#,
        r#"^@([A-Z_]+|[a-z_]+)@$"#,
    ])
    .expect("BUG: неверный regex в IGNORE_VALUE_REGEXES")
});

// -------- IGNORE: пути/файлы (RegexSet) --------
pub static IGNORE_PATH_REGEXES: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(&[
        r#"gitleaks\.toml"#,
        r#"(?i)\.(bmp|gif|jpe?g|svg|tiff?)$"#,
        r#"\.(eot|[ot]tf|woff2?)$"#,
        r#"(.*?)(doc|docx|zip|xls|pdf|bin|socket|vsidx|v2|suo|wsuo|\.dll|pdb|exe|gltf)$"#,
        r#"(^|/)?go\.(mod|sum|work(\.sum)?)$"#,
        r#"(^|/)vendor/modules\.txt$"#,
        r#"(?i)(^|/)vendor/(github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(/.*)?$"#,
        r#"(^|/)gradlew(\.bat)?$"#,
        r#"(^|/)gradle\.lockfile$"#,
        r#"(^|/)mvnw(\.cmd)?$"#,
        r#"(^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$"#,
        r#"(^|/)node_modules(/.*)?$"#,
        r#"(^|/)(npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$"#,
        r#"(^|/)bower_components(/.*)?$"#,
        r#"(^|/)(angular|bootstrap|jquery(-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(\.min)?\.js(\.map)?$"#,
        r#"(^|/)javascript\.json$"#,
        r#"(^|/)(Pipfile|poetry)\.lock$"#,
        r#"(?i)/?(v?env|virtualenv)/lib(64)?(/.*)?$"#,
        r#"(?i)(^|/)(lib(64)?/python[23](\.\d{1,2})+|python/[23](\.\d{1,2})+/lib(64)?)(/.*)?$"#,
        r#"(?i)(^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(/.+)?$"#,
        r#"(^|/)vendor/(bundle|ruby)(/.*?)?$"#,
        r#"\.gem$"#,
        r#"verification-metadata\.xml$"#,
        r#"Database\.refactorlog$"#,
    ])
    .expect("BUG: неверный regex в IGNORE_PATH_REGEXES")
});

pub fn normalize_value(s: &str) -> Cow<'_, str> {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"'))
            || (t.starts_with('\'') && t.ends_with('\''))
            || (t.starts_with('`') && t.ends_with('`')))
    {
        Cow::from(&t[1..t.len() - 1])
    } else {
        Cow::from(t)
    }
}

pub fn should_ignore_value(raw: &str) -> bool {
    let v = normalize_value(raw);
    if v.len() <= 2 {
        return true;
    }
    IGNORE_VALUE_REGEXES.is_match(&v)
}

pub fn should_ignore_path(path_like: &str) -> bool {
    IGNORE_PATH_REGEXES.is_match(path_like)
}

/// Shannon entropy (bits/char) и суммарная энтропия (bits).
pub fn shannon_entropy(bytes: &[u8]) -> (f64, f64, usize) {
    if bytes.is_empty() {
        return (0.0, 0.0, 0);
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in bytes {
        *freq.entry(b).or_insert(0) += 1;
    }

    let n = bytes.len() as f64;
    let mut h = 0.0;

    for &count in freq.values() {
        let p = count as f64 / n;
        h -= p * p.log2();
    }

    let total_bits = h * n;
    (h, total_bits, bytes.len())
}

/// Сканирует текст по PATTERNS:
/// - извлекает секрет через secretGroup (если нет — пробует (1) и (0))
/// - считает энтропию по entropyGroup/secretGroup (и фильтрует по entropy)
/// - дедуплицирует (rule_name, value) внутри одного вызова
pub fn scan_patterns(text: &str) -> Vec<ScanHit> {
    let mut out: Vec<ScanHit> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for spec in PATTERNS.iter() {
        let secret_idx = spec.secret_group.unwrap_or(1);
        let entropy_idx = spec
            .entropy_group
            .or(spec.secret_group)
            .unwrap_or(secret_idx);

        for cap in spec.re.captures_iter(text) {
            // 1) достаём «секрет»
            let raw_secret = cap
                .get(secret_idx)
                .or_else(|| cap.get(1))
                .or_else(|| cap.get(0))
                .map(|m| m.as_str());

            let Some(raw_secret) = raw_secret else {
                continue;
            };

            if should_ignore_value(raw_secret) {
                continue;
            }

            let secret_norm = normalize_value(raw_secret);
            if secret_norm.is_empty() {
                continue;
            }

            // 2) что считаем энтропией (если entropyGroup кривой — фолбэк на secret)
            let raw_entropy = cap
                .get(entropy_idx)
                .or_else(|| cap.get(secret_idx))
                .or_else(|| cap.get(0))
                .map(|m| m.as_str())
                .unwrap_or(raw_secret);

            let entropy_norm = normalize_value(raw_entropy);
            let (h, total_bits, len) = shannon_entropy(entropy_norm.as_bytes());

            if let Some(min_h) = spec.entropy {
                if h < min_h {
                    continue;
                }
            }

            let value = secret_norm.into_owned();
            if !seen.insert((spec.name.clone(), value.clone())) {
                continue;
            }

            out.push(ScanHit {
                rule_name: spec.name.clone(),
                value,
                entropy: h,
                total_bits,
                len,
            });
        }
    }

    out
}

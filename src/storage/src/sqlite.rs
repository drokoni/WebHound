use crate::models::{
    NewAnalysisFinding, NewEvent, NewOutUrl, NewRawFinding, NewScanRun, NewScreenshot,
    NewSubdomain,
};
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SqliteStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open sqlite database")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let this = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        this.migrate()?;
        Ok(this)
    }

    pub fn migrate(&self) -> Result<()> {
        let sql = r#"
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    config_json TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS out_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_out_urls_dedupe
ON out_urls(scan_run_id, url);
CREATE INDEX IF NOT EXISTS idx_out_urls_run ON out_urls(scan_run_id);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subdomains_dedupe
ON subdomains(scan_run_id, subdomain);
CREATE INDEX IF NOT EXISTS idx_subdomains_run ON subdomains(scan_run_id);

CREATE TABLE IF NOT EXISTS raw_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    source_path TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    line INTEGER,
    sample_kind TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    match_text TEXT NOT NULL,
    context_text TEXT NOT NULL,
    start_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    entropy_h REAL NOT NULL,
    entropy_total_bits REAL NOT NULL,
    value_len INTEGER NOT NULL,
    source_text_hash TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);
CREATE INDEX IF NOT EXISTS idx_raw_findings_run ON raw_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_raw_findings_type ON raw_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_raw_findings_source ON raw_findings(source_path);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raw_findings_dedupe
ON raw_findings (
    scan_run_id,
    source_path,
    COALESCE(line, -1),
    sample_kind,
    rule_id,
    match_text,
    start_offset,
    end_offset
);

CREATE TABLE IF NOT EXISTS analysis_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    raw_finding_id INTEGER,
    source_path TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    analysis_stage TEXT NOT NULL,
    line INTEGER,
    sample_kind TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    rule_id TEXT,
    rule_name TEXT,
    match_text TEXT NOT NULL,
    context_text TEXT NOT NULL,
    start_offset INTEGER,
    end_offset INTEGER,
    entropy_h REAL,
    entropy_total_bits REAL,
    value_len INTEGER,
    ml_model_name TEXT,
    ml_model_version TEXT,
    ml_label TEXT,
    ml_score REAL,
    ml_scores_json TEXT,
    final_label TEXT,
    final_confidence REAL,
    analyst_note TEXT,
    is_false_positive INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(raw_finding_id) REFERENCES raw_findings(id)
);
CREATE INDEX IF NOT EXISTS idx_analysis_findings_run ON analysis_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_analysis_findings_stage ON analysis_findings(analysis_stage);
CREATE INDEX IF NOT EXISTS idx_analysis_findings_raw_id ON analysis_findings(raw_finding_id);

CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    page_url TEXT NOT NULL,
    local_path TEXT NOT NULL,
    image_sha256 TEXT,
    width INTEGER,
    height INTEGER,
    file_size INTEGER,
    ml_model_name TEXT,
    ml_model_version TEXT,
    ml_label TEXT,
    ml_score REAL,
    ml_scores_json TEXT,
    user_label TEXT,
    user_label_updated_at TEXT,
    user_label_updated_by TEXT,
    analyst_note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);
CREATE INDEX IF NOT EXISTS idx_screenshots_run ON screenshots(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_screenshots_page_url ON screenshots(page_url);
CREATE UNIQUE INDEX IF NOT EXISTS idx_screenshots_dedupe
ON screenshots(scan_run_id, page_url, local_path);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    level TEXT NOT NULL,
    component TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(scan_run_id);
"#;

        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute_batch(sql).context("failed to run sqlite migrations")?;
        Ok(())
    }

    pub fn create_scan_run(&self, input: NewScanRun) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO scan_runs (target, mode, started_at, status, config_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![input.target, input.mode, now, input.status, input.config_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn finish_scan_run(&self, scan_run_id: i64, status: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "UPDATE scan_runs SET finished_at = ?1, status = ?2 WHERE id = ?3",
            params![now, status, scan_run_id],
        )?;
        Ok(())
    }

    pub fn insert_out_url(&self, row: &NewOutUrl) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO out_urls (scan_run_id, url, created_at) VALUES (?1, ?2, ?3)",
            params![row.scan_run_id, row.url, now],
        )?;
        Ok(())
    }

    pub fn insert_subdomain(&self, row: &NewSubdomain) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO subdomains (scan_run_id, subdomain, created_at) VALUES (?1, ?2, ?3)",
            params![row.scan_run_id, row.subdomain, now],
        )?;
        Ok(())
    }

    pub fn insert_raw_finding(&self, row: &NewRawFinding) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            r#"
            INSERT OR IGNORE INTO raw_findings (
                scan_run_id, source_path, source_kind, line, sample_kind, finding_type, rule_id,
                rule_name, match_text, context_text, start_offset, end_offset, entropy_h,
                entropy_total_bits, value_len, source_text_hash, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            "#,
            params![
                row.scan_run_id,
                row.source_path,
                row.source_kind,
                row.line.map(|v| v as i64),
                row.sample_kind,
                row.finding_type,
                row.rule_id,
                row.rule_name,
                row.match_text,
                row.context_text,
                row.start_offset as i64,
                row.end_offset as i64,
                row.entropy_h,
                row.entropy_total_bits,
                row.value_len as i64,
                row.source_text_hash,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn insert_analysis_finding(&self, row: &NewAnalysisFinding) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            r#"
            INSERT INTO analysis_findings (
                scan_run_id, raw_finding_id, source_path, source_kind, analysis_stage, line,
                sample_kind, finding_type, rule_id, rule_name, match_text, context_text,
                start_offset, end_offset, entropy_h, entropy_total_bits, value_len,
                ml_model_name, ml_model_version, ml_label, ml_score, ml_scores_json,
                final_label, final_confidence, analyst_note, is_false_positive, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                      ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28)
            "#,
            params![
                row.scan_run_id,
                row.raw_finding_id,
                row.source_path,
                row.source_kind,
                row.analysis_stage,
                row.line.map(|v| v as i64),
                row.sample_kind,
                row.finding_type,
                row.rule_id,
                row.rule_name,
                row.match_text,
                row.context_text,
                row.start_offset.map(|v| v as i64),
                row.end_offset.map(|v| v as i64),
                row.entropy_h,
                row.entropy_total_bits,
                row.value_len.map(|v| v as i64),
                row.ml_model_name,
                row.ml_model_version,
                row.ml_label,
                row.ml_score,
                row.ml_scores_json,
                row.final_label,
                row.final_confidence,
                row.analyst_note,
                if row.is_false_positive { 1 } else { 0 },
                now,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn insert_screenshot(&self, row: &NewScreenshot) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            r#"
            INSERT OR IGNORE INTO screenshots (
                scan_run_id, page_url, local_path, image_sha256, width, height, file_size,
                ml_model_name, ml_model_version, ml_label, ml_score, ml_scores_json,
                user_label, user_label_updated_at, user_label_updated_by, analyst_note,
                created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
            "#,
            params![
                row.scan_run_id,
                row.page_url,
                row.local_path,
                row.image_sha256,
                row.width.map(|v| v as i64),
                row.height.map(|v| v as i64),
                row.file_size.map(|v| v as i64),
                row.ml_model_name,
                row.ml_model_version,
                row.ml_label,
                row.ml_score,
                row.ml_scores_json,
                row.user_label,
                row.user_label_updated_at,
                row.user_label_updated_by,
                row.analyst_note,
                now,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn update_screenshot_user_label(
        &self,
        screenshot_id: i64,
        user_label: &str,
        analyst_note: Option<&str>,
        updated_by: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            r#"
            UPDATE screenshots
            SET user_label = ?1,
                user_label_updated_at = ?2,
                user_label_updated_by = ?3,
                analyst_note = ?4,
                updated_at = ?2
            WHERE id = ?5
            "#,
            params![user_label, now, updated_by, analyst_note, screenshot_id],
        )?;
        Ok(())
    }

    pub fn update_screenshot_ml(
        &self,
        local_path: &str,
        model_name: &str,
        model_version: Option<&str>,
        ml_label: &str,
        ml_score: f64,
        ml_scores_json: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            r#"
            UPDATE screenshots
            SET ml_model_name = ?1,
                ml_model_version = ?2,
                ml_label = ?3,
                ml_score = ?4,
                ml_scores_json = ?5,
                updated_at = ?6
            WHERE local_path = ?7
            "#,
            params![model_name, model_version, ml_label, ml_score, ml_scores_json, now, local_path],
        )?;
        Ok(())
    }

    pub fn insert_event(&self, row: &NewEvent) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO events (scan_run_id, level, component, message, details_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![row.scan_run_id, row.level, row.component, row.message, row.details_json, now],
        )?;
        Ok(())
    }
    pub fn upsert_screenshot_ml_only(
    &self,
    scan_run_id: i64,
    page_url: &str,
    local_path: &str,
    model_name: &str,
    model_version: Option<&str>,
    ml_label: &str,
    ml_score: f64,
    ml_scores_json: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let conn = self.conn.lock().expect("sqlite mutex poisoned");

    conn.execute(
        r#"
        INSERT INTO screenshots (
            scan_run_id,
            page_url,
            local_path,
            ml_model_name,
            ml_model_version,
            ml_label,
            ml_score,
            ml_scores_json,
            created_at,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
        "#,
        params![
            scan_run_id,
            page_url,
            local_path,
            model_name,
            model_version,
            ml_label,
            ml_score,
            ml_scores_json,
            now
        ],
    )?;

    Ok(())
}
pub fn list_raw_findings_for_run(&self, scan_run_id: i64) -> Result<Vec<crate::models::RawFindingRow>> {
    let conn = self.conn.lock().expect("sqlite mutex poisoned");
    let mut stmt = conn.prepare(
        r#"
        SELECT
            id, scan_run_id, source_path, source_kind, line, sample_kind,
            finding_type, rule_id, rule_name, match_text, context_text,
            start_offset, end_offset, entropy_h, entropy_total_bits, value_len, source_text_hash
        FROM raw_findings
        WHERE scan_run_id = ?1
        ORDER BY id ASC
        "#,
    )?;

    let rows = stmt.query_map(params![scan_run_id], |r| {
        Ok(crate::models::RawFindingRow {
            id: r.get(0)?,
            scan_run_id: r.get(1)?,
            source_path: r.get(2)?,
            source_kind: r.get(3)?,
            line: r.get::<_, Option<i64>>(4)?.map(|v| v as u32),
            sample_kind: r.get(5)?,
            finding_type: r.get(6)?,
            rule_id: r.get(7)?,
            rule_name: r.get(8)?,
            match_text: r.get(9)?,
            context_text: r.get(10)?,
            start_offset: r.get::<_, i64>(11)? as usize,
            end_offset: r.get::<_, i64>(12)? as usize,
            entropy_h: r.get(13)?,
            entropy_total_bits: r.get(14)?,
            value_len: r.get::<_, i64>(15)? as usize,
            source_text_hash: r.get(16)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}
pub fn find_screenshot_by_local_path(&self, local_path: &str) -> Result<Option<crate::models::ScreenshotRow>> {
    let conn = self.conn.lock().expect("sqlite mutex poisoned");
    let mut stmt = conn.prepare(
        r#"
        SELECT id, scan_run_id, page_url, local_path
        FROM screenshots
        WHERE local_path = ?1
        ORDER BY id DESC
        LIMIT 1
        "#,
    )?;

    let mut rows = stmt.query(params![local_path])?;
    if let Some(r) = rows.next()? {
        Ok(Some(crate::models::ScreenshotRow {
            id: r.get(0)?,
            scan_run_id: r.get(1)?,
            page_url: r.get(2)?,
            local_path: r.get(3)?,
        }))
    } else {
        Ok(None)
    }
}

}


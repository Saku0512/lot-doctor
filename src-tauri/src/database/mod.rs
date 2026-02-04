//! Database operations for storing scan history and device information

use crate::scanner::Device;
use rusqlite::{Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use thiserror::Error;

static DB: std::sync::OnceLock<Mutex<Connection>> = std::sync::OnceLock::new();

/// Database errors
#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Database not initialized")]
    NotInitialized,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Scan history record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub device_count: usize,
    pub average_score: u8,
    pub issues_found: usize,
}

/// Initialize database
pub fn init() -> Result<(), DbError> {
    let db_path = get_db_path();

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let conn = Connection::open(&db_path)?;

    // Create tables
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            device_count INTEGER NOT NULL,
            average_score INTEGER NOT NULL,
            issues_found INTEGER NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            data TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id)",
        [],
    )?;

    DB.set(Mutex::new(conn)).ok();

    Ok(())
}

fn get_db_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("iot-doctor")
        .join("data.db")
}

/// Save scan results
pub fn save_scan(devices: &[Device]) -> Result<String, DbError> {
    let conn = DB.get().ok_or(DbError::NotInitialized)?.lock().unwrap();

    let scan_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now();
    let device_count = devices.len();
    let average_score = if devices.is_empty() {
        0
    } else {
        devices.iter().map(|d| d.security_score as u32).sum::<u32>() / device_count as u32
    } as u8;
    let issues_found: usize = devices.iter().map(|d| d.issues.len()).sum();

    conn.execute(
        "INSERT INTO scans (id, timestamp, device_count, average_score, issues_found) VALUES (?1, ?2, ?3, ?4, ?5)",
        (&scan_id, timestamp.to_rfc3339(), device_count, average_score, issues_found),
    )?;

    for device in devices {
        let device_json = serde_json::to_string(device)?;
        conn.execute(
            "INSERT INTO devices (id, scan_id, data) VALUES (?1, ?2, ?3)",
            (&device.id, &scan_id, &device_json),
        )?;
    }

    Ok(scan_id)
}

/// Get scan history
pub fn get_scan_history() -> Result<Vec<ScanRecord>, DbError> {
    let conn = DB.get().ok_or(DbError::NotInitialized)?.lock().unwrap();

    let mut stmt = conn.prepare(
        "SELECT id, timestamp, device_count, average_score, issues_found FROM scans ORDER BY timestamp DESC LIMIT 50"
    )?;

    let records = stmt.query_map([], |row| {
        Ok(ScanRecord {
            id: row.get(0)?,
            timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            device_count: row.get(2)?,
            average_score: row.get(3)?,
            issues_found: row.get(4)?,
        })
    })?;

    records.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
}

/// Get device by ID
pub fn get_device(device_id: &str) -> Result<Option<Device>, DbError> {
    let conn = DB.get().ok_or(DbError::NotInitialized)?.lock().unwrap();

    let mut stmt = conn.prepare("SELECT data FROM devices WHERE id = ?1")?;
    let mut rows = stmt.query([device_id])?;

    if let Some(row) = rows.next()? {
        let data: String = row.get(0)?;
        let device: Device = serde_json::from_str(&data)?;
        Ok(Some(device))
    } else {
        Ok(None)
    }
}

/// Get devices from a specific scan
pub fn get_scan_devices(scan_id: &str) -> Result<Vec<Device>, DbError> {
    let conn = DB.get().ok_or(DbError::NotInitialized)?.lock().unwrap();

    let mut stmt = conn.prepare("SELECT data FROM devices WHERE scan_id = ?1")?;
    let rows = stmt.query_map([scan_id], |row| {
        let data: String = row.get(0)?;
        Ok(data)
    })?;

    let mut devices = Vec::new();
    for row in rows {
        let data = row?;
        let device: Device = serde_json::from_str(&data)?;
        devices.push(device);
    }

    Ok(devices)
}

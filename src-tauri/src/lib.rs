pub mod database;
pub mod report;
pub mod scanner;
pub mod vulndb;

use scanner::{Device, ScanLevel, ScanProgress};
use serde::{Deserialize, Serialize};
use tauri::Manager;

/// Start network scan
#[tauri::command]
async fn start_scan(
    app: tauri::AppHandle,
    level: ScanLevel,
) -> Result<Vec<Device>, String> {
    scanner::scan_network(&app, level)
        .await
        .map_err(|e| e.to_string())
}

/// Get scan history
#[tauri::command]
async fn get_scan_history() -> Result<Vec<database::ScanRecord>, String> {
    database::get_scan_history().map_err(|e| e.to_string())
}

/// Get device details
#[tauri::command]
async fn get_device_details(device_id: String) -> Result<Option<Device>, String> {
    database::get_device(&device_id).map_err(|e| e.to_string())
}

/// Generate security report
#[tauri::command]
async fn generate_report(
    devices: Vec<Device>,
    format: report::ReportFormat,
) -> Result<String, String> {
    report::generate(&devices, format).map_err(|e| e.to_string())
}

/// Check for vulnerabilities
#[tauri::command]
async fn check_vulnerabilities(device: Device) -> Result<Vec<vulndb::Vulnerability>, String> {
    vulndb::check_device(&device)
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Initialize database
            if let Err(e) = database::init() {
                eprintln!("Failed to initialize database: {}", e);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_scan,
            get_scan_history,
            get_device_details,
            generate_report,
            check_vulnerabilities,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

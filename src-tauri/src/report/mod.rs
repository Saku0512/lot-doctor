//! Report generation module

use crate::scanner::{Device, SecurityLevel, IssueSeverity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Report generation errors
#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Failed to generate report: {0}")]
    GenerationFailed(String),

    #[error("Template error: {0}")]
    TemplateError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Report format
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Text,
    Html,
    Json,
}

/// Generate security report
pub fn generate(devices: &[Device], format: ReportFormat) -> Result<String, ReportError> {
    match format {
        ReportFormat::Text => generate_text_report(devices),
        ReportFormat::Html => generate_html_report(devices),
        ReportFormat::Json => generate_json_report(devices),
    }
}

fn generate_text_report(devices: &[Device]) -> Result<String, ReportError> {
    let mut report = String::new();

    report.push_str("╔═══════════════════════════════════════════════════════════╗\n");
    report.push_str("║           IoT Doctor セキュリティ診断レポート             ║\n");
    report.push_str("╚═══════════════════════════════════════════════════════════╝\n\n");

    report.push_str(&format!("診断日時: {}\n", chrono::Local::now().format("%Y年%m月%d日 %H:%M:%S")));
    report.push_str(&format!("検出デバイス数: {}台\n\n", devices.len()));

    // Overall score
    let avg_score = if devices.is_empty() {
        0
    } else {
        devices.iter().map(|d| d.security_score as u32).sum::<u32>() / devices.len() as u32
    };

    report.push_str("【総合セキュリティスコア】\n");
    report.push_str(&format!("  {} / 100 点\n\n", avg_score));

    // Device details
    report.push_str("【検出されたデバイス】\n");
    report.push_str("─────────────────────────────────────────────────────────────\n");

    for (i, device) in devices.iter().enumerate() {
        let status = match device.security_level {
            SecurityLevel::Safe => "✓ 安全",
            SecurityLevel::Warning => "△ 注意",
            SecurityLevel::Danger => "✗ 危険",
            SecurityLevel::Unknown => "? 不明",
        };

        report.push_str(&format!(
            "\n{}. {} [{}]\n",
            i + 1,
            device.name.as_deref().unwrap_or("不明なデバイス"),
            status
        ));
        report.push_str(&format!("   IP: {} | MAC: {}\n", device.ip, device.mac));

        if let Some(ref vendor) = device.vendor {
            report.push_str(&format!("   メーカー: {}\n", vendor));
        }

        report.push_str(&format!("   セキュリティスコア: {} 点\n", device.security_score));

        if !device.issues.is_empty() {
            report.push_str("   問題点:\n");
            for issue in &device.issues {
                let severity_icon = match issue.severity {
                    IssueSeverity::Critical => "🔴",
                    IssueSeverity::High => "🟠",
                    IssueSeverity::Medium => "🟡",
                    IssueSeverity::Low => "🟢",
                    IssueSeverity::Info => "🔵",
                };
                report.push_str(&format!("     {} {}\n", severity_icon, issue.title));
            }
        }
    }

    // Remediation summary
    report.push_str("\n\n【推奨される対策】\n");
    report.push_str("─────────────────────────────────────────────────────────────\n");

    let mut remediation_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for device in devices {
        for issue in &device.issues {
            let device_name = device.name.as_deref().unwrap_or("不明なデバイス");
            remediation_map
                .entry(issue.remediation.clone())
                .or_default()
                .push(device_name.to_string());
        }
    }

    for (remediation, affected_devices) in remediation_map {
        report.push_str(&format!(
            "\n• {} (対象: {})\n",
            remediation,
            affected_devices.join(", ")
        ));
    }

    report.push_str("\n\n─────────────────────────────────────────────────────────────\n");
    report.push_str("このレポートはIoT Doctorによって自動生成されました。\n");

    Ok(report)
}

fn generate_html_report(devices: &[Device]) -> Result<String, ReportError> {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"ja\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("<title>IoT Doctor セキュリティ診断レポート</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: 'Noto Sans JP', sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }\n");
    html.push_str(".safe { color: #22c55e; } .warning { color: #f59e0b; } .danger { color: #ef4444; }\n");
    html.push_str(".device { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 16px 0; }\n");
    html.push_str(".issue { padding: 8px; margin: 4px 0; background: #fef2f2; border-radius: 4px; }\n");
    html.push_str("</style>\n</head>\n<body>\n");

    html.push_str("<h1>IoT Doctor セキュリティ診断レポート</h1>\n");
    html.push_str(&format!("<p>診断日時: {}</p>\n", chrono::Local::now().format("%Y年%m月%d日 %H:%M:%S")));
    html.push_str(&format!("<p>検出デバイス数: {}台</p>\n", devices.len()));

    for device in devices {
        let class = match device.security_level {
            SecurityLevel::Safe => "safe",
            SecurityLevel::Warning => "warning",
            SecurityLevel::Danger => "danger",
            SecurityLevel::Unknown => "",
        };

        html.push_str("<div class=\"device\">\n");
        html.push_str(&format!(
            "<h3 class=\"{}\">{}（スコア: {}）</h3>\n",
            class,
            device.name.as_deref().unwrap_or("不明なデバイス"),
            device.security_score
        ));
        html.push_str(&format!("<p>IP: {} | MAC: {}</p>\n", device.ip, device.mac));

        if !device.issues.is_empty() {
            html.push_str("<h4>検出された問題:</h4>\n");
            for issue in &device.issues {
                html.push_str(&format!("<div class=\"issue\"><strong>{}</strong><br>{}</div>\n",
                    issue.title, issue.description));
            }
        }

        html.push_str("</div>\n");
    }

    html.push_str("</body>\n</html>\n");

    Ok(html)
}

fn generate_json_report(devices: &[Device]) -> Result<String, ReportError> {
    #[derive(Serialize)]
    struct Report {
        generated_at: String,
        device_count: usize,
        average_score: u8,
        devices: Vec<Device>,
    }

    let avg_score = if devices.is_empty() {
        0
    } else {
        devices.iter().map(|d| d.security_score as u32).sum::<u32>() / devices.len() as u32
    } as u8;

    let report = Report {
        generated_at: chrono::Utc::now().to_rfc3339(),
        device_count: devices.len(),
        average_score: avg_score,
        devices: devices.to_vec(),
    };

    serde_json::to_string_pretty(&report)
        .map_err(|e| ReportError::GenerationFailed(e.to_string()))
}

//! Vulnerability database and checking

use crate::scanner::{Device, SecurityIssue, IssueSeverity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Vulnerability database errors
#[derive(Error, Debug)]
pub enum VulnDbError {
    #[error("Database lookup failed: {0}")]
    LookupFailed(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Known vulnerability entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub cve: Option<String>,
    pub severity: IssueSeverity,
    pub title: String,
    pub description: String,
    pub affected_vendors: Vec<String>,
    pub affected_products: Vec<String>,
    pub remediation: String,
}

/// Default credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultCredential {
    pub vendor: String,
    pub product: String,
    pub username: String,
    pub password: String,
}

/// Built-in default credentials database (for educational purposes)
const DEFAULT_CREDENTIALS: &[(&str, &str, &str, &str)] = &[
    ("Generic", "Router", "admin", "admin"),
    ("Generic", "Router", "admin", "password"),
    ("Generic", "Router", "admin", "1234"),
    ("Generic", "Camera", "admin", "admin"),
    ("Generic", "Camera", "admin", ""),
    ("Generic", "Camera", "root", "root"),
    // Note: In production, this would be loaded from an encrypted database
];

/// Check device for known vulnerabilities
pub async fn check_device(device: &Device) -> Result<Vec<Vulnerability>, VulnDbError> {
    let mut vulnerabilities = Vec::new();

    // Check for known vulnerable ports
    for port in &device.open_ports {
        if let Some(vuln) = check_port_vulnerability(port.number) {
            vulnerabilities.push(vuln);
        }
    }

    // Check vendor-specific vulnerabilities
    if let Some(ref vendor) = device.vendor {
        let vendor_vulns = check_vendor_vulnerabilities(vendor);
        vulnerabilities.extend(vendor_vulns);
    }

    Ok(vulnerabilities)
}

fn check_port_vulnerability(port: u16) -> Option<Vulnerability> {
    match port {
        23 => Some(Vulnerability {
            id: "IOTDOC-001".to_string(),
            cve: None,
            severity: IssueSeverity::High,
            title: "Telnetサービスが有効".to_string(),
            description: "Telnetは暗号化されていない通信を使用するため、\
                         認証情報が傍受される危険性があります。".to_string(),
            affected_vendors: vec!["*".to_string()],
            affected_products: vec!["*".to_string()],
            remediation: "Telnetを無効化し、SSHなどの暗号化された\
                         プロトコルを使用してください。".to_string(),
        }),
        21 => Some(Vulnerability {
            id: "IOTDOC-002".to_string(),
            cve: None,
            severity: IssueSeverity::Medium,
            title: "FTPサービスが有効".to_string(),
            description: "FTPは認証情報を平文で送信するため、\
                         セキュリティ上のリスクがあります。".to_string(),
            affected_vendors: vec!["*".to_string()],
            affected_products: vec!["*".to_string()],
            remediation: "FTPを無効化し、SFTPやSCPを使用してください。".to_string(),
        }),
        1900 => Some(Vulnerability {
            id: "IOTDOC-003".to_string(),
            cve: None,
            severity: IssueSeverity::Medium,
            title: "UPnPサービスが有効".to_string(),
            description: "UPnPは自動的にポート転送を設定できるため、\
                         悪意のあるソフトウェアに悪用される可能性があります。".to_string(),
            affected_vendors: vec!["*".to_string()],
            affected_products: vec!["*".to_string()],
            remediation: "UPnPが不要な場合は、ルーターの設定で\
                         無効化することを検討してください。".to_string(),
        }),
        _ => None,
    }
}

fn check_vendor_vulnerabilities(_vendor: &str) -> Vec<Vulnerability> {
    // TODO: Implement vendor-specific vulnerability checking
    // This would query a local or remote vulnerability database
    Vec::new()
}

/// Get default credentials for a vendor/product
pub fn get_default_credentials(vendor: &str, product: &str) -> Vec<DefaultCredential> {
    DEFAULT_CREDENTIALS
        .iter()
        .filter(|(v, p, _, _)| {
            (v.eq_ignore_ascii_case(vendor) || *v == "Generic")
                && (p.eq_ignore_ascii_case(product) || *p == "Generic")
        })
        .map(|(v, p, u, pw)| DefaultCredential {
            vendor: v.to_string(),
            product: p.to_string(),
            username: u.to_string(),
            password: pw.to_string(),
        })
        .collect()
}

/// Convert vulnerability to security issue
pub fn vulnerability_to_issue(vuln: &Vulnerability) -> SecurityIssue {
    SecurityIssue {
        id: vuln.id.clone(),
        severity: vuln.severity,
        title: vuln.title.clone(),
        description: vuln.description.clone(),
        remediation: vuln.remediation.clone(),
    }
}

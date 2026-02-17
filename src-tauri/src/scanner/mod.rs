//! Network scanning module
//!
//! Provides device discovery and security scanning functionality.

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tauri::Emitter;
use thiserror::Error;

pub mod arp;
pub mod ports;
pub mod fingerprint;
pub mod mdns;
pub mod nbns;
pub mod ssdp;

/// Scan level determining the depth of security analysis
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanLevel {
    /// Passive information gathering (ARP, mDNS, NetBIOS)
    #[default]
    Level1,
    /// Active scanning (port scan, banner grabbing)
    Level2,
    /// Vulnerability verification (requires explicit consent)
    Level3,
}

/// Security level of a device
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    Safe,
    Warning,
    Danger,
    Unknown,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Discovered network device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: Option<String>,
    pub device_type: DeviceType,
    pub ip: String,
    pub mac: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub open_ports: Vec<Port>,
    pub security_level: SecurityLevel,
    pub security_score: u8,
    pub issues: Vec<SecurityIssue>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// Device type classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[derive(PartialEq)]
pub enum DeviceType {
    Router,
    Camera,
    SmartSpeaker,
    SmartTv,
    SmartPlug,
    Printer,
    Nas,
    Computer,
    Smartphone,
    #[default]
    Unknown,
}

/// Open port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub is_secure: bool,
}

/// Security issue found on a device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub id: String,
    pub severity: IssueSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

/// Severity level of a security issue
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IssueSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Scan progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub phase: String,
    pub progress: u8,
    pub message: String,
}

/// Scanner errors
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Timeout during scan")]
    Timeout,

    #[error("Scan cancelled")]
    Cancelled,

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Perform network scan at specified level
pub async fn scan_network(
    app: &tauri::AppHandle,
    level: ScanLevel,
) -> Result<Vec<Device>, ScanError> {
    let mut devices = Vec::new();

    // Emit progress: Starting scan
    emit_progress(app, "初期化中...", 0);

    // Level 1: Passive scanning
    emit_progress(app, "ネットワークを検索中...", 10);

    // Phase 1: Execute ARP + mDNS + SSDP concurrently
    let (discovered_result, mdns_names, ssdp_names) = tokio::join!(
        arp::discover_devices(),
        // Run mDNS scan in a blocking thread since mdns-sd is synchronous
        tokio::task::spawn_blocking(|| {
            mdns::scan_mdns(std::time::Duration::from_secs(3))
        }),
        ssdp::scan_ssdp(std::time::Duration::from_secs(3)),
    );

    let discovered = discovered_result?;
    let mdns_map = mdns_names.map_err(|e| ScanError::Internal(e.to_string()))?;

    // Phase 2: Run NBNS queries on discovered IPs (needs ARP results first)
    emit_progress(app, "デバイス名を解決中...", 25);
    let ip_list: Vec<String> = discovered.iter().map(|(ip, _)| ip.clone()).collect();
    let nbns_names = nbns::scan_nbns(&ip_list, std::time::Duration::from_secs(2)).await;

    emit_progress(app, "デバイスを識別中...", 35);
    for (ip, mac) in discovered {
        let vendor = fingerprint::lookup_vendor(&mac);

        // Resolve hostname (DNS PTR)
        let dns_hostname: Option<String> = match ip.parse::<std::net::IpAddr>() {
            Ok(ip_addr) => dns_lookup::lookup_addr(&ip_addr).ok(),
            Err(_) => None,
        };

        // Gather names from all resolution methods
        let m_name = mdns_map.get(&ip).cloned();
        let nb_name = nbns_names.get(&ip).cloned();
        let ssdp_name = ssdp_names.get(&ip).cloned();

        // Determine display name
        // Priority: mDNS > NBNS > SSDP > DNS PTR > Vendor fallback
        let name: Option<String> = m_name.clone()
            .or(nb_name.clone())
            .or(ssdp_name)
            .or(dns_hostname.clone())
            .or(vendor.as_ref().map(|v| format!("{} デバイス", v)));

        // Identify device type using resolved name for better classification
        let device_type = fingerprint::identify_device_type(&mac, &vendor, &name);

        // hostname field: prefer DNS PTR, then mDNS, then NBNS
        let hostname = dns_hostname.or(m_name).or(nb_name);

        devices.push(Device {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            device_type,
            ip,
            mac,
            vendor,
            hostname,
            open_ports: Vec::new(),
            security_level: SecurityLevel::Unknown,
            security_score: 0,
            issues: Vec::new(),
            last_seen: chrono::Utc::now(),
        });
    }

    // Level 2: Active scanning (if requested)
    if matches!(level, ScanLevel::Level2 | ScanLevel::Level3) {
        emit_progress(app, "ポートをスキャン中...", 50);
        for device in &mut devices {
            device.open_ports = ports::scan_ports(&device.ip).await?;
        }

        emit_progress(app, "サービスを識別中...", 70);
        for device in &mut devices {
            fingerprint::identify_services(device).await;
        }
    }

    // Level 3: Vulnerability verification (if requested and consented)
    if matches!(level, ScanLevel::Level3) {
        emit_progress(app, "脆弱性を確認中...", 85);
        for device in &mut devices {
            check_vulnerabilities(device).await;
        }
    }

    // Calculate security scores
    emit_progress(app, "セキュリティスコアを計算中...", 95);
    for device in &mut devices {
        calculate_security_score(device);
    }

    emit_progress(app, "完了", 100);

    Ok(devices)
}

fn emit_progress(app: &tauri::AppHandle, phase: &str, progress: u8) {
    let _ = app.emit("scan-progress", ScanProgress {
        phase: phase.to_string(),
        progress,
        message: phase.to_string(),
    });
}

async fn check_vulnerabilities(device: &mut Device) {
    // Check for default passwords
    if has_default_password(device).await {
        device.issues.push(SecurityIssue {
            id: "default-password".to_string(),
            severity: IssueSeverity::Critical,
            title: "デフォルトパスワードが使用されています".to_string(),
            description: "このデバイスは工場出荷時のパスワードが使用されています。\
                         悪意のある第三者に不正アクセスされる危険があります。".to_string(),
            remediation: "デバイスの管理画面にログインし、パスワードを強力なものに変更してください。".to_string(),
        });
    }

    // Check for open telnet
    if device.open_ports.iter().any(|p| p.number == 23) {
        device.issues.push(SecurityIssue {
            id: "telnet-open".to_string(),
            severity: IssueSeverity::High,
            title: "Telnetポートが開放されています".to_string(),
            description: "Telnetは暗号化されていない通信プロトコルです。\
                         パスワードが平文で送信されるため、盗聴される危険があります。".to_string(),
            remediation: "Telnetを無効化し、SSHを使用するか、デバイスの管理画面からリモート管理を無効にしてください。".to_string(),
        });
    }

    // Check for UPnP
    if device.open_ports.iter().any(|p| p.number == 1900) {
        device.issues.push(SecurityIssue {
            id: "upnp-enabled".to_string(),
            severity: IssueSeverity::Medium,
            title: "UPnPが有効です".to_string(),
            description: "UPnPは自動的にポートを開放する機能です。\
                         悪意のあるソフトウェアに悪用される可能性があります。".to_string(),
            remediation: "ルーターの管理画面からUPnPを無効にすることを検討してください。".to_string(),
        });
    }
}

async fn has_default_password(_device: &Device) -> bool {
    // TODO: Implement actual default password checking
    false
}

fn calculate_security_score(device: &mut Device) {
    let mut score: i32 = 100;

    for issue in &device.issues {
        score -= match issue.severity {
            IssueSeverity::Critical => 40,
            IssueSeverity::High => 25,
            IssueSeverity::Medium => 15,
            IssueSeverity::Low => 5,
            IssueSeverity::Info => 0,
        };
    }

    // Deduct for open risky ports
    for port in &device.open_ports {
        if !port.is_secure {
            score -= 5;
        }
    }

    device.security_score = score.clamp(0, 100) as u8;
    device.security_level = match device.security_score {
        80..=100 => SecurityLevel::Safe,
        50..=79 => SecurityLevel::Warning,
        _ => SecurityLevel::Danger,
    };
}

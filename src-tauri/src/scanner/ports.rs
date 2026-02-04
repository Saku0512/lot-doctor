//! Port scanning functionality

use super::{Port, ScanError};

/// Common ports to scan for IoT devices
const COMMON_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    443,   // HTTPS
    554,   // RTSP (cameras)
    1883,  // MQTT
    1900,  // UPnP/SSDP
    5000,  // UPnP
    5353,  // mDNS
    8080,  // HTTP Alt
    8443,  // HTTPS Alt
    8883,  // MQTT TLS
    9000,  // Various IoT
];

/// Scan common ports on target IP
pub async fn scan_ports(ip: &str) -> Result<Vec<Port>, ScanError> {
    let mut open_ports = Vec::new();

    for &port in COMMON_PORTS {
        if is_port_open(ip, port).await {
            let service = identify_service(port);
            let is_secure = is_secure_service(port);

            open_ports.push(Port {
                number: port,
                protocol: "tcp".to_string(),
                service: Some(service.to_string()),
                version: None,
                is_secure,
            });
        }
    }

    Ok(open_ports)
}

async fn is_port_open(ip: &str, port: u16) -> bool {
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = format!("{}:{}", ip, port);
    std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

fn identify_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        443 => "HTTPS",
        554 => "RTSP",
        1883 => "MQTT",
        1900 => "UPnP",
        5000 => "UPnP",
        5353 => "mDNS",
        8080 => "HTTP",
        8443 => "HTTPS",
        8883 => "MQTT-TLS",
        _ => "Unknown",
    }
}

fn is_secure_service(port: u16) -> bool {
    matches!(port, 22 | 443 | 8443 | 8883)
}

/// Grab banner from service
pub async fn grab_banner(_ip: &str, _port: u16) -> Option<String> {
    // TODO: Implement banner grabbing
    None
}

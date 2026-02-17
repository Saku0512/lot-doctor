//! SSDP/UPnP device discovery
//!
//! Sends M-SEARCH multicast packets to discover UPnP devices on the network
//! and retrieves their friendly names from XML device descriptions.

use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;

const SSDP_MULTICAST_ADDR: &str = "239.255.255.250:1900";

/// M-SEARCH request packet for discovering all UPnP devices
const M_SEARCH_REQUEST: &str = "\
M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 2\r\n\
ST: ssdp:all\r\n\
\r\n";

/// Discover device names via SSDP/UPnP M-SEARCH.
/// Returns HashMap<IP address, friendly name>.
pub async fn scan_ssdp(timeout: Duration) -> HashMap<String, String> {
    let mut device_names: HashMap<String, String> = HashMap::new();

    // Bind to any available port
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind SSDP socket: {}", e);
            return device_names;
        }
    };

    // Send M-SEARCH multicast
    if let Err(e) = socket.send_to(M_SEARCH_REQUEST.as_bytes(), SSDP_MULTICAST_ADDR).await {
        eprintln!("Failed to send SSDP M-SEARCH: {}", e);
        return device_names;
    }

    // Collect LOCATION URLs from responses
    let mut location_map: HashMap<String, String> = HashMap::new(); // IP -> LOCATION URL
    let mut buf = [0u8; 4096];

    let collect_deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(collect_deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, addr))) => {
                let response = String::from_utf8_lossy(&buf[..len]);
                if let Some(location) = extract_header(&response, "LOCATION") {
                    let ip = addr.ip().to_string();
                    location_map.entry(ip).or_insert(location);
                }
            }
            _ => break, // Timeout or error
        }
    }

    // Fetch device descriptions from LOCATION URLs and extract friendly names
    let mut tasks = Vec::new();
    for (ip, location_url) in location_map {
        tasks.push(tokio::spawn(async move {
            match fetch_friendly_name(&location_url, Duration::from_secs(2)).await {
                Some(name) => Some((ip, name)),
                None => None,
            }
        }));
    }

    for task in tasks {
        if let Ok(Some((ip, name))) = task.await {
            device_names.insert(ip, name);
        }
    }

    device_names
}

/// Extract a header value from an HTTP response string (case-insensitive).
fn extract_header(response: &str, header_name: &str) -> Option<String> {
    let header_lower = header_name.to_lowercase();
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with(&header_lower) {
            if let Some(pos) = line.find(':') {
                return Some(line[pos + 1..].trim().to_string());
            }
        }
    }
    None
}

/// Fetch device description XML from a LOCATION URL and extract <friendlyName>.
async fn fetch_friendly_name(url: &str, timeout: Duration) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .ok()?;

    let response = client.get(url).send().await.ok()?;
    let body = response.text().await.ok()?;

    extract_xml_element(&body, "friendlyName")
}

/// Extract the text content of an XML element using quick-xml.
fn extract_xml_element(xml: &str, element_name: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut in_target = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let local_name = e.local_name();
                if local_name.as_ref() == element_name.as_bytes() {
                    in_target = true;
                }
            }
            Ok(Event::Text(ref e)) if in_target => {
                if let Ok(text) = e.unescape() {
                    let text = text.trim().to_string();
                    if !text.is_empty() {
                        return Some(text);
                    }
                }
            }
            Ok(Event::End(_)) if in_target => {
                in_target = false;
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    None
}

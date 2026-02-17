//! NetBIOS Name Service (NBNS) device name resolution
//!
//! Sends NBNS Node Status Requests (UDP port 137) to discover device hostnames.
//! Android phones, Windows PCs, and many IoT devices respond with their configured names.

use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;

/// NBNS Node Status Request packet for wildcard name query ("*")
/// This queries the remote host for all registered NetBIOS names.
fn build_nbns_status_request(transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);

    // Transaction ID (2 bytes)
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    // Flags: 0x0000 (standard query)
    packet.extend_from_slice(&[0x00, 0x00]);
    // Questions: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // Question section:
    // Name: "*" encoded as NetBIOS first-level encoding
    // Length prefix: 32 bytes
    packet.push(0x20);
    // "*" (0x2A) padded with spaces (0x20) to 16 bytes, then first-level encoded
    // First char: 0x2A -> 'C','K' (0x2A = 42 -> high nibble 2 -> 'C', low nibble A -> 'K')
    // Remaining 15 chars: 0x00 (null padding) -> 'A','A' each
    packet.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    // Null terminator for name
    packet.push(0x00);

    // Type: NBSTAT (0x0021) - Node Status Request
    packet.extend_from_slice(&[0x00, 0x21]);
    // Class: IN (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Parse a NBNS Node Status Response and extract the device name.
/// Returns the first UNIQUE name entry (typically the device hostname).
fn parse_nbns_response(data: &[u8]) -> Option<String> {
    // Minimum response size: 12 (header) + some answer data
    if data.len() < 57 {
        return None;
    }

    // Skip header (12 bytes) and question section
    // The answer section starts after the header
    // Find the answer section: skip past the name in the answer
    let mut pos = 12;

    // Skip the name field (could be a pointer 0xC0xx or a full name)
    if pos >= data.len() {
        return None;
    }
    if data[pos] & 0xC0 == 0xC0 {
        // Name pointer (2 bytes)
        pos += 2;
    } else {
        // Full name - skip until null terminator
        while pos < data.len() && data[pos] != 0 {
            pos += data[pos] as usize + 1;
        }
        pos += 1; // Skip null terminator
    }

    // Skip Type (2) + Class (2) + TTL (4) + Data Length (2)
    pos += 10;
    if pos >= data.len() {
        return None;
    }

    // Number of names
    let num_names = data[pos] as usize;
    pos += 1;

    // Each name entry is 18 bytes: 15 bytes name + 1 byte suffix + 2 bytes flags
    for _ in 0..num_names {
        if pos + 18 > data.len() {
            break;
        }

        let name_bytes = &data[pos..pos + 15];
        let _suffix = data[pos + 15];
        let flags = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);

        // Check if this is a UNIQUE name (bit 15 = 0 means unique, = 1 means group)
        let is_group = (flags & 0x8000) != 0;

        if !is_group {
            // Extract and clean the name (strip trailing spaces)
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end()
                .to_string();

            if !name.is_empty() {
                return Some(name);
            }
        }

        pos += 18;
    }

    None
}

/// Query NetBIOS names for discovered IPs.
/// Sends NBNS Node Status Requests to each IP and collects responses.
/// Returns HashMap<IP address, NetBIOS name>.
pub async fn scan_nbns(ips: &[String], timeout: Duration) -> HashMap<String, String> {
    let mut resolved_names = HashMap::new();

    if ips.is_empty() {
        return resolved_names;
    }

    // Process in batches to avoid resource exhaustion
    for chunk in ips.chunks(50) {
        let mut tasks = Vec::new();

        for ip in chunk {
            let ip = ip.clone();
            let timeout = timeout;
            tasks.push(tokio::spawn(async move {
                query_nbns_name(&ip, timeout).await.map(|name| (ip, name))
            }));
        }

        for task in tasks {
            if let Ok(Some((ip, name))) = task.await {
                resolved_names.insert(ip, name);
            }
        }
    }

    resolved_names
}

/// Send a single NBNS query to the specified IP and return the resolved name.
async fn query_nbns_name(ip: &str, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let target = format!("{}:137", ip);

    // Use a simple counter-based transaction ID
    let transaction_id = (ip.as_bytes().iter().map(|b| *b as u16).sum::<u16>()) ^ 0x1234;
    let request = build_nbns_status_request(transaction_id);

    socket.send_to(&request, &target).await.ok()?;

    let mut buf = [0u8; 1024];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => parse_nbns_response(&buf[..len]),
        _ => None,
    }
}

//! ARP-based device discovery

use super::ScanError;
use network_interface::{NetworkInterface, NetworkInterfaceConfig, V4IfAddr};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Discover devices on the local network using ARP
pub async fn discover_devices() -> Result<Vec<(String, String)>, ScanError> {
    // 1. Get local network interface
    let (interface_name, ip_addr, subnet_mask) = get_local_interface()
        .ok_or_else(|| ScanError::NetworkError("Could not find suitable network interface".to_string()))?;

    println!("Using interface: {} ({}) mask: {}", interface_name, ip_addr, subnet_mask);

    // 2. Perform Ping Sweep (ARP scan)
    // Calculate IP range and ping all hosts
    if let (Ok(ip), Ok(mask)) = (Ipv4Addr::from_str(&ip_addr), Ipv4Addr::from_str(&subnet_mask)) {
         let ips = get_ips_in_subnet(ip, mask);
         
         // Ping in batches to avoid too many open files/processes
         for chunk in ips.chunks(50) {
             let mut tasks = Vec::new();
             for target_ip in chunk {
                 let target_ip = *target_ip;
                 tasks.push(tokio::spawn(async move {
                     let _ = Command::new("ping")
                         .arg("-c")
                         .arg("1")
                         .arg("-W")
                         .arg("1") // 1 second timeout
                         .arg(target_ip.to_string())
                         .stdout(Stdio::null())
                         .stderr(Stdio::null())
                         .status()
                         .await;
                 }));
             }
             
             // Wait for batch to complete
             for task in tasks {
                 let _ = task.await;
             }
         }
    }

    // 3. Read ARP table
    parse_arp_table().await
}

/// Get the local network interface information
pub fn get_local_interface() -> Option<(String, String, String)> {
    let interfaces = NetworkInterface::show().ok()?;

    for iface in interfaces {
        // Skip loopback and down interfaces
        if iface.name == "lo" || iface.name.starts_with("docker") || iface.name.starts_with("br-") {
            continue;
        }

        // Find IPv4 address
        for addr in iface.addr {
            if let network_interface::Addr::V4(V4IfAddr { ip, netmask: Some(netmask), .. }) = addr {
                 // Check if it's a private IP (simple check)
                 if !ip.is_loopback() && !ip.is_unspecified() {
                     return Some((iface.name, ip.to_string(), netmask.to_string()));
                 }
            }
        }
    }
    None
}

fn get_ips_in_subnet(ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let network_u32 = ip_u32 & mask_u32;
    let broadcast_u32 = network_u32 | !mask_u32;

    let mut ips = Vec::new();
    // Start from network+1 to broadcast-1
    for i in (network_u32 + 1)..broadcast_u32 {
        ips.push(Ipv4Addr::from(i));
    }
    ips
}

async fn parse_arp_table() -> Result<Vec<(String, String)>, ScanError> {
    let file = tokio::fs::File::open("/proc/net/arp")
        .await
        .map_err(|e| ScanError::Internal(format!("Failed to open /proc/net/arp: {}", e)))?;
    
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut devices = Vec::new();

    // Skip header
    let _ = lines.next_line().await;

    while let Ok(Some(line)) = lines.next_line().await {
        // Format: IP address       HW type     Flags       HW address            Mask     Device
        // 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let ip = parts[0].to_string();
        let mac = parts[3].to_string();
        let _device = parts[5];

        // Filter out incomplete entries and match interface if needed (implied by ping sweep)
        if mac != "00:00:00:00:00:00" {
            devices.push((ip, mac));
        }
    }

    Ok(devices)
}

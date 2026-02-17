//! mDNS-based device discovery
//!
//! Uses Multicast DNS to discover devices and resolve their hostnames.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use mdns_sd::{ServiceDaemon, ServiceEvent};

/// Scan for mDNS services and resolve hostnames
pub fn scan_mdns(timeout: Duration) -> HashMap<String, String> {
    let mut resolved_names = HashMap::new();
    
    // Create a daemon
    let mdns = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to create mDNS daemon: {}", e);
            return resolved_names;
        }
    };

    // Browse for common services
    // Scanning for efficient service types for device discovery
    let services_to_scan = vec![
        "_googlecast._tcp.local.",       // Google devices
        "_airplay._tcp.local.",          // Apple devices (AirPlay)
        "_companion-link._tcp.local.",   // Apple devices (HomeKit/Sidecar)
        "_device-info._tcp.local.",      // General device info
        "_ipp._tcp.local.",              // Printers
        "_http._tcp.local.",             // Web interfaces
        "_smb._tcp.local.",              // Windows/NAS file sharing
        "_rdp._tcp.local.",              // Remote desktop
        "_raop._tcp.local.",             // AirPlay audio (Apple)
        "_sleep-proxy._udp.local.",      // Apple sleep proxy
        "_workstation._tcp.local.",      // Linux/macOS workstations
        "_homekit._tcp.local.",          // HomeKit accessories
        "_hap._tcp.local.",              // HomeKit Accessory Protocol
        "_matter._tcp.local.",           // Matter smart home devices
        "_spotify-connect._tcp.local.",  // Spotify Connect devices
        "_amzn-wplay._tcp.local.",       // Amazon devices
        "_androidtvremote2._tcp.local.", // Android TV
        "_touch-able._tcp.local.",       // iOS Remote app
    ];
    
    // Using a receiver to collect events
    // We browse all services concurrently
    let receiver = mdns.browse("_services._dns-sd._udp.local.").expect("Failed to browse");
    
    // Also explicitly browse specific services as discovery of _services can be unreliable for some devices
    for service in &services_to_scan {
        let _ = mdns.browse(service);
    }
    
    let deadline = Instant::now() + timeout;
    
    while Instant::now() < deadline {
        // Use a short timeout for recv to allow checking deadline
        if let Ok(event) = receiver.recv_timeout(Duration::from_millis(100)) {
            if let ServiceEvent::ServiceResolved(info) = event {
                // Get the "friendly name" part of the service instance name if possible
                let fullname = info.get_fullname();
                // Extract instance name (part before first dot)
                let instance_name = fullname.split('.').next().unwrap_or("").to_string();

                // Get hostname (e.g. "My-iPhone.local.")
                let hostname = info.get_hostname();
                let clean_hostname = hostname.trim_end_matches('.');

                // Check TXT records for friendly name (fn, n, name keys)
                let txt_name: Option<String> = info.get_properties().iter().find_map(|prop| {
                    let key = prop.key();
                    if key == "fn" || key == "n" || key == "name" {
                        let val = prop.val_str();
                        if !val.is_empty() {
                            Some(val.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                });

                // Priority: TXT friendly name > instance name > hostname
                let display_name = if let Some(ref tn) = txt_name {
                    tn.clone()
                } else if !instance_name.is_empty() && instance_name != clean_hostname {
                    instance_name
                } else {
                    clean_hostname.to_string()
                };

                for ip in info.get_addresses() {
                    // Update if we don't have a name or if current name is better (longer/more descriptive)
                    let ip_str = ip.to_string();
                    if let Some(existing) = resolved_names.get(&ip_str) {
                         if display_name.len() > existing.len() {
                             resolved_names.insert(ip_str, display_name.clone());
                         }
                    } else {
                        resolved_names.insert(ip_str, display_name.clone());
                    }
                }
            }
        }
    }
    
    // Stop browsing (daemon drop handles this, but good practice)
    let _ = mdns.stop_browse("_services._dns-sd._udp.local.");
    for service in &services_to_scan {
        let _ = mdns.stop_browse(service);
    }

    resolved_names
}

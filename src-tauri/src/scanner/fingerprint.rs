//! Device fingerprinting and identification

use super::{Device, DeviceType};

/// OUI (Organizationally Unique Identifier) database for vendor lookup
/// Format: First 3 bytes of MAC address -> Vendor name
const OUI_DATABASE: &[(&str, &str)] = &[
    ("00:1A:2B", "Buffalo Inc."),
    ("00:26:AB", "Buffalo Inc."),
    ("AC:22:0B", "Buffalo Inc."),
    ("10:6F:3F", "Buffalo Inc."),
    ("18:C2:BF", "I-O DATA DEVICE, INC."),
    ("00:A0:B0", "I-O DATA DEVICE, INC."),
    ("40:8D:5C", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("50:C7:BF", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("FC:EC:DA", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("A4:77:33", "Google, Inc."),
    ("D4:F5:47", "Google, Inc."),
    ("F4:F5:D8", "Google, Inc."),
    ("44:65:0D", "Amazon Technologies Inc."),
    ("68:54:FD", "Amazon Technologies Inc."),
    ("A0:02:DC", "Amazon Technologies Inc."),
    ("00:17:88", "Philips Lighting BV"),
    ("00:1F:E4", "Sony Corporation"),
    ("BC:30:D9", "Arcadyan Technology Corporation"),
    ("00:90:CC", "Planex Communications Inc."),
    ("00:22:CF", "PLANEX COMMUNICATIONS INC."),
    ("00:1C:B3", "Apple, Inc."),
    ("28:CF:DA", "Apple, Inc."),
    ("3C:06:30", "Apple, Inc."),
    ("D0:03:4B", "Apple, Inc."),
    ("F0:18:98", "Apple, Inc."),
];

/// Router vendor patterns
const ROUTER_VENDORS: &[&str] = &[
    "Buffalo",
    "TP-LINK",
    "Netgear",
    "ASUS",
    "Elecom",
    "NEC",
    "Yamaha",
    "I-O DATA",
    "Planex",
    "Corega",
];

/// Camera vendor patterns
const CAMERA_VENDORS: &[&str] = &[
    "Hikvision",
    "Dahua",
    "Axis",
    "Panasonic",
    "Sony",
    "TP-LINK",
    "Wyze",
    "Ring",
];

/// Smart speaker patterns
const SMART_SPEAKER_VENDORS: &[&str] = &[
    "Amazon",
    "Google",
    "Apple",
    "Sonos",
    "Bose",
];

/// Look up vendor from MAC address
pub fn lookup_vendor(mac: &str) -> Option<String> {
    let prefix = mac.to_uppercase()
        .chars()
        .take(8)
        .collect::<String>();

    for (oui, vendor) in OUI_DATABASE {
        if prefix == *oui {
            return Some(vendor.to_string());
        }
    }

    None
}

/// Identify device type from MAC and vendor
pub fn identify_device_type(_mac: &str, vendor: &Option<String>) -> DeviceType {
    let vendor_str = vendor.as_deref().unwrap_or("");

    // Check for router
    if ROUTER_VENDORS.iter().any(|v| vendor_str.contains(v)) {
        return DeviceType::Router;
    }

    // Check for camera
    if CAMERA_VENDORS.iter().any(|v| vendor_str.contains(v)) {
        return DeviceType::Camera;
    }

    // Check for smart speaker
    if SMART_SPEAKER_VENDORS.iter().any(|v| vendor_str.contains(v)) {
        return DeviceType::SmartSpeaker;
    }

    DeviceType::Unknown
}

/// Identify services running on device
pub async fn identify_services(device: &mut Device) {
    // Check open ports for service identification
    for port in &device.open_ports {
        match port.number {
            554 => {
                // RTSP usually means camera
                if device.device_type == DeviceType::Unknown {
                    device.device_type = DeviceType::Camera;
                }
            }
            1883 | 8883 => {
                // MQTT is common for IoT devices
            }
            631 => {
                // IPP - Printer
                if device.device_type == DeviceType::Unknown {
                    device.device_type = DeviceType::Printer;
                }
            }
            _ => {}
        }
    }
}

/// Check if device is using default credentials
pub async fn check_default_credentials(_device: &Device) -> bool {
    // TODO: Implement default credential checking
    // This would require a database of default credentials per vendor/model
    false
}

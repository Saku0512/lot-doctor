//! Device fingerprinting and identification

use super::{Device, DeviceType};

/// OUI (Organizationally Unique Identifier) database for vendor lookup
/// Format: First 3 bytes of MAC address -> Vendor name
const OUI_DATABASE: &[(&str, &str)] = &[
    // Buffalo
    ("00:1A:2B", "Buffalo Inc."),
    ("00:26:AB", "Buffalo Inc."),
    ("AC:22:0B", "Buffalo Inc."),
    ("10:6F:3F", "Buffalo Inc."),
    // I-O DATA
    ("18:C2:BF", "I-O DATA DEVICE, INC."),
    ("00:A0:B0", "I-O DATA DEVICE, INC."),
    // TP-LINK
    ("40:8D:5C", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("50:C7:BF", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("FC:EC:DA", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("30:B5:C2", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("60:E3:27", "TP-LINK TECHNOLOGIES CO.,LTD."),
    ("B0:4E:26", "TP-LINK TECHNOLOGIES CO.,LTD."),
    // Google
    ("A4:77:33", "Google, Inc."),
    ("D4:F5:47", "Google, Inc."),
    ("F4:F5:D8", "Google, Inc."),
    ("54:60:09", "Google, Inc."),
    ("30:FD:38", "Google, Inc."),
    ("48:D6:D5", "Google, Inc."),
    ("E4:F0:42", "Google, Inc."),
    ("6C:AD:F8", "Google, Inc."),
    // Amazon
    ("44:65:0D", "Amazon Technologies Inc."),
    ("68:54:FD", "Amazon Technologies Inc."),
    ("A0:02:DC", "Amazon Technologies Inc."),
    ("FC:65:DE", "Amazon Technologies Inc."),
    ("40:B4:CD", "Amazon Technologies Inc."),
    ("74:C2:46", "Amazon Technologies Inc."),
    ("84:D6:D0", "Amazon Technologies Inc."),
    ("F0:F0:A4", "Amazon Technologies Inc."),
    // Philips
    ("00:17:88", "Philips Lighting BV"),
    // Arcadyan
    ("BC:30:D9", "Arcadyan Technology Corporation"),
    // Planex
    ("00:90:CC", "Planex Communications Inc."),
    ("00:22:CF", "PLANEX COMMUNICATIONS INC."),
    // Apple
    ("00:1C:B3", "Apple, Inc."),
    ("28:CF:DA", "Apple, Inc."),
    ("3C:06:30", "Apple, Inc."),
    ("D0:03:4B", "Apple, Inc."),
    ("F0:18:98", "Apple, Inc."),
    ("A4:83:E7", "Apple, Inc."),
    ("DC:A4:CA", "Apple, Inc."),
    ("F0:D4:F6", "Apple, Inc."),
    ("A8:66:7F", "Apple, Inc."),
    ("14:7D:DA", "Apple, Inc."),
    ("88:66:A5", "Apple, Inc."),
    ("8C:85:90", "Apple, Inc."),
    ("AC:BC:32", "Apple, Inc."),
    ("C8:69:CD", "Apple, Inc."),
    ("E0:B5:2D", "Apple, Inc."),
    ("F4:5C:89", "Apple, Inc."),
    ("10:DD:B1", "Apple, Inc."),
    ("1C:91:48", "Apple, Inc."),
    ("34:C0:59", "Apple, Inc."),
    ("40:A6:D9", "Apple, Inc."),
    ("48:A1:95", "Apple, Inc."),
    ("54:4E:90", "Apple, Inc."),
    ("60:03:08", "Apple, Inc."),
    ("6C:96:CF", "Apple, Inc."),
    ("70:DE:E2", "Apple, Inc."),
    ("78:7B:8A", "Apple, Inc."),
    ("7C:D1:C3", "Apple, Inc."),
    ("84:FC:FE", "Apple, Inc."),
    ("90:27:E4", "Apple, Inc."),
    ("98:01:A7", "Apple, Inc."),
    ("A0:99:9B", "Apple, Inc."),
    ("A4:B1:97", "Apple, Inc."),
    ("B0:34:95", "Apple, Inc."),
    ("BC:52:B7", "Apple, Inc."),
    ("C0:A5:3E", "Apple, Inc."),
    // Samsung
    ("00:1A:8A", "Samsung Electronics Co.,Ltd"),
    ("00:21:19", "Samsung Electronics Co.,Ltd"),
    ("8C:F5:A3", "Samsung Electronics Co.,Ltd"),
    ("AC:5F:3E", "Samsung Electronics Co.,Ltd"),
    ("C0:97:27", "Samsung Electronics Co.,Ltd"),
    ("5C:3A:45", "Samsung Electronics Co.,Ltd"),
    ("10:D5:42", "Samsung Electronics Co.,Ltd"),
    ("78:47:1D", "Samsung Electronics Co.,Ltd"),
    ("D0:22:BE", "Samsung Electronics Co.,Ltd"),
    ("E4:7C:F9", "Samsung Electronics Co.,Ltd"),
    ("34:14:5F", "Samsung Electronics Co.,Ltd"),
    ("90:18:7C", "Samsung Electronics Co.,Ltd"),
    ("A8:9F:BA", "Samsung Electronics Co.,Ltd"),
    ("B4:3A:28", "Samsung Electronics Co.,Ltd"),
    ("C4:73:1E", "Samsung Electronics Co.,Ltd"),
    ("FC:A8:9A", "Samsung Electronics Co.,Ltd"),
    ("14:49:E0", "Samsung Electronics Co.,Ltd"),
    ("1C:AF:05", "Samsung Electronics Co.,Ltd"),
    ("30:07:4D", "Samsung Electronics Co.,Ltd"),
    ("40:4E:36", "Samsung Electronics Co.,Ltd"),
    ("58:C3:8B", "Samsung Electronics Co.,Ltd"),
    ("6C:C7:EC", "Samsung Electronics Co.,Ltd"),
    ("84:25:DB", "Samsung Electronics Co.,Ltd"),
    ("98:83:89", "Samsung Electronics Co.,Ltd"),
    ("BC:14:EF", "Samsung Electronics Co.,Ltd"),
    ("CC:07:AB", "Samsung Electronics Co.,Ltd"),
    ("E8:E5:D6", "Samsung Electronics Co.,Ltd"),
    ("F8:04:2E", "Samsung Electronics Co.,Ltd"),
    // Xiaomi
    ("28:6C:07", "Xiaomi Communications Co Ltd"),
    ("64:CC:2E", "Xiaomi Communications Co Ltd"),
    ("7C:1D:D9", "Xiaomi Communications Co Ltd"),
    ("0C:1D:AF", "Xiaomi Communications Co Ltd"),
    ("34:80:B3", "Xiaomi Communications Co Ltd"),
    ("50:64:2B", "Xiaomi Communications Co Ltd"),
    ("78:11:DC", "Xiaomi Communications Co Ltd"),
    ("8C:DE:F9", "Xiaomi Communications Co Ltd"),
    ("A4:77:58", "Xiaomi Communications Co Ltd"),
    ("B0:E2:35", "Xiaomi Communications Co Ltd"),
    ("C4:0B:CB", "Xiaomi Communications Co Ltd"),
    ("DC:D8:7D", "Xiaomi Communications Co Ltd"),
    ("F0:B4:29", "Xiaomi Communications Co Ltd"),
    ("18:59:36", "Xiaomi Communications Co Ltd"),
    ("58:44:98", "Xiaomi Communications Co Ltd"),
    // Huawei
    ("00:E0:FC", "Huawei Technologies Co.,Ltd"),
    ("04:F9:38", "Huawei Technologies Co.,Ltd"),
    ("20:F3:A3", "Huawei Technologies Co.,Ltd"),
    ("48:46:FB", "Huawei Technologies Co.,Ltd"),
    ("70:72:3C", "Huawei Technologies Co.,Ltd"),
    ("88:28:B3", "Huawei Technologies Co.,Ltd"),
    ("AC:61:75", "Huawei Technologies Co.,Ltd"),
    ("C8:D1:5E", "Huawei Technologies Co.,Ltd"),
    ("E0:24:7F", "Huawei Technologies Co.,Ltd"),
    ("EC:CB:30", "Huawei Technologies Co.,Ltd"),
    ("14:30:04", "Huawei Technologies Co.,Ltd"),
    ("24:44:27", "Huawei Technologies Co.,Ltd"),
    ("3C:47:11", "Huawei Technologies Co.,Ltd"),
    ("54:A5:1B", "Huawei Technologies Co.,Ltd"),
    ("78:F5:57", "Huawei Technologies Co.,Ltd"),
    // Sony
    ("00:1F:E4", "Sony Corporation"),
    ("00:13:A9", "Sony Corporation"),
    ("00:24:BE", "Sony Corporation"),
    ("04:5D:4B", "Sony Corporation"),
    ("28:3F:69", "Sony Corporation"),
    ("40:B8:37", "Sony Corporation"),
    ("78:84:3C", "Sony Corporation"),
    ("AC:9B:0A", "Sony Corporation"),
    ("B4:52:7E", "Sony Corporation"),
    ("FC:0F:E6", "Sony Corporation"),
    // OPPO
    ("3C:77:E6", "OPPO Digital, Inc."),
    ("54:A0:50", "OPPO Digital, Inc."),
    ("A4:3D:78", "OPPO Digital, Inc."),
    ("CC:2D:83", "OPPO Digital, Inc."),
    ("E8:BB:A8", "OPPO Digital, Inc."),
    ("74:A5:28", "OPPO Digital, Inc."),
    ("90:6C:AC", "OPPO Digital, Inc."),
    ("18:D7:17", "OPPO Digital, Inc."),
    // ASUS
    ("00:1A:92", "ASUSTek COMPUTER INC."),
    ("1C:87:2C", "ASUSTek COMPUTER INC."),
    ("2C:56:DC", "ASUSTek COMPUTER INC."),
    ("54:04:A6", "ASUSTek COMPUTER INC."),
    ("AC:9E:17", "ASUSTek COMPUTER INC."),
    ("D8:50:E6", "ASUSTek COMPUTER INC."),
    // NEC
    ("00:0B:A2", "NEC Corporation"),
    ("00:30:13", "NEC Corporation"),
    ("00:70:4C", "NEC Corporation"),
    // Netgear
    ("00:14:6C", "NETGEAR"),
    ("00:1F:33", "NETGEAR"),
    ("20:E5:2A", "NETGEAR"),
    ("44:94:FC", "NETGEAR"),
    ("6C:B0:CE", "NETGEAR"),
    ("B0:7F:B9", "NETGEAR"),
    ("C4:04:15", "NETGEAR"),
    // Raspberry Pi
    ("B8:27:EB", "Raspberry Pi Foundation"),
    ("DC:A6:32", "Raspberry Pi Foundation"),
    ("E4:5F:01", "Raspberry Pi Foundation"),
    // Espressif (ESP32/ESP8266)
    ("24:0A:C4", "Espressif Inc."),
    ("30:AE:A4", "Espressif Inc."),
    ("A4:CF:12", "Espressif Inc."),
    ("CC:50:E3", "Espressif Inc."),
    ("84:CC:A8", "Espressif Inc."),
    // LG Electronics
    ("00:1C:62", "LG Electronics"),
    ("10:68:3F", "LG Electronics"),
    ("2C:54:CF", "LG Electronics"),
    ("58:A2:B5", "LG Electronics"),
    ("A8:23:FE", "LG Electronics"),
    // Panasonic
    ("00:0E:6B", "Panasonic Corporation"),
    ("00:1B:52", "Panasonic Corporation"),
    ("10:5F:06", "Panasonic Corporation"),
    ("34:FC:EF", "Panasonic Corporation"),
    // Nintendo
    ("00:09:BF", "Nintendo Co.,Ltd"),
    ("00:17:AB", "Nintendo Co.,Ltd"),
    ("00:1E:35", "Nintendo Co.,Ltd"),
    ("00:24:1E", "Nintendo Co.,Ltd"),
    ("34:AF:2C", "Nintendo Co.,Ltd"),
    ("58:BD:A3", "Nintendo Co.,Ltd"),
    ("7C:BB:8A", "Nintendo Co.,Ltd"),
    ("98:B6:E9", "Nintendo Co.,Ltd"),
    ("E8:4E:CE", "Nintendo Co.,Ltd"),
    // Microsoft (Xbox, Surface)
    ("28:18:78", "Microsoft Corporation"),
    ("60:45:BD", "Microsoft Corporation"),
    ("7C:1E:52", "Microsoft Corporation"),
    ("C8:3F:26", "Microsoft Corporation"),
    // Intel (PCs, laptops)
    ("00:1E:64", "Intel Corporate"),
    ("3C:97:0E", "Intel Corporate"),
    ("68:05:CA", "Intel Corporate"),
    ("8C:EC:4B", "Intel Corporate"),
    // Hikvision
    ("C0:56:E3", "Hangzhou Hikvision Digital Technology"),
    ("44:19:B6", "Hangzhou Hikvision Digital Technology"),
    ("54:C4:15", "Hangzhou Hikvision Digital Technology"),
    // Dahua
    ("3C:EF:8C", "Zhejiang Dahua Technology Co., Ltd."),
    ("A0:BD:CD", "Zhejiang Dahua Technology Co., Ltd."),
    // Sonos
    ("00:0E:58", "Sonos, Inc."),
    ("34:7E:5C", "Sonos, Inc."),
    ("48:A6:B8", "Sonos, Inc."),
    ("78:28:CA", "Sonos, Inc."),
    // Bose
    ("04:52:C7", "Bose Corporation"),
    ("08:DF:1F", "Bose Corporation"),
    // Elecom
    ("00:1D:62", "ELECOM CO.,LTD."),
    ("74:03:BD", "ELECOM CO.,LTD."),
    ("C8:2E:47", "ELECOM CO.,LTD."),
    // OnePlus
    ("94:65:2D", "OnePlus Technology (Shenzhen) Co., Ltd"),
    ("C0:EE:40", "OnePlus Technology (Shenzhen) Co., Ltd"),
    // Motorola
    ("00:04:56", "Motorola Mobility LLC"),
    ("68:C4:4D", "Motorola Mobility LLC"),
    ("E8:65:D4", "Motorola Mobility LLC"),
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
    "Arcadyan",
    "NETGEAR",
];

/// Camera vendor patterns
const CAMERA_VENDORS: &[&str] = &[
    "Hikvision",
    "Dahua",
    "Axis",
    "Panasonic",
    "Wyze",
    "Ring",
];

/// Smart speaker patterns
const SMART_SPEAKER_VENDORS: &[&str] = &[
    "Sonos",
    "Bose",
];

/// Smartphone vendor patterns
const SMARTPHONE_VENDORS: &[&str] = &[
    "Samsung",
    "Xiaomi",
    "Huawei",
    "OPPO",
    "OnePlus",
    "Motorola",
];

/// Smart TV vendor patterns
const SMART_TV_VENDORS: &[&str] = &[
    "LG Electronics",
];

/// Gaming console vendor patterns
const GAMING_VENDORS: &[&str] = &[
    "Nintendo",
    "Microsoft",
];

/// IoT / Embedded device patterns
const IOT_VENDORS: &[&str] = &[
    "Raspberry Pi",
    "Espressif",
];

/// Smartphone name patterns (case-insensitive matching)
const SMARTPHONE_NAME_PATTERNS: &[&str] = &[
    "iphone", "ipad", "galaxy", "pixel", "android",
    "redmi", "xperia", "huawei", "oppo", "oneplus",
    "aquos", "arrows", "motorola", "moto ",
    "sm-", "gt-", "sch-", "sgh-",
];

/// Smart TV name patterns
const TV_NAME_PATTERNS: &[&str] = &[
    "tv", "テレビ", "bravia", "viera", "regza", "aquos",
];

/// Computer name patterns
const COMPUTER_NAME_PATTERNS: &[&str] = &[
    "macbook", "imac", "mac-mini", "desktop", "laptop",
    "surface", "thinkpad", "dell", "hp-", "lenovo",
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

/// Identify device type from MAC, vendor, and resolved device name
pub fn identify_device_type(_mac: &str, vendor: &Option<String>, name: &Option<String>) -> DeviceType {
    // First, check name-based patterns (most reliable when a name is available)
    if let Some(ref n) = name {
        let lower = n.to_lowercase();

        // Check smartphone patterns
        if SMARTPHONE_NAME_PATTERNS.iter().any(|p| lower.contains(p)) {
            return DeviceType::Smartphone;
        }

        // Check computer patterns
        if COMPUTER_NAME_PATTERNS.iter().any(|p| lower.contains(p)) {
            return DeviceType::Computer;
        }

        // Check TV patterns (but skip if it also matches smartphone patterns like "AQUOS")
        if TV_NAME_PATTERNS.iter().any(|p| lower.contains(p)) {
            return DeviceType::SmartTv;
        }
    }

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

    // Check for smartphone vendors
    if SMARTPHONE_VENDORS.iter().any(|v| vendor_str.contains(v)) {
        return DeviceType::Smartphone;
    }

    // Check for smart TV vendors
    if SMART_TV_VENDORS.iter().any(|v| vendor_str.contains(v)) {
        return DeviceType::SmartTv;
    }

    // Check for gaming consoles
    if GAMING_VENDORS.iter().any(|v| vendor_str.contains(v)) {
        return DeviceType::SmartPlug; // Reusing as gaming doesn't have own type
    }

    // Apple devices: need name to distinguish iPhone/Mac/Apple TV
    if vendor_str.contains("Apple") {
        // Default Apple to smartphone (most common on home networks)
        return DeviceType::Smartphone;
    }

    // Google devices: could be Pixel phone or Nest/Chromecast
    if vendor_str.contains("Google") {
        return DeviceType::SmartSpeaker;
    }

    // Amazon devices: usually Echo speakers
    if vendor_str.contains("Amazon") {
        return DeviceType::SmartSpeaker;
    }

    // Sony: could be TV, camera, or phone
    if vendor_str.contains("Sony") {
        return DeviceType::SmartTv;
    }

    // IoT devices
    if IOT_VENDORS.iter().any(|v| vendor_str.contains(v)) {
        return DeviceType::SmartPlug;
    }

    // Intel usually means PC/laptop
    if vendor_str.contains("Intel") {
        return DeviceType::Computer;
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

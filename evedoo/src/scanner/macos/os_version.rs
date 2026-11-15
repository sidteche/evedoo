// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! macOS OS version scanner.
//!
//! Emits the running macOS operating system itself as one inventory entry so it correlates
//! against `apple:macos`, `apple:mac_os_x`, `apple:mac_os`, and `apple:darwin` CPE identities.
//!
//! Reads identity from `/System/Library/CoreServices/SystemVersion.plist` (or ServerVersion.plist)
//! in pure Rust.

use std::fs;
use std::path::PathBuf;

use tracing::{debug, warn};

use crate::models::{Architecture, DetectedSoftware};

/// macOS system version metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemVersionInfo {
    pub product_name: String,
    pub product_version: String,
    pub product_build_version: Option<String>,
    pub product_user_visible_version: Option<String>,
}

/// Scanner for macOS OS Version.
pub struct MacOsVersionScanner {
    custom_path: Option<PathBuf>,
}

impl MacOsVersionScanner {
    pub fn new() -> Self {
        Self { custom_path: None }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            custom_path: Some(path),
        }
    }

    /// Read OS version from `SystemVersion.plist`.
    pub fn scan(&self) -> Option<DetectedSoftware> {
        let path = if let Some(ref p) = self.custom_path {
            p.clone()
        } else {
            PathBuf::from("/System/Library/CoreServices/SystemVersion.plist")
        };

        if !path.is_file() {
            debug!("macOS SystemVersion.plist not found at {}", path.display());
            return None;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read macOS SystemVersion.plist: {}", e);
                return None;
            }
        };

        let info = parse_system_version_plist(&content)?;
        debug!("macOS OS identity: {} ({})", info.product_name, info.product_version);

        let marketing_name = macos_marketing_name(&info.product_version);
        let display_name = if let Some(m) = marketing_name {
            format!("macOS {} {}", m, info.product_version)
        } else {
            format!("macOS {}", info.product_version)
        };

        Some(DetectedSoftware {
            name: display_name,
            version: Some(info.product_version.clone()),
            publisher: Some("Apple Inc.".to_string()),
            install_location: Some("/System/Library/CoreServices".to_string()),
            install_date: None,
            registry_key: format!("os://macos/{}", info.product_version),
            architecture: Architecture::Unknown,
        })
    }
}

impl Default for MacOsVersionScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse `SystemVersion.plist` content into `SystemVersionInfo`.
pub fn parse_system_version_plist(content: &str) -> Option<SystemVersionInfo> {
    let extract_key = |key_name: &str| -> Option<String> {
        let pattern = format!("<key>{}</key>", key_name);
        let idx = content.find(&pattern)?;
        let rest = &content[idx + pattern.len()..];
        let str_start = rest.find("<string>")? + 8;
        let str_end = rest[str_start..].find("</string>")? + str_start;
        Some(rest[str_start..str_end].trim().to_string())
    };

    let product_name = extract_key("ProductName").unwrap_or_else(|| "macOS".to_string());
    let product_version = extract_key("ProductVersion")?;
    let product_build_version = extract_key("ProductBuildVersion");
    let product_user_visible_version = extract_key("ProductUserVisibleVersion");

    Some(SystemVersionInfo {
        product_name,
        product_version,
        product_build_version,
        product_user_visible_version,
    })
}

/// Map macOS major version to marketing code name.
fn macos_marketing_name(version: &str) -> Option<&'static str> {
    let major = version.split('.').next()?.parse::<u32>().ok()?;
    match major {
        15 => Some("Sequoia"),
        14 => Some("Sonoma"),
        13 => Some("Ventura"),
        12 => Some("Monterey"),
        11 => Some("Big Sur"),
        10 => {
            let minor = version.split('.').nth(1)?.parse::<u32>().ok()?;
            match minor {
                15 => Some("Catalina"),
                14 => Some("Mojave"),
                13 => Some("High Sierra"),
                12 => Some("Sierra"),
                11 => Some("El Capitan"),
                10 => Some("Yosemite"),
                9 => Some("Mavericks"),
                8 => Some("Mountain Lion"),
                7 => Some("Lion"),
                6 => Some("Snow Leopard"),
                5 => Some("Leopard"),
                4 => Some("Tiger"),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM_VERSION_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ProductBuildVersion</key>
    <string>24B91</string>
    <key>ProductCopyright</key>
    <string>1983-2024 Apple Inc.</string>
    <key>ProductName</key>
    <string>macOS</string>
    <key>ProductUserVisibleVersion</key>
    <string>15.1</string>
    <key>ProductVersion</key>
    <string>15.1</string>
    <key>iOSSupportVersion</key>
    <string>18.1</string>
</dict>
</plist>"#;

    #[test]
    fn parses_system_version_plist() {
        let info = parse_system_version_plist(SYSTEM_VERSION_PLIST).unwrap();
        assert_eq!(info.product_name, "macOS");
        assert_eq!(info.product_version, "15.1");
        assert_eq!(info.product_build_version.as_deref(), Some("24B91"));
        assert_eq!(info.product_user_visible_version.as_deref(), Some("15.1"));
    }

    #[test]
    fn maps_marketing_names() {
        assert_eq!(macos_marketing_name("15.1"), Some("Sequoia"));
        assert_eq!(macos_marketing_name("14.5"), Some("Sonoma"));
        assert_eq!(macos_marketing_name("13.6.7"), Some("Ventura"));
        assert_eq!(macos_marketing_name("12.7.4"), Some("Monterey"));
        assert_eq!(macos_marketing_name("11.7.10"), Some("Big Sur"));
        assert_eq!(macos_marketing_name("10.15.7"), Some("Catalina"));
    }

    #[test]
    fn scans_mock_system_version_file() {
        let tmp = std::env::temp_dir().join("evedoo_os_version_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let plist_path = tmp.join("SystemVersion.plist");
        fs::write(&plist_path, SYSTEM_VERSION_PLIST).unwrap();

        let scanner = MacOsVersionScanner::with_path(plist_path);
        let sw = scanner.scan().unwrap();

        assert_eq!(sw.name, "macOS Sequoia 15.1");
        assert_eq!(sw.version.as_deref(), Some("15.1"));
        assert_eq!(sw.registry_key, "os://macos/15.1");
        assert_eq!(sw.publisher.as_deref(), Some("Apple Inc."));

        let _ = fs::remove_dir_all(&tmp);
    }
}

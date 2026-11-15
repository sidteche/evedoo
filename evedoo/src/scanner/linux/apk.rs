// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Alpine Linux `apk` installed packages database scanner.
//!
//! Parses `/lib/apk/db/installed` (or `/etc/apk/installed`) to inventory
//! installed Alpine packages.
//!
//! Emits `DetectedSoftware` entries with `apk://{package}` registry keys.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

#[allow(dead_code)]
pub struct ApkScanner {
    db_paths: Vec<PathBuf>,
}

#[allow(dead_code)]
impl ApkScanner {
    pub fn new() -> Self {
        Self {
            db_paths: vec![
                PathBuf::from("/lib/apk/db/installed"),
                PathBuf::from("/var/lib/apk/db/installed"),
            ],
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            db_paths: vec![path],
        }
    }

    /// Scan installed packages from a custom rootfs path.
    pub fn scan_rootfs(root: &std::path::Path) -> Vec<DetectedSoftware> {
        let scanner = Self {
            db_paths: vec![
                root.join("lib/apk/db/installed"),
                root.join("var/lib/apk/db/installed"),
            ],
        };
        scanner.scan()
    }

    /// Scan installed packages from Alpine apk database.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        for path in &self.db_paths {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(path) {
                    debug!("Parsing Alpine apk database at {:?}", path);
                    return parse_apk_installed(&content);
                }
            }
        }

        Vec::new()
    }
}

impl Default for ApkScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure Rust parser for Alpine `/lib/apk/db/installed`.
pub fn parse_apk_installed(content: &str) -> Vec<DetectedSoftware> {
    let mut results = Vec::new();
    let mut current_fields: HashMap<char, String> = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(pkg) = process_apk_record(&current_fields) {
                results.push(pkg);
            }
            current_fields.clear();
            continue;
        }

        let mut chars = trimmed.chars();
        if let (Some(key), Some(':')) = (chars.next(), chars.next()) {
            let val = chars.as_str().trim().to_string();
            current_fields.insert(key, val);
        }
    }

    if let Some(pkg) = process_apk_record(&current_fields) {
        results.push(pkg);
    }

    results
}

fn process_apk_record(fields: &HashMap<char, String>) -> Option<DetectedSoftware> {
    let package = fields.get(&'P')?.trim();
    if package.is_empty() {
        return None;
    }

    let version = fields.get(&'V').map(|v| v.trim().to_string());
    let arch_str = fields.get(&'A').map(|a| a.trim().to_ascii_lowercase());
    let architecture = match arch_str.as_deref() {
        Some("x86_64") => Architecture::X64,
        Some("x86") => Architecture::X86,
        _ => Architecture::Unknown,
    };

    let publisher = fields
        .get(&'m')
        .map(|m| m.trim().to_string())
        .or_else(|| Some("apk".to_string()));

    Some(DetectedSoftware {
        name: package.to_string(),
        version,
        publisher,
        install_location: None,
        install_date: None,
        registry_key: format!("apk://{}", package),
        architecture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const APK_SAMPLE: &str = r#"
P:musl
V:1.2.4-r2
T:the musl c-library
U:https://musl.libc.org/
A:x86_64
S:624388
I:634880
m:Timo Teras <timo.teras@iki.fi>
t:1683880000
c:4a3b2c1d

P:busybox
V:1.36.1-r2
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
A:x86_64
S:502016
I:966656
m:Sören Tempel <soeren+alpine@soeren-tempel.net>
t:1685000000
c:5b6c7d8e
"#;

    #[test]
    fn parses_apk_installed_entries() {
        let pkgs = parse_apk_installed(APK_SAMPLE);
        assert_eq!(pkgs.len(), 2);

        let musl = pkgs.iter().find(|p| p.name == "musl").unwrap();
        assert_eq!(musl.version.as_deref(), Some("1.2.4-r2"));
        assert_eq!(musl.registry_key, "apk://musl");
        assert_eq!(musl.architecture, Architecture::X64);
        assert!(musl.publisher.as_ref().unwrap().contains("Timo Teras"));

        let busybox = pkgs.iter().find(|p| p.name == "busybox").unwrap();
        assert_eq!(busybox.version.as_deref(), Some("1.36.1-r2"));
        assert_eq!(busybox.registry_key, "apk://busybox");
    }

    #[test]
    fn handles_empty_apk_db() {
        let pkgs = parse_apk_installed("");
        assert!(pkgs.is_empty());
    }
}

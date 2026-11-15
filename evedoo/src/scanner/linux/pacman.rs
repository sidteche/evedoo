// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Arch Linux `pacman` database scanner.
//!
//! Scans package descriptors in `/var/lib/pacman/local/*/desc`.
//! Emits `DetectedSoftware` entries with `pacman://{package}` registry keys.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

#[allow(dead_code)]
pub struct PacmanScanner {
    local_db_dir: PathBuf,
}

#[allow(dead_code)]
impl PacmanScanner {
    pub fn new() -> Self {
        Self {
            local_db_dir: PathBuf::from("/var/lib/pacman/local"),
        }
    }

    pub fn with_dir(dir: PathBuf) -> Self {
        Self { local_db_dir: dir }
    }

    /// Scan installed pacman packages from a custom rootfs path.
    pub fn scan_rootfs(root: &std::path::Path) -> Vec<DetectedSoftware> {
        let scanner = Self::with_dir(root.join("var/lib/pacman/local"));
        scanner.scan()
    }

    /// Scan installed pacman packages in `/var/lib/pacman/local/*/desc`.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        if !self.local_db_dir.exists() {
            debug!("pacman local directory not found at {:?}", self.local_db_dir);
            return Vec::new();
        }

        parse_pacman_local_dir(&self.local_db_dir)
    }
}

impl Default for PacmanScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Walk all subdirectory `desc` files in `local_dir`.
pub fn parse_pacman_local_dir(local_dir: &Path) -> Vec<DetectedSoftware> {
    let mut results = Vec::new();

    let entries = match fs::read_dir(local_dir) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let desc_file = path.join("desc");
            if desc_file.exists() {
                if let Ok(content) = fs::read_to_string(&desc_file) {
                    if let Some(pkg) = parse_pacman_desc(&content) {
                        results.push(pkg);
                    }
                }
            }
        }
    }

    results
}

/// Pure Rust parser for an Arch Linux pacman `desc` file.
pub fn parse_pacman_desc(content: &str) -> Option<DetectedSoftware> {
    let mut sections: HashMap<String, String> = HashMap::new();
    let mut current_tag: Option<String> = None;
    let mut current_val = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('%') && trimmed.ends_with('%') && trimmed.len() > 2 {
            if let Some(tag) = current_tag.take() {
                sections.insert(tag, current_val.trim().to_string());
                current_val.clear();
            }
            let tag_name = &trimmed[1..trimmed.len() - 1];
            current_tag = Some(tag_name.to_string());
        } else if current_tag.is_some() && !trimmed.is_empty() {
            if !current_val.is_empty() {
                current_val.push(' ');
            }
            current_val.push_str(trimmed);
        }
    }

    if let Some(tag) = current_tag {
        sections.insert(tag, current_val.trim().to_string());
    }

    let name = sections.get("NAME")?.trim();
    if name.is_empty() {
        return None;
    }

    let version = sections.get("VERSION").map(|v| v.trim().to_string());
    let arch_str = sections.get("ARCH").map(|a| a.trim().to_ascii_lowercase());
    let architecture = match arch_str.as_deref() {
        Some("x86_64") => Architecture::X64,
        Some("i686" | "i386") => Architecture::X86,
        _ => Architecture::Unknown,
    };

    let publisher = sections
        .get("PACKAGER")
        .map(|p| p.trim().to_string())
        .or_else(|| Some("pacman".to_string()));

    Some(DetectedSoftware {
        name: name.to_string(),
        version,
        publisher,
        install_location: None,
        install_date: None,
        registry_key: format!("pacman://{}", name),
        architecture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACMAN_DESC_SAMPLE: &str = r#"
%NAME%
openssl

%VERSION%
3.0.7-1

%BASE%
openssl

%DESC%
The Open Source toolkit for Secure Sockets Layer and Transport Layer Security

%URL%
https://www.openssl.org

%ARCH%
x86_64

%BUILDDATE%
1667380000

%INSTALLDATE%
1668000000

%PACKAGER%
Arch Linux Packager <packager@archlinux.org>

%SIZE%
8400000
"#;

    #[test]
    fn parses_pacman_desc() {
        let pkg = parse_pacman_desc(PACMAN_DESC_SAMPLE).expect("should parse desc");
        assert_eq!(pkg.name, "openssl");
        assert_eq!(pkg.version.as_deref(), Some("3.0.7-1"));
        assert_eq!(pkg.registry_key, "pacman://openssl");
        assert_eq!(pkg.architecture, Architecture::X64);
        assert!(pkg.publisher.as_ref().unwrap().contains("Arch Linux Packager"));
    }

    #[test]
    fn handles_empty_or_malformed_desc() {
        assert!(parse_pacman_desc("").is_none());
        assert!(parse_pacman_desc("%VERSION%\n1.0\n").is_none());
    }
}

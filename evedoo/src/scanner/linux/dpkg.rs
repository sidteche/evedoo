// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Debian `dpkg` status database scanner.
//!
//! Parses `/var/lib/dpkg/status` to inventory installed packages on Debian,
//! Ubuntu, and derivative distributions.
//!
//! Emits `DetectedSoftware` entries with `dpkg://{package}` registry keys.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

#[allow(dead_code)]
pub struct DpkgScanner {
    status_path: PathBuf,
}

#[allow(dead_code)]
impl DpkgScanner {
    pub fn new() -> Self {
        Self {
            status_path: PathBuf::from("/var/lib/dpkg/status"),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { status_path: path }
    }

    /// Scan installed dpkg packages from a custom rootfs path.
    pub fn scan_rootfs(root: &std::path::Path) -> Vec<DetectedSoftware> {
        let scanner = Self::with_path(root.join("var/lib/dpkg/status"));
        scanner.scan()
    }

    /// Scan installed dpkg packages from `/var/lib/dpkg/status`.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        if !self.status_path.exists() {
            debug!("dpkg status file not found at {:?}", self.status_path);
            return Vec::new();
        }

        let content = match fs::read_to_string(&self.status_path) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to read dpkg status file {:?}: {}", self.status_path, e);
                return Vec::new();
            }
        };

        parse_dpkg_status(&content)
    }
}

impl Default for DpkgScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure Rust parser for Debian `/var/lib/dpkg/status` RFC822-style content.
pub fn parse_dpkg_status(content: &str) -> Vec<DetectedSoftware> {
    let mut results = Vec::new();

    // Blocks are separated by blank lines
    let mut current_fields: HashMap<String, String> = HashMap::new();
    let mut last_key: Option<String> = None;

    for line in content.lines() {
        let trimmed_end = line.trim_end();

        if trimmed_end.is_empty() {
            if let Some(pkg) = process_dpkg_block(&current_fields) {
                results.push(pkg);
            }
            current_fields.clear();
            last_key = None;
            continue;
        }

        // Multiline field continuation
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(ref k) = last_key {
                if let Some(val) = current_fields.get_mut(k) {
                    val.push('\n');
                    val.push_str(line.trim());
                }
            }
            continue;
        }

        // Header field: "Key: Value"
        if let Some((key, val)) = line.split_once(':') {
            let k = key.trim().to_ascii_lowercase();
            let v = val.trim().to_string();
            current_fields.insert(k.clone(), v);
            last_key = Some(k);
        }
    }

    // Trailing block
    if let Some(pkg) = process_dpkg_block(&current_fields) {
        results.push(pkg);
    }

    results
}

fn process_dpkg_block(fields: &HashMap<String, String>) -> Option<DetectedSoftware> {
    let package = fields.get("package")?.trim();
    if package.is_empty() {
        return None;
    }

    // Status: e.g. "install ok installed", "hold ok installed"
    // Must contain "installed" and NOT contain "deinstall", "purge", "not-installed", "config-files"
    let status = fields.get("status")?.to_ascii_lowercase();
    let status_parts: Vec<&str> = status.split_whitespace().collect();
    let is_installed = status_parts.contains(&"installed")
        && !status_parts.iter().any(|&p| p == "deinstall" || p == "purge" || p == "not-installed" || p == "config-files");

    if !is_installed {
        return None;
    }

    let version = fields.get("version").map(|v| v.trim().to_string());
    let arch_str = fields.get("architecture").map(|a| a.trim().to_ascii_lowercase());
    let architecture = match arch_str.as_deref() {
        Some("amd64" | "x86_64") => Architecture::X64,
        Some("i386" | "i686") => Architecture::X86,
        _ => Architecture::Unknown,
    };

    let publisher = fields
        .get("maintainer")
        .or_else(|| fields.get("source"))
        .map(|s| s.trim().to_string())
        .or_else(|| Some("dpkg".to_string()));

    Some(DetectedSoftware {
        name: package.to_string(),
        version,
        publisher,
        install_location: None,
        install_date: None,
        registry_key: format!("dpkg://{}", package),
        architecture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DPKG_SAMPLE: &str = r#"
Package: libssl3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 5120
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit - shared libraries
 This package is part of the OpenSSL project's implementation of the SSL
 and TLS cryptographic protocols for secure communication over the Internet.

Package: nginx
Status: deinstall ok config-files
Priority: optional
Section: httpd
Installed-Size: 1024
Maintainer: Debian Nginx Team <pkg-nginx-maintainers@alioth-lists.debian.net>
Architecture: amd64
Version: 1.22.1-9

Package: curl
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 420
Maintainer: Alessandro Ghedini <ghedo@debian.org>
Architecture: i386
Version: 7.88.1-10+deb12u5

Package: uninstalled-pkg
Status: purge ok not-installed
Architecture: amd64
Version: 1.0.0
"#;

    #[test]
    fn parses_installed_packages_only() {
        let pkgs = parse_dpkg_status(DPKG_SAMPLE);
        assert_eq!(pkgs.len(), 2);

        let libssl = pkgs.iter().find(|p| p.name == "libssl3").unwrap();
        assert_eq!(libssl.version.as_deref(), Some("3.0.11-1~deb12u2"));
        assert_eq!(libssl.registry_key, "dpkg://libssl3");
        assert_eq!(libssl.architecture, Architecture::X64);
        assert!(libssl.publisher.as_ref().unwrap().contains("Debian OpenSSL Team"));

        let curl = pkgs.iter().find(|p| p.name == "curl").unwrap();
        assert_eq!(curl.version.as_deref(), Some("7.88.1-10+deb12u5"));
        assert_eq!(curl.registry_key, "dpkg://curl");
        assert_eq!(curl.architecture, Architecture::X86);
    }

    #[test]
    fn ignores_deinstalled_and_purged_packages() {
        let pkgs = parse_dpkg_status(DPKG_SAMPLE);
        assert!(!pkgs.iter().any(|p| p.name == "nginx"));
        assert!(!pkgs.iter().any(|p| p.name == "uninstalled-pkg"));
    }

    #[test]
    fn scanner_handles_nonexistent_file() {
        let scanner = DpkgScanner::with_path(PathBuf::from("/nonexistent/dpkg/status"));
        let pkgs = scanner.scan();
        assert!(pkgs.is_empty());
    }
}

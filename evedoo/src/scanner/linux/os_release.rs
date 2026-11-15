// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Linux OS release scanner (`/etc/os-release`).
//!
//! Parses `/etc/os-release` (and `/usr/lib/os-release`) to inventory the host
//! Linux distribution identity.
//!
//! Emits a `DetectedSoftware` entry with `os://linux/{id}` registry key.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

#[allow(dead_code)]
pub struct OsReleaseScanner {
    paths: Vec<PathBuf>,
}

#[allow(dead_code)]
impl OsReleaseScanner {
    pub fn new() -> Self {
        Self {
            paths: vec![
                PathBuf::from("/etc/os-release"),
                PathBuf::from("/usr/lib/os-release"),
            ],
        }
    }

    pub fn with_paths(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }

    /// Scan Linux OS release information from a custom rootfs path.
    pub fn scan_rootfs(root: &std::path::Path) -> Option<DetectedSoftware> {
        let scanner = Self::with_paths(vec![
            root.join("etc/os-release"),
            root.join("usr/lib/os-release"),
        ]);
        scanner.scan()
    }

    /// Scan Linux OS release information.
    pub fn scan(&self) -> Option<DetectedSoftware> {
        for path in &self.paths {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(path) {
                    debug!("Parsing Linux os-release at {:?}", path);
                    if let Some(sw) = parse_os_release(&content) {
                        return Some(sw);
                    }
                }
            }
        }
        None
    }
}

impl Default for OsReleaseScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure Rust parser for `/etc/os-release` or `/usr/lib/os-release` content.
pub fn parse_os_release(content: &str) -> Option<DetectedSoftware> {
    let mut fields: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, val)) = trimmed.split_once('=') {
            let k = key.trim().to_uppercase();
            let v = unquote_os_release_value(val.trim());
            fields.insert(k, v);
        }
    }

    let id = fields.get("ID").map(|s| s.to_ascii_lowercase())?;
    if id.is_empty() {
        return None;
    }

    let name = fields
        .get("PRETTY_NAME")
        .or_else(|| fields.get("NAME"))
        .cloned()
        .unwrap_or_else(|| id.clone());

    let version = fields
        .get("VERSION_ID")
        .or_else(|| fields.get("VERSION"))
        .cloned();

    let publisher = fields.get("NAME").cloned().or_else(|| Some("Linux".to_string()));

    let architecture = if cfg!(target_arch = "x86_64") {
        Architecture::X64
    } else if cfg!(target_arch = "x86") {
        Architecture::X86
    } else {
        Architecture::Unknown
    };

    Some(DetectedSoftware {
        name,
        version,
        publisher,
        install_location: None,
        install_date: None,
        registry_key: format!("os://linux/{}", id),
        architecture,
    })
}

fn unquote_os_release_value(val: &str) -> String {
    let s = val.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_OS_RELEASE: &str = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"#;

    const RHEL_OS_RELEASE: &str = r#"
NAME="Red Hat Enterprise Linux"
VERSION="9.3 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.3"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"
"#;

    const ALPINE_OS_RELEASE: &str = r#"
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.1
PRETTY_NAME="Alpine Linux v3.19"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
"#;

    #[test]
    fn parses_ubuntu_os_release() {
        let sw = parse_os_release(UBUNTU_OS_RELEASE).expect("should parse ubuntu");
        assert_eq!(sw.name, "Ubuntu 22.04.3 LTS");
        assert_eq!(sw.version.as_deref(), Some("22.04"));
        assert_eq!(sw.registry_key, "os://linux/ubuntu");
        assert_eq!(sw.publisher.as_deref(), Some("Ubuntu"));
    }

    #[test]
    fn parses_rhel_os_release() {
        let sw = parse_os_release(RHEL_OS_RELEASE).expect("should parse rhel");
        assert_eq!(sw.name, "Red Hat Enterprise Linux 9.3 (Plow)");
        assert_eq!(sw.version.as_deref(), Some("9.3"));
        assert_eq!(sw.registry_key, "os://linux/rhel");
    }

    #[test]
    fn parses_alpine_os_release() {
        let sw = parse_os_release(ALPINE_OS_RELEASE).expect("should parse alpine");
        assert_eq!(sw.name, "Alpine Linux v3.19");
        assert_eq!(sw.version.as_deref(), Some("3.19.1"));
        assert_eq!(sw.registry_key, "os://linux/alpine");
    }
}

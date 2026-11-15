//! Windows OS version scanner.
//!
//! Emits the running OS itself as one inventory entry so it correlates
//! against `microsoft:windows_10_*` / `windows_11_*` / `windows_server_*`
//! CPE identities — the single largest CVE population in NVD. The full
//! build string (`10.0.<build>.<UBR>`) is the version, so range checks
//! against `version_end_excluding` (the fixed build of a cumulative
//! update) work with the existing structured `Version` comparison: a
//! fully patched machine produces no findings, a stale one shows exactly
//! the CVEs its missing updates fix.
//!
//! Identity comes from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
//! `ProductName` still reports "Windows 10" on Windows 11 (a documented
//! compatibility quirk), so the 10-vs-11 split uses the build number
//! (>= 22000 → Windows 11). Release comes from `DisplayVersion` ("25H2"),
//! falling back to the older `ReleaseId` ("1909").
//!
//! SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
use tracing::{debug, warn};
#[cfg(target_os = "windows")]
use winreg::enums::HKEY_LOCAL_MACHINE;
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[cfg(target_os = "windows")]
use crate::models::Architecture;
use crate::models::DetectedSoftware;

pub struct OsVersionScanner;

impl OsVersionScanner {
    pub fn new() -> Self {
        OsVersionScanner
    }

    /// Read the OS identity from the registry. Returns `None` on non-Windows.
    #[cfg(not(target_os = "windows"))]
    pub fn scan(&self) -> Option<DetectedSoftware> {
        None
    }

    /// Read the OS identity from the registry. Returns `None` (with a
    /// warning) if the CurrentVersion key is unreadable.
    #[cfg(target_os = "windows")]
    pub fn scan(&self) -> Option<DetectedSoftware> {
        let key = match RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        {
            Ok(k) => k,
            Err(e) => {
                warn!("OS version scan failed to open CurrentVersion key: {}", e);
                return None;
            }
        };

        let product_name: String = key.get_value("ProductName").unwrap_or_default();
        let build: u32 = key
            .get_value::<String, _>("CurrentBuildNumber")
            .ok()
            .and_then(|s| s.parse().ok())?;
        let ubr: u32 = key.get_value("UBR").unwrap_or(0u32);
        let display_version: String = key
            .get_value("DisplayVersion")
            .or_else(|_| key.get_value("ReleaseId"))
            .unwrap_or_default();

        let name = windows_display_name(&product_name, build, &display_version);
        let version = format!("10.0.{}.{}", build, ubr);
        debug!("OS identity: {} ({})", name, version);

        Some(DetectedSoftware {
            name,
            version: Some(version),
            publisher: Some("Microsoft Corporation".to_string()),
            install_location: None,
            install_date: None,
            registry_key: format!("os://windows/{}.{}", build, ubr),
            architecture: Architecture::Unknown,
        })
    }
}

impl Default for OsVersionScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Assemble the display name that maps onto the release-specific curated
/// CPE entry ("Windows 11 25H2" → `microsoft:windows_11_25h2`).
#[allow(dead_code)]
fn windows_display_name(product_name: &str, build: u32, display_version: &str) -> String {
    // Server editions keep their marketing name ("Windows Server 2022"),
    // which already matches the windows_server_* curated aliases.
    if product_name.contains("Server") {
        return product_name
            .split_whitespace()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
    }

    let family = if build >= 22000 { "Windows 11" } else { "Windows 10" };
    if display_version.is_empty() {
        family.to_string()
    } else {
        format!("{} {}", family, display_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_11_detected_by_build_despite_product_name_lie() {
        // Windows 11 registry still says "Windows 10 Home" in ProductName.
        assert_eq!(
            windows_display_name("Windows 10 Home", 26200, "25H2"),
            "Windows 11 25H2"
        );
        assert_eq!(
            windows_display_name("Windows 10 Pro", 22631, "23H2"),
            "Windows 11 23H2"
        );
    }

    #[test]
    fn windows_10_stays_windows_10() {
        assert_eq!(
            windows_display_name("Windows 10 Home", 19045, "22H2"),
            "Windows 10 22H2"
        );
        // Build 21996 is the last Windows 10 range.
        assert_eq!(
            windows_display_name("Windows 10 Pro", 21996, "21H2"),
            "Windows 10 21H2"
        );
    }

    #[test]
    fn server_uses_marketing_name() {
        assert_eq!(
            windows_display_name("Windows Server 2022 Datacenter", 20348, "21H2"),
            "Windows Server 2022"
        );
        assert_eq!(
            windows_display_name("Windows Server 2019 Standard", 17763, "1809"),
            "Windows Server 2019"
        );
    }

    #[test]
    fn missing_display_version_falls_back_to_family() {
        assert_eq!(windows_display_name("Windows 10 Pro", 19045, ""), "Windows 10");
    }

    #[test]
    fn scan_does_not_panic() {
        let _ = OsVersionScanner::new().scan();
    }
}

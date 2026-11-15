//! Windows Registry scanner for detecting installed software.
//!
//! SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
use std::collections::HashSet;

#[cfg(target_os = "windows")]
use tracing::{debug, warn};
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

use crate::error::Result;
#[cfg(target_os = "windows")]
use crate::error::ScanError;
#[cfg(target_os = "windows")]
use crate::models::Architecture;
use crate::models::DetectedSoftware;

/// Registry paths for installed software
#[cfg(target_os = "windows")]
const UNINSTALL_PATHS: &[(&str, Architecture)] = &[
    // 64-bit applications on 64-bit Windows
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        Architecture::X64,
    ),
    // 32-bit applications on 64-bit Windows (WOW64)
    (
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        Architecture::X86,
    ),
];

#[cfg(target_os = "windows")]
const USER_UNINSTALL_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// Windows Registry scanner
pub struct RegistryScanner {
    #[allow(dead_code)]
    pub scan_system: bool,
    #[allow(dead_code)]
    pub scan_user: bool,
}

#[cfg(not(target_os = "windows"))]
impl RegistryScanner {
    /// Create a new registry scanner (non-Windows fallback)
    pub fn new() -> Self {
        Self {
            scan_system: true,
            scan_user: true,
        }
    }

    /// Non-Windows fallback: returns empty software list
    pub fn scan(&self) -> Result<Vec<DetectedSoftware>> {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "windows")]
impl RegistryScanner {
    /// Create a new registry scanner
    pub fn new() -> Self {
        Self {
            scan_system: true,
            scan_user: true,
        }
    }

    /// Scan all registry locations for installed software
    pub fn scan(&self) -> Result<Vec<DetectedSoftware>> {
        let mut software = Vec::new();
        let mut seen = HashSet::new();

        // Scan system-wide installations (HKLM)
        if self.scan_system {
            for (path, arch) in UNINSTALL_PATHS {
                match self.scan_hklm(path, *arch) {
                    Ok(apps) => {
                        for app in apps {
                            let key =
                                format!("{}|{}", app.name, app.version.as_deref().unwrap_or(""));
                            if seen.insert(key) {
                                software.push(app);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to scan HKLM\\{}: {}", path, e);
                    }
                }
            }
        }

        // Scan user installations (HKCU)
        if self.scan_user {
            match self.scan_hkcu() {
                Ok(apps) => {
                    for app in apps {
                        let key = format!("{}|{}", app.name, app.version.as_deref().unwrap_or(""));
                        if seen.insert(key) {
                            software.push(app);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to scan HKCU: {}", e);
                }
            }
        }

        debug!("Found {} installed software packages", software.len());
        Ok(software)
    }

    /// Scan HKEY_LOCAL_MACHINE uninstall keys
    fn scan_hklm(&self, path: &str, arch: Architecture) -> Result<Vec<DetectedSoftware>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let uninstall_key = hklm
            .open_subkey_with_flags(path, KEY_READ)
            .map_err(|e| ScanError::RegistryError(format!("Cannot open {}: {}", path, e)))?;

        self.scan_uninstall_key(&uninstall_key, &format!("HKLM\\{}", path), arch)
    }

    /// Scan HKEY_CURRENT_USER uninstall keys
    fn scan_hkcu(&self) -> Result<Vec<DetectedSoftware>> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let uninstall_key = hkcu
            .open_subkey_with_flags(USER_UNINSTALL_PATH, KEY_READ)
            .map_err(|e| ScanError::RegistryError(format!("Cannot open HKCU uninstall: {}", e)))?;

        self.scan_uninstall_key(
            &uninstall_key,
            &format!("HKCU\\{}", USER_UNINSTALL_PATH),
            Architecture::Unknown,
        )
    }

    /// Scan an uninstall registry key for software entries
    fn scan_uninstall_key(
        &self,
        uninstall_key: &RegKey,
        base_path: &str,
        arch: Architecture,
    ) -> Result<Vec<DetectedSoftware>> {
        let mut software = Vec::new();

        for subkey_name in uninstall_key.enum_keys().filter_map(|r| r.ok()) {
            if let Ok(subkey) = uninstall_key.open_subkey_with_flags(&subkey_name, KEY_READ) {
                if let Some(app) = self.parse_software_entry(&subkey, &subkey_name, base_path, arch)
                {
                    software.push(app);
                }
            }
        }

        Ok(software)
    }

    /// Parse a single software entry from registry
    fn parse_software_entry(
        &self,
        key: &RegKey,
        subkey_name: &str,
        base_path: &str,
        arch: Architecture,
    ) -> Option<DetectedSoftware> {
        // Get display name - required field
        let name: String = key.get_value("DisplayName").ok()?;

        // Skip if it's a system component or update
        let system_component: u32 = key.get_value("SystemComponent").unwrap_or(0);
        if system_component == 1 {
            return None;
        }

        // Skip Windows updates and hotfixes
        if name.starts_with("KB") || name.contains("Security Update") || name.contains("Hotfix") {
            return None;
        }

        // Skip entries without proper names
        if name.is_empty() || name.starts_with("{") {
            return None;
        }

        // A tagged DisplayVersion such as Python's "3.14-64" is refined from
        // the DisplayName's "Python 3.14.7" — see refine_version_from_name.
        let raw_version: Option<String> = key.get_value("DisplayVersion").ok();
        let version = crate::normalize::names::refine_version_from_name(
            &name,
            raw_version.as_deref(),
        );
        let publisher: Option<String> = key.get_value("Publisher").ok();
        let install_location: Option<String> = key.get_value("InstallLocation").ok();
        let install_date: Option<String> = key.get_value("InstallDate").ok();

        debug!("Found: {} v{:?} by {:?}", name, version, publisher);

        Some(DetectedSoftware {
            name,
            version,
            publisher,
            install_location,
            install_date,
            registry_key: format!("{}\\{}", base_path, subkey_name),
            architecture: arch,
        })
    }
}

impl Default for RegistryScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = RegistryScanner::new();
        assert!(scanner.scan_system);
        assert!(scanner.scan_user);
    }

    #[test]
    fn scan_does_not_panic() {
        let scanner = RegistryScanner::new();
        // Must not panic; result may be Ok or Err depending on permissions
        let _ = scanner.scan();
    }

    #[test]
    fn seen_deduplication() {
        let mut seen: HashSet<String> = HashSet::new();
        let key1 = format!("{}|{}", "Git", "2.43.0");
        let key2 = format!("{}|{}", "Git", "2.43.0");
        assert!(seen.insert(key1));
        assert!(!seen.insert(key2)); // duplicate is rejected
    }
}

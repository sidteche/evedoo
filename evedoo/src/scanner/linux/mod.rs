// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Linux and Unix Package & Binary Scanners.
//!
//! Provides comprehensive inventory scanners for Linux environments:
//! - [`os_release`]: Distribution detection via `/etc/os-release` (`os://linux/{id}`)
//! - [`dpkg`]: Debian / Ubuntu status database scanner (`dpkg://{package}`)
//! - [`rpm`]: RHEL / Fedora / CentOS SQLite RPM database & DNF module states (`rpm://{package}`)
//! - [`pacman`]: Arch Linux local database scanner (`pacman://{package}`)
//! - [`apk`]: Alpine Linux installed packages database (`apk://{package}`)
//! - [`elf_fingerprint`]: 32-bit & 64-bit ELF header and dynamic section fingerprinter (`elf://{path}`)

pub mod apk;
pub mod dpkg;
pub mod elf_fingerprint;
pub mod os_release;
pub mod pacman;
pub mod rpm;

#[allow(unused_imports)]
pub use apk::{parse_apk_installed, ApkScanner};
#[allow(unused_imports)]
pub use dpkg::{parse_dpkg_status, DpkgScanner};
#[allow(unused_imports)]
pub use elf_fingerprint::{parse_elf_bytes, scan_elf_file, ElfFingerprintScanner};
#[allow(unused_imports)]
pub use os_release::{parse_os_release, OsReleaseScanner};
#[allow(unused_imports)]
pub use pacman::{parse_pacman_desc, parse_pacman_local_dir, PacmanScanner};
#[allow(unused_imports)]
pub use rpm::{parse_dnf_module_states, parse_rpm_db_sqlite, parse_rpm_db_sqlite_conn, RpmScanner};

use std::collections::HashSet;
use tracing::debug;

use crate::models::DetectedSoftware;

/// Unified Linux scanner aggregating all package and binary scanners.
#[allow(dead_code)]
pub struct LinuxScanner {
    pub os_scanner: OsReleaseScanner,
    pub dpkg_scanner: DpkgScanner,
    pub rpm_scanner: RpmScanner,
    pub pacman_scanner: PacmanScanner,
    pub apk_scanner: ApkScanner,
    pub elf_scanner: ElfFingerprintScanner,
}

#[allow(dead_code)]
impl LinuxScanner {
    pub fn new() -> Self {
        Self {
            os_scanner: OsReleaseScanner::new(),
            dpkg_scanner: DpkgScanner::new(),
            rpm_scanner: RpmScanner::new(),
            pacman_scanner: PacmanScanner::new(),
            apk_scanner: ApkScanner::new(),
            elf_scanner: ElfFingerprintScanner::new(),
        }
    }

    pub fn with_elf_roots(roots: Vec<std::path::PathBuf>) -> Self {
        Self {
            os_scanner: OsReleaseScanner::new(),
            dpkg_scanner: DpkgScanner::new(),
            rpm_scanner: RpmScanner::new(),
            pacman_scanner: PacmanScanner::new(),
            apk_scanner: ApkScanner::new(),
            elf_scanner: ElfFingerprintScanner::with_roots(roots),
        }
    }

    /// Run all Linux scanners and return deduplicated inventory entries.
    /// Safe fallback on non-Linux platforms (gracefully returns empty or available packages).
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let mut results = Vec::new();
        let mut seen_keys = HashSet::new();

        // 1. OS Release
        if let Some(os_info) = self.os_scanner.scan() {
            if seen_keys.insert(os_info.registry_key.clone()) {
                results.push(os_info);
            }
        }

        // 2. Package Managers
        let dpkg_pkgs = self.dpkg_scanner.scan();
        debug!("Linux dpkg scan found {} packages", dpkg_pkgs.len());
        for pkg in dpkg_pkgs {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        let rpm_pkgs = self.rpm_scanner.scan();
        debug!("Linux rpm scan found {} packages", rpm_pkgs.len());
        for pkg in rpm_pkgs {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        let pacman_pkgs = self.pacman_scanner.scan();
        debug!("Linux pacman scan found {} packages", pacman_pkgs.len());
        for pkg in pacman_pkgs {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        let apk_pkgs = self.apk_scanner.scan();
        debug!("Linux apk scan found {} packages", apk_pkgs.len());
        for pkg in apk_pkgs {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        // 3. ELF Binary Fingerprinter
        let elf_pkgs = self.elf_scanner.scan();
        debug!("Linux ELF scan found {} binaries/libraries", elf_pkgs.len());
        for pkg in elf_pkgs {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        results
    }

    /// Run Linux scanners against a custom rootfs (container image, chroot, offline disk).
    pub fn scan_rootfs(&self, root: &std::path::Path) -> Vec<DetectedSoftware> {
        let mut results = Vec::new();
        let mut seen_keys = HashSet::new();

        // 1. OS Release
        if let Some(os_info) = OsReleaseScanner::scan_rootfs(root) {
            if seen_keys.insert(os_info.registry_key.clone()) {
                results.push(os_info);
            }
        }

        // 2. Package Managers
        for pkg in DpkgScanner::scan_rootfs(root) {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        for pkg in RpmScanner::scan_rootfs(root) {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        for pkg in PacmanScanner::scan_rootfs(root) {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        for pkg in ApkScanner::scan_rootfs(root) {
            if seen_keys.insert(pkg.registry_key.clone()) {
                results.push(pkg);
            }
        }

        results
    }
}

impl Default for LinuxScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_scanner_does_not_panic() {
        let scanner = LinuxScanner::with_elf_roots(vec![]);
        let _ = scanner.scan();
    }

    #[test]
    fn test_linux_scanner_scan_rootfs() {
        let dir = std::env::temp_dir().join(format!("evedoo_test_rootfs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(dir.join("etc"));
        let _ = std::fs::create_dir_all(dir.join("var/lib/dpkg"));

        std::fs::write(
            dir.join("etc/os-release"),
            "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
        )
        .unwrap();

        std::fs::write(
            dir.join("var/lib/dpkg/status"),
            "Package: bash\nStatus: install ok installed\nVersion: 5.2.21-2ubuntu4\nArchitecture: amd64\n\n",
        )
        .unwrap();

        let scanner = LinuxScanner::new();
        let pkgs = scanner.scan_rootfs(&dir);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name.contains("Ubuntu") && p.version.as_deref() == Some("24.04")));
        assert!(pkgs.iter().any(|p| p.name == "bash" && p.version.as_deref() == Some("5.2.21-2ubuntu4")));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

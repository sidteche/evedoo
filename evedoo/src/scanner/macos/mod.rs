// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! macOS Scanner aggregator.
//!
//! Combines:
//! - [`BundleScanner`]: Applications and `Info.plist` files (`bundle://{id}`, `app://{name}`)
//! - [`HomebrewScanner`]: Formulae and Casks (`brew://{formula}`, `cask://{cask}`)
//! - [`MasScanner`]: Mac App Store receipts (`mas://{id}`)
//! - [`MacOsVersionScanner`]: macOS OS identity and build version (`os://macos/{version}`)
//! - [`MachoFingerprintScanner`]: Mach-O binary fingerprinter (`macho://{path}`)
//!
//! Safe to run across platforms (gracefully returns empty inventory if macOS paths are absent).

pub mod bundle;
pub mod homebrew;
pub mod macho_fingerprint;
pub mod mas;
pub mod os_version;

#[allow(unused_imports)]
pub use bundle::{parse_plist, BundleScanner, PlistMetadata};
#[allow(unused_imports)]
pub use homebrew::HomebrewScanner;
#[allow(unused_imports)]
pub use macho_fingerprint::{parse_macho, MachoFingerprintScanner, MachoInfo};
#[allow(unused_imports)]
pub use mas::MasScanner;
#[allow(unused_imports)]
pub use os_version::{parse_system_version_plist, MacOsVersionScanner, SystemVersionInfo};

use std::collections::HashSet;
use tracing::debug;

use crate::models::DetectedSoftware;

/// Master scanner for macOS environments.
#[allow(dead_code)]
pub struct MacOsScanner {
    bundle_scanner: BundleScanner,
    homebrew_scanner: HomebrewScanner,
    mas_scanner: MasScanner,
    os_scanner: MacOsVersionScanner,
    macho_scanner: MachoFingerprintScanner,
}

#[allow(dead_code)]
impl MacOsScanner {
    pub fn new() -> Self {
        Self {
            bundle_scanner: BundleScanner::new(),
            homebrew_scanner: HomebrewScanner::new(),
            mas_scanner: MasScanner::new(),
            os_scanner: MacOsVersionScanner::new(),
            macho_scanner: MachoFingerprintScanner::new(),
        }
    }

    /// Run all macOS scanners and aggregate detected software into a deduplicated inventory.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // 1. Operating System
        if let Some(os) = self.os_scanner.scan() {
            let key = (os.name.to_lowercase(), os.version.clone());
            if seen.insert(key) {
                results.push(os);
            }
        }

        // 2. Application Bundles
        for item in self.bundle_scanner.scan() {
            let key = (item.name.to_lowercase(), item.version.clone());
            if seen.insert(key) {
                results.push(item);
            }
        }

        // 3. Homebrew Formulae & Casks
        for item in self.homebrew_scanner.scan() {
            let key = (item.name.to_lowercase(), item.version.clone());
            if seen.insert(key) {
                results.push(item);
            }
        }

        // 4. Mac App Store Applications
        for item in self.mas_scanner.scan() {
            let key = (item.name.to_lowercase(), item.version.clone());
            if seen.insert(key) {
                results.push(item);
            }
        }

        // 5. Mach-O Fingerprinted Libraries
        for item in self.macho_scanner.scan() {
            let key = (item.name.to_lowercase(), item.version.clone());
            if seen.insert(key) {
                results.push(item);
            }
        }

        debug!("macOS scanner: total {} items detected", results.len());
        results
    }
}

impl Default for MacOsScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_scanner_does_not_panic_on_any_platform() {
        let scanner = MacOsScanner::new();
        let _ = scanner.scan();
    }
}

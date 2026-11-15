// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Homebrew Formulae and Casks scanner for macOS.
//!
//! Scans Homebrew installations at `/opt/homebrew` (Apple Silicon) and
//! `/usr/local` (Intel x86_64) without shelling out to `brew`:
//! - Formulae: inspects `{prefix}/Cellar/{formula}/{version}/INSTALL_RECEIPT.json`
//!   and emits `brew://{formula}`.
//! - Casks: inspects `{prefix}/Caskroom/{cask}/{version}`
//!   and emits `cask://{cask}`.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

/// Scanner for Homebrew packages (Formulae & Casks).
pub struct HomebrewScanner {
    custom_prefixes: Vec<PathBuf>,
}

impl HomebrewScanner {
    pub fn new() -> Self {
        Self {
            custom_prefixes: Vec::new(),
        }
    }

    pub fn with_prefixes(prefixes: Vec<PathBuf>) -> Self {
        Self {
            custom_prefixes: prefixes,
        }
    }

    /// Default Homebrew prefix locations.
    pub fn default_prefixes() -> Vec<PathBuf> {
        let mut prefixes = Vec::new();

        if let Ok(prefix) = std::env::var("HOMEBREW_PREFIX") {
            let p = PathBuf::from(prefix);
            if p.is_dir() {
                prefixes.push(p);
            }
        }

        for path_str in &["/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"] {
            let p = PathBuf::from(path_str);
            if p.is_dir() && !prefixes.contains(&p) {
                prefixes.push(p);
            }
        }

        prefixes
    }

    /// Scan all Homebrew Formulae and Casks.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let prefixes = if !self.custom_prefixes.is_empty() {
            self.custom_prefixes.clone()
        } else {
            Self::default_prefixes()
        };

        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for prefix in &prefixes {
            debug!("Homebrew scanner: checking prefix {}", prefix.display());
            let cellar = prefix.join("Cellar");
            if cellar.is_dir() {
                self.scan_cellar(&cellar, &mut results, &mut seen);
            }

            let caskroom = prefix.join("Caskroom");
            if caskroom.is_dir() {
                self.scan_caskroom(&caskroom, &mut results, &mut seen);
            }
        }

        debug!("Homebrew scanner: found {} packages", results.len());
        results
    }

    fn scan_cellar(
        &self,
        cellar: &Path,
        results: &mut Vec<DetectedSoftware>,
        seen: &mut HashSet<String>,
    ) {
        let entries = match fs::read_dir(cellar) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let formula_dir = entry.path();
            if !formula_dir.is_dir() {
                continue;
            }

            let formula_name = match formula_dir.file_name().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Read versions inside formula directory
            let version_entries = match fs::read_dir(&formula_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for v_entry in version_entries.flatten() {
                let v_dir = v_entry.path();
                if !v_dir.is_dir() {
                    continue;
                }

                let dir_version = match v_dir.file_name().and_then(|s| s.to_str()) {
                    Some(v) => v.to_string(),
                    None => continue,
                };

                // Skip hidden directories (e.g. .brew)
                if dir_version.starts_with('.') {
                    continue;
                }

                let (version, publisher) = Self::parse_install_receipt(&v_dir)
                    .unwrap_or_else(|| (dir_version.clone(), "Homebrew".to_string()));

                let registry_key = format!("brew://{}", formula_name);
                if seen.insert(format!("{}|{}", registry_key, version)) {
                    results.push(DetectedSoftware {
                        name: formula_name.clone(),
                        version: Some(version),
                        publisher: Some(publisher),
                        install_location: Some(v_dir.to_string_lossy().to_string()),
                        install_date: None,
                        registry_key,
                        architecture: Architecture::Unknown,
                    });
                }
            }
        }
    }

    fn scan_caskroom(
        &self,
        caskroom: &Path,
        results: &mut Vec<DetectedSoftware>,
        seen: &mut HashSet<String>,
    ) {
        let entries = match fs::read_dir(caskroom) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let cask_dir = entry.path();
            if !cask_dir.is_dir() {
                continue;
            }

            let cask_name = match cask_dir.file_name().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let version_entries = match fs::read_dir(&cask_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for v_entry in version_entries.flatten() {
                let v_dir = v_entry.path();
                if !v_dir.is_dir() {
                    continue;
                }

                let version = match v_dir.file_name().and_then(|s| s.to_str()) {
                    Some(v) => v.to_string(),
                    None => continue,
                };

                // Ignore .metadata or internal hidden folders
                if version.starts_with('.') || version == ".metadata" {
                    continue;
                }

                let registry_key = format!("cask://{}", cask_name);
                if seen.insert(format!("{}|{}", registry_key, version)) {
                    results.push(DetectedSoftware {
                        name: cask_name.clone(),
                        version: Some(version),
                        publisher: Some("Homebrew Cask".to_string()),
                        install_location: Some(v_dir.to_string_lossy().to_string()),
                        install_date: None,
                        registry_key,
                        architecture: Architecture::Unknown,
                    });
                }
            }
        }
    }

    /// Parse `INSTALL_RECEIPT.json` to extract precise version and source info.
    fn parse_install_receipt(version_dir: &Path) -> Option<(String, String)> {
        let receipt_path = version_dir.join("INSTALL_RECEIPT.json");
        if !receipt_path.is_file() {
            return None;
        }

        let content = fs::read_to_string(&receipt_path).ok()?;
        let json: serde_json::Value = serde_json::from_str(&content).ok()?;

        let version = json
            .get("pkg_version")
            .and_then(|v| v.as_str())
            .or_else(|| {
                json.get("source")
                    .and_then(|s| s.get("versions"))
                    .and_then(|v| v.get("stable"))
                    .and_then(|v| v.as_str())
            })?
            .to_string();

        Some((version, "Homebrew".to_string()))
    }
}

impl Default for HomebrewScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_mock_homebrew_cellar_and_caskroom() {
        let tmp = std::env::temp_dir().join("evedoo_brew_test");
        let _ = fs::remove_dir_all(&tmp);

        // 1. Create Cellar with openssl@3
        let cellar = tmp.join("Cellar");
        let openssl_v_dir = cellar.join("openssl@3").join("3.3.0_1");
        fs::create_dir_all(&openssl_v_dir).unwrap();

        let receipt_json = r#"{
            "homebrew_version": "4.3.0",
            "pkg_version": "3.3.0_1",
            "source": {
                "spec": "stable",
                "versions": {
                    "stable": "3.3.0"
                }
            }
        }"#;
        fs::write(openssl_v_dir.join("INSTALL_RECEIPT.json"), receipt_json).unwrap();

        // 2. Create Caskroom with visual-studio-code
        let caskroom = tmp.join("Caskroom");
        let vscode_v_dir = caskroom.join("visual-studio-code").join("1.89.1");
        fs::create_dir_all(&vscode_v_dir).unwrap();
        // Add a .metadata dir that should be ignored
        fs::create_dir_all(caskroom.join("visual-studio-code").join(".metadata")).unwrap();

        let scanner = HomebrewScanner::with_prefixes(vec![tmp.clone()]);
        let results = scanner.scan();

        assert_eq!(results.len(), 2);

        let openssl = results.iter().find(|s| s.name == "openssl@3").unwrap();
        assert_eq!(openssl.version.as_deref(), Some("3.3.0_1"));
        assert_eq!(openssl.registry_key, "brew://openssl@3");
        assert_eq!(openssl.publisher.as_deref(), Some("Homebrew"));

        let vscode = results.iter().find(|s| s.name == "visual-studio-code").unwrap();
        assert_eq!(vscode.version.as_deref(), Some("1.89.1"));
        assert_eq!(vscode.registry_key, "cask://visual-studio-code");
        assert_eq!(vscode.publisher.as_deref(), Some("Homebrew Cask"));

        let _ = fs::remove_dir_all(&tmp);
    }
}

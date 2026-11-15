//! Scoop package scanner.
//!
//! Detects packages installed by Scoop by reading the active manifest for
//! each app under `%SCOOP%\apps\<name>\current\manifest.json` (default
//! `%USERPROFILE%\scoop`). Filesystem-based so it works even when the `scoop`
//! shim is not on PATH.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::path::PathBuf;

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

pub struct ScoopScanner;

impl ScoopScanner {
    pub fn new() -> Self {
        ScoopScanner
    }

    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let install_dir = match Self::install_dir() {
            Some(p) => p,
            None => {
                debug!("Scoop install directory not found");
                return Vec::new();
            }
        };

        let apps_dir = install_dir.join("apps");
        if !apps_dir.is_dir() {
            debug!("Scoop apps dir missing: {}", apps_dir.display());
            return Vec::new();
        }

        let entries = match fs::read_dir(&apps_dir) {
            Ok(e) => e,
            Err(e) => {
                debug!("Failed to read {}: {}", apps_dir.display(), e);
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        for entry in entries.flatten() {
            let app_dir = entry.path();
            if !app_dir.is_dir() {
                continue;
            }
            let app_name = match app_dir.file_name().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Scoop stores each installed version in its own directory and
            // keeps a "current" junction pointing at the active one. The
            // "scoop" meta-app is Scoop itself — include it, it's software too.
            let manifest_path = app_dir.join("current").join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }

            let body = match fs::read_to_string(&manifest_path) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to read {}: {}", manifest_path.display(), e);
                    continue;
                }
            };

            let version = match parse_manifest_version(&body) {
                Some(v) => v,
                None => {
                    debug!("No version field in {}", manifest_path.display());
                    continue;
                }
            };

            debug!("Scoop: {} v{}", app_name, version);
            results.push(DetectedSoftware {
                name: app_name.clone(),
                version: Some(version),
                publisher: Some("scoop".to_string()),
                install_location: Some(app_dir.join("current").to_string_lossy().into_owned()),
                install_date: None,
                registry_key: format!("scoop://{}", app_name),
                architecture: Architecture::Unknown,
            });
        }

        results
    }

    /// Locate the Scoop install directory. Honours the `SCOOP` env var set by
    /// per-user Scoop installs, falls back to the documented default
    /// `%USERPROFILE%\scoop`.
    fn install_dir() -> Option<PathBuf> {
        if let Ok(p) = env::var("SCOOP") {
            let path = PathBuf::from(p);
            if path.is_dir() {
                return Some(path);
            }
        }
        if let Ok(home) = env::var("USERPROFILE") {
            let path = PathBuf::from(home).join("scoop");
            if path.is_dir() {
                return Some(path);
            }
        }
        None
    }
}

impl Default for ScoopScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the `version` string from a Scoop manifest JSON document. Scoop
/// manifests are always top-level objects with a `version` string field.
fn parse_manifest_version(json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value.get("version")?.as_str().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "version": "2.44.0",
        "description": "Fast, scalable, distributed revision control system",
        "homepage": "https://git-scm.com/",
        "license": "GPL-2.0-only",
        "architecture": {
            "64bit": {
                "url": "https://example.com/git.zip"
            }
        }
    }"#;

    #[test]
    fn parses_version_from_manifest() {
        assert_eq!(parse_manifest_version(SAMPLE).as_deref(), Some("2.44.0"));
    }

    #[test]
    fn returns_none_on_malformed_json() {
        assert!(parse_manifest_version("not json").is_none());
    }

    #[test]
    fn returns_none_when_version_missing() {
        let json = r#"{"description": "no version here"}"#;
        assert!(parse_manifest_version(json).is_none());
    }

    #[test]
    fn returns_none_when_version_not_string() {
        // Scoop always uses string versions; a numeric one is malformed.
        let json = r#"{"version": 2.44}"#;
        assert!(parse_manifest_version(json).is_none());
    }

    #[test]
    fn scoop_scanner_does_not_panic() {
        // On Linux CI and machines without Scoop, scan() must return an
        // empty Vec rather than panicking.
        let _ = ScoopScanner::new().scan();
    }
}

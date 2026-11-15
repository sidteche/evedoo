//! Package ecosystem scanner: pip, npm, cargo.
//!
//! Runs package managers (if available on PATH) and converts installed packages
//! into DetectedSoftware entries for CVE matching.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::process::{Command, Stdio};

use tracing::{debug, warn};

use crate::models::{Architecture, DetectedSoftware};

pub struct PackageScanner;

impl PackageScanner {
    pub fn new() -> Self {
        PackageScanner
    }

    /// Scan all available package ecosystems. Gracefully skips any tool not found.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let mut results = Vec::new();
        results.extend(self.scan_pip());
        results.extend(self.scan_npm());
        results.extend(self.scan_cargo());
        results
    }

    // ── pip ──────────────────────────────────────────────────────────────────

    fn scan_pip(&self) -> Vec<DetectedSoftware> {
        let output = match Self::run_command("pip", &["list", "--format=json"]) {
            Some(o) => o,
            None => {
                debug!("pip not found or returned no output — skipping");
                return Vec::new();
            }
        };

        let packages: Vec<serde_json::Value> = match serde_json::from_str(&output) {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse pip output: {}", e);
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        for pkg in packages {
            let name = match pkg.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let version = pkg.get("version").and_then(|v| v.as_str()).map(str::to_string);
            results.push(Self::make_software(name, version, "pip"));
        }

        debug!("pip: found {} packages", results.len());
        results
    }

    // ── npm ──────────────────────────────────────────────────────────────────

    fn scan_npm(&self) -> Vec<DetectedSoftware> {
        // npm list -g --json may exit with code 1 on peer-dep issues but still
        // emit valid JSON on stdout — capture stdout regardless of exit code.
        let output = match Self::run_command_ignore_status("npm", &["list", "-g", "--json"]) {
            Some(o) => o,
            None => {
                debug!("npm not found — skipping");
                return Vec::new();
            }
        };

        let root: serde_json::Value = match serde_json::from_str(&output) {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse npm output: {}", e);
                return Vec::new();
            }
        };

        let deps = match root.get("dependencies").and_then(|d| d.as_object()) {
            Some(d) => d,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        for (name, info) in deps {
            let version = info
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            results.push(Self::make_software(name.clone(), version, "npm"));
        }

        debug!("npm: found {} global packages", results.len());
        results
    }

    // ── cargo ─────────────────────────────────────────────────────────────────

    fn scan_cargo(&self) -> Vec<DetectedSoftware> {
        let output = match Self::run_command("cargo", &["install", "--list"]) {
            Some(o) => o,
            None => {
                debug!("cargo not found — skipping");
                return Vec::new();
            }
        };

        // Output format:
        //   sccache v0.7.7:
        //       sccache
        //   ripgrep v14.1.1:
        //       rg
        let mut results = Vec::new();
        for line in output.lines() {
            // Top-level entries don't start with whitespace and end with ":"
            if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
                let entry = line.trim_end_matches(':');
                // Split "name v1.2.3" on " v"
                if let Some(idx) = entry.find(" v") {
                    let name = entry[..idx].to_string();
                    let version = Some(entry[idx + 2..].to_string());
                    results.push(Self::make_software(name, version, "cargo"));
                }
            }
        }

        debug!("cargo: found {} installed crates", results.len());
        results
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Run a command and return stdout if it exits successfully.
    fn run_command(program: &str, args: &[&str]) -> Option<String> {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success() && !o.stdout.is_empty())
            .and_then(|o| String::from_utf8(o.stdout).ok())
    }

    /// Run a command and return stdout even if the exit code is non-zero (npm quirk).
    fn run_command_ignore_status(program: &str, args: &[&str]) -> Option<String> {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| !o.stdout.is_empty())
            .and_then(|o| String::from_utf8(o.stdout).ok())
    }

    fn make_software(name: String, version: Option<String>, ecosystem: &str) -> DetectedSoftware {
        let registry_key = format!("{}://{}", ecosystem, name);
        let publisher = Some(ecosystem.to_string());
        DetectedSoftware {
            name,
            version,
            publisher,
            install_location: None,
            install_date: None,
            registry_key,
            architecture: Architecture::Unknown,
        }
    }
}

impl Default for PackageScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Python packages installed under `<install_root>/Lib/site-packages`, read
/// from each `*.dist-info/METADATA` — no subprocess.
///
/// `pip list` only reports the environment whose `pip` is first on PATH. A
/// machine with several Pythons (the Microsoft Store build, the python.org
/// install manager, one bundled inside pgAdmin) had every other environment's
/// packages missed: the Store Python's pip 26.1.2, and CVE-2026-13346 against
/// it, never reached the matcher. Callers pass the install location of every
/// detected product, so any install that *contains* a site-packages directory
/// is covered — an observable property, not a list of Python product names.
///
/// Only `.dist-info` (installed wheels, PEP 376) is read; `.egg-info` is left
/// to `pip list`, since its layout varies (file or directory) and it is rare in
/// modern environments.
pub fn site_packages_software(install_root: &std::path::Path) -> Vec<DetectedSoftware> {
    let site = install_root.join("Lib").join("site-packages");
    let Ok(entries) = std::fs::read_dir(&site) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dist_info = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".dist-info"));
        if !is_dist_info || !path.is_dir() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path.join("METADATA")) else {
            continue;
        };
        let Some((name, version)) = parse_metadata(&text) else {
            continue;
        };
        let mut sw = PackageScanner::make_software(name, Some(version), "pip");
        sw.install_location = Some(site.to_string_lossy().into_owned());
        out.push(sw);
    }
    debug!("site-packages {}: found {} packages", site.display(), out.len());
    out
}

/// `(Name, Version)` from a core-metadata file. Headers end at the first blank
/// line; anything after is the long description, where a "Version:" line is
/// prose rather than the package version.
fn parse_metadata(text: &str) -> Option<(String, String)> {
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Name:") {
            name.get_or_insert_with(|| v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version.get_or_insert_with(|| v.trim().to_string());
        }
    }
    match (name, version) {
        (Some(n), Some(v)) if !n.is_empty() && !v.is_empty() => Some((n, v)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "evedoo-sitepkg-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn dist_info(&self, site: &str, dir: &str, metadata: &str) {
            let d = self.0.join(site).join(dir);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("METADATA"), metadata).unwrap();
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn packages_are_read_from_an_installs_site_packages() {
        // The Store build of Python keeps pip 26.1.2 at
        // <InstallLocation>\Lib\site-packages\pip-26.1.2.dist-info. `pip list`
        // only ever saw whichever pip was first on PATH, so this install's
        // packages — and CVE-2026-13346 against pip — were never inventoried.
        let s = Scratch::new();
        s.dist_info(
            "Lib/site-packages",
            "pip-26.1.2.dist-info",
            "Metadata-Version: 2.1\nName: pip\nVersion: 26.1.2\nSummary: x\n",
        );

        let found = site_packages_software(s.path());

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "pip");
        assert_eq!(found[0].version.as_deref(), Some("26.1.2"));
        assert!(found[0].registry_key.starts_with("pip://"));
        assert!(found[0]
            .install_location
            .as_deref()
            .is_some_and(|l| l.contains("site-packages")));
    }

    #[test]
    fn an_install_without_site_packages_yields_nothing() {
        let s = Scratch::new();
        assert!(site_packages_software(s.path()).is_empty());
    }

    #[test]
    fn metadata_headers_stop_at_the_body() {
        // A "Version:" line inside the long description is not the version.
        let text = "Name: requests\nVersion: 2.31.0\n\nVersion: 9.9.9 in the README\n";
        assert_eq!(
            parse_metadata(text),
            Some(("requests".to_string(), "2.31.0".to_string()))
        );
    }

    #[test]
    fn metadata_without_a_name_or_version_is_skipped() {
        assert_eq!(parse_metadata("Name: x\n"), None);
        assert_eq!(parse_metadata("Version: 1.0\n"), None);
        assert_eq!(parse_metadata(""), None);
    }

    #[test]
    fn non_dist_info_directories_are_ignored() {
        let s = Scratch::new();
        s.dist_info("Lib/site-packages", "pip", "Name: pip\nVersion: 26.1.2\n");
        s.dist_info(
            "Lib/site-packages",
            "requests-2.31.0.egg-info",
            "Name: requests\nVersion: 2.31.0\n",
        );
        assert!(site_packages_software(s.path()).is_empty());
    }
}

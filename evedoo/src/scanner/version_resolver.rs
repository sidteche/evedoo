//! Version resolver for software entries that lack a version string.
//!
//! Strategy (applied in order, stops at first success):
//!   1. Registry fallback — re-open the key and check Version / MajorVersion+MinorVersion
//!   2. CLI whitelist   — run a known-safe binary with --version and parse stdout
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::process::{Command, Stdio};

use tracing::debug;
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

use crate::models::DetectedSoftware;

/// A whitelisted CLI tool whose `--version` output we know how to parse.
struct CliEntry {
    /// Substring to match against DetectedSoftware.name (case-insensitive)
    name_contains: &'static str,
    /// Executable name (looked up on PATH)
    command: &'static str,
    /// Arguments to pass
    args: &'static [&'static str],
    /// Prefix to strip from the first stdout line before extracting the version token
    strip_prefix: &'static str,
}

const CLI_WHITELIST: &[CliEntry] = &[
    CliEntry {
        name_contains: "git",
        command: "git",
        args: &["--version"],
        strip_prefix: "git version ",
    },
    CliEntry {
        name_contains: "python",
        command: "python",
        args: &["--version"],
        strip_prefix: "Python ",
    },
    CliEntry {
        name_contains: "node",
        command: "node",
        args: &["--version"],
        strip_prefix: "v",
    },
    CliEntry {
        name_contains: "ruby",
        command: "ruby",
        args: &["--version"],
        strip_prefix: "ruby ",
    },
    CliEntry {
        name_contains: "go ",
        command: "go",
        args: &["version"],
        // "go version go1.21.0 windows/amd64" — strip "go version go", take up to space
        strip_prefix: "go version go",
    },
    CliEntry {
        name_contains: "rust",
        command: "rustc",
        args: &["--version"],
        strip_prefix: "rustc ",
    },
    CliEntry {
        name_contains: "php",
        command: "php",
        args: &["--version"],
        strip_prefix: "PHP ",
    },
];

/// Resolves missing version strings for detected software entries.
pub struct VersionResolver {
    /// Cache: CLI command → resolved version (avoid running the same binary twice)
    cache: HashMap<&'static str, Option<String>>,
}

impl VersionResolver {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Attempt to fill in missing versions for all software items in place.
    pub fn resolve_missing_versions(&mut self, software: &mut [DetectedSoftware]) {
        for sw in software.iter_mut() {
            if sw.version.is_some() {
                continue; // already has a version
            }

            // Strategy 1: registry fallback
            if let Some(v) = self.try_registry_fallback(&sw.registry_key) {
                debug!("Version resolved via registry fallback for {}: {}", sw.name, v);
                sw.version = Some(v);
                continue;
            }

            // Strategy 2: CLI whitelist
            if let Some(v) = self.try_cli_version(sw) {
                debug!("Version resolved via CLI for {}: {}", sw.name, v);
                sw.version = Some(v);
            }
        }
    }

    /// Re-open the registry key and check additional value names.
    #[cfg(target_os = "windows")]
    fn try_registry_fallback(&self, registry_key: &str) -> Option<String> {
        // registry_key format: "HKLM\SOFTWARE\...\subkey" or "HKCU\SOFTWARE\...\subkey"
        let (hive, subpath) = if let Some(rest) = registry_key.strip_prefix("HKLM\\") {
            (HKEY_LOCAL_MACHINE, rest)
        } else {
            // pip://, npm://, cargo:// keys have no registry key to re-open.
            (HKEY_CURRENT_USER, registry_key.strip_prefix("HKCU\\")?)
        };

        let root = RegKey::predef(hive);
        let key = root.open_subkey_with_flags(subpath, KEY_READ).ok()?;

        // Try plain "Version" string first
        if let Ok(v) = key.get_value::<String, _>("Version") {
            if !v.is_empty() && v != "0" {
                return Some(v);
            }
        }

        // Try MajorVersion + MinorVersion + BuildVersion (DWORD values)
        let major: u32 = key.get_value("MajorVersion").unwrap_or(0);
        let minor: u32 = key.get_value("MinorVersion").unwrap_or(0);
        let build: u32 = key.get_value("BuildVersion").unwrap_or(0);

        if major > 0 || minor > 0 {
            return Some(format!("{}.{}.{}", major, minor, build));
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    fn try_registry_fallback(&self, _registry_key: &str) -> Option<String> {
        None
    }

    /// Run a whitelisted CLI binary and parse its version output.
    fn try_cli_version(&mut self, sw: &DetectedSoftware) -> Option<String> {
        let name_lower = sw.name.to_lowercase();

        for entry in CLI_WHITELIST {
            if !name_lower.contains(entry.name_contains) {
                continue;
            }

            // Use cached result if we already ran this binary
            if let Some(cached) = self.cache.get(entry.command) {
                return cached.clone();
            }

            let result = Self::run_cli(entry);
            self.cache.insert(entry.command, result.clone());
            return result;
        }

        None
    }

    fn run_cli(entry: &CliEntry) -> Option<String> {
        let output = Command::new(entry.command)
            .args(entry.args)
            .stdin(Stdio::null())
            .stderr(Stdio::piped()) // some tools (python) print to stderr
            .stdout(Stdio::piped())
            .output()
            .ok()?;

        // Try stdout first, fall back to stderr (python --version goes to stderr on 2.x)
        let raw = if !output.stdout.is_empty() {
            String::from_utf8_lossy(&output.stdout).into_owned()
        } else {
            String::from_utf8_lossy(&output.stderr).into_owned()
        };

        let first_line = raw.lines().next()?;
        Self::parse_version_line(first_line, entry.strip_prefix)
    }

    /// Strip a known prefix and extract the first version-like token.
    fn parse_version_line(line: &str, strip_prefix: &str) -> Option<String> {
        let rest = if strip_prefix.is_empty() {
            line
        } else {
            line.strip_prefix(strip_prefix).unwrap_or(line)
        };

        // Take the first whitespace-delimited token that looks like a version
        let token = rest.split_whitespace().next()?;

        // Must contain at least one digit
        if token.chars().any(|c| c.is_ascii_digit()) {
            Some(token.trim_end_matches(|c: char| !c.is_alphanumeric()).to_string())
        } else {
            None
        }
    }
}

impl Default for VersionResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::VersionResolver;

    #[test]
    fn parse_git_version() {
        let v = VersionResolver::parse_version_line("git version 2.43.0.windows.1", "git version ");
        assert_eq!(v.as_deref(), Some("2.43.0.windows.1"));
    }

    #[test]
    fn parse_python_version() {
        let v = VersionResolver::parse_version_line("Python 3.12.0", "Python ");
        assert_eq!(v.as_deref(), Some("3.12.0"));
    }

    #[test]
    fn parse_node_version() {
        let v = VersionResolver::parse_version_line("v20.11.0", "v");
        assert_eq!(v.as_deref(), Some("20.11.0"));
    }

    #[test]
    fn parse_go_version() {
        let v = VersionResolver::parse_version_line("go version go1.21.0 windows/amd64", "go version go");
        assert_eq!(v.as_deref(), Some("1.21.0"));
    }

    #[test]
    fn parse_empty_line() {
        let v = VersionResolver::parse_version_line("", "");
        assert!(v.is_none());
    }
}

//! Configuration and compliance auditing engine.
//!
//! The bundled benchmarks are Evedoo's own checks, derived from a subset of the
//! DISA STIGs and mapped to NIST SP 800-53 controls. They are not DISA's
//! publications (see [`AUDIT_DISCLAIMER`]).
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod builtin;
pub mod evaluator;
pub mod policy;
pub mod report;

pub use builtin::*;
pub use evaluator::*;
pub use policy::*;
pub use report::*;

use std::path::Path;
use anyhow::{bail, Context, Result};

/// What the audit needs to know about the machine it runs on.
#[derive(Debug, Clone)]
pub struct HostOs {
    /// The audit reads the Windows registry and service configuration.
    pub is_windows: bool,
    /// Detected OS name, e.g. "Windows 11", "Windows Server 2022".
    pub name: Option<String>,
}

impl HostOs {
    /// Detect the local host.
    pub fn detect() -> Self {
        let is_windows = cfg!(target_os = "windows");
        let name = if is_windows {
            crate::scanner::OsVersionScanner::new().scan().map(|os| os.name)
        } else {
            Some(std::env::consts::OS.to_string())
        };
        Self { is_windows, name }
    }
}

/// The bundled benchmark that matches a detected Windows version.
fn bundled_id_for(os_name: &str) -> Option<&'static str> {
    let name = os_name.to_ascii_lowercase();
    if name.contains("server 2022") {
        Some("windows-server-2022")
    } else if name.contains("server") {
        None
    } else if name.contains("windows 11") {
        Some("windows-11")
    } else if name.contains("windows 10") {
        Some("windows-10")
    } else {
        None
    }
}

fn bundled_list() -> String {
    list_bundled_benchmarks()
        .into_iter()
        .map(|(id, title, os)| format!("  - {:<22} {} (target: {})", id, title, os))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Decide which benchmark to evaluate.
///
/// - `policy` is a JSON benchmark file and is the only way a file is read.
/// - `benchmark` names a bundled benchmark and is never treated as a path.
/// - With neither, the bundled benchmark matching the detected Windows
///   version is used; the returned note says so when there was no exact match.
///
/// A benchmark whose target is Windows is refused on a non-Windows host: its
/// registry and service checks cannot be evaluated there, and reporting every
/// one of them as "not found" would look like a real result.
pub fn resolve_benchmark(
    benchmark: Option<&str>,
    policy: Option<&Path>,
    host: &HostOs,
) -> Result<(Benchmark, Option<String>)> {
    let mut note = None;

    let chosen = if let Some(path) = policy {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read benchmark policy file '{}'", path.display()))?;
        serde_json::from_str::<Benchmark>(&content)
            .with_context(|| format!("Failed to parse benchmark JSON in '{}'", path.display()))?
    } else if let Some(name) = benchmark {
        match get_bundled_benchmark(name) {
            Some(bundled) => bundled,
            None => bail!(
                "Unknown bundled benchmark '{}'. Use --policy <file> for a custom JSON benchmark.\n\
                 Bundled benchmarks:\n{}",
                name,
                bundled_list()
            ),
        }
    } else {
        if !host.is_windows {
            bail!(
                "The bundled benchmarks audit Windows configuration and can only run on a Windows host \
                 (this host: {}). Use --policy <file> for a custom JSON benchmark.",
                host.name.as_deref().unwrap_or("unknown")
            );
        }
        let detected = host.name.as_deref().unwrap_or("an undetected Windows version");
        let id = match host.name.as_deref().and_then(bundled_id_for) {
            Some(id) => id,
            None => {
                note = Some(format!(
                    "No bundled benchmark matches {}; using the Windows 11 checks. \
                     Pass --benchmark to choose another.",
                    detected
                ));
                "windows-11"
            }
        };
        match get_bundled_benchmark(id) {
            Some(bundled) => bundled,
            None => bail!("Bundled benchmark '{}' is missing", id),
        }
    };

    if !host.is_windows && chosen.target_os.to_ascii_lowercase().starts_with("windows") {
        bail!(
            "Benchmark '{}' targets Windows ({}) and can only be evaluated on a Windows host (this host: {}).",
            chosen.id,
            chosen.target_os,
            host.name.as_deref().unwrap_or("unknown")
        );
    }

    Ok((chosen, note))
}

/// Evaluate `benchmark` against the local system.
pub fn run_audit(benchmark: &Benchmark) -> AuditSummary {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string());
    evaluate_benchmark(benchmark, &hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows(name: &str) -> HostOs {
        HostOs { is_windows: true, name: Some(name.to_string()) }
    }

    fn linux() -> HostOs {
        HostOs { is_windows: false, name: Some("Ubuntu 24.04".to_string()) }
    }

    #[test]
    fn bundled_benchmarks_evaluate() {
        for id in ["windows-11", "ms-edge"] {
            let benchmark = get_bundled_benchmark(id).unwrap();
            let summary = run_audit(&benchmark);
            assert_eq!(summary.benchmark_id, benchmark.id);
            assert!(!summary.results.is_empty());
        }
    }

    /// On Linux or macOS every registry rule used to come back "not found",
    /// and the user was handed a Windows 11 compliance score for a host that
    /// is not Windows at all.
    #[test]
    fn windows_benchmark_is_refused_on_a_non_windows_host() {
        let err = resolve_benchmark(Some("windows-11"), None, &linux()).unwrap_err().to_string();
        assert!(err.contains("Windows"), "{err}");
        let err = resolve_benchmark(None, None, &linux()).unwrap_err().to_string();
        assert!(err.contains("Windows"), "{err}");
    }

    #[test]
    fn default_benchmark_follows_the_detected_windows_version() {
        for (os, id) in [
            ("Windows 11", "U_MS_Windows_11_STIG"),
            ("Windows 10", "U_MS_Windows_10_STIG"),
            ("Windows Server 2022", "U_MS_Windows_Server_2022_STIG"),
        ] {
            let (benchmark, note) = resolve_benchmark(None, None, &windows(os)).unwrap();
            assert_eq!(benchmark.id, id, "{os}");
            assert!(note.is_none(), "{os}: {note:?}");
        }
    }

    #[test]
    fn unrecognised_windows_version_falls_back_with_a_note() {
        let (benchmark, note) = resolve_benchmark(None, None, &windows("Windows Server 2019")).unwrap();
        assert_eq!(benchmark.id, "U_MS_Windows_11_STIG");
        let note = note.expect("the fallback must be stated");
        assert!(note.contains("Windows Server 2019"), "{note}");
    }

    #[test]
    fn explicit_benchmark_wins_over_detection() {
        let (benchmark, note) = resolve_benchmark(Some("ms-edge"), None, &windows("Windows 11")).unwrap();
        assert_eq!(benchmark.id, "U_MS_Edge_STIG");
        assert!(note.is_none());
    }

    /// `--benchmark` names a bundled benchmark and nothing else. It used to be
    /// opened as a file first, so a file called `windows-11` in the working
    /// directory silently replaced the bundled rules.
    #[test]
    fn benchmark_name_is_never_read_as_a_file() {
        let dir = std::env::temp_dir().join(format!("evedoo-audit-name-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let planted = dir.join("planted-benchmark");
        std::fs::write(&planted, r#"{"id":"PLANTED","title":"x","version":"1","publisher":"x","target_os":"windows","rules":[]}"#).unwrap();

        let by_name = resolve_benchmark(Some(planted.to_str().unwrap()), None, &windows("Windows 11"));
        assert!(by_name.is_err(), "a path given to --benchmark must not be loaded");

        let (by_policy, _) = resolve_benchmark(None, Some(&planted), &windows("Windows 11")).unwrap();
        assert_eq!(by_policy.id, "PLANTED");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn policy_for_a_non_windows_target_is_not_blocked_by_the_host_check() {
        let dir = std::env::temp_dir().join(format!("evedoo-audit-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("linux.json");
        std::fs::write(&policy, r#"{"id":"CUSTOM","title":"x","version":"1","publisher":"x","target_os":"linux","rules":[]}"#).unwrap();
        let (benchmark, _) = resolve_benchmark(None, Some(&policy), &linux()).unwrap();
        assert_eq!(benchmark.id, "CUSTOM");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

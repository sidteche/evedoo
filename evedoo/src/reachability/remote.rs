//! Remote module enumeration over the existing WinRM session.
//!
//! The script block is a fixed constant with NO interpolated values (SEC-8),
//! so its injection surface is eliminated by construction rather than by
//! escaping. PowerShell here is the transport, as in `remote/scanners.rs`;
//! all parsing and logic stay in Rust.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use tracing::warn;

use super::{normalize_path, Coverage, ModuleMap};
use crate::remote::RemoteSession;

/// Emits one `COVERAGE<TAB>readable<TAB>total` line followed by one
/// `MODULE<TAB>path` line per distinct loaded module.
///
/// Accessing `$p.Modules` throws for processes the caller cannot open, so the
/// try/catch is what distinguishes readable from unreadable processes — the
/// remote equivalent of a failed `CreateToolhelp32Snapshot`.
///
/// `[char]9` is used rather than a literal tab so the delimiter survives any
/// whitespace normalisation between here and the remote shell.
pub const MODULE_SCRIPT: &str = r#"
$total = 0
$readable = 0
$paths = New-Object System.Collections.Generic.HashSet[string]
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
  $total = $total + 1
  try {
    foreach ($m in $p.Modules) { [void]$paths.Add($m.FileName) }
    $readable = $readable + 1
  } catch { }
}
Write-Output ("COVERAGE" + [char]9 + $readable + [char]9 + $total)
foreach ($x in $paths) { Write-Output ("MODULE" + [char]9 + $x) }
"#;

/// Parse the collector's output.
///
/// A missing or malformed COVERAGE line yields an incomplete map, so FR-74
/// forces every classification to `Unknown`. Truncated or error output must
/// never be read as "this machine has nothing loaded".
pub fn parse_output(raw: &str) -> ModuleMap {
    let mut paths: HashSet<String> = HashSet::new();
    let mut coverage: Option<Coverage> = None;

    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("COVERAGE\t") {
            let mut parts = rest.split('\t');
            if let (Some(r), Some(t)) = (parts.next(), parts.next()) {
                if let (Ok(r), Ok(t)) = (r.trim().parse::<usize>(), t.trim().parse::<usize>()) {
                    coverage = Some(Coverage {
                        readable: r,
                        total: t,
                    });
                }
            }
        } else if let Some(path) = line.strip_prefix("MODULE\t") {
            let p = path.trim();
            if !p.is_empty() {
                paths.insert(normalize_path(p));
            }
        }
    }

    match coverage {
        Some(c) => ModuleMap::new(paths, c),
        None => {
            // Deliberately discard any MODULE lines gathered: without a
            // coverage line we cannot say how much of the machine they
            // represent, and a partial set presented as complete would be
            // worse than no data.
            ModuleMap::empty_unknown()
        }
    }
}

/// Collect reachability from a remote host. Any failure yields a map that
/// determines nothing (FR-76) — a failed collection observed nothing, which
/// is not the same as observing nothing loaded.
pub fn collect(session: &RemoteSession) -> ModuleMap {
    match session.execute(MODULE_SCRIPT) {
        Ok(out) => parse_output(&out),
        Err(e) => {
            warn!("Remote reachability collection failed: {e}");
            ModuleMap::empty_unknown()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reachability::{normalize_path, Reachability};

    #[test]
    fn parses_coverage_and_module_lines() {
        let raw = "COVERAGE\t7\t9\n\
                   MODULE\tC:\\Windows\\System32\\ntdll.dll\n\
                   MODULE\tC:\\App\\libcurl.dll\n";
        let map = parse_output(raw);

        assert_eq!(map.coverage().readable, 7);
        assert_eq!(map.coverage().total, 9);
        assert!(map.contains_normalized(&normalize_path(r"C:\App\libcurl.dll")));
        assert!(!map.is_complete(), "7 of 9 is not complete coverage");
    }

    #[test]
    fn complete_coverage_is_reported_complete() {
        let map = parse_output("COVERAGE\t9\t9\nMODULE\tC:\\x\\y.dll\n");
        assert!(map.is_complete());
    }

    /// Garbage, a truncated stream, or an error message must determine
    /// nothing rather than assert an empty machine.
    #[test]
    fn output_without_coverage_line_determines_nothing() {
        for raw in ["", "Access is denied.", "MODULE\tC:\\x\\y.dll\n"] {
            let map = parse_output(raw);
            assert!(
                !map.is_complete(),
                "missing COVERAGE must never yield a complete sweep: {raw:?}"
            );
        }
    }

    #[test]
    fn malformed_coverage_line_determines_nothing() {
        let map = parse_output("COVERAGE\tnotanumber\t9\nMODULE\tC:\\x\\y.dll\n");
        assert!(!map.is_complete());
    }

    /// SEC-8. The command must be a constant with nothing interpolated.
    #[test]
    fn script_block_has_no_interpolation_placeholders() {
        assert!(!MODULE_SCRIPT.contains("{}"));
        assert!(!MODULE_SCRIPT.contains("{0}"));
        assert!(
            !MODULE_SCRIPT.contains('\''),
            "no quoted interpolation slots"
        );
    }

    /// An empty machine with full coverage still classifies as NotObserved,
    /// not Unknown — proving parse_output feeds the FR-74 machinery.
    #[test]
    fn full_coverage_with_no_modules_still_permits_a_negative() {
        use crate::models::{Architecture, DetectedSoftware};
        let map = parse_output("COVERAGE\t4\t4\n");
        let s = DetectedSoftware {
            name: "T".into(),
            version: None,
            publisher: None,
            install_location: None,
            install_date: None,
            registry_key: r"pe://C:\App\x.dll".into(),
            architecture: Architecture::X64,
        };
        assert_eq!(
            crate::reachability::classify(&s, &map),
            Reachability::NotObserved
        );
    }
}

//! Runtime reachability: whether a finding's code is mapped into a live
//! process right now, as opposed to merely present on disk.
//!
//! The governing rule (spec §2) is that reachability may RAISE a finding's
//! priority and may never lower one. A scan samples seconds of a machine that
//! runs for months, so "not loaded now" is not evidence of safety.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::models::DetectedSoftware;

pub mod local;
pub mod remote;

/// Whether a finding's code is mapped into a live process.
///
/// `Unknown` is an honesty state, not an error state. Only `Loaded` affects
/// scoring, so `Unknown` and `NotObserved` behave identically today — but they
/// make different claims to a reader, and collapsing them is how an
/// observation gap becomes a false assurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// A module at this path is mapped into at least one live process.
    Loaded,
    /// Coverage was complete for this scan and no such module was mapped.
    NotObserved,
    /// Not determined: incomplete coverage, a reassess against a stored
    /// snapshot, a failed remote collection, or an unevaluable finding.
    #[default]
    Unknown,
}

impl std::fmt::Display for Reachability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reachability::Loaded => write!(f, "Loaded"),
            Reachability::NotObserved => write!(f, "Not loaded"),
            Reachability::Unknown => write!(f, "Unknown"),
        }
    }
}

/// How much of the process list the collector could actually read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    pub readable: usize,
    pub total: usize,
}

/// The set of module paths mapped into live processes, plus how complete the
/// sweep was.
#[derive(Debug, Clone, Default)]
pub struct ModuleMap {
    paths: HashSet<String>,
    coverage: Coverage,
}

impl ModuleMap {
    pub fn new(paths: HashSet<String>, coverage: Coverage) -> Self {
        Self { paths, coverage }
    }

    /// A map that determines nothing: used when collection was skipped
    /// (`--no-reachability`), failed, or is inapplicable (`reassess`).
    /// `total = 1, readable = 0` makes it deliberately incomplete, so FR-74
    /// forces every classification to `Unknown` through the normal path
    /// rather than through a special case.
    pub fn empty_unknown() -> Self {
        Self {
            paths: HashSet::new(),
            coverage: Coverage {
                readable: 0,
                total: 1,
            },
        }
    }

    pub fn is_complete(&self) -> bool {
        self.coverage.readable >= self.coverage.total
    }

    pub fn coverage(&self) -> Coverage {
        self.coverage
    }

    /// Test accessor. Takes an already-normalised path.
    ///
    /// `cfg(test)` rather than an `allow(dead_code)`: nothing in production
    /// reads a single path, and an unconditional pub method here would be
    /// indistinguishable from one that had genuinely fallen out of use.
    #[cfg(test)]
    pub fn contains_normalized(&self, path: &str) -> bool {
        self.paths.contains(path)
    }
}

/// Lowercase and canonicalise separators so Windows path comparisons behave.
/// Trailing separators are stripped so containment prefixes are exact.
pub fn normalize_path(p: &str) -> String {
    let lowered = p.trim().to_ascii_lowercase().replace('/', "\\");
    lowered.trim_end_matches('\\').to_string()
}

/// The negative that a non-match resolves to. Never `NotObserved` unless the
/// sweep was complete (FR-74).
fn negative_for(map: &ModuleMap) -> Reachability {
    if map.is_complete() {
        Reachability::NotObserved
    } else {
        Reachability::Unknown
    }
}

/// Classify one finding's software against the collected module set (FR-77).
pub fn classify(software: &DetectedSoftware, map: &ModuleMap) -> Reachability {
    let key = &software.registry_key;

    // `pe://` keys are the absolute path of the image itself, so this is an
    // identity comparison. Filename matching is deliberately excluded: it
    // would re-conflate sibling copies of a bundled library, which is the
    // exact distinction this feature exists to draw.
    if let Some(path) = key.strip_prefix("pe://") {
        return if map.paths.contains(&normalize_path(path)) {
            Reachability::Loaded
        } else {
            negative_for(map)
        };
    }

    // These have no single on-disk image to match against.
    if key.starts_with("pip://")
        || key.starts_with("npm://")
        || key.starts_with("cargo://")
        || key.starts_with("os://")
    {
        return Reachability::Unknown;
    }

    // Package-manager entries: any loaded module under the install directory.
    // Without a directory the finding is unevaluable, and an unevaluable
    // finding is Unknown — reporting it as NotObserved would assert an
    // observation that was never made.
    let Some(dir) = software.install_location.as_deref() else {
        return Reachability::Unknown;
    };
    let dir = normalize_path(dir);
    if dir.is_empty() {
        return Reachability::Unknown;
    }

    // The trailing separator matters: without it `...\App` would also match
    // `...\AppTwo\x.dll`.
    let prefix = format!("{dir}\\");
    if map.paths.iter().any(|p| p.starts_with(&prefix)) {
        Reachability::Loaded
    } else {
        negative_for(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Architecture, DetectedSoftware};
    use std::collections::HashSet;

    fn sw(registry_key: &str, install_location: Option<&str>) -> DetectedSoftware {
        DetectedSoftware {
            name: "Test".into(),
            version: Some("1.0".into()),
            publisher: None,
            install_location: install_location.map(|s| s.to_string()),
            install_date: None,
            registry_key: registry_key.into(),
            architecture: Architecture::X64,
        }
    }

    fn map_of(paths: &[&str], readable: usize, total: usize) -> ModuleMap {
        let set: HashSet<String> = paths.iter().map(|p| normalize_path(p)).collect();
        ModuleMap::new(set, Coverage { readable, total })
    }

    /// FR-74. The single most important behaviour here: an incomplete sweep
    /// must not be able to say "not loaded". Only a complete sweep may.
    #[test]
    fn partial_coverage_forces_unknown_not_not_observed() {
        let m = map_of(&[r"C:\Other\thing.dll"], 5, 9);
        let s = sw(r"pe://C:\App\libcurl.dll", None);
        assert_eq!(classify(&s, &m), Reachability::Unknown);
    }

    /// The contrast case: with full coverage, a non-match is a real negative.
    #[test]
    fn full_coverage_non_match_is_not_observed() {
        let m = map_of(&[r"C:\Other\thing.dll"], 9, 9);
        let s = sw(r"pe://C:\App\libcurl.dll", None);
        assert_eq!(classify(&s, &m), Reachability::NotObserved);
    }

    /// FR-77. `pe://` keys ARE absolute paths, so this is identity, not
    /// inference. Case and separator differences must still match.
    #[test]
    fn pe_finding_matches_on_exact_path_case_insensitively() {
        let m = map_of(&[r"C:\App\libcurl.dll"], 9, 9);
        let s = sw(r"pe://c:/APP/LibCurl.DLL", None);
        assert_eq!(classify(&s, &m), Reachability::Loaded);
    }

    /// The noise class this whole feature exists to split. Three copies of the
    /// same library, one loaded. Filename matching would mark all three.
    #[test]
    fn three_sibling_copies_are_distinguished() {
        let m = map_of(&[r"C:\AppA\libcurl.dll"], 9, 9);
        let a = sw(r"pe://C:\AppA\libcurl.dll", None);
        let b = sw(r"pe://C:\AppB\libcurl.dll", None);
        let c = sw(r"pe://C:\AppC\libcurl.dll", None);

        assert_eq!(classify(&a, &m), Reachability::Loaded);
        assert_eq!(classify(&b, &m), Reachability::NotObserved);
        assert_eq!(classify(&c, &m), Reachability::NotObserved);
    }

    /// FR-77. Package-manager findings have no single image path, so any
    /// loaded module under the install directory counts.
    #[test]
    fn registry_finding_matches_by_install_directory_containment() {
        let m = map_of(&[r"C:\Program Files\Vendor\App\bin\helper.dll"], 9, 9);
        let s = sw("registry://vendor-app", Some(r"C:\Program Files\Vendor\App"));
        assert_eq!(classify(&s, &m), Reachability::Loaded);
    }

    /// Containment must not leak to a sibling directory sharing a prefix.
    #[test]
    fn containment_does_not_match_sibling_prefix_directory() {
        let m = map_of(&[r"C:\Program Files\Vendor\AppTwo\x.dll"], 9, 9);
        let s = sw("registry://vendor-app", Some(r"C:\Program Files\Vendor\App"));
        assert_eq!(classify(&s, &m), Reachability::NotObserved);
    }

    /// Spec §6. An unevaluable finding is Unknown, never NotObserved —
    /// asserting an observation that was never made is the same defect as
    /// FR-74, arriving through a different door. install_location is
    /// Option<String> and is genuinely absent for many registry/AppX entries.
    #[test]
    fn finding_without_install_location_is_unknown() {
        let m = map_of(&[r"C:\Anything\x.dll"], 9, 9);
        let s = sw("registry://no-location", None);
        assert_eq!(classify(&s, &m), Reachability::Unknown);
    }

    /// Spec §6. Ecosystem and OS findings have no single on-disk image.
    #[test]
    fn ecosystem_and_os_findings_are_unknown() {
        let m = map_of(&[r"C:\Anything\x.dll"], 9, 9);
        for key in ["pip://requests", "npm://lodash", "cargo://serde", "os://windows"] {
            let s = sw(key, Some(r"C:\Anything"));
            assert_eq!(
                classify(&s, &m),
                Reachability::Unknown,
                "{key} has no meaningful single image to match"
            );
        }
    }

    /// A map from a failed or skipped collection determines nothing.
    #[test]
    fn empty_unknown_map_classifies_everything_unknown() {
        let m = ModuleMap::empty_unknown();
        let s = sw(r"pe://C:\App\libcurl.dll", None);
        assert_eq!(classify(&s, &m), Reachability::Unknown);
    }

    #[test]
    fn default_reachability_is_unknown() {
        assert_eq!(Reachability::default(), Reachability::Unknown);
    }

    #[test]
    fn serde_uses_snake_case_per_dc6() {
        // DC-6: `loaded` | `not_observed` | `unknown`
        assert_eq!(
            serde_json::to_string(&Reachability::NotObserved).unwrap(),
            "\"not_observed\""
        );
        assert_eq!(
            serde_json::from_str::<Reachability>("\"loaded\"").unwrap(),
            Reachability::Loaded
        );
    }
}

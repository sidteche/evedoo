// SPDX-License-Identifier: Apache-2.0

//! Assigns `FindingStatus` (FR-59, FR-60).
//!
//! Must run *before* the new inventory snapshot overwrites the old one — the
//! difference between `New` and `NewlyApplicable` is precisely "was this
//! software in the previous snapshot", and that answer is destroyed by the
//! write.

use crate::models::{Finding, FindingStatus};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The host was observed just now.
    Scan,
    /// Stored inventory was re-correlated; nothing was observed. Constructed
    /// by `evedoo reassess` and by this module's own tests.
    Reassess,
}

/// Tag each finding. `previous_keys` is `(cve_id, software_name)` from the
/// last run; `previous_inventory` is the `registry_key` set from the previous
/// snapshot.
pub fn reconcile(
    findings: &mut [Finding],
    previous_keys: &HashSet<(String, String)>,
    previous_inventory: &HashSet<String>,
    mode: Mode,
) {
    for f in findings.iter_mut() {
        let key = (f.vulnerability.cve_id.clone(), f.software.name.clone());
        if previous_keys.contains(&key) {
            f.status = FindingStatus::Persisting;
            continue;
        }
        // The finding is new to the record. Which kind of new depends on
        // whether we already knew about the software.
        let software_known = previous_inventory.contains(&f.software.registry_key);
        f.status = match mode {
            // Reassessment observed nothing, so it can never claim software
            // appeared — every unrecorded finding is newly applicable.
            Mode::Reassess => FindingStatus::NewlyApplicable,
            Mode::Scan if software_known => FindingStatus::NewlyApplicable,
            Mode::Scan => FindingStatus::New,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Architecture, DetectedSoftware, Finding, MatchConfidence,
                        Remediation, Severity, Vulnerability};
    use std::collections::HashSet;

    fn finding(cve: &str, name: &str, key: &str) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: name.to_string(),
                version: Some("1.0".to_string()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: key.to_string(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: cve.to_string(),
                description: String::new(),
                cvss_score: Some(7.5),
                severity: Severity::High,
                published_date: None,
                references: vec![],
                remediation: Remediation::default(),
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Exact,
            vendor: Some("v".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        }
    }

    fn keys(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs.iter().map(|(c, n)| (c.to_string(), n.to_string())).collect()
    }

    fn inv(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    #[test]
    fn unseen_software_yields_new() {
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[]), &inv(&[]), Mode::Scan);
        assert_eq!(f[0].status, FindingStatus::New);
    }

    #[test]
    fn known_software_with_a_new_cve_yields_newly_applicable() {
        // The software was already in the previous snapshot; only the CVE is
        // new. This is the distinction that makes reassessment worth running.
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[]), &inv(&["pe://a.exe"]), Mode::Scan);
        assert_eq!(f[0].status, FindingStatus::NewlyApplicable);
    }

    #[test]
    fn previously_recorded_finding_persists() {
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[("CVE-1", "Alpha")]), &inv(&["pe://a.exe"]), Mode::Scan);
        assert_eq!(f[0].status, FindingStatus::Persisting);
    }

    #[test]
    fn reassess_never_emits_new() {
        // Reassessment observes no machine state, so it cannot claim software
        // appeared (FR-59) — even when the previous inventory is empty.
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[]), &inv(&[]), Mode::Reassess);
        assert_eq!(f[0].status, FindingStatus::NewlyApplicable);
        assert_ne!(f[0].status, FindingStatus::New);
    }

    #[test]
    fn filters_do_not_influence_status() {
        // FR-61 regression guard: a previous run that recorded only some
        // findings must not make the rest look New once filtering moves to
        // presentation. Same inputs, same statuses, regardless of severity.
        let mut a = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        let mut b = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        b[0].vulnerability.severity = Severity::Low;
        let k = keys(&[("CVE-1", "Alpha")]);
        let i = inv(&["pe://a.exe"]);
        reconcile(&mut a, &k, &i, Mode::Scan);
        reconcile(&mut b, &k, &i, Mode::Scan);
        assert_eq!(a[0].status, b[0].status);
    }
}

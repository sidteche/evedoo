// SPDX-License-Identifier: Apache-2.0

//! The single correlation pass (FR-62).
//!
//! Local scan, remote scan and reassessment all call this, so the three
//! cannot drift apart. It runs **unfiltered** (FR-61): severity and confidence
//! are presentation concerns, because filtering here would make persisted
//! findings and their delta status depend on which flags an invocation used.

use crate::matcher::CveMatcher;
use crate::models::{DetectedSoftware, Finding, FindingStatus};
use tracing::info;

pub struct CorrelationOutcome {
    pub findings: Vec<Finding>,
    /// Items that correlated to no applicable CVE, plus items whose lookup
    /// errored — both are "nothing to report" and are bucketed together
    /// here. An errored lookup is indistinguishable from a clean no-match
    /// downstream (the `--show-unmatched` coverage diagnostic in main.rs
    /// splits on identity resolution, not lookup success); the only trace
    /// of an error is the `info!` logged where it occurs, below, which a
    /// default run does not show.
    pub without_cves: Vec<DetectedSoftware>,
}

pub fn correlate(inventory: Vec<DetectedSoftware>, matcher: &CveMatcher) -> CorrelationOutcome {
    let mut findings = Vec::new();
    let mut without_cves = Vec::new();

    for sw in inventory {
        match matcher.find_vulnerabilities(&sw) {
            Ok(matches) if !matches.is_empty() => {
                for (mut vuln, confidence, vendor) in matches {
                    vuln.remediation.upgrade_command = crate::matcher::build_upgrade_command(
                        &sw.registry_key,
                        &sw.name,
                        vuln.remediation.fixed_version.as_deref(),
                    );
                    findings.push(Finding {
                        software: sw.clone(),
                        vulnerability: vuln,
                        confidence,
                        vendor,
                        // Assigned by reconcile(); correlate never guesses.
                        status: FindingStatus::New,
                        risk: None,
                        excepted: None,
                        reachability: Default::default(),
                    });
                }
            }
            Ok(_) => without_cves.push(sw),
            Err(e) => {
                info!("Error matching {}: {}", sw.name, e);
                without_cves.push(sw);
            }
        }
    }

    CorrelationOutcome { findings, without_cves }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Architecture;

    fn sw(name: &str) -> DetectedSoftware {
        DetectedSoftware {
            name: name.to_string(),
            version: Some("1.2.3".to_string()),
            publisher: None,
            install_location: None,
            install_date: None,
            registry_key: format!("pe://{name}.exe"),
            architecture: Architecture::X64,
        }
    }

    #[test]
    fn outcome_partitions_matched_and_unmatched() {
        // An empty matcher fixture correlates nothing, so every item must land
        // in `without_cves` and none in `findings`.
        let matcher = crate::matcher::tests_support::empty_matcher("correlate_partitions");
        let out = correlate(vec![sw("Alpha"), sw("Beta")], &matcher);
        assert!(out.findings.is_empty());
        assert_eq!(out.without_cves.len(), 2);
    }

    #[test]
    fn every_finding_starts_unclassified() {
        // Status is assigned later by reconcile(); correlate must not guess.
        let matcher = crate::matcher::tests_support::empty_matcher("correlate_unclassified");
        let out = correlate(vec![sw("Alpha")], &matcher);
        for f in &out.findings {
            assert_eq!(f.status, FindingStatus::New);
            assert!(f.risk.is_none());
            assert!(f.excepted.is_none());
        }
    }
}

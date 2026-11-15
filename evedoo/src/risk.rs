// SPDX-License-Identifier: Apache-2.0

//! Risk score and priority tier (FR-63..FR-66).
//!
//! The form is multiplicative, not a weighted sum: an additive blend cannot
//! express that a CVSS 9.8 with EPSS 0.001 is not urgent — it floors such a
//! finding around 40 no matter how the weights are chosen.
//!
//! Thresholds are calibrated against the CVE corpus rather than chosen by
//! taste. At P1 >= 60 / P2 >= 15 / P3 >= 9 the corpus splits 2.0% / 8.6% /
//! 14.9% / 74.5%, which is a usable triage pyramid. Earlier guesses of
//! 70/40/15 put 86% of CVEs in P4 using raw EPSS, and 92% in P1+P2 using the
//! percentile — both useless.
//!
//! **Measured against a real scan** (Task 9b, 868 findings, one Windows 11
//! desktop): P1 1.5% / P2 47.2% / P3 3.3% / P4 47.9%. P1 stayed well clear of
//! the ~25% ceiling that would indicate a mis-set `P1_MIN` for real
//! inventory, so the thresholds are unchanged. P2 and P3 traded places
//! relative to the corpus split — real installed software is a biased
//! sample skewed toward widely-deployed desktop applications, which tend to
//! carry a known (often non-trivial) EPSS score rather than the corpus's
//! long tail of obscure, low-EPSS CVEs, so more of them clear `P2_MIN` and
//! fewer land in the `P3_MIN` band or below. Worth re-measuring across more
//! machines before treating `P2_MIN`/`P3_MIN` as mis-set; only the P1 gate
//! was in this task's remit.

use crate::models::{Priority, RiskAssessment, Vulnerability};
use crate::reachability::Reachability;

/// Median EPSS across scored CVEs, used when a CVE has none (FR-66).
/// Re-derive whenever the thresholds below are recalibrated.
pub const MEDIAN_EPSS: f32 = 0.00696;

pub const P1_MIN: f32 = 60.0;
pub const P2_MIN: f32 = 15.0;
pub const P3_MIN: f32 = 9.0;

/// Likelihood floor applied when a reference carries NVD's `Exploit` tag.
/// Deliberately small: the tag covers 23.1% of the corpus, so it corroborates
/// rather than proves.
const EXPLOIT_FLOOR: f32 = 0.10;
/// Likelihood floor for CISA KEV membership — confirmed exploitation.
const KEV_FLOOR: f32 = 0.90;

/// Multiplier derived from an asset's fleet tags (FR-65). 1.0 for an
/// unregistered host, which is the normal single-machine case.
pub fn criticality_for(tags: &str) -> f32 {
    let lower = tags.to_ascii_lowercase();
    let has = |t: &str| lower.split(',').any(|x| x.trim() == t);
    if has("critical") {
        1.25
    } else if has("prod") || has("production") {
        1.15
    } else if has("lab") || has("test") || has("dev") {
        0.85
    } else {
        1.0
    }
}

/// Multiplier applied when a finding's code is mapped into a live process
/// (FR-78). Chosen to match the top of the `criticality_for` scale so the two
/// multipliers stay commensurate and neither silently dominates.
///
/// There is deliberately no factor below 1.0. A scan is a seconds-long sample
/// of a machine that runs for months, so "not loaded right now" is not
/// evidence of safety and must never reduce a score.
pub const REACH_LOADED_FACTOR: f32 = 1.25;

fn reach_factor(r: Reachability) -> f32 {
    match r {
        Reachability::Loaded => REACH_LOADED_FACTOR,
        Reachability::NotObserved | Reachability::Unknown => 1.0,
    }
}

pub fn assess(
    v: &Vulnerability,
    has_exploit_ref: bool,
    criticality: f32,
    reachability: Reachability,
) -> RiskAssessment {
    let epss_known = v.epss_score.is_some();
    let mut likelihood = v.epss_score.unwrap_or(MEDIAN_EPSS);
    if v.in_kev {
        likelihood = likelihood.max(KEV_FLOOR);
    }
    if has_exploit_ref {
        likelihood = likelihood.max(EXPLOIT_FLOOR);
    }

    let impact = (v.cvss_score.unwrap_or(0.0) / 10.0).clamp(0.0, 1.0);
    let score = (100.0
        * impact.powf(0.4)
        * likelihood.powf(0.6)
        * criticality
        * reach_factor(reachability))
    .clamp(0.0, 100.0);

    let mut tier = if score >= P1_MIN {
        Priority::P1
    } else if score >= P2_MIN {
        Priority::P2
    } else if score >= P3_MIN {
        Priority::P3
    } else {
        Priority::P4
    };

    // Confirmed in-the-wild exploitation outranks the arithmetic.
    if v.in_kev {
        tier = Priority::P1;
    }
    // An unknown likelihood must not be presented as a low one (FR-66).
    if !epss_known && tier == Priority::P4 {
        tier = Priority::P3;
    }

    RiskAssessment { score, tier, epss_known }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Remediation, Severity, Vulnerability};

    fn vuln(cvss: f32, epss: Option<f32>, kev: bool) -> Vulnerability {
        Vulnerability {
            cve_id: "CVE-2024-0001".into(),
            description: String::new(),
            cvss_score: Some(cvss),
            severity: Severity::High,
            published_date: None,
            references: vec![],
            remediation: Remediation::default(),
            epss_score: epss,
            epss_percentile: None,
            in_kev: kev,
            kev_due_date: None,
            kev_ransomware_use: None,
        }
    }

    #[test]
    fn high_cvss_with_negligible_epss_is_not_urgent() {
        // The premise the whole feature rests on: CVSS 9.8 + EPSS 0.001 is
        // not a fire. A purely additive blend cannot express this.
        let r = assess(&vuln(9.8, Some(0.001), false), false, 1.0, Reachability::Unknown);
        assert!(r.score < 9.0, "expected low score, got {}", r.score);
        assert_eq!(r.tier, Priority::P4);
    }

    #[test]
    fn moderate_cvss_in_kev_is_urgent() {
        let r = assess(&vuln(7.5, Some(0.02), true), false, 1.0, Reachability::Unknown);
        assert!(r.score > 60.0, "expected high score, got {}", r.score);
        assert_eq!(r.tier, Priority::P1);
    }

    #[test]
    fn kev_forces_p1_regardless_of_score() {
        // Low CVSS keeps the number modest; KEV still means "patch this".
        let r = assess(&vuln(2.0, Some(0.001), true), false, 1.0, Reachability::Unknown);
        assert_eq!(r.tier, Priority::P1);
    }

    #[test]
    fn kev_with_unknown_epss_still_lands_p1() {
        // Guards the order of the two `if` blocks in `assess`: the KEV branch
        // sets P1 before the unknown-EPSS floor (which only raises P4 to P3)
        // ever runs, so the floor must not be able to demote a KEV finding.
        let r = assess(&vuln(7.5, None, true), false, 1.0, Reachability::Unknown);
        assert_eq!(r.tier, Priority::P1);
    }

    #[test]
    fn unknown_epss_is_floored_at_p3_and_marked() {
        // Absence of an EPSS score is absence of evidence. A CVSS 10 with no
        // EPSS scores ~5 and would otherwise land in P4 (FR-66).
        let r = assess(&vuln(10.0, None, false), false, 1.0, Reachability::Unknown);
        assert!(!r.epss_known);
        assert_eq!(r.tier, Priority::P3);
    }

    #[test]
    fn known_epss_is_marked_known() {
        assert!(assess(&vuln(5.0, Some(0.2), false), false, 1.0, Reachability::Unknown).epss_known);
    }

    #[test]
    fn exploit_tag_raises_a_low_epss_finding() {
        let without = assess(&vuln(7.0, Some(0.001), false), false, 1.0, Reachability::Unknown).score;
        let with = assess(&vuln(7.0, Some(0.001), false), true, 1.0, Reachability::Unknown).score;
        assert!(with > without, "exploit-tagged reference must raise likelihood");
    }

    #[test]
    fn score_is_monotonic_in_both_axes() {
        let a = assess(&vuln(5.0, Some(0.1), false), false, 1.0, Reachability::Unknown).score;
        let b = assess(&vuln(9.0, Some(0.1), false), false, 1.0, Reachability::Unknown).score;
        let c = assess(&vuln(5.0, Some(0.5), false), false, 1.0, Reachability::Unknown).score;
        assert!(b > a, "raising CVSS must not lower the score");
        assert!(c > a, "raising EPSS must not lower the score");
    }

    #[test]
    fn criticality_never_pushes_past_one_hundred() {
        let r = assess(&vuln(10.0, Some(0.99), true), true, 1.25, Reachability::Unknown);
        assert!(r.score <= 100.0, "score must clamp, got {}", r.score);
    }

    #[test]
    fn criticality_reads_fleet_tags() {
        assert_eq!(criticality_for("prod,web,critical"), 1.25);
        assert_eq!(criticality_for("prod,web"), 1.15);
        assert_eq!(criticality_for("lab"), 0.85);
        assert_eq!(criticality_for(""), 1.0);
        assert_eq!(criticality_for("unrelated,tags"), 1.0);
    }

    /// FR-78, and the constraint the whole feature rests on: a finding that
    /// is not loaded must score EXACTLY what it scores today. Not "roughly",
    /// not "close to" — a scan is a seconds-long sample of a machine that
    /// runs for months, so a non-observation must cost nothing.
    #[test]
    fn unloaded_and_unknown_never_change_the_score() {
        let v = vuln(7.5, Some(0.2), false);
        let baseline = assess(&v, false, 1.0, Reachability::Unknown);
        let not_observed = assess(&v, false, 1.0, Reachability::NotObserved);

        assert_eq!(baseline.score, not_observed.score);
        assert_eq!(baseline.tier, not_observed.tier);
    }

    #[test]
    fn loaded_raises_the_score_by_exactly_the_factor() {
        let v = vuln(7.5, Some(0.2), false);
        let base = assess(&v, false, 1.0, Reachability::NotObserved);
        let loaded = assess(&v, false, 1.0, Reachability::Loaded);

        let expected = (base.score * REACH_LOADED_FACTOR).min(100.0);
        assert!(
            (loaded.score - expected).abs() < 0.001,
            "loaded {} should be base {} * {}",
            loaded.score,
            base.score,
            REACH_LOADED_FACTOR
        );
    }

    /// No reachability value may ever reduce a score below the unloaded
    /// baseline. This is the guard that would catch a well-meaning future
    /// "demote dormant findings" change.
    #[test]
    fn no_reachability_value_lowers_the_score() {
        for cvss in [1.0_f32, 5.0, 9.8] {
            for epss in [None, Some(0.01_f32), Some(0.9)] {
                let v = vuln(cvss, epss, false);
                let base = assess(&v, false, 1.0, Reachability::NotObserved).score;
                for r in [
                    Reachability::Loaded,
                    Reachability::NotObserved,
                    Reachability::Unknown,
                ] {
                    assert!(
                        assess(&v, false, 1.0, r).score >= base,
                        "reachability {r:?} lowered the score for cvss={cvss} epss={epss:?}"
                    );
                }
            }
        }
    }

    /// The score is clamped, so the boost cannot push past the scale.
    #[test]
    fn loaded_score_stays_within_the_scale() {
        let v = vuln(10.0, Some(0.99), true);
        let loaded = assess(&v, true, 1.25, Reachability::Loaded);
        assert!(loaded.score <= 100.0);
    }
}

//! Data models for the Evedoo vulnerability scanner.
//!
//! SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Software detected on the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSoftware {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub install_date: Option<String>,
    pub registry_key: String,
    pub architecture: Architecture,
}

/// System architecture
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Architecture {
    X64,
    X86,
    #[default]
    Unknown,
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::X64 => write!(f, "64-bit"),
            Architecture::X86 => write!(f, "32-bit"),
            Architecture::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Match confidence level for a finding
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchConfidence {
    /// Curated mapping: display name matched a known (vendor, product) pair
    Exact,
    /// Exact product + vendor validated via publisher field
    High,
    /// Product-only match, vendor not confirmed
    Medium,
    /// Fuzzy/fallback match
    Low,
}

impl std::fmt::Display for MatchConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchConfidence::Exact => write!(f, "Exact"),
            MatchConfidence::High => write!(f, "High"),
            MatchConfidence::Medium => write!(f, "Medium"),
            MatchConfidence::Low => write!(f, "Low"),
        }
    }
}

impl MatchConfidence {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "exact" => MatchConfidence::Exact,
            "high" => MatchConfidence::High,
            "medium" => MatchConfidence::Medium,
            "low" => MatchConfidence::Low,
            _ => MatchConfidence::Low,
        }
    }
}

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    pub fn from_score(score: f32) -> Self {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// A matched vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub severity: Severity,
    pub published_date: Option<String>,
    pub references: Vec<String>,
    pub remediation: Remediation,
    /// EPSS probability of exploitation in the next 30 days, `[0, 1]`.
    #[serde(default)]
    pub epss_score: Option<f32>,
    /// EPSS percentile rank, `[0, 1]`.
    #[serde(default)]
    pub epss_percentile: Option<f32>,
    /// True if CISA has added this CVE to the Known Exploited Vulnerabilities catalog.
    #[serde(default)]
    pub in_kev: bool,
    /// CISA-mandated remediation due date for federal agencies (YYYY-MM-DD).
    #[serde(default)]
    pub kev_due_date: Option<String>,
    /// "Known" or "Unknown" — whether CISA has tied this CVE to ransomware activity.
    #[serde(default)]
    pub kev_ransomware_use: Option<String>,
}

/// Remediation recommendation with patch intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub recommendation: String,
    pub fixed_version: Option<String>,
    pub vendor_advisory: Option<String>,
    /// Microsoft KB article IDs extracted from NVD references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kb_articles: Vec<String>,
    /// Auto-generated upgrade command (winget, pip, npm, choco, scoop).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_command: Option<String>,
}

impl Default for Remediation {
    fn default() -> Self {
        Self {
            recommendation: "Update to the latest version or contact vendor for patches."
                .to_string(),
            fixed_version: None,
            vendor_advisory: None,
            kb_articles: Vec::new(),
            upgrade_command: None,
        }
    }
}

/// Why a finding is in the report. `New` and `NewlyApplicable` are distinct on
/// purpose (FR-60): "you installed something vulnerable" and "a CVE was
/// published against what you already had" need different operator responses,
/// and collapsing them makes reassessment pointless.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    /// Software was absent from the previous inventory snapshot.
    New,
    /// Software was already known; the CVE data now matches it.
    NewlyApplicable,
    /// Present in the previous run and still present.
    Persisting,
    /// Software removed, or its version now falls outside the affected range.
    Resolved,
    /// CVE data changed such that the match no longer holds.
    NoLongerApplicable,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::New                 => write!(f, "New"),
            FindingStatus::NewlyApplicable      => write!(f, "NewlyApplicable"),
            FindingStatus::Persisting           => write!(f, "Persisting"),
            FindingStatus::Resolved             => write!(f, "Resolved"),
            FindingStatus::NoLongerApplicable   => write!(f, "NoLongerApplicable"),
        }
    }
}

/// Triage bucket. `P1 < P2` so a plain sort puts the most urgent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    P1,
    P2,
    P3,
    P4,
}

impl Priority {
    /// Parses `--min-priority`. The command line rejects anything but
    /// `p1`..`p4` before this runs (`parse_min_priority` in main.rs), so the
    /// `P4` fallback is unreachable from the CLI; it remains the permissive
    /// choice (`tier <= P4` always holds) for any other caller.
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "P1" => Priority::P1,
            "P2" => Priority::P2,
            "P3" => Priority::P3,
            _ => Priority::P4,
        }
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::P1 => write!(f, "P1"),
            Priority::P2 => write!(f, "P2"),
            Priority::P3 => write!(f, "P3"),
            Priority::P4 => write!(f, "P4"),
        }
    }
}

/// Risk assessment for one finding (FR-63).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// `[0, 100]`.
    pub score: f32,
    pub tier: Priority,
    /// False when the CVE had no EPSS score: `score` used the corpus median
    /// and `tier` was floored at P3 (FR-66). Reports should mark such a score
    /// provisional rather than presenting it as measured.
    pub epss_known: bool,
}

/// The exception that suppressed a finding (FR-70). Its presence is a change
/// of view, never a change of record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExceptionRef {
    pub id: i64,
    pub owner: String,
    pub reason: String,
    pub expires_at: String,
}

/// A vulnerability finding linking software to CVE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub software: DetectedSoftware,
    pub vulnerability: Vulnerability,
    pub confidence: MatchConfidence,
    pub vendor: Option<String>,
    pub status: FindingStatus,
    /// Populated by the risk stage (FR-63); `None` if scoring was skipped.
    #[serde(default)]
    pub risk: Option<RiskAssessment>,
    /// Set when an exception matched (FR-70). The finding stays in the
    /// pipeline and in history regardless.
    #[serde(default)]
    pub excepted: Option<ExceptionRef>,
    /// Whether this finding's code was mapped into a live process at scan
    /// time (FR-73). `#[serde(default)]` keeps older JSON artifacts readable
    /// per DC-3; they deserialise as `Unknown`, which is exactly right —
    /// those scans never determined it.
    #[serde(default)]
    pub reachability: crate::reachability::Reachability,
}

/// Whether the scan ran locally or against a remote machine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanMode {
    Local,
    Remote,
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::Local => write!(f, "Local"),
            ScanMode::Remote => write!(f, "Remote"),
        }
    }
}

/// Complete scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_time: DateTime<Utc>,
    pub hostname: String,
    #[serde(default = "default_scan_mode")]
    pub scan_mode: ScanMode,
    pub total_software: usize,
    pub total_vulnerabilities: usize,
    pub findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub software_without_cves: Vec<DetectedSoftware>,
    /// Whether `finding.status` (New/NewlyApplicable/Persisting/...) reflects
    /// a real comparison against a previous run. `correlate()` stamps every
    /// finding with the placeholder `FindingStatus::New` before reconciliation
    /// (see `correlate.rs`); this flag is `false` until `reconcile::reconcile`
    /// has actually run against a real baseline (`--no-history`, a history-DB
    /// open failure, or a `load_previous_keys` read failure all leave it
    /// `false`). Reports must not present a per-finding delta status while
    /// this is `false` — doing so asserts a comparison the tool never made.
    /// `#[serde(default)]` so JSON from a previous release (which never wrote
    /// this field) still parses as `false`, the safe/conservative default.
    #[serde(default)]
    pub delta_known: bool,
}

fn default_scan_mode() -> ScanMode {
    ScanMode::Local
}

impl ScanResult {
    pub fn new(hostname: String) -> Self {
        Self {
            scan_time: Utc::now(),
            hostname,
            scan_mode: ScanMode::Local,
            total_software: 0,
            total_vulnerabilities: 0,
            findings: Vec::new(),
            resolved_findings: Vec::new(),
            software_without_cves: Vec::new(),
            delta_known: false,
        }
    }

    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.vulnerability.severity == severity)
            .count()
    }

    /// Sort findings into priority order: KEV → EPSS score → CVSS score →
    /// published date. All tiers descending so the most urgent finding lands
    /// at index 0. CVSS is the third sort key (not first) because CISA KEV
    /// status is a stronger "this is being exploited" signal than a CVSS
    /// base score in isolation.
    pub fn sort_findings_by_priority(&mut self) {
        self.findings.sort_by(|a, b| {
            let av = &a.vulnerability;
            let bv = &b.vulnerability;
            bv.in_kev
                .cmp(&av.in_kev)
                .then_with(|| {
                    bv.epss_score
                        .unwrap_or(0.0)
                        .partial_cmp(&av.epss_score.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    bv.cvss_score
                        .unwrap_or(0.0)
                        .partial_cmp(&av.cvss_score.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| bv.published_date.cmp(&av.published_date))
        });
    }

    /// Sort findings by computed risk (FR-67, `--sort risk`): priority tier
    /// ascending (P1 first — `Priority`'s `Ord` already puts P1 < P4), then
    /// score descending within a tier. A finding with no risk assessment
    /// (scoring skipped, or a resolved stub) is never treated as more urgent
    /// than a scored one — it sorts after every tier, not at some numeric
    /// default that could accidentally outrank a real P4.
    pub fn sort_findings_by_risk(&mut self) {
        self.findings.sort_by(|a, b| {
            let a_tier = a.risk.as_ref().map(|r| r.tier);
            let b_tier = b.risk.as_ref().map(|r| r.tier);
            let tier_cmp = match (a_tier, b_tier) {
                (Some(at), Some(bt)) => at.cmp(&bt),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            };
            tier_cmp.then_with(|| {
                let a_score = a.risk.as_ref().map(|r| r.score).unwrap_or(0.0);
                let b_score = b.risk.as_ref().map(|r| r.score).unwrap_or(0.0);
                b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
            })
        });
    }
}

/// Database CVE record
#[derive(Debug, Clone)]
pub struct CveRecord {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub severity: Option<String>,
    pub published_date: Option<String>,
}

/// Database CPE match record.
///
/// Vendor and product are not stored on the record: callers already know the
/// `(vendor, product)` pair they queried with, so re-copying them per row
/// would be pure waste. The index keeps them on the `IndexedCpe` side for key
/// construction and drops them here.
#[derive(Debug, Clone)]
pub struct CpeMatchRecord {
    pub cve_id: String,
    /// Exact version pinned in the CPE URI (`cpe:2.3:a:vendor:product:1.2.3:*`).
    /// `None` if the CPE used `*` or `-`. Used as a fallback when no range is set.
    pub version: Option<String>,
    pub version_start_including: Option<String>,
    pub version_end_excluding: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    /// CPE `target_sw` — the ecosystem the product runs in (`python`,
    /// `node.js`, `wordpress`, ...). `None` for `*`/`-` or pre-target_sw
    /// databases. Gates ecosystem packages against ecosystem CPE rows.
    pub target_sw: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_status_display() {
        assert_eq!(FindingStatus::New.to_string(),               "New");
        assert_eq!(FindingStatus::NewlyApplicable.to_string(),   "NewlyApplicable");
        assert_eq!(FindingStatus::Persisting.to_string(),        "Persisting");
        assert_eq!(FindingStatus::Resolved.to_string(),          "Resolved");
        assert_eq!(FindingStatus::NoLongerApplicable.to_string(),"NoLongerApplicable");
    }

    #[test]
    fn remediation_default_recommendation_is_the_friendly_sentence() {
        // Regression guard: this default is read by history.rs's
        // load_resolved_finding as report-visible text. A derive(Default)
        // would silently turn it into "", so this must stay a manual impl.
        assert_eq!(
            Remediation::default().recommendation,
            "Update to the latest version or contact vendor for patches."
        );
    }

    #[test]
    fn match_confidence_ordering() {
        assert!(MatchConfidence::Exact  < MatchConfidence::High);
        assert!(MatchConfidence::High   < MatchConfidence::Medium);
        assert!(MatchConfidence::Medium < MatchConfidence::Low);
    }

    #[test]
    fn match_confidence_from_str_round_trip() {
        assert_eq!(MatchConfidence::from_str("exact"),  MatchConfidence::Exact);
        assert_eq!(MatchConfidence::from_str("high"),   MatchConfidence::High);
        assert_eq!(MatchConfidence::from_str("medium"), MatchConfidence::Medium);
        assert_eq!(MatchConfidence::from_str("low"),    MatchConfidence::Low);
        assert_eq!(MatchConfidence::from_str("bogus"),  MatchConfidence::Low);
    }

    fn mk_finding(
        cve: &str,
        cvss: Option<f32>,
        severity: Severity,
        in_kev: bool,
        epss: Option<f32>,
    ) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: "App".into(),
                version: None,
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: String::new(),
                architecture: Architecture::Unknown,
            },
            vulnerability: Vulnerability {
                cve_id: cve.into(),
                description: String::new(),
                cvss_score: cvss,
                severity,
                published_date: Some("2024-01-01".into()),
                references: vec![],
                remediation: Remediation::default(),
                epss_score: epss,
                epss_percentile: None,
                in_kev,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::High,
            vendor: None,
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        }
    }

    #[test]
    fn sort_puts_kev_before_high_cvss_non_kev() {
        // A KEV entry with a mediocre CVSS should outrank a 9.8 critical
        // that is *not* on CISA's exploited list.
        let mut result = ScanResult::new("h".into());
        result.findings.push(mk_finding(
            "CVE-2024-CRIT",
            Some(9.8),
            Severity::Critical,
            false,
            Some(0.10),
        ));
        result.findings.push(mk_finding(
            "CVE-2024-KEV",
            Some(6.5),
            Severity::Medium,
            true,
            Some(0.05),
        ));
        result.sort_findings_by_priority();
        assert_eq!(result.findings[0].vulnerability.cve_id, "CVE-2024-KEV");
        assert_eq!(result.findings[1].vulnerability.cve_id, "CVE-2024-CRIT");
    }

    #[test]
    fn sort_epss_breaks_tie_among_non_kev() {
        // Two non-KEV findings with the same CVSS — the higher EPSS should win.
        let mut result = ScanResult::new("h".into());
        result.findings.push(mk_finding(
            "CVE-LOW-EPSS",
            Some(7.5),
            Severity::High,
            false,
            Some(0.02),
        ));
        result.findings.push(mk_finding(
            "CVE-HIGH-EPSS",
            Some(7.5),
            Severity::High,
            false,
            Some(0.85),
        ));
        result.sort_findings_by_priority();
        assert_eq!(result.findings[0].vulnerability.cve_id, "CVE-HIGH-EPSS");
    }

    #[test]
    fn sort_cvss_breaks_tie_when_epss_equal() {
        let mut result = ScanResult::new("h".into());
        result.findings.push(mk_finding(
            "CVE-LOW-CVSS",
            Some(4.0),
            Severity::Medium,
            false,
            None,
        ));
        result.findings.push(mk_finding(
            "CVE-HIGH-CVSS",
            Some(9.0),
            Severity::Critical,
            false,
            None,
        ));
        result.sort_findings_by_priority();
        assert_eq!(result.findings[0].vulnerability.cve_id, "CVE-HIGH-CVSS");
    }

    fn mk_finding_with_risk(cve: &str, tier: Priority, score: f32) -> Finding {
        let mut f = mk_finding(cve, Some(5.0), Severity::Medium, false, Some(0.1));
        f.risk = Some(RiskAssessment { score, tier, epss_known: true });
        f
    }

    /// `--sort risk` (FR-67) orders by priority tier — P1 first — not by the
    /// raw KEV/EPSS/CVSS/date dimensions `sort_findings_by_priority` uses.
    #[test]
    fn sort_by_risk_orders_p1_before_p4() {
        let mut result = ScanResult::new("h".into());
        result.findings.push(mk_finding_with_risk("CVE-P4", Priority::P4, 2.0));
        result.findings.push(mk_finding_with_risk("CVE-P1", Priority::P1, 80.0));
        result.sort_findings_by_risk();
        assert_eq!(result.findings[0].vulnerability.cve_id, "CVE-P1");
        assert_eq!(result.findings[1].vulnerability.cve_id, "CVE-P4");
    }

    /// Within the same tier, the higher score must sort first — tier alone
    /// is too coarse to order two P1s against each other.
    #[test]
    fn sort_by_risk_breaks_tier_ties_on_score() {
        let mut result = ScanResult::new("h".into());
        result.findings.push(mk_finding_with_risk("CVE-LOWER", Priority::P1, 65.0));
        result.findings.push(mk_finding_with_risk("CVE-HIGHER", Priority::P1, 95.0));
        result.sort_findings_by_risk();
        assert_eq!(result.findings[0].vulnerability.cve_id, "CVE-HIGHER");
    }

    /// A finding with no risk assessment (e.g. scoring was skipped) must
    /// never be presented as more urgent than a scored one — it sorts last,
    /// not first via some numeric default.
    #[test]
    fn sort_by_risk_places_unscored_findings_last() {
        let mut result = ScanResult::new("h".into());
        result.findings.push(mk_finding("CVE-UNSCORED", Some(5.0), Severity::Medium, false, Some(0.1)));
        result.findings.push(mk_finding_with_risk("CVE-P4", Priority::P4, 2.0));
        result.sort_findings_by_risk();
        assert_eq!(result.findings[0].vulnerability.cve_id, "CVE-P4");
        assert_eq!(result.findings[1].vulnerability.cve_id, "CVE-UNSCORED");
    }
}

#[cfg(test)]
mod operationalisation_tests {
    use super::*;

    #[test]
    fn every_status_survives_a_json_round_trip() {
        for s in [
            FindingStatus::New,
            FindingStatus::NewlyApplicable,
            FindingStatus::Persisting,
            FindingStatus::Resolved,
            FindingStatus::NoLongerApplicable,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: FindingStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn priority_sorts_most_urgent_first() {
        let mut v = vec![Priority::P3, Priority::P1, Priority::P4, Priority::P2];
        v.sort();
        assert_eq!(v, vec![Priority::P1, Priority::P2, Priority::P3, Priority::P4]);
    }

    #[test]
    fn json_without_risk_or_excepted_still_parses() {
        // DC-3: new fields are additive, so output from a previous release
        // must still deserialize.
        let legacy = r#"{
            "software": {"name":"App","version":"1.0","publisher":null,
                         "install_location":null,"install_date":null,
                         "registry_key":"pe://app.exe","architecture":"X64"},
            "vulnerability": {"cve_id":"CVE-2024-0001","description":"d",
                              "cvss_score":7.5,"severity":"High",
                              "published_date":null,"references":[],
                              "remediation":{"recommendation":"",
                                             "fixed_version":null,
                                             "vendor_advisory":null}},
            "confidence":"Exact","vendor":"v","status":"New"
        }"#;
        let f: Finding = serde_json::from_str(legacy).expect("legacy JSON must parse");
        assert!(f.risk.is_none());
        assert!(f.excepted.is_none());
    }

    #[test]
    fn delta_known_defaults_to_false() {
        // A fresh ScanResult has run neither correlate() nor reconcile(), so
        // there is nothing to compare against yet.
        let result = ScanResult::new("host".into());
        assert!(!result.delta_known);
    }

    #[test]
    fn scan_result_json_without_delta_known_still_parses() {
        // DC-3: delta_known is additive. JSON written by a previous release
        // (before this field existed) must still deserialize, and must land
        // on the conservative `false` default rather than failing to parse
        // or fabricating `true`.
        let legacy = r#"{
            "scan_time": "2024-01-01T00:00:00Z",
            "hostname": "host",
            "total_software": 0,
            "total_vulnerabilities": 0,
            "findings": [],
            "resolved_findings": [],
            "software_without_cves": []
        }"#;
        let result: ScanResult = serde_json::from_str(legacy).expect("legacy JSON must parse");
        assert!(!result.delta_known);
    }
}

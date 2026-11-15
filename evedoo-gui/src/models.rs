// Serde structs mirroring evedoo's JSON output for deserialization.
//
// These are standalone copies (not imported from evedoo crate) to avoid
// pulling in winreg and other Windows-only scanner dependencies.
//
// SPDX-License-Identifier: Apache-2.0

// Some fields exist solely for serde deserialization fidelity with the CLI's
// JSON output and are not directly read by the GUI code.

use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ScanResult {
    pub scan_time: DateTime<Utc>,
    pub hostname: String,
    #[serde(default = "default_scan_mode")]
    pub scan_mode: ScanMode,
    pub total_software: usize,
    pub total_vulnerabilities: usize,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub resolved_findings: Vec<Finding>,
    #[serde(default)]
    pub software_without_cves: Vec<DetectedSoftware>,
    /// Whether `finding.status` reflects a real comparison against a
    /// previous run (status-honesty fix, mirrors `evedoo::models::ScanResult`).
    /// `#[serde(default)]` so JSON from a evedoo build that predates this
    /// field still deserializes, landing on the conservative `false`.
    #[serde(default)]
    pub delta_known: bool,
}

fn default_scan_mode() -> ScanMode {
    ScanMode::Local
}

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectedSoftware {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub install_date: Option<String>,
    pub registry_key: String,
    pub architecture: Architecture,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub severity: Severity,
    pub published_date: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub remediation: Remediation,
    #[serde(default)]
    pub epss_score: Option<f32>,
    #[serde(default)]
    pub epss_percentile: Option<f32>,
    #[serde(default)]
    pub in_kev: bool,
    #[serde(default)]
    pub kev_due_date: Option<String>,
    #[serde(default)]
    pub kev_ransomware_use: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Remediation {
    pub recommendation: String,
    pub fixed_version: Option<String>,
    pub vendor_advisory: Option<String>,
    #[serde(default)]
    pub kb_articles: Vec<String>,
    #[serde(default)]
    pub upgrade_command: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchConfidence {
    Exact,
    High,
    Medium,
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    New,
    NewlyApplicable,
    Persisting,
    Resolved,
    NoLongerApplicable,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::New => write!(f, "New"),
            FindingStatus::NewlyApplicable => write!(f, "NewlyApplicable"),
            FindingStatus::Persisting => write!(f, "Persisting"),
            FindingStatus::Resolved => write!(f, "Resolved"),
            FindingStatus::NoLongerApplicable => write!(f, "NoLongerApplicable"),
        }
    }
}

/// Triage bucket. `P1 < P2` so a plain sort puts the most urgent first.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    P1,
    P2,
    P3,
    P4,
}

/// Risk assessment for one finding (FR-63).
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExceptionRef {
    pub id: i64,
    pub owner: String,
    pub reason: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum ScanMode {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum Architecture {
    X64,
    X86,
    Unknown,
}

//! JSON report generator.
//!
//! SPDX-License-Identifier: Apache-2.0

use super::Reporter;
use crate::error::{Result, ScanError};
use crate::models::ScanResult;

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn generate(&self, result: &ScanResult) -> Result<String> {
        let mut value =
            serde_json::to_value(result).map_err(|e| ScanError::SerializationError(e.to_string()))?;
        // Additive: readers that deserialize into `ScanResult` ignore it.
        if let Some(object) = value.as_object_mut() {
            object.insert("data_notice".to_string(), super::NVD_NOTICE.into());
        }
        serde_json::to_string_pretty(&value).map_err(|e| ScanError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Status-honesty fix: `delta_known` is the machine-readable signal that
    /// a JSON consumer (e.g. the GUI, or a pipeline reading `-f json`) needs
    /// to tell a real per-finding `status` apart from `correlate()`'s
    /// placeholder `FindingStatus::New`, which is never replaced when the
    /// delta wasn't actually computed (`--no-history`, a history-DB-open
    /// failure, or a `load_previous_keys` read failure). It must reach the
    /// artifact in both states.
    #[test]
    fn json_report_carries_the_nvd_notice_and_still_parses_as_a_scan_result() {
        let json = JsonReporter.generate(&ScanResult::new("host".into())).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["data_notice"], crate::report::NVD_NOTICE);
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hostname, "host");
    }

    #[test]
    fn json_report_surfaces_delta_known_true() {
        let mut result = ScanResult::new("host".into());
        result.delta_known = true;
        let json = JsonReporter.generate(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["delta_known"], true);
    }

    #[test]
    fn json_report_surfaces_delta_known_false() {
        let result = ScanResult::new("host".into());
        let json = JsonReporter.generate(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["delta_known"], false);
    }

    /// DC-6. The JSON artifact carries `reachability` per finding as one of
    /// `loaded` | `not_observed` | `unknown`. This is a published data
    /// contract, and it reaches the artifact only because `Finding`
    /// serialises directly — nothing in json.rs mentions the field, so
    /// without this test the contract would rest on an implementation
    /// detail no one is watching.
    #[test]
    fn json_report_carries_reachability_per_dc6() {
        use crate::models::{
            Architecture, DetectedSoftware, Finding, FindingStatus, MatchConfidence, Remediation,
            ScanResult, Severity, Vulnerability,
        };
        use crate::reachability::Reachability;

        let mut result = ScanResult::new("host".into());
        result.findings.push(Finding {
            software: DetectedSoftware {
                name: "App".into(),
                version: Some("1.0".into()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: "pe://c:/app/x.dll".into(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: "CVE-2024-0001".into(),
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
            vendor: None,
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Reachability::Loaded,
        });

        let json = JsonReporter.generate(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["findings"][0]["reachability"], "loaded");
    }
}

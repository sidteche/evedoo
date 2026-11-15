//! SPDX 2.3 SBOM report generator (inventory only, no vulnerability section).
//!
//! SPDX-License-Identifier: Apache-2.0

use serde::Serialize;
use uuid::Uuid;

use super::Reporter;
use crate::error::{Result, ScanError};
use crate::models::{DetectedSoftware, ScanResult};

pub struct SpdxReporter;

impl Reporter for SpdxReporter {
    fn generate(&self, result: &ScanResult) -> Result<String> {
        let doc = build_document(result);
        serde_json::to_string_pretty(&doc)
            .map_err(|e| ScanError::SerializationError(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// SPDX 2.3 JSON schema structs (private, serialization-only)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: &'static str,
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdx_id: &'static str,
    name: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    packages: Vec<SpdxPackage>,
    relationships: Vec<SpdxRelationship>,
}

#[derive(Serialize)]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<String>,
    download_location: &'static str,
    files_analyzed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxRelationship {
    spdx_element_id: String,
    related_spdx_element: &'static str,
    relationship_type: &'static str,
}

// ---------------------------------------------------------------------------
// Document construction
// ---------------------------------------------------------------------------

fn build_document(result: &ScanResult) -> SpdxDocument {
    let mut packages: Vec<SpdxPackage> = Vec::new();
    let mut relationships: Vec<SpdxRelationship> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut pkg_idx: usize = 0;

    // Collect all software: from findings, resolved, and clean
    let all_software = result
        .findings
        .iter()
        .map(|f| &f.software)
        .chain(result.resolved_findings.iter().map(|f| &f.software))
        .chain(result.software_without_cves.iter());

    for sw in all_software {
        let key = format!(
            "{}|{}",
            sw.name.to_lowercase(),
            sw.version.as_deref().unwrap_or("")
        );
        if !seen.insert(key) {
            continue;
        }

        let spdx_id = format!("SPDXRef-Package-{}", pkg_idx);
        pkg_idx += 1;

        packages.push(software_to_package(sw, &spdx_id));
        relationships.push(SpdxRelationship {
            spdx_element_id: spdx_id,
            related_spdx_element: "SPDXRef-DOCUMENT",
            relationship_type: "DESCRIBED_BY",
        });
    }

    SpdxDocument {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: "SPDXRef-DOCUMENT",
        name: format!("evedoo-sbom-{}", result.hostname),
        document_namespace: format!(
            "https://evedoo.dev/sbom/{}",
            Uuid::new_v4()
        ),
        creation_info: SpdxCreationInfo {
            created: result.scan_time.to_rfc3339(),
            creators: vec![format!(
                "Tool: evedoo-{}",
                env!("CARGO_PKG_VERSION")
            )],
        },
        packages,
        relationships,
    }
}

fn software_to_package(sw: &DetectedSoftware, spdx_id: &str) -> SpdxPackage {
    let supplier = sw
        .publisher
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| format!("Organization: {}", p));

    SpdxPackage {
        spdx_id: spdx_id.to_string(),
        name: sw.name.clone(),
        version_info: sw.version.clone(),
        supplier,
        download_location: "NOASSERTION",
        files_analyzed: false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    fn test_scan_result() -> ScanResult {
        let mut result = ScanResult::new("TEST-HOST".into());
        result.total_software = 2;

        result.findings.push(Finding {
            software: DetectedSoftware {
                name: "Python".into(),
                version: Some("3.12.0".into()),
                publisher: Some("Python Software Foundation".into()),
                install_location: None,
                install_date: None,
                registry_key: "registry://python".into(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: "CVE-2024-0002".into(),
                description: "Test".into(),
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
            confidence: MatchConfidence::High,
            vendor: Some("python".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        });

        result.software_without_cves.push(DetectedSoftware {
            name: "7-Zip".into(),
            version: Some("24.08".into()),
            publisher: None,
            install_location: None,
            install_date: None,
            registry_key: "registry://7zip".into(),
            architecture: Architecture::X64,
        });

        result
    }

    #[test]
    fn spdx_generates_valid_json() {
        let result = test_scan_result();
        let reporter = SpdxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        assert_eq!(parsed["dataLicense"], "CC0-1.0");
        assert_eq!(parsed["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(parsed["name"].as_str().unwrap().contains("TEST-HOST"));
    }

    #[test]
    fn spdx_includes_all_packages() {
        let result = test_scan_result();
        let reporter = SpdxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let packages = parsed["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2); // Python + 7-Zip

        let python = &packages[0];
        assert_eq!(python["name"], "Python");
        assert_eq!(python["versionInfo"], "3.12.0");
        assert_eq!(
            python["supplier"],
            "Organization: Python Software Foundation"
        );
        assert_eq!(python["downloadLocation"], "NOASSERTION");
        assert_eq!(python["filesAnalyzed"], false);
    }

    #[test]
    fn spdx_has_relationships() {
        let result = test_scan_result();
        let reporter = SpdxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let rels = parsed["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), 2);
        assert_eq!(rels[0]["relationshipType"], "DESCRIBED_BY");
        assert_eq!(rels[0]["relatedSpdxElement"], "SPDXRef-DOCUMENT");
    }

    #[test]
    fn spdx_empty_scan() {
        let result = ScanResult::new("EMPTY-HOST".into());
        let reporter = SpdxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["packages"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["relationships"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn spdx_no_duplicate_packages() {
        let mut result = test_scan_result();
        // Add duplicate software (same name+version from resolved findings)
        result.resolved_findings.push(Finding {
            software: DetectedSoftware {
                name: "Python".into(),
                version: Some("3.12.0".into()),
                publisher: Some("Python Software Foundation".into()),
                install_location: None,
                install_date: None,
                registry_key: "registry://python".into(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: "CVE-2024-0099".into(),
                description: "Old".into(),
                cvss_score: None,
                severity: Severity::Low,
                published_date: None,
                references: vec![],
                remediation: Remediation::default(),
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Medium,
            vendor: None,
            status: FindingStatus::Resolved,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        });

        let reporter = SpdxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        // Still only 2 packages (Python deduped)
        assert_eq!(parsed["packages"].as_array().unwrap().len(), 2);
    }
}

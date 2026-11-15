//! CycloneDX 1.6 SBOM report generator with VEX vulnerability data.
//!
//! SPDX-License-Identifier: Apache-2.0

use serde::Serialize;
use uuid::Uuid;

use super::Reporter;
use crate::error::{Result, ScanError};
use crate::models::{DetectedSoftware, Finding, FindingStatus, ScanResult};

pub struct CycloneDxReporter;

impl Reporter for CycloneDxReporter {
    fn generate(&self, result: &ScanResult) -> Result<String> {
        let bom = build_bom(result);
        serde_json::to_string_pretty(&bom)
            .map_err(|e| ScanError::SerializationError(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// CycloneDX 1.6 JSON schema structs (private, serialization-only)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CdxBom {
    bom_format: &'static str,
    spec_version: &'static str,
    serial_number: String,
    version: u32,
    metadata: CdxMetadata,
    components: Vec<CdxComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<CdxVulnerability>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CdxMetadata {
    timestamp: String,
    tools: CdxTools,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<CdxComponent>,
}

#[derive(Serialize)]
struct CdxTools {
    components: Vec<CdxToolComponent>,
}

#[derive(Serialize)]
struct CdxToolComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CdxComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<CdxSupplier>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<CdxProperty>,
}

#[derive(Serialize)]
struct CdxSupplier {
    name: String,
}

#[derive(Serialize)]
struct CdxProperty {
    name: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CdxVulnerability {
    id: String,
    source: CdxSource,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ratings: Vec<CdxRating>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<CdxAnalysis>,
    affects: Vec<CdxAffect>,
}

#[derive(Serialize)]
struct CdxSource {
    name: &'static str,
    url: String,
}

#[derive(Serialize)]
struct CdxRating {
    score: f32,
    severity: String,
    method: &'static str,
}

#[derive(Serialize)]
struct CdxAnalysis {
    state: &'static str,
}

#[derive(Serialize)]
struct CdxAffect {
    #[serde(rename = "ref")]
    affect_ref: String,
}

// ---------------------------------------------------------------------------
// BOM construction
// ---------------------------------------------------------------------------

fn build_bom(result: &ScanResult) -> CdxBom {
    // Collect all unique software as components.
    // Start with software that has findings, then add clean software.
    let mut components: Vec<CdxComponent> = Vec::new();
    let mut seen_refs: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Add software from findings
    for finding in result.findings.iter().chain(result.resolved_findings.iter()) {
        let bom_ref = make_bom_ref(&finding.software);
        if seen_refs.insert(bom_ref.clone()) {
            components.push(software_to_component(&finding.software, &bom_ref));
        }
    }

    // Add software without CVEs
    for sw in &result.software_without_cves {
        let bom_ref = make_bom_ref(sw);
        if seen_refs.insert(bom_ref.clone()) {
            components.push(software_to_component(sw, &bom_ref));
        }
    }

    // Build vulnerability entries (VEX)
    let vulnerabilities: Vec<CdxVulnerability> = result
        .findings
        .iter()
        .chain(result.resolved_findings.iter())
        .map(finding_to_vulnerability)
        .collect();

    CdxBom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
        version: 1,
        metadata: CdxMetadata {
            timestamp: result.scan_time.to_rfc3339(),
            tools: CdxTools {
                components: vec![CdxToolComponent {
                    component_type: "application",
                    name: "evedoo",
                    version: env!("CARGO_PKG_VERSION"),
                }],
            },
            component: Some(CdxComponent {
                component_type: "device",
                bom_ref: format!("host:{}", result.hostname),
                name: result.hostname.clone(),
                version: None,
                supplier: None,
                properties: vec![],
            }),
        },
        components,
        vulnerabilities,
    }
}

fn make_bom_ref(sw: &DetectedSoftware) -> String {
    format!(
        "{}|{}",
        sw.name.to_lowercase(),
        sw.version.as_deref().unwrap_or("unknown")
    )
}

fn software_to_component(sw: &DetectedSoftware, bom_ref: &str) -> CdxComponent {
    let mut properties = Vec::new();

    // Detection source from registry_key scheme prefix
    let source = detection_source(&sw.registry_key);
    properties.push(CdxProperty {
        name: "evedoo:source".to_string(),
        value: source.to_string(),
    });

    if let Some(loc) = &sw.install_location {
        if !loc.is_empty() {
            properties.push(CdxProperty {
                name: "evedoo:install_location".to_string(),
                value: loc.clone(),
            });
        }
    }

    CdxComponent {
        component_type: "application",
        bom_ref: bom_ref.to_string(),
        name: sw.name.clone(),
        version: sw.version.clone(),
        supplier: sw
            .publisher
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| CdxSupplier { name: p.clone() }),
        properties,
    }
}

fn finding_to_vulnerability(finding: &Finding) -> CdxVulnerability {
    let vuln = &finding.vulnerability;
    let bom_ref = make_bom_ref(&finding.software);

    let mut ratings = Vec::new();
    if let Some(score) = vuln.cvss_score {
        ratings.push(CdxRating {
            score,
            severity: vuln.severity.to_string().to_lowercase(),
            method: "CVSSv3",
        });
    }

    // NoLongerApplicable is grouped with Resolved ("no longer exploitable
    // here"); NewlyApplicable is grouped with New/Persisting under the
    // existing catch-all ("still something to act on").
    let state = match finding.status {
        FindingStatus::Resolved | FindingStatus::NoLongerApplicable => "resolved",
        FindingStatus::New | FindingStatus::NewlyApplicable | FindingStatus::Persisting => {
            "exploitable"
        }
    };

    let desc = if vuln.description.is_empty() {
        None
    } else {
        Some(vuln.description.clone())
    };

    CdxVulnerability {
        id: vuln.cve_id.clone(),
        source: CdxSource {
            name: "NVD",
            url: format!("https://nvd.nist.gov/vuln/detail/{}", vuln.cve_id),
        },
        ratings,
        description: desc,
        analysis: Some(CdxAnalysis { state }),
        affects: vec![CdxAffect {
            affect_ref: bom_ref,
        }],
    }
}

fn detection_source(registry_key: &str) -> &str {
    if let Some(idx) = registry_key.find("://") {
        &registry_key[..idx]
    } else {
        "unknown"
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
        result.total_vulnerabilities = 1;

        result.findings.push(Finding {
            software: DetectedSoftware {
                name: "Google Chrome".into(),
                version: Some("120.0.6099.109".into()),
                publisher: Some("Google LLC".into()),
                install_location: Some("C:\\Program Files\\Google\\Chrome".into()),
                install_date: None,
                registry_key: "registry://chrome".into(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: "CVE-2024-0001".into(),
                description: "Test vulnerability in Chrome".into(),
                cvss_score: Some(8.8),
                severity: Severity::High,
                published_date: Some("2024-01-15".into()),
                references: vec!["https://example.com/advisory".into()],
                remediation: Remediation::default(),
                epss_score: Some(0.5),
                epss_percentile: Some(0.9),
                in_kev: true,
                kev_due_date: Some("2024-02-01".into()),
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Exact,
            vendor: Some("google".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        });

        result.software_without_cves.push(DetectedSoftware {
            name: "Notepad++".into(),
            version: Some("8.7".into()),
            publisher: Some("Notepad++ Team".into()),
            install_location: None,
            install_date: None,
            registry_key: "registry://notepadpp".into(),
            architecture: Architecture::X64,
        });

        result
    }

    #[test]
    fn cyclonedx_generates_valid_json() {
        let result = test_scan_result();
        let reporter = CycloneDxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.6");
        assert!(parsed["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(parsed["version"], 1);
    }

    #[test]
    fn cyclonedx_includes_all_components() {
        let result = test_scan_result();
        let reporter = CycloneDxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let components = parsed["components"].as_array().unwrap();
        assert_eq!(components.len(), 2); // Chrome + Notepad++

        let chrome = &components[0];
        assert_eq!(chrome["name"], "Google Chrome");
        assert_eq!(chrome["version"], "120.0.6099.109");
        assert_eq!(chrome["supplier"]["name"], "Google LLC");
    }

    #[test]
    fn cyclonedx_includes_vulnerabilities() {
        let result = test_scan_result();
        let reporter = CycloneDxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let vulns = parsed["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["id"], "CVE-2024-0001");
        assert_eq!(vulns[0]["source"]["name"], "NVD");
        assert_eq!(vulns[0]["ratings"][0]["score"], 8.8);
        assert_eq!(vulns[0]["analysis"]["state"], "exploitable");
    }

    #[test]
    fn cyclonedx_resolved_finding_state() {
        let mut result = test_scan_result();
        result.findings[0].status = FindingStatus::Resolved;
        // Move to resolved
        let f = result.findings.remove(0);
        result.resolved_findings.push(f);

        let reporter = CycloneDxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let vulns = parsed["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns[0]["analysis"]["state"], "resolved");
    }

    #[test]
    fn cyclonedx_empty_scan() {
        let result = ScanResult::new("EMPTY-HOST".into());
        let reporter = CycloneDxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["components"].as_array().unwrap().len(), 0);
        // vulnerabilities key should be absent (skip_serializing_if = empty)
        assert!(parsed.get("vulnerabilities").is_none());
    }

    #[test]
    fn cyclonedx_detection_source_property() {
        let result = test_scan_result();
        let reporter = CycloneDxReporter;
        let output = reporter.generate(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let props = parsed["components"][0]["properties"].as_array().unwrap();
        let source_prop = props.iter().find(|p| p["name"] == "evedoo:source").unwrap();
        assert_eq!(source_prop["value"], "registry");
    }

    /// P21-HTML-RESIDUAL investigated CycloneDX alongside HTML and found no
    /// defect to fix. The VEX mapping collapses `New | NewlyApplicable |
    /// Persisting` into "exploitable" and `Resolved | NoLongerApplicable` into
    /// "resolved". When `delta_known` is false every finding sits at
    /// `correlate()`'s placeholder `New`, and `resolved_findings` is
    /// necessarily empty because only the history path fills it — the same
    /// path that sets `delta_known = true`. So the emitted analysis state is
    /// identical either way, and gating it would be a change with no
    /// observable effect.
    ///
    /// This test locks that reasoning down. It fails if someone later adds
    /// `delta_known`-dependent branching to the VEX state mapping, which would
    /// silently change SBOM output for downstream consumers.
    #[test]
    fn cyclonedx_state_is_identical_regardless_of_delta_known() {
        let mut unknown_delta = test_scan_result();
        unknown_delta.delta_known = false;
        let mut known_delta = test_scan_result();
        known_delta.delta_known = true;

        let reporter = CycloneDxReporter;
        let a: serde_json::Value =
            serde_json::from_str(&reporter.generate(&unknown_delta).unwrap()).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(&reporter.generate(&known_delta).unwrap()).unwrap();

        // serialNumber is a fresh UUID and the metadata timestamp moves, so
        // compare only the vulnerabilities array — that is what carries state.
        assert_eq!(
            a["vulnerabilities"], b["vulnerabilities"],
            "delta_known must not change CycloneDX VEX output"
        );
        assert_eq!(
            a["vulnerabilities"][0]["analysis"]["state"], "exploitable",
            "a present, matched finding is exploitable regardless of delta knowledge"
        );
    }
}

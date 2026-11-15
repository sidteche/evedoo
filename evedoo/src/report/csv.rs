//! CSV report generator with enterprise-compatible columns.
//!
//! SPDX-License-Identifier: Apache-2.0

use chrono::Utc;

use super::{sanitize_csv_cell, Reporter};
use crate::error::{Result, ScanError};
use crate::models::ScanResult;

pub struct CsvReporter;

/// Free-function entry point `report::generate_report` calls for
/// `OutputFormat::Csv`, mirroring `text::generate_text`'s shape even though
/// CSV takes no extra parameter (FR-67: the risk columns are unconditional).
pub(crate) fn generate_csv(result: &ScanResult) -> Result<String> {
    CsvReporter.generate(result)
}

impl Reporter for CsvReporter {
    fn generate(&self, result: &ScanResult) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());

        // Enterprise-compatible header columns. KEV/EPSS columns are appended
        // at the end so existing ingest pipelines keep working against the
        // original column layout.
        wtr.write_record([
            "Asset Name",
            "Vulnerability Title",
            "Vulnerability ID",
            "Vulnerability CVE IDs",
            "Vulnerability CVSS Score",
            "Severity",
            "Vulnerability Severity Level",
            "Asset OS Name",
            "Asset OS Family",
            "Asset ID",
            "Vulnerability Proof",
            "Vulnerability Solution",
            "Service Port",
            "Site Name",
            "Vulnerability Age",
            "Vulnerable Since",
            "Age(Days)",
            "Vulnerability Published Date",
            "Reintroduced Date",
            "Vulnerability Test Date",
            "Vulnerability Additional URLs",
            "Vulnerability Description",
            "Category",
            "Application",
            "Match Confidence",
            "Vendor Name",
            "Software Classification",
            "CVE URL",
            "Finding Status",
            "In KEV",
            "KEV Due Date",
            "EPSS Score",
            "EPSS Percentile",
            "Fixed Version",
            "KB Articles",
            "Upgrade Command",
            "Risk Score",
            "Priority",
            "Reachability",
        ])
        .map_err(|e| ScanError::SerializationError(e.to_string()))?;

        let scan_date = result.scan_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let os_name = get_os_name();
        let os_family = "Windows";

        // Write findings
        for finding in &result.findings {
            // Calculate vulnerability age in days
            let age_days = finding
                .vulnerability
                .published_date
                .as_ref()
                .and_then(|pd| chrono::NaiveDate::parse_from_str(&pd[..10], "%Y-%m-%d").ok())
                .map(|pd| {
                    let today = Utc::now().date_naive();
                    (today - pd).num_days()
                })
                .unwrap_or(0);

            // Format references as semicolon-separated list
            let additional_urls = finding.vulnerability.references.join("; ");

            // Truncate description for CSV readability
            let description: String = finding
                .vulnerability
                .description
                .chars()
                .take(500)
                .collect();

            // Severity level (numeric)
            let severity_level = match finding.vulnerability.severity {
                crate::models::Severity::Critical => "4",
                crate::models::Severity::High => "3",
                crate::models::Severity::Medium => "2",
                crate::models::Severity::Low => "1",
                crate::models::Severity::Unknown => "0",
            };

            // Finding Status (status-honesty fix): `correlate()` stamps every
            // finding with the placeholder `FindingStatus::New` before
            // reconciliation ever runs. When `result.delta_known` is false
            // (--no-history, a history-DB-open failure, or a
            // `load_previous_keys` read failure — see `ScanResult::delta_known`'s
            // doc comment), that placeholder was never replaced with a real
            // comparison, so writing it into this machine-readable column
            // would be a false claim a downstream pipeline could act on.
            // "Unknown" says plainly that no delta was computed, rather than
            // asserting one that never happened.
            let status_cell = if result.delta_known {
                finding.status.to_string()
            } else {
                "Unknown".to_string()
            };

            let in_kev_cell = if finding.vulnerability.in_kev { "Yes" } else { "No" };
            let epss_score_cell = finding
                .vulnerability
                .epss_score
                .map(|s| format!("{:.5}", s))
                .unwrap_or_default();
            let epss_percentile_cell = finding
                .vulnerability
                .epss_percentile
                .map(|s| format!("{:.5}", s))
                .unwrap_or_default();

            let title = finding
                .vulnerability
                .description
                .chars()
                .take(100)
                .collect::<String>();
            let app_str = format!(
                "{} v{}",
                finding.software.name,
                finding.software.version.as_deref().unwrap_or("unknown")
            );
            let kb_articles_str = finding.vulnerability.remediation.kb_articles.join("; ");

            wtr.write_record([
                // Asset Name
                sanitize_csv_cell(&result.hostname).as_ref(),
                // Vulnerability Title (first 100 chars of description as title)
                sanitize_csv_cell(&title).as_ref(),
                // Vulnerability ID
                sanitize_csv_cell(&finding.vulnerability.cve_id).as_ref(),
                // Vulnerability CVE IDs
                sanitize_csv_cell(&finding.vulnerability.cve_id).as_ref(),
                // Vulnerability CVSS Score
                &finding
                    .vulnerability
                    .cvss_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_default(),
                // Severity
                &finding.vulnerability.severity.to_string(),
                // Vulnerability Severity Level (numeric: Critical=4, High=3, Medium=2, Low=1)
                severity_level,
                // Asset OS Name
                sanitize_csv_cell(&os_name).as_ref(),
                // Asset OS Family
                os_family,
                // Asset ID (using hostname as identifier)
                sanitize_csv_cell(&result.hostname).as_ref(),
                // Vulnerability Proof (registry key where software was found)
                sanitize_csv_cell(&finding.software.registry_key).as_ref(),
                // Vulnerability Solution
                sanitize_csv_cell(&finding.vulnerability.remediation.recommendation).as_ref(),
                // Service Port (N/A for registry-based scanning)
                "",
                // Site Name
                sanitize_csv_cell(&result.hostname).as_ref(),
                // Vulnerability Age (human readable)
                &format!("{} days", age_days),
                // Vulnerable Since (first detection - using scan date for now)
                &scan_date,
                // Age(Days)
                &age_days.to_string(),
                // Vulnerability Published Date
                finding
                    .vulnerability
                    .published_date
                    .as_deref()
                    .unwrap_or(""),
                // Reintroduced Date (blank - would need scan history)
                "",
                // Vulnerability Test Date
                &scan_date,
                // Vulnerability Additional URLs
                &additional_urls,
                // Vulnerability Description
                sanitize_csv_cell(&description).as_ref(),
                // Category (based on severity for now)
                &format!("{} Severity Vulnerability", finding.vulnerability.severity),
                // Application
                sanitize_csv_cell(&app_str).as_ref(),
                // Match Confidence
                &finding.confidence.to_string(),
                // Vendor Name (CPE vendor resolved during matching)
                sanitize_csv_cell(finding.vendor.as_deref().unwrap_or("")).as_ref(),
                // Software Classification
                classify_software(
                    &finding.software.name,
                    finding.software.publisher.as_deref(),
                ),
                // CVE URL
                &format!(
                    "https://nvd.nist.gov/vuln/detail/{}",
                    finding.vulnerability.cve_id.to_lowercase()
                ),
                // Finding Status
                &status_cell,
                // In KEV
                in_kev_cell,
                // KEV Due Date
                finding
                    .vulnerability
                    .kev_due_date
                    .as_deref()
                    .unwrap_or(""),
                // EPSS Score
                &epss_score_cell,
                // EPSS Percentile
                &epss_percentile_cell,
                // Fixed Version
                sanitize_csv_cell(
                    finding
                        .vulnerability
                        .remediation
                        .fixed_version
                        .as_deref()
                        .unwrap_or("")
                ).as_ref(),
                // KB Articles
                sanitize_csv_cell(&kb_articles_str).as_ref(),
                // Upgrade Command
                sanitize_csv_cell(
                    finding
                        .vulnerability
                        .remediation
                        .upgrade_command
                        .as_deref()
                        .unwrap_or("")
                ).as_ref(),
                // Risk Score (FR-67: always present in machine formats)
                &finding.risk.as_ref().map(|r| format!("{:.1}", r.score)).unwrap_or_default(),
                // Priority
                &finding.risk.as_ref().map(|r| format!("{:?}", r.tier)).unwrap_or_default(),
                // Reachability (FR-80). A fixed-width machine format has no
                // "omit" option, so the literal value is always carried —
                // including Unknown, which is honest here in a way a blank
                // cell would not be.
                &finding.reachability.to_string(),
            ])
            .map_err(|e| ScanError::SerializationError(e.to_string()))?;
        }

        // Write resolved findings (from previous scan, now gone)
        for finding in &result.resolved_findings {
            let title = finding.vulnerability.description.chars().take(100).collect::<String>();
            let app_str = format!(
                "{} v{}",
                finding.software.name,
                finding.software.version.as_deref().unwrap_or("unknown")
            );

            wtr.write_record([
                sanitize_csv_cell(&result.hostname).as_ref(),
                sanitize_csv_cell(&title).as_ref(),
                sanitize_csv_cell(&finding.vulnerability.cve_id).as_ref(),
                sanitize_csv_cell(&finding.vulnerability.cve_id).as_ref(),
                "",   // no CVSS for resolved stubs
                &finding.vulnerability.severity.to_string(),
                "0",
                sanitize_csv_cell(&os_name).as_ref(),
                os_family,
                sanitize_csv_cell(&result.hostname).as_ref(),
                sanitize_csv_cell(&finding.software.registry_key).as_ref(),
                "",
                "", "", "", &scan_date, "", "", "", "", "", "", "",
                sanitize_csv_cell(&app_str).as_ref(),
                &finding.confidence.to_string(),
                sanitize_csv_cell(finding.vendor.as_deref().unwrap_or("")).as_ref(),
                classify_software(&finding.software.name, finding.software.publisher.as_deref()),
                &format!("https://nvd.nist.gov/vuln/detail/{}", finding.vulnerability.cve_id.to_lowercase()),
                "Resolved",
                "",     // In KEV (resolved — unknown)
                "",     // KEV Due Date
                "",     // EPSS Score
                "",     // EPSS Percentile
                "",     // Fixed Version
                "",     // KB Articles
                "",     // Upgrade Command
                "",     // Risk Score (resolved stubs are never scored)
                "",     // Priority
                "",     // Reachability (resolved stubs are never classified)
            ])
            .map_err(|e| ScanError::SerializationError(e.to_string()))?;
        }

        wtr.flush()
            .map_err(|e| ScanError::SerializationError(e.to_string()))?;

        String::from_utf8(
            wtr.into_inner()
                .map_err(|e| ScanError::SerializationError(e.to_string()))?,
        )
        .map_err(|e| ScanError::SerializationError(e.to_string()))
    }
}

/// Classify software into a broad category based on name and publisher
fn classify_software(name: &str, publisher: Option<&str>) -> &'static str {
    let n = name.to_lowercase();
    let p = publisher.unwrap_or("").to_lowercase();
    if n.contains("chrome")
        || n.contains("firefox")
        || n.contains("edge")
        || n.contains("opera")
        || n.contains("browser")
    {
        "Browser"
    } else if n.contains("runtime")
        || n.contains("redistributable")
        || n.contains("visual c++")
        || n.contains(".net")
        || n.contains("java")
    {
        "Runtime"
    } else if p.contains("microsoft")
        && (n.contains("windows") || n.contains("driver") || n.contains("update"))
    {
        "OS Component"
    } else {
        "Application"
    }
}

/// Get Windows OS name from environment
fn get_os_name() -> String {
    // Try to get OS version info
    std::env::var("OS").unwrap_or_else(|_| "Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::{classify_software, generate_csv};
    use crate::models::{
        Architecture, DetectedSoftware, Finding, FindingStatus, MatchConfidence, Priority,
        Remediation, RiskAssessment, ScanResult, Severity, Vulnerability,
    };

    fn sample_scan_result() -> ScanResult {
        let mut r = ScanResult::new("testhost".into());
        r.total_software = 1;
        r.findings.push(Finding {
            software: DetectedSoftware {
                name: "Alpha".into(),
                version: Some("1.0.0".into()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: "pe://alpha.exe".into(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: "CVE-2024-0001".into(),
                description: "Test vulnerability".into(),
                cvss_score: Some(7.5),
                severity: Severity::High,
                published_date: Some("2024-01-01".into()),
                references: vec![],
                remediation: Remediation::default(),
                epss_score: Some(0.2),
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Exact,
            vendor: Some("vendor".into()),
            status: FindingStatus::New,
            risk: Some(RiskAssessment { score: 41.3, tier: Priority::P2, epss_known: true }),
            excepted: None,
            reachability: Default::default(),
        });
        r.total_vulnerabilities = r.findings.len();
        r
    }

    #[test]
    fn csv_carries_risk_columns_unconditionally() {
        // FR-67: machine formats always include the fields, so pipelines can
        // use them without anyone passing a flag.
        let result = sample_scan_result();
        let csv = generate_csv(&result).unwrap();
        let header = csv.lines().next().unwrap();
        assert!(header.contains("Risk Score"), "header was: {header}");
        assert!(header.contains("Priority"), "header was: {header}");
    }

    /// Locates the "Finding Status" cell in the first data row by header
    /// index, rather than a fixed column number, so this test does not need
    /// updating every time a column is inserted elsewhere.
    fn finding_status_cell(csv_text: &str) -> String {
        let mut rdr = csv::Reader::from_reader(csv_text.as_bytes());
        let headers = rdr.headers().unwrap().clone();
        let idx = headers
            .iter()
            .position(|h| h == "Finding Status")
            .expect("Finding Status column must exist");
        let record = rdr.records().next().unwrap().unwrap();
        record.get(idx).unwrap().to_string()
    }

    /// Status-honesty fix: `correlate()` stamps every finding with the
    /// placeholder `FindingStatus::New` before reconciliation runs. When
    /// `result.delta_known` is false (the fixture's default —
    /// `--no-history`/a history-read failure in the real pipeline), writing
    /// that placeholder into the CSV would hand a downstream pipeline a
    /// fabricated delta with no way to tell it apart from a real one.
    #[test]
    fn csv_finding_status_reads_unknown_when_delta_not_known() {
        let result = sample_scan_result();
        assert!(!result.delta_known, "fixture must start with the conservative default");
        let csv_text = generate_csv(&result).unwrap();
        assert_eq!(finding_status_cell(&csv_text), "Unknown");
    }

    #[test]
    fn csv_finding_status_reads_real_status_when_delta_known() {
        let mut result = sample_scan_result();
        result.delta_known = true;
        let csv_text = generate_csv(&result).unwrap();
        assert_eq!(finding_status_cell(&csv_text), "New");
    }

    #[test]
    fn browser_classification() {
        assert_eq!(classify_software("Google Chrome", Some("Google LLC")), "Browser");
        assert_eq!(classify_software("Mozilla Firefox", None), "Browser");
        assert_eq!(classify_software("Microsoft Edge", None), "Browser");
        assert_eq!(classify_software("Opera Browser", None), "Browser");
    }

    #[test]
    fn runtime_classification() {
        assert_eq!(classify_software("Microsoft .NET Runtime 8.0", Some("Microsoft")), "Runtime");
        assert_eq!(classify_software("Visual C++ 2022 Redistributable", Some("Microsoft")), "Runtime");
        assert_eq!(classify_software("Java SE Runtime Environment", Some("Oracle")), "Runtime");
    }

    #[test]
    fn os_component_classification() {
        assert_eq!(
            classify_software("Windows Update Health Tools", Some("Microsoft Corporation")),
            "OS Component"
        );
    }

    #[test]
    fn application_fallback() {
        assert_eq!(classify_software("VLC media player", Some("VideoLAN")), "Application");
        assert_eq!(classify_software("7-Zip", None), "Application");
        assert_eq!(classify_software("Discord", Some("Discord Inc.")), "Application");
    }

    /// FR-80. CSV is a fixed-width machine format with no "omit" option, so
    /// it always carries the value — the literal string is honest there in a
    /// way a blank cell would not be.
    #[test]
    fn csv_has_reachability_column_with_the_value() {
        let mut result = sample_scan_result();
        result.findings[0].reachability = crate::reachability::Reachability::Loaded;
        let out = generate_csv(&result).unwrap();
        let mut rdr = csv::Reader::from_reader(out.as_bytes());
        let headers = rdr.headers().unwrap().clone();
        let idx = headers
            .iter()
            .position(|h| h == "Reachability")
            .expect("Reachability column must exist");
        let row = rdr.records().next().unwrap().unwrap();
        assert_eq!(&row[idx], "Loaded");
    }

    #[test]
    fn csv_neutralizes_formula_injection() {
        let mut result = sample_scan_result();
        result.findings[0].software.name = "=HYPERLINK(\"http://evil\",\"x\")".to_string();
        let out = generate_csv(&result).unwrap();
        let mut rdr = csv::Reader::from_reader(out.as_bytes());
        let headers = rdr.headers().unwrap().clone();
        let idx = headers
            .iter()
            .position(|h| h == "Application")
            .expect("Application column must exist");
        let row = rdr.records().next().unwrap().unwrap();
        assert!(row[idx].starts_with('\''), "Formula injection must be neutralized: {}", &row[idx]);
    }
}

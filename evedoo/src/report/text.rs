//! Human-readable text report generator.
//!
//! SPDX-License-Identifier: Apache-2.0

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::models::{ScanResult, Severity};

/// Renders the human-readable text report. `show_risk` gates the
/// `Priority:` line per finding (FR-67: default text output must not
/// change). Unlike the other formats, text takes this extra parameter, so
/// it is not wrapped in the `Reporter` trait's argument-free `generate`;
/// `report::generate_report` calls this directly for `OutputFormat::Text`.
pub(crate) fn generate_text(result: &ScanResult, show_risk: bool) -> Result<String> {
    let mut output = String::new();

    // Header
    output.push_str(&format!("\n{}\n", "═".repeat(70).bright_blue()));
    output.push_str(&format!(
        "{}\n",
        "  EVEDOO VULNERABILITY SCAN REPORT".bright_white().bold()
    ));
    output.push_str(&format!("{}\n\n", "═".repeat(70).bright_blue()));

    // Summary
    output.push_str(&format!(
        "  {} {}\n",
        "Hostname:".bright_white(),
        result.hostname
    ));
    output.push_str(&format!(
        "  {} {}\n",
        "Scan Time:".bright_white(),
        result.scan_time.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    output.push_str(&format!(
        "  {} {}\n",
        "Software Scanned:".bright_white(),
        result.total_software
    ));
    output.push_str(&format!(
        "  {} {}\n\n",
        "Vulnerabilities Found:".bright_white(),
        result.total_vulnerabilities
    ));

    // Severity breakdown
    output.push_str(&format!("{}\n", "  SEVERITY BREAKDOWN".bright_yellow()));
    output.push_str(&format!("  {}\n", "─".repeat(50)));

    let critical = result.count_by_severity(Severity::Critical);
    let high = result.count_by_severity(Severity::High);
    let medium = result.count_by_severity(Severity::Medium);
    let low = result.count_by_severity(Severity::Low);

    output.push_str(&format!(
        "  {} {} {}\n",
        "🔴".red(),
        "Critical:".bright_red(),
        critical
    ));
    output.push_str(&format!(
        "  {} {} {}\n",
        "🟠",
        "High:".bright_yellow(),
        high
    ));
    output.push_str(&format!("  {} {} {}\n", "🟡", "Medium:".yellow(), medium));
    output.push_str(&format!("  {} {} {}\n\n", "🔵", "Low:".bright_blue(), low));

    // Findings by severity
    if result.total_vulnerabilities > 0 {
        output.push_str(&format!("{}\n", "═".repeat(70).bright_blue()));
        output.push_str(&format!(
            "{}\n",
            "  VULNERABILITY DETAILS".bright_white().bold()
        ));
        output.push_str(&format!("{}\n\n", "═".repeat(70).bright_blue()));

        // Findings are pre-sorted by main.rs into priority order
        // (KEV → EPSS → CVSS → published date), so the text report walks
        // them in that order directly.
        for finding in &result.findings {
            let severity_color = match finding.vulnerability.severity {
                Severity::Critical => "CRITICAL".bright_red().bold().to_string(),
                Severity::High => "HIGH".bright_yellow().bold().to_string(),
                Severity::Medium => "MEDIUM".yellow().to_string(),
                Severity::Low => "LOW".bright_blue().to_string(),
                Severity::Unknown => "UNKNOWN".white().to_string(),
            };

            let mut header_tags = String::new();
            if finding.vulnerability.in_kev {
                header_tags.push(' ');
                header_tags.push_str(&"[KEV]".bright_red().bold().to_string());
            }
            if let Some(epss) = finding.vulnerability.epss_score {
                header_tags.push_str(&format!(" EPSS={:.2}", epss));
            }

            output.push_str(&format!(
                "  {} [{}] ({}){}\n",
                finding.vulnerability.cve_id.bright_white().bold(),
                severity_color,
                finding.confidence,
                header_tags,
            ));

            // Status (B4, final whole-branch review; gated by delta_known
            // per the status-honesty fix): `reassess`'s entire purpose is
            // distinguishing `NewlyApplicable` from `Persisting` (FR-59,
            // FR-60), so when the delta is actually known this is
            // unconditional — unlike --risk/Priority below, "why is this
            // finding in the report" is not opt-in information. But
            // `correlate()` stamps every finding with the placeholder
            // `FindingStatus::New` before reconciliation, and on
            // `--no-history` or a history-read failure that placeholder is
            // never replaced with a real comparison. Rendering it anyway
            // would assert a delta the tool never computed, so this line is
            // skipped entirely — not shown with a caveat — when
            // `result.delta_known` is false.
            if result.delta_known {
                output.push_str(&format!("  {} {}\n", "Status:".bright_white(), finding.status));
            }

            // Reachability (FR-80). Omitted entirely when undetermined,
            // matching the status rule above: a placeholder would assert an
            // observation the scan never made. Unlike status this is not
            // gated on delta_known — reachability is measured on this run,
            // not compared against a previous one.
            if finding.reachability != crate::reachability::Reachability::Unknown {
                output.push_str(&format!(
                    "  {} {}\n",
                    "Reachability:".bright_white(),
                    finding.reachability
                ));
            }

            // Priority (FR-67) — opt-in via --risk; hidden by default so
            // the plain-text report never changes shape unasked.
            if show_risk {
                if let Some(ref risk) = finding.risk {
                    let provisional = if risk.epss_known { "" } else { " (provisional — no EPSS)" };
                    output.push_str(&format!(
                        "  {} {} (score {:.1}){}\n",
                        "Priority:".bright_white(),
                        risk.tier,
                        risk.score,
                        provisional
                    ));
                }
            }

            if let Some(ref due) = finding.vulnerability.kev_due_date {
                output.push_str(&format!(
                    "  {} {}\n",
                    "CISA Due Date:".bright_red(),
                    due
                ));
            }

            output.push_str(&format!(
                "  {} {} v{}\n",
                "Software:".bright_white(),
                finding.software.name,
                finding.software.version.as_deref().unwrap_or("unknown")
            ));

            if let Some(ref location) = finding.software.install_location {
                output.push_str(&format!("  {} {}\n", "Location:".bright_white(), location));
            }

            if let Some(score) = finding.vulnerability.cvss_score {
                output.push_str(&format!(
                    "  {} {:.1}\n",
                    "CVSS Score:".bright_white(),
                    score
                ));
            }

            // Truncate description
            let desc: String = finding
                .vulnerability
                .description
                .chars()
                .take(200)
                .collect();
            output.push_str(&format!(
                "  {} {}...\n",
                "Description:".bright_white(),
                desc
            ));

            output.push_str(&format!(
                "  {} {}\n",
                "Remediation:".bright_green(),
                finding.vulnerability.remediation.recommendation
            ));

            if let Some(ref ver) = finding.vulnerability.remediation.fixed_version {
                output.push_str(&format!(
                    "  {} {}\n",
                    "Fixed in:".bright_white(),
                    ver
                ));
            }

            if !finding.vulnerability.remediation.kb_articles.is_empty() {
                output.push_str(&format!(
                    "  {} {}\n",
                    "KB Patches:".bright_white(),
                    finding.vulnerability.remediation.kb_articles.join(", ")
                ));
            }

            if let Some(ref cmd) = finding.vulnerability.remediation.upgrade_command {
                output.push_str(&format!(
                    "  {} {}\n",
                    "Upgrade:".bright_cyan(),
                    cmd
                ));
            }

            if let Some(ref advisory) = finding.vulnerability.remediation.vendor_advisory {
                output.push_str(&format!("  {} {}\n", "Advisory:".bright_white(), advisory));
            }

            output.push_str(&format!("  {}\n\n", "─".repeat(60)));
        }
    } else {
        output.push_str(&format!(
            "\n  {} {}\n\n",
            "✓".bright_green().bold(),
            "No known vulnerabilities found!".bright_green()
        ));
    }

    // Resolved findings section
    if !result.resolved_findings.is_empty() {
        output.push_str(&format!("{}\n", "═".repeat(70).bright_blue()));
        output.push_str(&format!(
            "{}\n",
            "  ✓ RESOLVED SINCE LAST SCAN".bright_green().bold()
        ));
        output.push_str(&format!("{}\n\n", "═".repeat(70).bright_blue()));
        for finding in &result.resolved_findings {
            output.push_str(&format!(
                "  {} [RESOLVED] — {} v{}\n",
                finding.vulnerability.cve_id.bright_white(),
                finding.software.name,
                finding.software.version.as_deref().unwrap_or("unknown")
            ));
        }
        output.push('\n');
    }

    // Footer
    output.push_str(&format!("{}\n", "═".repeat(70).bright_blue()));
    output.push_str("  Powered by Evedoo - https://github.com/sidteche/evedoo\n");
    output.push_str(&format!("  {}\n", super::NVD_NOTICE));
    output.push_str(&format!("{}\n", "═".repeat(70).bright_blue()));

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Architecture, DetectedSoftware, Finding, FindingStatus, MatchConfidence, Priority,
        Remediation, RiskAssessment, Vulnerability,
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
    fn text_report_carries_the_nvd_notice() {
        let text = generate_text(&ScanResult::new("host".into()), false).unwrap();
        assert!(text.contains(crate::report::NVD_NOTICE));
    }

    #[test]
    fn text_report_hides_risk_unless_asked() {
        // FR-67: default text output must not change.
        let result = sample_scan_result();
        let plain = generate_text(&result, false).unwrap();
        assert!(!plain.contains("Priority:"), "risk must be opt-in in text output");
        let with_risk = generate_text(&result, true).unwrap();
        assert!(with_risk.contains("Priority:"));
    }

    /// B4, final whole-branch review: the text report must render each
    /// finding's `FindingStatus` unconditionally with respect to `show_risk`
    /// (not gated behind it) — `reassess`'s whole reason for existing is
    /// separating `NewlyApplicable` from `Persisting` (FR-59, FR-60), and
    /// before this the distinction appeared nowhere in a default report.
    /// `delta_known` must be set for this — see
    /// `text_report_hides_status_when_delta_not_known` below for the
    /// opposite case, where the delta genuinely is not known.
    #[test]
    fn text_report_always_shows_finding_status() {
        let mut result = sample_scan_result();
        result.delta_known = true;
        result.findings[0].status = FindingStatus::NewlyApplicable;
        let plain = generate_text(&result, false).unwrap();
        assert!(
            plain.contains("Status:"),
            "finding status must render even when --risk was not requested"
        );
        assert!(plain.contains("NewlyApplicable"));
    }

    /// Status-honesty fix: `correlate()` stamps every finding with the
    /// placeholder `FindingStatus::New` before reconciliation ever runs
    /// (`correlate.rs`). On `--no-history`, a history-DB-open failure, or a
    /// `load_previous_keys` read failure, that placeholder is never replaced
    /// — `main.rs::persist_then_present` leaves `ScanResult::delta_known`
    /// at its default `false` on every one of those paths. Presenting
    /// `Status: New` anyway would assert a delta the tool never computed, so
    /// the text report must omit the line entirely rather than show a
    /// status it cannot support.
    #[test]
    fn text_report_hides_status_when_delta_not_known() {
        let result = sample_scan_result();
        assert!(!result.delta_known, "fixture must start with the conservative default");
        let plain = generate_text(&result, false).unwrap();
        assert!(
            !plain.contains("Status:"),
            "must not present a delta status when the delta is not known: {plain}"
        );
    }

    /// FR-80. Same rule `delta_known` established for status: when the value
    /// is undetermined the line is omitted entirely, not shown with a caveat.
    /// A placeholder would assert an observation that was never made.
    #[test]
    fn text_report_omits_reachability_when_unknown() {
        let mut result = sample_scan_result();
        for f in &mut result.findings {
            f.reachability = crate::reachability::Reachability::Unknown;
        }
        let plain = generate_text(&result, false).unwrap();
        assert!(!plain.contains("Reachability:"));
    }

    /// The other half of the gate: a determined value must actually appear,
    /// or "always omit" would satisfy the test above while erasing the feature.
    #[test]
    fn text_report_shows_reachability_when_loaded() {
        let mut result = sample_scan_result();
        for f in &mut result.findings {
            f.reachability = crate::reachability::Reachability::Loaded;
        }
        let plain = generate_text(&result, false).unwrap();
        assert!(plain.contains("Reachability:"));
        assert!(plain.contains("Loaded"));
    }
}

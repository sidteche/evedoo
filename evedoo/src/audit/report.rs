//! Multi-format compliance audit report generation (Text, JSON, CSV, HTML).
//!
//! SPDX-License-Identifier: Apache-2.0

use owo_colors::OwoColorize;

use super::policy::{AuditSeverity, AuditSummary, RuleStatus, AUDIT_DISCLAIMER};

/// Generates a colored, human-readable terminal report.
pub fn generate_text_report(summary: &AuditSummary) -> String {
    let mut output = String::new();

    // ── Header ──────────────────────────────────────────────────────────
    output.push_str(&format!("\n{}\n", "═".repeat(74).bright_blue()));
    output.push_str(&format!(
        "{}\n",
        "  EVEDOO COMPLIANCE AUDIT REPORT".bright_white().bold()
    ));
    output.push_str(&format!("{}\n\n", "═".repeat(74).bright_blue()));

    // ── Benchmark & Host Info ──────────────────────────────────────────
    output.push_str(&format!(
        "  {} {}\n",
        "Benchmark:".bright_white().bold(),
        summary.benchmark_title
    ));
    output.push_str(&format!(
        "  {} {}\n",
        "Benchmark ID:".bright_white(),
        summary.benchmark_id
    ));
    output.push_str(&format!(
        "  {} {}\n",
        "Hostname:".bright_white(),
        summary.target_host
    ));
    output.push_str(&format!(
        "  {} {}\n\n",
        "Audit Time:".bright_white(),
        summary.scan_time.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // ── Compliance Score & Summary KPI ─────────────────────────────────
    let score_color = if summary.compliance_score >= 80.0 {
        format!("{:.1}%", summary.compliance_score).bright_green().bold().to_string()
    } else if summary.compliance_score >= 50.0 {
        format!("{:.1}%", summary.compliance_score).bright_yellow().bold().to_string()
    } else {
        format!("{:.1}%", summary.compliance_score).bright_red().bold().to_string()
    };

    output.push_str(&format!(
        "  {} {}\n",
        "Pass Rate (bundled checks):".bright_white().bold(),
        score_color
    ));
    output.push_str(&format!("  {}\n", summary.scope_statement()));
    output.push_str(&format!(
        "  {} Total: {} | Passed: {} | Failed: {} | N/A: {} | Errors: {}\n\n",
        "Rules Evaluated:".bright_white(),
        summary.total_rules,
        summary.passed_rules.bright_green(),
        if summary.failed_rules > 0 {
            summary.failed_rules.bright_red().to_string()
        } else {
            summary.failed_rules.to_string()
        },
        summary.na_rules,
        if summary.error_rules > 0 {
            summary.error_rules.bright_red().to_string()
        } else {
            summary.error_rules.to_string()
        }
    ));

    // ── Severity Breakdown ─────────────────────────────────────────────
    output.push_str(&format!("{}\n", "  DISA STIG SEVERITY BREAKDOWN".bright_yellow()));
    output.push_str(&format!("  {}\n", "─".repeat(54)));

    output.push_str(&format!(
        "  🔴 {} {:<14} Passed: {:<3} Failed: {}\n",
        "CAT I   (High):".bright_red().bold(),
        "",
        summary.cat1_passed.bright_green(),
        if summary.cat1_failed > 0 {
            summary.cat1_failed.bright_red().to_string()
        } else {
            summary.cat1_failed.to_string()
        }
    ));
    output.push_str(&format!(
        "  🟠 {} {:<14} Passed: {:<3} Failed: {}\n",
        "CAT II  (Medium):".bright_yellow().bold(),
        "",
        summary.cat2_passed.bright_green(),
        if summary.cat2_failed > 0 {
            summary.cat2_failed.bright_yellow().to_string()
        } else {
            summary.cat2_failed.to_string()
        }
    ));
    output.push_str(&format!(
        "  🔵 {} {:<14} Passed: {:<3} Failed: {}\n\n",
        "CAT III (Low):".bright_blue().bold(),
        "",
        summary.cat3_passed.bright_green(),
        if summary.cat3_failed > 0 {
            summary.cat3_failed.bright_blue().to_string()
        } else {
            summary.cat3_failed.to_string()
        }
    ));

    // ── Failed Rules Details ───────────────────────────────────────────
    let failed_rules: Vec<_> = summary
        .results
        .iter()
        .filter(|r| r.status == RuleStatus::Fail || r.status == RuleStatus::Error)
        .collect();

    if !failed_rules.is_empty() {
        output.push_str(&format!("{}\n", "═".repeat(74).bright_blue()));
        output.push_str(&format!(
            "{}\n",
            "  FAILED COMPLIANCE RULES & REMEDIATIONS".bright_red().bold()
        ));
        output.push_str(&format!("{}\n\n", "═".repeat(74).bright_blue()));

        for rule in failed_rules {
            let sev_badge = match rule.severity {
                AuditSeverity::CatI => "[CAT I - High]".bright_red().bold().to_string(),
                AuditSeverity::CatII => "[CAT II - Medium]".bright_yellow().bold().to_string(),
                AuditSeverity::CatIII => "[CAT III - Low]".bright_blue().bold().to_string(),
            };

            let stig_label = rule
                .stig_id
                .as_deref()
                .map(|s| format!(" [{}]", s))
                .unwrap_or_default();

            output.push_str(&format!(
                "  {} {}{}\n",
                sev_badge,
                rule.rule_id.bright_white().bold(),
                stig_label.bright_cyan()
            ));

            output.push_str(&format!(
                "  {} {}\n",
                "Title:".bright_white(),
                rule.title
            ));

            if !rule.nist_controls.is_empty() {
                output.push_str(&format!(
                    "  {} {}\n",
                    "NIST Controls:".bright_white(),
                    rule.nist_controls.join(", ").cyan()
                ));
            }

            if let Some(ref expected) = rule.expected_value {
                output.push_str(&format!(
                    "  {} {}\n",
                    "Expected:".bright_white(),
                    expected
                ));
            }

            if let Some(ref actual) = rule.actual_value {
                output.push_str(&format!("  {} {}\n", "Actual:".bright_white(), actual));
            }

            output.push_str(&format!(
                "  {} {}\n",
                "Finding:".bright_red(),
                rule.details
            ));

            output.push_str(&format!(
                "  {} {}\n",
                "Fix:".bright_green().bold(),
                rule.fix_text
            ));

            output.push_str(&format!("  {}\n\n", "─".repeat(60)));
        }
    } else {
        output.push_str(&format!(
            "  {} {}\n\n",
            "✓".bright_green().bold(),
            "All compliance checks passed!".bright_green().bold()
        ));
    }

    // ── Footer ──────────────────────────────────────────────────────────
    output.push_str(&format!("{}\n", "═".repeat(74).bright_blue()));
    output.push_str("  Powered by Evedoo Compliance Auditor (Apache-2.0)\n");
    output.push_str(&format!("  {}\n", AUDIT_DISCLAIMER));
    output.push_str(&format!("{}\n", "═".repeat(74).bright_blue()));

    output
}

/// Generates a structured JSON report object.
pub fn generate_json_report(summary: &AuditSummary) -> serde_json::Value {
    let mut value = serde_json::to_value(summary).unwrap_or(serde_json::Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("scope".to_string(), summary.scope_statement().into());
        object.insert("disclaimer".to_string(), AUDIT_DISCLAIMER.into());
    }
    value
}

/// Generates a standard CSV report string.
pub fn generate_csv_report(summary: &AuditSummary) -> String {
    let mut wtr = csv::Writer::from_writer(Vec::new());

    // Write header
    let _ = wtr.write_record([
        "Benchmark ID",
        "Benchmark Title",
        "Hostname",
        "Audit Date",
        "Rule ID",
        "STIG ID",
        "Severity",
        "NIST Controls",
        "Status",
        "Rule Title",
        "Expected Value",
        "Actual Value",
        "Finding Details",
        "Fix Recommendation",
    ]);

    let audit_date = summary.scan_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    for r in &summary.results {
        let _ = wtr.write_record([
            crate::report::sanitize_csv_cell(&summary.benchmark_id).as_ref(),
            crate::report::sanitize_csv_cell(&summary.benchmark_title).as_ref(),
            crate::report::sanitize_csv_cell(&summary.target_host).as_ref(),
            &audit_date,
            crate::report::sanitize_csv_cell(&r.rule_id).as_ref(),
            crate::report::sanitize_csv_cell(r.stig_id.as_deref().unwrap_or("")).as_ref(),
            r.severity.as_str(),
            &r.nist_controls.join("; "),
            r.status.as_str(),
            crate::report::sanitize_csv_cell(&r.title).as_ref(),
            crate::report::sanitize_csv_cell(r.expected_value.as_deref().unwrap_or("")).as_ref(),
            crate::report::sanitize_csv_cell(r.actual_value.as_deref().unwrap_or("")).as_ref(),
            crate::report::sanitize_csv_cell(&r.details).as_ref(),
            crate::report::sanitize_csv_cell(&r.fix_text).as_ref(),
        ]);
    }

    let _ = wtr.flush();
    String::from_utf8(wtr.into_inner().unwrap_or_default()).unwrap_or_default()
}

/// Generates a standalone, modern HTML compliance report.
pub fn generate_html_report(summary: &AuditSummary) -> String {
    let audit_date = summary.scan_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let score_color = if summary.compliance_score >= 80.0 {
        "#22c55e"
    } else if summary.compliance_score >= 50.0 {
        "#eab308"
    } else {
        "#ef4444"
    };

    let mut rows_html = String::new();
    for (idx, r) in summary.results.iter().enumerate() {
        let (status_class, status_badge) = match r.status {
            RuleStatus::Pass => ("pass", "PASS"),
            RuleStatus::Fail => ("fail", "FAIL"),
            RuleStatus::NotApplicable => ("na", "N/A"),
            RuleStatus::Error => ("error", "ERROR"),
        };

        let (sev_class, sev_label) = match r.severity {
            AuditSeverity::CatI => ("cat1", "CAT I (High)"),
            AuditSeverity::CatII => ("cat2", "CAT II (Medium)"),
            AuditSeverity::CatIII => ("cat3", "CAT III (Low)"),
        };

        let nist_tags: String = r
            .nist_controls
            .iter()
            .map(|c| format!(r#"<span class="badge nist">{}</span>"#, html_escape(c)))
            .collect::<Vec<_>>()
            .join(" ");

        let stig_text = r.stig_id.as_deref().unwrap_or("—");
        let expected_text = r.expected_value.as_deref().unwrap_or("—");
        let actual_text = r.actual_value.as_deref().unwrap_or("—");

        rows_html.push_str(&format!(
            r#"<tr class="rule-row {status_class} {sev_class}" data-index="{idx}">
                <td><span class="badge status-{status_class}">{status_badge}</span></td>
                <td><span class="badge sev-{sev_class}">{sev_label}</span></td>
                <td class="mono font-semibold">{rule_id}</td>
                <td class="mono">{stig_id}</td>
                <td>
                    <div class="rule-title">{title}</div>
                    <div class="rule-nist">{nist_tags}</div>
                </td>
                <td class="mono text-sm">{expected}</td>
                <td class="mono text-sm">{actual}</td>
                <td class="fix-cell text-sm">{fix}</td>
            </tr>"#,
            status_class = status_class,
            status_badge = status_badge,
            sev_class = sev_class,
            sev_label = sev_label,
            idx = idx,
            rule_id = html_escape(&r.rule_id),
            stig_id = html_escape(stig_text),
            title = html_escape(&r.title),
            nist_tags = nist_tags,
            expected = html_escape(expected_text),
            actual = html_escape(actual_text),
            fix = html_escape(&r.fix_text),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Audit Report - {benchmark_title}</title>
    <style>
        :root {{
            --bg-page: #0f172a;
            --bg-card: #1e293b;
            --bg-card-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --color-cat1: #ef4444;
            --color-cat2: #f59e0b;
            --color-cat3: #3b82f6;
            --color-pass: #22c55e;
            --color-fail: #ef4444;
            --color-na: #64748b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-page);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }}
        h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; }}
        .subtitle {{ color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }}
        
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .kpi-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 1.25rem;
            text-align: center;
        }}
        .kpi-label {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .kpi-value {{ font-size: 2rem; font-weight: 800; margin-top: 0.5rem; }}
        .kpi-score {{ color: {score_color}; }}
        
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .filter-buttons {{ display: flex; gap: 0.5rem; }}
        .btn {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.15s ease;
        }}
        .btn:hover {{ background-color: var(--bg-card-hover); }}
        .btn.active {{ background-color: #3b82f6; border-color: #3b82f6; color: #fff; }}
        .search-box input {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            width: 280px;
        }}
        .search-box input:focus {{ outline: none; border-color: #3b82f6; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--bg-card);
            border-radius: 0.75rem;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        th, td {{
            padding: 0.875rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #1a2234;
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        tr:hover td {{ background-color: rgba(255, 255, 255, 0.02); }}
        
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge.status-pass {{ background-color: rgba(34, 197, 94, 0.15); color: var(--color-pass); border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge.status-fail {{ background-color: rgba(239, 68, 68, 0.15); color: var(--color-fail); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge.status-na {{ background-color: rgba(100, 116, 139, 0.15); color: var(--color-na); }}
        .badge.status-error {{ background-color: rgba(239, 68, 68, 0.2); color: var(--color-fail); }}
        
        .badge.sev-cat1 {{ background-color: rgba(239, 68, 68, 0.15); color: var(--color-cat1); }}
        .badge.sev-cat2 {{ background-color: rgba(245, 158, 11, 0.15); color: var(--color-cat2); }}
        .badge.sev-cat3 {{ background-color: rgba(59, 130, 246, 0.15); color: var(--color-cat3); }}
        .badge.nist {{ background-color: #0f172a; color: #38bdf8; border: 1px solid #334155; font-size: 0.7rem; }}
        
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .font-semibold {{ font-weight: 600; }}
        .rule-title {{ font-weight: 500; margin-bottom: 0.25rem; }}
        .fix-cell {{ color: #4ade80; }}
        footer {{
            margin-top: 3rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Compliance Audit: {benchmark_title}</h1>
                <div class="subtitle">Host: <strong>{hostname}</strong> &bull; Benchmark ID: {benchmark_id} &bull; Date: {audit_date}</div>
            </div>
        </header>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Pass Rate (bundled checks)</div>
                <div class="kpi-value kpi-score">{compliance_score:.1}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Passed Rules</div>
                <div class="kpi-value" style="color: var(--color-pass);">{passed_rules}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Failed Rules</div>
                <div class="kpi-value" style="color: var(--color-fail);">{failed_rules}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">CAT I Failures</div>
                <div class="kpi-value" style="color: var(--color-cat1);">{cat1_failed}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">CAT II Failures</div>
                <div class="kpi-value" style="color: var(--color-cat2);">{cat2_failed}</div>
            </div>
        </div>

        <div class="controls">
            <div class="filter-buttons">
                <button class="btn active" onclick="filterRules('all')">All ({total_rules})</button>
                <button class="btn" onclick="filterRules('fail')">Failed Only ({failed_rules})</button>
                <button class="btn" onclick="filterRules('cat1')">CAT I (High)</button>
                <button class="btn" onclick="filterRules('cat2')">CAT II (Medium)</button>
                <button class="btn" onclick="filterRules('cat3')">CAT III (Low)</button>
            </div>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search rule ID, title, NIST..." onkeyup="searchTable()">
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Rule ID</th>
                    <th>STIG ID</th>
                    <th>Rule Title & NIST Controls</th>
                    <th>Expected</th>
                    <th>Actual</th>
                    <th>Remediation Fix</th>
                </tr>
            </thead>
            <tbody id="rulesTable">
                {rows_html}
            </tbody>
        </table>

        <footer>
            <div>{scope}</div>
            <div>{disclaimer}</div>
            Generated by Evedoo &mdash; Apache-2.0 configuration auditor
        </footer>
    </div>

    <script>
        function filterRules(type) {{
            const buttons = document.querySelectorAll('.filter-buttons .btn');
            buttons.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            const rows = document.querySelectorAll('#rulesTable tr');
            rows.forEach(row => {{
                if (type === 'all') {{
                    row.style.display = '';
                }} else if (type === 'fail') {{
                    row.style.display = row.classList.contains('fail') ? '' : 'none';
                }} else if (type === 'cat1') {{
                    row.style.display = row.classList.contains('cat1') ? '' : 'none';
                }} else if (type === 'cat2') {{
                    row.style.display = row.classList.contains('cat2') ? '' : 'none';
                }} else if (type === 'cat3') {{
                    row.style.display = row.classList.contains('cat3') ? '' : 'none';
                }}
            }});
        }}

        function searchTable() {{
            const filter = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('#rulesTable tr');
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(filter) ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>"#,
        benchmark_title = html_escape(&summary.benchmark_title),
        hostname = html_escape(&summary.target_host),
        benchmark_id = html_escape(&summary.benchmark_id),
        audit_date = audit_date,
        score_color = score_color,
        compliance_score = summary.compliance_score,
        scope = html_escape(&summary.scope_statement()),
        disclaimer = html_escape(AUDIT_DISCLAIMER),
        passed_rules = summary.passed_rules,
        failed_rules = summary.failed_rules,
        cat1_failed = summary.cat1_failed,
        cat2_failed = summary.cat2_failed,
        total_rules = summary.total_rules,
        rows_html = rows_html,
    )
}

/// Helper function to escape HTML special characters.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::policy::RuleResult;

    fn sample_summary() -> AuditSummary {
        let results = vec![
            RuleResult {
                rule_id: "WN11-CC-000010".to_string(),
                title: "SMBv1 must be disabled".to_string(),
                stig_id: Some("V-253378".to_string()),
                severity: AuditSeverity::CatI,
                nist_controls: vec!["CM-6".to_string(), "SC-7".to_string()],
                status: RuleStatus::Pass,
                actual_value: Some("0".to_string()),
                expected_value: Some("0".to_string()),
                details: "Matches expected".to_string(),
                fix_text: "Disable SMBv1".to_string(),
            },
            RuleResult {
                rule_id: "WN11-CC-000020".to_string(),
                title: "LLMNR must be disabled".to_string(),
                stig_id: Some("V-253380".to_string()),
                severity: AuditSeverity::CatII,
                nist_controls: vec!["CM-6".to_string()],
                status: RuleStatus::Fail,
                actual_value: Some("1".to_string()),
                expected_value: Some("0".to_string()),
                details: "LLMNR is enabled".to_string(),
                fix_text: "Set EnableMulticast to 0".to_string(),
            },
        ];

        AuditSummary::from_results(
            "U_MS_Windows_11_STIG".to_string(),
            "Microsoft Windows 11 STIG".to_string(),
            "testhost".to_string(),
            results,
        )
    }

    #[test]
    fn every_report_format_carries_the_disclaimer_and_the_scope() {
        let summary = AuditSummary::from_results(
            "U_TEST".to_string(),
            "Evedoo baseline checks derived from the Test STIG (V1R1)".to_string(),
            "HOST".to_string(),
            Vec::new(),
        );
        let scope = summary.scope_statement();
        assert!(scope.contains("not a full STIG assessment"), "{scope}");

        let text = generate_text_report(&summary);
        let html = generate_html_report(&summary);
        let json = generate_json_report(&summary);
        // CSV is one row per rule for spreadsheets and has no place for prose;
        // its "Benchmark Title" column carries the "derived from" wording.
        for (format, body) in [("text", &text), ("html", &html)] {
            assert!(body.contains(AUDIT_DISCLAIMER), "{format} report lacks the disclaimer");
            assert!(body.contains("not a full STIG assessment"), "{format} report lacks the scope statement");
        }
        assert_eq!(json["disclaimer"], AUDIT_DISCLAIMER);
        assert_eq!(json["scope"], scope);
        // The summary fields stay at the top level of the JSON document.
        assert_eq!(json["benchmark_id"], "U_TEST");
    }

    #[test]
    fn test_text_report_generation() {
        let summary = sample_summary();
        let report = generate_text_report(&summary);
        assert!(report.contains("EVEDOO COMPLIANCE AUDIT REPORT"));
        assert!(report.contains("Microsoft Windows 11 STIG"));
        assert!(report.contains("testhost"));
        assert!(report.contains("50.0%"));
        assert!(report.contains("WN11-CC-000020"));
        assert!(report.contains("Set EnableMulticast to 0"));
    }

    #[test]
    fn test_json_report_generation() {
        let summary = sample_summary();
        let json_val = generate_json_report(&summary);
        assert_eq!(json_val["benchmark_id"], "U_MS_Windows_11_STIG");
        assert_eq!(json_val["passed_rules"], 1);
        assert_eq!(json_val["failed_rules"], 1);
        assert_eq!(json_val["results"][0]["rule_id"], "WN11-CC-000010");
    }

    #[test]
    fn test_csv_report_generation() {
        let summary = sample_summary();
        let csv = generate_csv_report(&summary);
        assert!(csv.contains("Benchmark ID"));
        assert!(csv.contains("WN11-CC-000010"));
        assert!(csv.contains("WN11-CC-000020"));
        assert!(csv.contains("V-253378"));
    }

    #[test]
    fn test_csv_report_neutralizes_formula_injection() {
        let mut summary = sample_summary();
        summary.results[0].fix_text = "=cmd|'/c calc'!A1".to_string();
        let csv = generate_csv_report(&summary);
        assert!(csv.contains("'=cmd|'/c calc'!A1"));
    }

    #[test]
    fn test_html_report_generation() {
        let summary = sample_summary();
        let html = generate_html_report(&summary);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Microsoft Windows 11 STIG"));
        assert!(html.contains("WN11-CC-000010"));
        assert!(html.contains("WN11-CC-000020"));
        assert!(html.contains("Set EnableMulticast to 0"));
    }
}

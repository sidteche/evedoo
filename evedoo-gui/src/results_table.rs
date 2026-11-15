// Sortable vulnerability findings table with detail expansion.
//
// SPDX-License-Identifier: Apache-2.0

use crate::models::{Finding, Severity};
use eframe::egui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    CveId,
    Severity,
    Cvss,
    Epss,
    Kev,
    Software,
    Version,
    Confidence,
}

pub struct ResultsTableState {
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    /// Index of the expanded row (if any).
    pub expanded_row: Option<usize>,
}

impl Default for ResultsTableState {
    fn default() -> Self {
        Self {
            sort_column: SortColumn::Cvss,
            sort_ascending: false,
            expanded_row: None,
        }
    }
}

/// Sort findings in place based on current table state.
pub fn sort_findings(findings: &mut [Finding], state: &ResultsTableState) {
    findings.sort_by(|a, b| {
        let ord = match state.sort_column {
            SortColumn::CveId => a.vulnerability.cve_id.cmp(&b.vulnerability.cve_id),
            SortColumn::Severity => a.vulnerability.severity.cmp(&b.vulnerability.severity),
            SortColumn::Cvss => a
                .vulnerability
                .cvss_score
                .unwrap_or(0.0)
                .partial_cmp(&b.vulnerability.cvss_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Epss => a
                .vulnerability
                .epss_score
                .unwrap_or(0.0)
                .partial_cmp(&b.vulnerability.epss_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Kev => a.vulnerability.in_kev.cmp(&b.vulnerability.in_kev),
            SortColumn::Software => a.software.name.to_lowercase().cmp(&b.software.name.to_lowercase()),
            SortColumn::Version => a
                .software
                .version
                .as_deref()
                .unwrap_or("")
                .cmp(b.software.version.as_deref().unwrap_or("")),
            SortColumn::Confidence => a.confidence.cmp(&b.confidence),
        };
        if state.sort_ascending { ord } else { ord.reverse() }
    });
}

/// Render a clickable column header. Returns true if clicked.
fn column_header(ui: &mut egui::Ui, label: &str, col: SortColumn, state: &ResultsTableState) -> bool {
    let arrow = if state.sort_column == col {
        if state.sort_ascending { " ^" } else { " v" }
    } else {
        ""
    };
    let text = format!("{}{}", label, arrow);
    ui.selectable_label(false, text).clicked()
}

/// Render the summary bar above the table.
pub fn render_summary(ui: &mut egui::Ui, findings: &[Finding]) {
    let critical = findings.iter().filter(|f| f.vulnerability.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.vulnerability.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.vulnerability.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.vulnerability.severity == Severity::Low).count();
    let kev = findings.iter().filter(|f| f.vulnerability.in_kev).count();

    ui.horizontal(|ui| {
        ui.strong(format!("{} findings", findings.len()));
        ui.separator();
        ui.colored_label(egui::Color32::from_rgb(220, 50, 50), format!("{} Critical", critical));
        ui.separator();
        ui.colored_label(egui::Color32::from_rgb(230, 130, 40), format!("{} High", high));
        ui.separator();
        ui.colored_label(egui::Color32::from_rgb(200, 180, 40), format!("{} Medium", medium));
        ui.separator();
        ui.colored_label(egui::Color32::from_rgb(80, 140, 210), format!("{} Low", low));
        if kev > 0 {
            ui.separator();
            ui.colored_label(egui::Color32::from_rgb(200, 40, 40), format!("{} KEV", kev));
        }
    });
}

/// Severity color for table rows.
fn severity_color(severity: Severity) -> egui::Color32 {
    match severity {
        Severity::Critical => egui::Color32::from_rgb(220, 50, 50),
        Severity::High => egui::Color32::from_rgb(230, 130, 40),
        Severity::Medium => egui::Color32::from_rgb(200, 180, 40),
        Severity::Low => egui::Color32::from_rgb(80, 140, 210),
        Severity::Unknown => egui::Color32::GRAY,
    }
}

/// Render the findings table. Handles sorting header clicks and row expansion.
pub fn render_table(ui: &mut egui::Ui, findings: &[Finding], state: &mut ResultsTableState) {
    if findings.is_empty() {
        ui.label("No findings to display.");
        return;
    }

    let columns = [
        ("CVE ID", SortColumn::CveId),
        ("Severity", SortColumn::Severity),
        ("CVSS", SortColumn::Cvss),
        ("EPSS", SortColumn::Epss),
        ("KEV", SortColumn::Kev),
        ("Software", SortColumn::Software),
        ("Version", SortColumn::Version),
        ("Confidence", SortColumn::Confidence),
    ];

    egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("findings_table")
            .striped(true)
            .min_col_width(60.0)
            .show(ui, |ui| {
                // Header row
                for (label, col) in &columns {
                    if column_header(ui, label, *col, state) {
                        if state.sort_column == *col {
                            state.sort_ascending = !state.sort_ascending;
                        } else {
                            state.sort_column = *col;
                            state.sort_ascending = false;
                        }
                    }
                }
                ui.end_row();

                // Data rows
                for (idx, finding) in findings.iter().enumerate() {
                    let v = &finding.vulnerability;
                    let s = &finding.software;

                    // CVE ID (clickable to expand)
                    let resp = ui.selectable_label(
                        state.expanded_row == Some(idx),
                        &v.cve_id,
                    );
                    if resp.clicked() {
                        state.expanded_row = if state.expanded_row == Some(idx) {
                            None
                        } else {
                            Some(idx)
                        };
                    }

                    ui.colored_label(severity_color(v.severity), v.severity.to_string());
                    ui.label(v.cvss_score.map_or("-".to_string(), |s| format!("{:.1}", s)));
                    ui.label(v.epss_score.map_or("-".to_string(), |s| format!("{:.3}", s)));
                    ui.label(if v.in_kev { "YES" } else { "" });
                    ui.label(&s.name);
                    ui.label(s.version.as_deref().unwrap_or("-"));
                    ui.label(finding.confidence.to_string());
                    ui.end_row();

                    // Expanded detail row
                    if state.expanded_row == Some(idx) {
                        ui.label(""); // skip first column
                        ui.end_row();
                        render_detail(ui, finding);
                        ui.end_row();
                    }
                }
            });
    });
}

fn render_detail(ui: &mut egui::Ui, finding: &Finding) {
    let v = &finding.vulnerability;
    let r = &v.remediation;

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(600.0);

        ui.strong("Description:");
        ui.label(&v.description);
        ui.add_space(4.0);

        ui.strong("Remediation:");
        ui.label(&r.recommendation);

        if let Some(fixed) = &r.fixed_version {
            ui.horizontal(|ui| {
                ui.strong("Fixed in:");
                ui.label(fixed);
            });
        }

        if let Some(cmd) = &r.upgrade_command {
            ui.horizontal(|ui| {
                ui.strong("Upgrade:");
                ui.code(cmd);
            });
        }

        if !r.kb_articles.is_empty() {
            ui.horizontal(|ui| {
                ui.strong("KB Articles:");
                ui.label(r.kb_articles.join(", "));
            });
        }

        if let Some(epss) = v.epss_score {
            ui.horizontal(|ui| {
                ui.strong("EPSS:");
                ui.label(format!(
                    "{:.1}% ({}th percentile)",
                    epss * 100.0,
                    v.epss_percentile.map_or("-".to_string(), |p| format!("{:.0}", p * 100.0))
                ));
            });
        }

        if v.in_kev {
            ui.horizontal(|ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(200, 40, 40),
                    "CISA Known Exploited Vulnerability",
                );
                if let Some(due) = &v.kev_due_date {
                    ui.label(format!("Due: {}", due));
                }
            });
        }

        if let Some(pub_date) = &v.published_date {
            ui.horizontal(|ui| {
                ui.strong("Published:");
                ui.label(pub_date);
            });
        }

        ui.horizontal(|ui| {
            ui.strong("Status:");
            ui.label(finding.status.to_string());
            if let Some(vendor) = &finding.vendor {
                ui.separator();
                ui.strong("Vendor:");
                ui.label(vendor);
            }
        });
    });
}

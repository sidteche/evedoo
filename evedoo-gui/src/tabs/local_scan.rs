// Local Scan tab — configure and run a local vulnerability scan.
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::AppConfig;
use eframe::egui;

pub struct LocalScanState {
    pub database_path: String,
    pub severity_critical: bool,
    pub severity_high: bool,
    pub severity_medium: bool,
    pub severity_low: bool,
    pub min_confidence: usize, // 0=Exact, 1=High, 2=Medium, 3=Low
    pub csv_output_path: String,
}

impl Default for LocalScanState {
    fn default() -> Self {
        Self {
            database_path: String::new(),
            severity_critical: true,
            severity_high: true,
            severity_medium: true,
            severity_low: false,
            min_confidence: 1, // High
            csv_output_path: "evedoo_report.csv".to_string(),
        }
    }
}

impl LocalScanState {
    /// Sync defaults from config on first use.
    pub fn init_from_config(&mut self, config: &AppConfig) {
        if self.database_path.is_empty() {
            self.database_path = config.default_db_path.clone();
        }
    }

    /// Base scan arguments (shared across JSON/CSV/HTML runs).
    fn base_args(&self) -> Vec<String> {
        let mut args = vec![
            "scan".to_string(),
            "--database".to_string(),
            self.database_path.clone(),
        ];

        let severities = build_severity_filter(
            self.severity_critical,
            self.severity_high,
            self.severity_medium,
            self.severity_low,
        );
        if !severities.is_empty() {
            args.push("--severity".to_string());
            args.push(severities);
        }

        args.push("--min-confidence".to_string());
        args.push(confidence_str(self.min_confidence).to_string());

        args
    }

    /// Build args for the primary JSON scan (parsed by GUI).
    pub fn build_args(&self) -> Vec<String> {
        let mut args = self.base_args();
        args.extend(["--format".to_string(), "json".to_string(), "--no-history".to_string()]);
        args
    }

    /// Build args for CSV export to file.
    pub fn build_csv_args(&self) -> Vec<String> {
        let mut args = self.base_args();
        args.extend([
            "--format".to_string(),
            "csv".to_string(),
            "--output".to_string(),
            self.csv_output_path.clone(),
            "--no-history".to_string(),
        ]);
        args
    }

    /// Build args for HTML report served in browser.
    pub fn build_html_args(&self) -> Vec<String> {
        let mut args = self.base_args();
        args.extend([
            "--format".to_string(),
            "html".to_string(),
            "--serve".to_string(),
            "--no-history".to_string(),
        ]);
        args
    }
}

pub fn render(ui: &mut egui::Ui, state: &mut LocalScanState, is_running: bool) -> bool {
    ui.heading("Local Scan");
    ui.add_space(8.0);

    let mut run_clicked = false;

    egui::Grid::new("local_scan_grid")
        .num_columns(3)
        .spacing([8.0, 8.0])
        .show(ui, |ui| {
            ui.label("Database:");
            ui.add(
                egui::TextEdit::singleline(&mut state.database_path)
                    .desired_width(400.0)
                    .hint_text("vulndb.sqlite"),
            );
            if ui.button("Browse...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("SQLite", &["sqlite", "db"])
                    .pick_file()
                {
                    state.database_path = path.to_string_lossy().to_string();
                }
            }
            ui.end_row();

            ui.label("CSV Output:");
            ui.add(
                egui::TextEdit::singleline(&mut state.csv_output_path)
                    .desired_width(400.0)
                    .hint_text("evedoo_report.csv"),
            );
            if ui.button("Browse...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("CSV", &["csv"])
                    .save_file()
                {
                    state.csv_output_path = path.to_string_lossy().to_string();
                }
            }
            ui.end_row();

            ui.label("Severity Filter:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.severity_critical, "Critical");
                ui.checkbox(&mut state.severity_high, "High");
                ui.checkbox(&mut state.severity_medium, "Medium");
                ui.checkbox(&mut state.severity_low, "Low");
            });
            ui.label("");
            ui.end_row();

            ui.label("Min Confidence:");
            egui::ComboBox::from_id_salt("local_confidence")
                .selected_text(confidence_str(state.min_confidence))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut state.min_confidence, 0, "Exact");
                    ui.selectable_value(&mut state.min_confidence, 1, "High");
                    ui.selectable_value(&mut state.min_confidence, 2, "Medium");
                    ui.selectable_value(&mut state.min_confidence, 3, "Low");
                });
            ui.label("");
            ui.end_row();
        });

    ui.add_space(12.0);

    ui.horizontal(|ui| {
        let btn = ui.add_enabled(!is_running, egui::Button::new("Run Scan"));
        if btn.clicked() {
            run_clicked = true;
        }
        if is_running {
            ui.spinner();
            ui.label("Scanning...");
        }
    });

    run_clicked
}

fn confidence_str(idx: usize) -> &'static str {
    match idx {
        0 => "exact",
        1 => "high",
        2 => "medium",
        3 => "low",
        _ => "high",
    }
}

fn build_severity_filter(critical: bool, high: bool, medium: bool, low: bool) -> String {
    let mut parts = Vec::new();
    if critical { parts.push("critical"); }
    if high { parts.push("high"); }
    if medium { parts.push("medium"); }
    if low { parts.push("low"); }
    parts.join(",")
}

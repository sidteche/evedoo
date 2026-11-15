// Remote Scan tab — configure and run a WinRM remote vulnerability scan.
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::AppConfig;
use eframe::egui;

pub struct RemoteScanState {
    pub target: String,
    pub port: String,
    pub username: String,
    pub password: String,
    pub use_ssl: bool,
    pub skip_tls_verify: bool,
    pub database_path: String,
    pub severity_critical: bool,
    pub severity_high: bool,
    pub severity_medium: bool,
    pub severity_low: bool,
    pub min_confidence: usize,
    pub csv_output_path: String,
}

impl Default for RemoteScanState {
    fn default() -> Self {
        Self {
            target: String::new(),
            port: "5985".to_string(),
            username: String::new(),
            password: String::new(),
            use_ssl: false,
            skip_tls_verify: false,
            database_path: String::new(),
            severity_critical: true,
            severity_high: true,
            severity_medium: true,
            severity_low: false,
            min_confidence: 1,
            csv_output_path: "evedoo_remote_report.csv".to_string(),
        }
    }
}

impl RemoteScanState {
    pub fn init_from_config(&mut self, config: &AppConfig) {
        if self.database_path.is_empty() {
            self.database_path = config.default_db_path.clone();
        }
    }

    /// The password, handed to the child on stdin (SEC-5) — never in argv,
    /// the environment block, or on disk. Paired with the `--password-stdin`
    /// flag added by `base_args`.
    pub fn stdin_secret(&self) -> Option<String> {
        Some(self.password.clone())
    }

    /// Base scan arguments (shared across JSON/CSV/HTML runs).
    ///
    /// Deliberately excludes the password — see [`Self::stdin_secret`].
    fn base_args(&self) -> Vec<String> {
        let mut args = vec![
            "remote-scan".to_string(),
            "--target".to_string(),
            self.target.clone(),
            "--port".to_string(),
            self.port.clone(),
            "--username".to_string(),
            self.username.clone(),
            "--password-stdin".to_string(),
            "--database".to_string(),
            self.database_path.clone(),
        ];

        if self.use_ssl {
            args.push("--use-ssl".to_string());
        }
        if self.skip_tls_verify {
            args.push("--skip-tls-verify".to_string());
        }

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

pub fn render(ui: &mut egui::Ui, state: &mut RemoteScanState, is_running: bool) -> bool {
    ui.heading("Remote Scan");
    ui.add_space(8.0);

    let mut run_clicked = false;

    egui::Grid::new("remote_scan_grid")
        .num_columns(3)
        .spacing([8.0, 8.0])
        .show(ui, |ui| {
            // Target
            ui.label("Target Host:");
            ui.add(
                egui::TextEdit::singleline(&mut state.target)
                    .desired_width(300.0)
                    .hint_text("hostname or IP"),
            );
            ui.label("");
            ui.end_row();

            // Port
            ui.label("Port:");
            ui.add(
                egui::TextEdit::singleline(&mut state.port)
                    .desired_width(80.0)
                    .hint_text("5985"),
            );
            ui.label("(5985=HTTP, 5986=HTTPS)");
            ui.end_row();

            // Username
            ui.label("Username:");
            ui.add(
                egui::TextEdit::singleline(&mut state.username)
                    .desired_width(300.0)
                    .hint_text("DOMAIN\\admin or admin@domain"),
            );
            ui.label("");
            ui.end_row();

            // Password
            ui.label("Password:");
            ui.add(
                egui::TextEdit::singleline(&mut state.password)
                    .password(true)
                    .desired_width(300.0),
            );
            ui.label("");
            ui.end_row();

            // SSL options
            ui.label("Connection:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.use_ssl, "Use SSL");
                ui.checkbox(&mut state.skip_tls_verify, "Skip TLS Verify");
            });
            if state.skip_tls_verify {
                ui.colored_label(
                    egui::Color32::from_rgb(230, 160, 40),
                    "Warning: TLS validation disabled",
                );
            } else {
                ui.label("");
            }
            ui.end_row();

            // Database
            ui.label("Database:");
            ui.add(
                egui::TextEdit::singleline(&mut state.database_path)
                    .desired_width(300.0)
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

            // CSV output
            ui.label("CSV Output:");
            ui.add(
                egui::TextEdit::singleline(&mut state.csv_output_path)
                    .desired_width(300.0)
                    .hint_text("evedoo_remote_report.csv"),
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

            // Severity filter
            ui.label("Severity Filter:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.severity_critical, "Critical");
                ui.checkbox(&mut state.severity_high, "High");
                ui.checkbox(&mut state.severity_medium, "Medium");
                ui.checkbox(&mut state.severity_low, "Low");
            });
            ui.label("");
            ui.end_row();

            // Min confidence
            ui.label("Min Confidence:");
            egui::ComboBox::from_id_salt("remote_confidence")
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
        let can_run = !is_running && !state.target.is_empty() && !state.username.is_empty();
        let btn = ui.add_enabled(can_run, egui::Button::new("Run Remote Scan"));
        if btn.clicked() {
            run_clicked = true;
        }
        if is_running {
            ui.spinner();
            ui.label("Scanning remote host...");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hostile_state() -> RemoteScanState {
        RemoteScanState {
            target: "host.example.com".into(),
            username: "admin".into(),
            password: "S3cr3t-P@ssw0rd!".into(),
            database_path: "vulndb.sqlite".into(),
            ..Default::default()
        }
    }

    /// SEC-3: the password must never reach the child's argument vector —
    /// argv is captured by 4688/Sysmon/EDR command-line telemetry.
    #[test]
    fn password_never_appears_in_any_argv() {
        let s = hostile_state();
        for args in [s.build_args(), s.build_csv_args(), s.build_html_args()] {
            assert!(
                !args.iter().any(|a| a.contains("S3cr3t-P@ssw0rd!")),
                "password leaked into argv: {args:?}"
            );
            assert!(
                !args.iter().any(|a| a == "--password"),
                "--password flag still present: {args:?}"
            );
        }
    }

    /// SEC-5: the password reaches the child on stdin — never argv, never the
    /// environment block — and the CLI is told to expect it there.
    #[test]
    fn password_is_passed_on_stdin() {
        let s = hostile_state();
        assert_eq!(s.stdin_secret(), Some("S3cr3t-P@ssw0rd!".to_string()));
        for args in [s.build_args(), s.build_csv_args(), s.build_html_args()] {
            assert!(
                args.contains(&"--password-stdin".to_string()),
                "--password-stdin must be requested: {args:?}"
            );
        }
    }

    /// Non-secret arguments must survive the change.
    #[test]
    fn non_secret_args_are_preserved() {
        let args = hostile_state().build_args();
        assert!(args.contains(&"remote-scan".to_string()));
        assert!(args.contains(&"host.example.com".to_string()));
        assert!(args.contains(&"admin".to_string()));
    }
}

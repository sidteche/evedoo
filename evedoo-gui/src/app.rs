// Main application state and eframe::App implementation.
//
// SPDX-License-Identifier: Apache-2.0

use crate::command::{self, CommandOutput};
use crate::config::AppConfig;
use crate::models::ScanResult;
use crate::results_table::{self, ResultsTableState};
use crate::tabs::{local_scan, remote_scan, settings, update_db};
use eframe::egui;
use std::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    LocalScan,
    RemoteScan,
    UpdateDb,
    Settings,
}

/// Follow-up commands to run after the primary JSON scan succeeds.
struct FollowUpCommands {
    program: String,
    csv_args: Vec<String>,
    html_args: Vec<String>,
    /// Secrets for the child's environment rather than its argv (SEC-3).
    envs: Vec<(String, String)>,
    /// Secret written to the child's stdin (SEC-5) — strongest channel.
    stdin_secret: Option<String>,
}

pub struct EvedooApp {
    active_tab: Tab,
    config: AppConfig,
    initialized: bool,

    // Tab states
    local_scan: local_scan::LocalScanState,
    remote_scan: remote_scan::RemoteScanState,
    update_db: update_db::UpdateDbState,
    settings: settings::SettingsState,

    // Primary command execution (JSON scan / DB update)
    command_tx: mpsc::Sender<CommandOutput>,
    command_rx: mpsc::Receiver<CommandOutput>,
    is_running: bool,
    status_message: String,
    status_is_error: bool,

    // Follow-up commands queued after successful scan
    pending_followups: Option<FollowUpCommands>,
    /// Count of fire-and-forget follow-up processes still running.
    followup_running: u32,
    followup_tx: mpsc::Sender<CommandOutput>,
    followup_rx: mpsc::Receiver<CommandOutput>,

    // Results
    scan_results: Option<ScanResult>,
    sorted_findings: Vec<crate::models::Finding>,
    table_state: ResultsTableState,

    // Log
    log_output: String,
}

impl EvedooApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let (ftx, frx) = mpsc::channel();
        Self {
            active_tab: Tab::LocalScan,
            config: AppConfig::load(),
            initialized: false,
            local_scan: local_scan::LocalScanState::default(),
            remote_scan: remote_scan::RemoteScanState::default(),
            update_db: update_db::UpdateDbState::default(),
            settings: settings::SettingsState::default(),
            command_tx: tx,
            command_rx: rx,
            is_running: false,
            status_message: String::new(),
            status_is_error: false,
            pending_followups: None,
            followup_running: 0,
            followup_tx: ftx,
            followup_rx: frx,
            scan_results: None,
            sorted_findings: Vec::new(),
            table_state: ResultsTableState::default(),
            log_output: String::new(),
        }
    }

    fn init_tabs(&mut self) {
        if !self.initialized {
            self.local_scan.init_from_config(&self.config);
            self.remote_scan.init_from_config(&self.config);
            self.update_db.init_from_config(&self.config);
            self.initialized = true;
        }
    }

    fn poll_command(&mut self) {
        while let Ok(msg) = self.command_rx.try_recv() {
            match msg {
                CommandOutput::StderrLine(line) => {
                    self.log_output.push_str(&line);
                    self.log_output.push('\n');
                }
                CommandOutput::Finished {
                    exit_code,
                    stdout,
                    stderr: _,
                } => {
                    self.is_running = false;
                    if exit_code == Some(0) {
                        // Try to parse JSON scan results.
                        // The CLI mixes banner/progress text with the JSON
                        // report on stdout, so we extract the JSON object.
                        match extract_json(&stdout)
                            .and_then(|json| serde_json::from_str::<ScanResult>(json).ok())
                        {
                            Some(result) => {
                                self.status_message = format!(
                                    "Scan complete: {} findings across {} software on {}",
                                    result.total_vulnerabilities,
                                    result.total_software,
                                    result.hostname,
                                );
                                self.status_is_error = false;
                                self.sorted_findings = result.findings.clone();
                                results_table::sort_findings(
                                    &mut self.sorted_findings,
                                    &self.table_state,
                                );
                                self.scan_results = Some(result);

                                // Fire follow-up CSV + HTML commands
                                self.fire_followups();
                            }
                            None => {
                                // Not JSON output (e.g., db update) — show stdout in log
                                self.log_output.push_str(&stdout);
                                self.status_message = "Command completed successfully.".to_string();
                                self.status_is_error = false;
                            }
                        }
                    } else {
                        self.status_message = format!(
                            "Command failed (exit code: {})",
                            exit_code.map_or("unknown".to_string(), |c| c.to_string()),
                        );
                        self.status_is_error = true;
                        if !stdout.is_empty() {
                            self.log_output.push_str(&stdout);
                        }
                    }
                }
                CommandOutput::Error(err) => {
                    self.is_running = false;
                    self.status_message = err;
                    self.status_is_error = true;
                }
            }
        }

        // Poll follow-up command results (fire-and-forget, just log output)
        while let Ok(msg) = self.followup_rx.try_recv() {
            match msg {
                CommandOutput::StderrLine(line) => {
                    self.log_output.push_str(&line);
                    self.log_output.push('\n');
                }
                CommandOutput::Finished { exit_code, stdout, .. } => {
                    self.followup_running = self.followup_running.saturating_sub(1);
                    if exit_code == Some(0) {
                        // Check if this was a CSV export (stdout will be empty since --output)
                        if stdout.is_empty() || !stdout.contains('{') {
                            self.log_output.push_str("CSV report exported.\n");
                        }
                        // HTML serve doesn't finish (blocks until Ctrl+C), so we
                        // won't normally see this — but log it if it does.
                    } else {
                        self.log_output.push_str(&format!(
                            "Follow-up command failed (exit code: {})\n",
                            exit_code.map_or("unknown".to_string(), |c| c.to_string()),
                        ));
                        if !stdout.is_empty() {
                            self.log_output.push_str(&stdout);
                        }
                    }
                }
                CommandOutput::Error(err) => {
                    self.followup_running = self.followup_running.saturating_sub(1);
                    self.log_output.push_str(&format!("Follow-up error: {}\n", err));
                }
            }
        }
    }

    /// Spawn queued CSV and HTML follow-up commands after a successful scan.
    fn fire_followups(&mut self) {
        if let Some(followups) = self.pending_followups.take() {
            // CSV export
            self.log_output.push_str("Exporting CSV report...\n");
            self.followup_running += 1;
            command::spawn_command_with_env(
                followups.program.clone(),
                followups.csv_args,
                followups.envs.clone(),
                followups.stdin_secret.clone(),
                self.followup_tx.clone(),
            );

            // HTML serve (opens browser)
            self.log_output.push_str("Launching HTML report in browser...\n");
            self.followup_running += 1;
            command::spawn_command_with_env(
                followups.program,
                followups.html_args,
                followups.envs,
                followups.stdin_secret,
                self.followup_tx.clone(),
            );
        }
    }

    fn start_scan(&mut self, program: String, args: Vec<String>, followups: FollowUpCommands) {
        self.is_running = true;
        self.log_output.clear();
        self.status_message = "Scanning...".to_string();
        self.status_is_error = false;
        self.scan_results = None;
        self.sorted_findings.clear();
        self.table_state.expanded_row = None;
        let envs = followups.envs.clone();
        let stdin_secret = followups.stdin_secret.clone();
        self.pending_followups = Some(followups);
        command::spawn_command_with_env(program, args, envs, stdin_secret, self.command_tx.clone());
    }

    fn start_db_update(
        &mut self,
        program: String,
        args: Vec<String>,
        envs: Vec<(String, String)>,
    ) {
        self.is_running = true;
        self.log_output.clear();
        self.status_message = "Updating database...".to_string();
        self.status_is_error = false;
        self.pending_followups = None;
        command::spawn_command_with_env(program, args, envs, None, self.command_tx.clone());
    }
}

impl eframe::App for EvedooApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.init_tabs();
        self.poll_command();

        // Repaint while any command is running
        if self.is_running || self.followup_running > 0 {
            ctx.request_repaint();
        }

        // Top panel: tab bar
        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::LocalScan, "Local Scan");
                ui.selectable_value(&mut self.active_tab, Tab::RemoteScan, "Remote Scan");
                ui.selectable_value(&mut self.active_tab, Tab::UpdateDb, "Update DB");
                ui.selectable_value(&mut self.active_tab, Tab::Settings, "Settings");
            });
        });

        // Bottom panel: status bar
        egui::TopBottomPanel::bottom("status_bar")
            .min_height(24.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.is_running || self.followup_running > 0 {
                        ui.spinner();
                    }
                    if self.status_is_error {
                        ui.colored_label(egui::Color32::from_rgb(220, 50, 50), &self.status_message);
                    } else {
                        ui.label(&self.status_message);
                    }
                    if self.followup_running > 0 {
                        ui.separator();
                        ui.label(format!("Generating reports... ({})", self.followup_running));
                    }
                });
            });

        // Bottom panel: log output (collapsible)
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .min_height(60.0)
            .default_height(120.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Log Output");
                    if ui.small_button("Clear").clicked() {
                        self.log_output.clear();
                    }
                });
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.log_output.as_str())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY),
                        );
                    });
            });

        // Central panel: tab content + results
        egui::CentralPanel::default().show(ctx, |ui| {
            // Tab content
            match self.active_tab {
                Tab::LocalScan => {
                    if local_scan::render(ui, &mut self.local_scan, self.is_running) {
                        let program = self.config.evedoo_exe_path.clone();
                        let args = self.local_scan.build_args();
                        let followups = FollowUpCommands {
                            program: program.clone(),
                            csv_args: self.local_scan.build_csv_args(),
                            html_args: self.local_scan.build_html_args(),
                            envs: Vec::new(),
                            stdin_secret: None,
                        };
                        self.start_scan(program, args, followups);
                    }
                }
                Tab::RemoteScan => {
                    if remote_scan::render(ui, &mut self.remote_scan, self.is_running) {
                        let program = self.config.evedoo_exe_path.clone();
                        let args = self.remote_scan.build_args();
                        let followups = FollowUpCommands {
                            program: program.clone(),
                            csv_args: self.remote_scan.build_csv_args(),
                            html_args: self.remote_scan.build_html_args(),
                            envs: Vec::new(),
                            stdin_secret: self.remote_scan.stdin_secret(),
                        };
                        self.start_scan(program, args, followups);
                    }
                }
                Tab::UpdateDb => {
                    if update_db::render(ui, &mut self.update_db, &self.config, self.is_running) {
                        let args = self.update_db.build_args();
                        let envs = self.update_db.secret_envs(&self.config);
                        let program = self.config.cve_db_builder_exe_path.clone();
                        self.start_db_update(program, args, envs);
                    }
                }
                Tab::Settings => {
                    settings::render(ui, &mut self.config, &mut self.settings);
                }
            }

            // Results section (shown below scan tabs)
            if self.active_tab == Tab::LocalScan || self.active_tab == Tab::RemoteScan {
                ui.add_space(12.0);
                ui.separator();

                if !self.sorted_findings.is_empty() {
                    results_table::render_summary(ui, &self.sorted_findings);
                    ui.add_space(4.0);

                    let prev_col = self.table_state.sort_column;
                    let prev_asc = self.table_state.sort_ascending;

                    results_table::render_table(ui, &self.sorted_findings, &mut self.table_state);

                    // Re-sort if column/direction changed
                    if self.table_state.sort_column != prev_col
                        || self.table_state.sort_ascending != prev_asc
                    {
                        results_table::sort_findings(
                            &mut self.sorted_findings,
                            &self.table_state,
                        );
                    }
                } else if self.scan_results.is_some() {
                    ui.label("No vulnerabilities found.");
                }
            }
        });
    }
}

/// Extract the JSON object from CLI stdout that may contain banner/progress text.
///
/// The evedoo CLI prints banner, progress, and the JSON report all to stdout.
/// We find the outermost `{ ... }` block which is the scan result JSON.
fn extract_json(output: &str) -> Option<&str> {
    let start = output.find('{')?;
    let end = output.rfind('}')?;
    if end > start {
        Some(&output[start..=end])
    } else {
        None
    }
}

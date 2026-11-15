// Update DB tab — sync NVD database via cve-db-builder.
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::AppConfig;
use eframe::egui;

pub struct UpdateDbState {
    pub api_key: String,
    pub use_settings_key: bool,
    pub output_path: String,
    pub incremental: bool,
    pub enrichment_only: bool,
    pub skip_kev: bool,
    pub skip_epss: bool,
}

impl Default for UpdateDbState {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            use_settings_key: true,
            output_path: String::new(),
            incremental: true,
            enrichment_only: false,
            skip_kev: false,
            skip_epss: false,
        }
    }
}

impl UpdateDbState {
    pub fn init_from_config(&mut self, config: &AppConfig) {
        if self.output_path.is_empty() {
            self.output_path = config.default_db_path.clone();
        }
    }

    pub fn effective_api_key(&self, config: &AppConfig) -> String {
        if self.use_settings_key {
            config.nvd_api_key.clone()
        } else {
            self.api_key.clone()
        }
    }

    /// API key passed through the child's environment rather than argv
    /// (SEC-3). `cve-db-builder` reads `NVD_API_KEY` via clap's `env`
    /// attribute. Lower value than the WinRM password — it is a rate-limit
    /// token — but it costs nothing to route it the same way.
    pub fn secret_envs(&self, config: &AppConfig) -> Vec<(String, String)> {
        let key = self.effective_api_key(config);
        if key.is_empty() {
            Vec::new()
        } else {
            vec![("NVD_API_KEY".to_string(), key)]
        }
    }

    /// Build CLI arguments. Deliberately excludes the API key — see
    /// [`Self::secret_envs`].
    pub fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        args.push("--output".to_string());
        args.push(self.output_path.clone());

        if self.incremental {
            args.push("--update".to_string());
        }
        if self.enrichment_only {
            args.push("--enrichment-only".to_string());
        }
        if self.skip_kev {
            args.push("--skip-kev".to_string());
        }
        if self.skip_epss {
            args.push("--skip-epss".to_string());
        }

        args
    }
}

pub fn render(ui: &mut egui::Ui, state: &mut UpdateDbState, config: &AppConfig, is_running: bool) -> bool {
    ui.heading("Update CVE Database");
    ui.add_space(8.0);

    let mut run_clicked = false;

    egui::Grid::new("update_db_grid")
        .num_columns(3)
        .spacing([8.0, 8.0])
        .show(ui, |ui| {
            // API Key source
            ui.label("NVD API Key:");
            ui.horizontal(|ui| {
                ui.radio_value(&mut state.use_settings_key, true, "Use from Settings");
                ui.radio_value(&mut state.use_settings_key, false, "Custom:");
            });
            ui.label("");
            ui.end_row();

            if !state.use_settings_key {
                ui.label("");
                ui.add(
                    egui::TextEdit::singleline(&mut state.api_key)
                        .password(true)
                        .desired_width(400.0)
                        .hint_text("Enter NVD API key"),
                );
                ui.label("");
                ui.end_row();
            }

            // Output path
            ui.label("Output Database:");
            ui.add(
                egui::TextEdit::singleline(&mut state.output_path)
                    .desired_width(400.0)
                    .hint_text("vulndb.sqlite"),
            );
            if ui.button("Browse...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("SQLite", &["sqlite", "db"])
                    .save_file()
                {
                    state.output_path = path.to_string_lossy().to_string();
                }
            }
            ui.end_row();

            // Options
            ui.label("Sync Mode:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.incremental, "Incremental update");
                ui.checkbox(&mut state.enrichment_only, "Enrichment only (skip NVD)");
            });
            ui.label("");
            ui.end_row();

            ui.label("Skip:");
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.skip_kev, "Skip CISA KEV");
                ui.checkbox(&mut state.skip_epss, "Skip EPSS");
            });
            ui.label("");
            ui.end_row();
        });

    ui.add_space(12.0);

    let has_key = !state.effective_api_key(config).is_empty() || state.enrichment_only;

    ui.horizontal(|ui| {
        let can_run = !is_running && has_key;
        let btn = ui.add_enabled(can_run, egui::Button::new("Update Database"));
        if btn.clicked() {
            run_clicked = true;
        }
        if !has_key && !is_running {
            ui.colored_label(
                egui::Color32::from_rgb(230, 160, 40),
                "API key required (set in Settings or enter above)",
            );
        }
        if is_running {
            ui.spinner();
            ui.label("Updating database (this may take several minutes)...");
        }
    });

    run_clicked
}

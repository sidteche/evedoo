// Settings tab — API key, exe paths, default database path.
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::AppConfig;
use eframe::egui;

pub struct SettingsState {
    pub saved_toast_timer: f32,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            saved_toast_timer: 0.0,
        }
    }
}

pub fn render(ui: &mut egui::Ui, config: &mut AppConfig, state: &mut SettingsState) {
    ui.heading("Settings");
    ui.add_space(8.0);

    egui::Grid::new("settings_grid")
        .num_columns(3)
        .spacing([8.0, 8.0])
        .show(ui, |ui| {
            // NVD API Key
            ui.label("NVD API Key:");
            ui.add(
                egui::TextEdit::singleline(&mut config.nvd_api_key)
                    .password(true)
                    .desired_width(400.0)
                    .hint_text("Enter your NVD API key"),
            );
            // Only the real environment can be detected here: a key read from a
            // `.env` is copied into the config field, not exported (see
            // config::load_env_api_key), so it shows as a filled field instead.
            let has_env_key = std::env::var("NVD_API_KEY").is_ok_and(|k| !k.trim().is_empty());
            if has_env_key {
                ui.colored_label(
                    egui::Color32::from_rgb(60, 180, 60),
                    "Loaded from NVD_API_KEY environment variable",
                );
            } else {
                ui.label("(free from nvd.nist.gov)");
            }
            ui.end_row();

            // Default database path
            ui.label("Database Path:");
            ui.add(
                egui::TextEdit::singleline(&mut config.default_db_path)
                    .desired_width(400.0)
                    .hint_text("vulndb.sqlite"),
            );
            if ui.button("Browse...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("SQLite", &["sqlite", "db"])
                    .pick_file()
                {
                    config.default_db_path = path.to_string_lossy().to_string();
                }
            }
            ui.end_row();

            // Evedoo exe path
            ui.label("evedoo.exe:");
            ui.add(
                egui::TextEdit::singleline(&mut config.evedoo_exe_path)
                    .desired_width(400.0)
                    .hint_text("evedoo.exe"),
            );
            if ui.button("Browse...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Executable", &["exe"])
                    .pick_file()
                {
                    config.evedoo_exe_path = path.to_string_lossy().to_string();
                }
            }
            ui.end_row();

            // CVE DB builder exe path
            ui.label("cve-db-builder.exe:");
            ui.add(
                egui::TextEdit::singleline(&mut config.cve_db_builder_exe_path)
                    .desired_width(400.0)
                    .hint_text("cve-db-builder.exe"),
            );
            if ui.button("Browse...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Executable", &["exe"])
                    .pick_file()
                {
                    config.cve_db_builder_exe_path = path.to_string_lossy().to_string();
                }
            }
            ui.end_row();
        });

    ui.add_space(16.0);

    ui.horizontal(|ui| {
        if ui.button("Save Settings").clicked() {
            config.save();
            state.saved_toast_timer = 2.0;
        }

        if state.saved_toast_timer > 0.0 {
            ui.colored_label(egui::Color32::from_rgb(60, 180, 60), "Settings saved!");
            state.saved_toast_timer -= ui.input(|i| i.predicted_dt);
        }
    });
}

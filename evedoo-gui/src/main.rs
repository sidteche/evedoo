// Evedoo GUI — egui companion for the Evedoo vulnerability scanner.
//
// SPDX-License-Identifier: Apache-2.0

mod app;
mod command;
mod config;
#[allow(dead_code)]
mod models;
mod results_table;
mod tabs;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Evedoo — Vulnerability Scanner")
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "evedoo-gui",
        options,
        Box::new(|cc| Ok(Box::new(app::EvedooApp::new(cc)))),
    )
}

//! Interactive menu (`evedoo menu`).
//!
//! A keyboard-driven front end over the same subcommands the CLI exposes, for
//! operators who would rather not memorise flags. Navigation is a pure lookup
//! over a data table (`model`), rendering is a pure string build (`render`),
//! and everything that touches the terminal or spawns work is isolated in
//! `term` and `actions` so the rest stays testable.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod actions;
pub mod model;
pub mod render;
pub mod status;
pub mod term;

pub use model::{Action, Screen};

use owo_colors::OwoColorize;

/// Run the interactive menu until the user leaves.
pub fn run() {
    term::enable_virtual_terminal();
    term::set_title(concat!("Evedoo ", env!("CARGO_PKG_VERSION")));

    let mut screen = Screen::Main;

    loop {
        // Re-probed each redraw so the header reflects a database the user
        // just built or a scan that just changed history, rather than the
        // state at launch.
        let status = status::Status::probe(&actions::database_path());

        term::clear();
        print!("{}", render::render(screen, &status));
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let Some(key) = term::read_key() else {
            // stdin closed: nothing more can be read, so leaving is the only
            // option that does not spin forever.
            println!();
            return;
        };

        match screen.route(key) {
            Some(Action::Quit) => {
                term::clear();
                return;
            }
            Some(Action::Back) => screen = Screen::Main,
            Some(Action::Go(next)) => screen = next,
            Some(Action::Elevate) => {
                if actions::relaunch_elevated() {
                    return;
                }
                term::pause("   Press any key to continue . . .");
            }
            Some(Action::Run(task)) => {
                term::clear();
                println!();
                actions::execute(task);
                term::pause(&format!("   {}", "Press any key to return to the menu . . .".bright_black()));
            }
            // An unbound key is a typo, not an error worth a message; the
            // loop simply redraws.
            None => {}
        }
    }
}

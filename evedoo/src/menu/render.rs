//! Screen rendering.
//!
//! Pure string building: `render` takes a screen and the status facts and
//! returns exactly what should be printed. No terminal calls live here, so the
//! layout is asserted in tests rather than eyeballed.
//!
//! SPDX-License-Identifier: Apache-2.0

use owo_colors::OwoColorize;

use super::model::{Item, Screen};
use super::status::Status;

/// Inner width of the rules, chosen to sit comfortably in an 80-column console.
const WIDTH: usize = 62;

/// Column the annotation dash starts at, measured from the start of the label.
const ANNOTATION_COL: usize = 26;

fn rule() -> String {
    format!("  {}", "-".repeat(WIDTH).bright_black())
}

/// One selectable row: `[K] Label            - annotation`.
fn row(item: &Item) -> String {
    let key = format!("[{}]", item.key);
    let label_cell = format!("{:<width$}", item.label, width = ANNOTATION_COL);
    if item.annotation.is_empty() {
        format!("      {} {}", key.bright_cyan(), item.label.white())
    } else {
        format!(
            "      {} {} - {}",
            key.bright_cyan(),
            label_cell.white(),
            item.annotation.bright_black()
        )
    }
}

/// The full screen, banner to prompt.
pub fn render(screen: Screen, status: &Status) -> String {
    let mut out = String::new();

    out.push('\n');
    out.push_str(&format!(
        "   {} {}\n",
        "EVEDOO".bright_cyan().bold(),
        env!("CARGO_PKG_VERSION").bright_black()
    ));
    out.push_str(&format!("   {}\n", screen.title().bright_black()));
    out.push('\n');

    // Status band. Only shown on the main screen — repeating it on every
    // submenu turns a useful fact into wallpaper nobody reads.
    if screen == Screen::Main {
        out.push_str(&format!("   {}\n", status.database_line()));
        out.push_str(&format!("   {}\n", status.session_line()));
        out.push('\n');
    }

    out.push_str(&rule());
    out.push('\n');

    for group in screen.groups() {
        out.push('\n');
        if !group.title.is_empty() {
            out.push_str(&format!("     {}\n", group.title.bright_green()));
            out.push('\n');
        }
        for item in group.items {
            out.push_str(&row(item));
            out.push('\n');
        }
    }

    if !screen.groups().is_empty() {
        out.push('\n');
        out.push_str(&rule());
        out.push('\n');
    }

    out.push('\n');
    for item in screen.items().iter().skip(
        screen
            .groups()
            .iter()
            .map(|g| g.items.len())
            .sum::<usize>(),
    ) {
        out.push_str(&row(item));
        out.push('\n');
    }
    out.push('\n');

    out.push_str(&rule());
    out.push_str("\n\n");

    out.push_str(&format!(
        "   {} [{}] : ",
        "Choose a menu option using your keyboard".bright_green(),
        screen.key_hint()
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::super::status::Status;
    use super::*;

    /// Colour codes make assertions unreadable and would make every test
    /// depend on whether the runner is a tty.
    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn fixture() -> Status {
        Status::fixture()
    }

    #[test]
    fn every_item_on_every_screen_appears_exactly_once() {
        // A row the renderer drops is a feature the user cannot reach, and a
        // row rendered twice means the layout logic is double-counting groups.
        for &screen in super::super::model::ALL_SCREENS {
            let text = plain(&render(screen, &fixture()));
            for item in screen.items() {
                let needle = format!("[{}] {}", item.key, item.label);
                assert_eq!(
                    text.matches(&needle).count(),
                    1,
                    "{:?} renders {:?} {} times:\n{}",
                    screen,
                    needle,
                    text.matches(&needle).count(),
                    text
                );
            }
        }
    }

    #[test]
    fn the_prompt_hint_lists_keys_the_screen_accepts() {
        let text = plain(&render(Screen::Main, &fixture()));
        assert!(text.contains("Choose a menu option using your keyboard"));
        assert!(
            text.contains(&format!("[{}]", Screen::Main.key_hint())),
            "prompt missing key hint:\n{text}"
        );
    }

    #[test]
    fn the_status_band_shows_only_on_the_main_screen() {
        // It is the one place the user is deciding what to do; on a submenu
        // they have already decided and it is just noise.
        let main = plain(&render(Screen::Main, &fixture()));
        assert!(main.contains("CVE DB:"), "main screen lost its status band");

        for &screen in super::super::model::ALL_SCREENS
            .iter()
            .filter(|s| **s != Screen::Main)
        {
            let text = plain(&render(screen, &fixture()));
            assert!(
                !text.contains("CVE DB:"),
                "{screen:?} should not repeat the status band"
            );
        }
    }

    #[test]
    fn no_rendered_line_overflows_an_eighty_column_console() {
        // Wrapping turns the aligned annotation column into a ragged mess.
        for &screen in super::super::model::ALL_SCREENS {
            for line in plain(&render(screen, &fixture())).lines() {
                assert!(
                    line.chars().count() <= 80,
                    "{:?} line is {} cols:\n{}",
                    screen,
                    line.chars().count(),
                    line
                );
            }
        }
    }

    #[test]
    fn annotations_line_up_in_one_column() {
        // The MAS layout this mirrors reads because every dash is at the same
        // offset; drifting dashes are what make a text menu look homemade.
        let text = plain(&render(Screen::Main, &fixture()));
        // Only item rows: the status band carries its own dashes at other
        // offsets and is not part of the aligned column.
        let dash_columns: Vec<usize> = text
            .lines()
            .filter(|l| l.trim_start().starts_with('['))
            .filter_map(|l| l.find(" - "))
            .collect();
        assert!(dash_columns.len() > 3, "expected several annotated rows");
        assert!(
            dash_columns.windows(2).all(|w| w[0] == w[1]),
            "annotation dashes are not aligned: {dash_columns:?}"
        );
    }
}

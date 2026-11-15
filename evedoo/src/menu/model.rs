//! Menu structure and key routing.
//!
//! The menu is data, not control flow: every screen is a table of items, and
//! routing is a lookup in that table. Keeping it that way means the whole
//! navigation surface is unit-testable without a terminal.
//!
//! SPDX-License-Identifier: Apache-2.0

/// A screen the menu can be showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Main,
    Database,
    Export,
    Audit,
    Fleet,
    Exceptions,
    Interfaces,
    Troubleshoot,
    Help,
}

/// A unit of work the menu can perform. Execution lives in `actions.rs`; this
/// enum only names the work so routing stays pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    DbUpdateIncremental,
    DbUpdateFull,
    DbEnrichmentOnly,
    DbOptionalFeeds,
    DbStatus,
    QuickScan,
    WebReport,
    Reassess,
    ExportCsv,
    ExportJson,
    ExportCycloneDx,
    ExportSpdx,
    AuditWindows11,
    AuditWindows10,
    AuditServer2022,
    AuditEdge,
    AuditCustomPolicy,
    FleetList,
    FleetAdd,
    FleetReport,
    ScheduleList,
    ScheduleCreate,
    ScheduleRemove,
    ExceptionList,
    ExceptionAdd,
    ExceptionRemove,
    LaunchGui,
    LaunchStudio,
    ShowPaths,
    VerifyInstall,
    ReachabilityCheck,
}

/// What a keypress means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Navigate to another screen.
    Go(Screen),
    /// Return to the previous screen (always Main — the tree is one deep).
    Back,
    /// Re-run this process with an elevation prompt.
    Elevate,
    /// Perform a unit of work, then return to the current screen.
    Run(Task),
    /// Leave the menu.
    Quit,
}

/// One selectable row.
pub struct Item {
    pub key: char,
    pub label: &'static str,
    /// Right-hand column, rendered after a dash. Empty means no annotation.
    pub annotation: &'static str,
    pub action: Action,
}

/// A titled run of items. An empty `title` renders as an unlabelled block.
pub struct Group {
    pub title: &'static str,
    pub items: &'static [Item],
}

const fn item(key: char, label: &'static str, annotation: &'static str, action: Action) -> Item {
    Item {
        key,
        label,
        annotation,
        action,
    }
}

// ----------------------------------------------------------------- Main

static MAIN_DATABASE: &[Item] = &[
    item(
        '1',
        "Update Database",
        "incremental / full / enrichment",
        Action::Go(Screen::Database),
    ),
    item(
        '2',
        "Database Status",
        "counts, last sync, staleness",
        Action::Run(Task::DbStatus),
    ),
];

static MAIN_SCAN: &[Item] = &[
    item('3', "Quick Scan", "console report", Action::Run(Task::QuickScan)),
    item(
        '4',
        "Web Report",
        "HTML + local server, opens browser",
        Action::Run(Task::WebReport),
    ),
    item(
        '5',
        "Export",
        "CSV (Excel) / JSON / SBOM",
        Action::Go(Screen::Export),
    ),
    item(
        '6',
        "Reassess",
        "re-correlate stored inventory",
        Action::Run(Task::Reassess),
    ),
];

static MAIN_COMPLIANCE: &[Item] = &[item(
    '7',
    "Configuration Audit",
    "DISA STIG / NIST 800-53",
    Action::Go(Screen::Audit),
)];

static MAIN_FOOTER: &[Item] = &[
    item('8', "Fleet & Schedule", "", Action::Go(Screen::Fleet)),
    item('9', "Exceptions", "", Action::Go(Screen::Exceptions)),
    item(
        'U',
        "User Interfaces",
        "GUI / Studio",
        Action::Go(Screen::Interfaces),
    ),
    item('T', "Troubleshoot", "", Action::Go(Screen::Troubleshoot)),
    item('H', "Help", "", Action::Go(Screen::Help)),
    item('0', "Exit", "", Action::Quit),
];

static MAIN_GROUPS: &[Group] = &[
    Group {
        title: "CVE Database:",
        items: MAIN_DATABASE,
    },
    Group {
        title: "Scan:",
        items: MAIN_SCAN,
    },
    Group {
        title: "Compliance:",
        items: MAIN_COMPLIANCE,
    },
];

// ------------------------------------------------------------- Submenus

static BACK: &[Item] = &[item('0', "Back", "", Action::Back)];

static DATABASE_ITEMS: &[Item] = &[
    item(
        '1',
        "Incremental Update",
        "~8 day delta feed, fastest",
        Action::Run(Task::DbUpdateIncremental),
    ),
    item(
        '2',
        "Full Rebuild",
        "FKIE-CAD mirror, no API key",
        Action::Run(Task::DbUpdateFull),
    ),
    item(
        '3',
        "Enrichment Only",
        "EPSS + KEV + CPE dictionary",
        Action::Run(Task::DbEnrichmentOnly),
    ),
    item(
        '4',
        "Optional Vendor Feeds",
        "MSRC / Ubuntu (experimental)",
        Action::Run(Task::DbOptionalFeeds),
    ),
];

static EXPORT_ITEMS: &[Item] = &[
    item('1', "CSV", "opens in Excel", Action::Run(Task::ExportCsv)),
    item(
        '2',
        "JSON",
        "machine format, full fields",
        Action::Run(Task::ExportJson),
    ),
    item('3', "CycloneDX SBOM", "", Action::Run(Task::ExportCycloneDx)),
    item('4', "SPDX SBOM", "", Action::Run(Task::ExportSpdx)),
];

static AUDIT_ITEMS: &[Item] = &[
    item(
        '1',
        "Windows 11",
        "DISA STIG V1R4",
        Action::Run(Task::AuditWindows11),
    ),
    item(
        '2',
        "Windows 10",
        "DISA STIG V2R8",
        Action::Run(Task::AuditWindows10),
    ),
    item(
        '3',
        "Windows Server 2022",
        "DISA STIG V1R3",
        Action::Run(Task::AuditServer2022),
    ),
    item(
        '4',
        "Microsoft Edge",
        "DISA STIG V1R2",
        Action::Run(Task::AuditEdge),
    ),
    item(
        '5',
        "Custom Policy File",
        "JSON benchmark",
        Action::Run(Task::AuditCustomPolicy),
    ),
];

static FLEET_ITEMS: &[Item] = &[
    item('1', "List Assets", "", Action::Run(Task::FleetList)),
    item('2', "Add Asset", "", Action::Run(Task::FleetAdd)),
    item(
        '3',
        "Fleet Report",
        "rank upgrades by risk removed",
        Action::Run(Task::FleetReport),
    ),
    item('4', "List Schedules", "", Action::Run(Task::ScheduleList)),
    item(
        '5',
        "Create Schedule",
        "Windows Task Scheduler",
        Action::Run(Task::ScheduleCreate),
    ),
    item('6', "Remove Schedule", "", Action::Run(Task::ScheduleRemove)),
];

static EXCEPTION_ITEMS: &[Item] = &[
    item('1', "List Exceptions", "", Action::Run(Task::ExceptionList)),
    item(
        '2',
        "Accept a Risk",
        "requires an expiry date",
        Action::Run(Task::ExceptionAdd),
    ),
    item('3', "Remove Exception", "", Action::Run(Task::ExceptionRemove)),
];

static INTERFACE_ITEMS: &[Item] = &[
    item(
        '1',
        "Evedoo GUI",
        "egui companion app",
        Action::Run(Task::LaunchGui),
    ),
    item(
        '2',
        "Evedoo Studio",
        "React workspace, npm run dev",
        Action::Run(Task::LaunchStudio),
    ),
];

static TROUBLESHOOT_ITEMS: &[Item] = &[
    item(
        '1',
        "Verify Installation",
        "binaries, database, versions",
        Action::Run(Task::VerifyInstall),
    ),
    item(
        '2',
        "Show Paths & Environment",
        "",
        Action::Run(Task::ShowPaths),
    ),
    item(
        '3',
        "Reachability Check",
        "how much needs elevation",
        Action::Run(Task::ReachabilityCheck),
    ),
    item(
        'E',
        "Relaunch Elevated",
        "full reachability coverage",
        Action::Elevate,
    ),
];

impl Screen {
    /// Heading shown under the banner.
    pub fn title(self) -> &'static str {
        match self {
            Screen::Main => "Vulnerability Scanner & Compliance Auditor",
            Screen::Database => "Update CVE Database",
            Screen::Export => "Export Scan Results",
            Screen::Audit => "Configuration Audit",
            Screen::Fleet => "Fleet & Schedule",
            Screen::Exceptions => "Accepted-Risk Exceptions",
            Screen::Interfaces => "User Interfaces",
            Screen::Troubleshoot => "Troubleshoot",
            Screen::Help => "Help",
        }
    }

    /// Rule-separated groups above the footer.
    pub fn groups(self) -> &'static [Group] {
        match self {
            Screen::Main => MAIN_GROUPS,
            _ => &[],
        }
    }

    /// Items below the final rule. On a submenu this is the whole body.
    pub fn footer(self) -> &'static [Item] {
        match self {
            Screen::Main => MAIN_FOOTER,
            Screen::Database => DATABASE_ITEMS,
            Screen::Export => EXPORT_ITEMS,
            Screen::Audit => AUDIT_ITEMS,
            Screen::Fleet => FLEET_ITEMS,
            Screen::Exceptions => EXCEPTION_ITEMS,
            Screen::Interfaces => INTERFACE_ITEMS,
            Screen::Troubleshoot => TROUBLESHOOT_ITEMS,
            Screen::Help => BACK,
        }
    }

    /// Every selectable item on this screen, body then footer, with the
    /// implicit Back row appended on any submenu that does not spell one out.
    pub fn items(self) -> Vec<&'static Item> {
        let mut all: Vec<&'static Item> = self.groups().iter().flat_map(|g| g.items.iter()).collect();
        all.extend(self.footer().iter());
        if self != Screen::Main && !all.iter().any(|i| i.action == Action::Back) {
            all.extend(BACK.iter());
        }
        all
    }

    /// What a keypress does here, or `None` if the key is not bound.
    ///
    /// Case-insensitive: a menu that answers to `U` but not lowercase reads as
    /// broken to anyone not holding shift.
    pub fn route(self, key: char) -> Option<Action> {
        let pressed = key.to_ascii_uppercase();
        self.items()
            .into_iter()
            .find(|i| i.key.to_ascii_uppercase() == pressed)
            .map(|i| i.action)
    }

    /// The bracketed hint in the prompt, built from the real key set so it
    /// cannot drift from what the menu actually accepts.
    pub fn key_hint(self) -> String {
        let keys: Vec<String> = self.items().iter().map(|i| i.key.to_string()).collect();
        match keys.len() {
            0 => String::new(),
            1..=4 => keys.join(","),
            _ => format!(
                "{}...{},{}",
                keys[..3].join(","),
                keys[keys.len() - 2],
                keys[keys.len() - 1]
            ),
        }
    }
}

/// Every screen the menu can reach, for exhaustive testing.
#[cfg(test)]
pub const ALL_SCREENS: &[Screen] = &[
    Screen::Main,
    Screen::Database,
    Screen::Export,
    Screen::Audit,
    Screen::Fleet,
    Screen::Exceptions,
    Screen::Interfaces,
    Screen::Troubleshoot,
    Screen::Help,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_screen_binds_one_key_twice() {
        // A duplicate key makes an item silently unreachable: `route` takes the
        // first match and the second row becomes decoration.
        for &screen in ALL_SCREENS {
            let mut keys: Vec<char> = screen
                .items()
                .iter()
                .map(|i| i.key.to_ascii_uppercase())
                .collect();
            let before = keys.len();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(
                keys.len(),
                before,
                "{:?} binds a key more than once: {:?}",
                screen,
                screen
                    .items()
                    .iter()
                    .map(|i| (i.key, i.label))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn every_screen_can_be_left() {
        // A submenu with no way back strands the user; Main must offer Quit.
        for &screen in ALL_SCREENS {
            let actions: Vec<Action> = screen.items().iter().map(|i| i.action).collect();
            let escapable = actions.contains(&Action::Back) || actions.contains(&Action::Quit);
            assert!(escapable, "{screen:?} has no Back and no Quit");
        }
    }

    #[test]
    fn routing_is_case_insensitive() {
        assert_eq!(Screen::Main.route('u'), Screen::Main.route('U'));
        assert_eq!(Screen::Main.route('u'), Some(Action::Go(Screen::Interfaces)));
        assert_eq!(Screen::Troubleshoot.route('e'), Some(Action::Elevate));
    }

    #[test]
    fn an_unbound_key_routes_nowhere() {
        // Returning an action for a stray keypress would run work nobody asked
        // for; the loop redraws instead.
        assert_eq!(Screen::Main.route('q'), None);
        assert_eq!(Screen::Main.route('\r'), None);
        assert_eq!(Screen::Export.route('9'), None);
    }

    #[test]
    fn zero_exits_the_main_screen_and_backs_out_of_submenus() {
        assert_eq!(Screen::Main.route('0'), Some(Action::Quit));
        for &screen in ALL_SCREENS.iter().filter(|s| **s != Screen::Main) {
            assert_eq!(screen.route('0'), Some(Action::Back), "{screen:?}");
        }
    }

    #[test]
    fn every_submenu_is_reachable_from_main() {
        // A screen with no route into it is dead code the user cannot see.
        let reachable: Vec<Screen> = Screen::Main
            .items()
            .iter()
            .filter_map(|i| match i.action {
                Action::Go(s) => Some(s),
                _ => None,
            })
            .collect();
        for &screen in ALL_SCREENS.iter().filter(|s| **s != Screen::Main) {
            assert!(
                reachable.contains(&screen),
                "{screen:?} is unreachable from Main"
            );
        }
    }

    #[test]
    fn key_hint_matches_the_keys_actually_bound() {
        let hint = Screen::Main.key_hint();
        assert!(hint.starts_with("1,2,3"), "got {hint:?}");
        assert!(hint.ends_with("H,0"), "got {hint:?}");
    }
}

//! Turning a chosen `Task` into a command, and running it.
//!
//! Work is dispatched by re-invoking this same executable with the subcommand
//! the user would otherwise have typed, rather than calling the command
//! handlers in-process. That keeps one code path for every entry point: what
//! the menu runs is exactly what the CLI runs, output and exit codes included,
//! and a fix to a subcommand cannot miss the menu.
//!
//! Argument construction is pure and tested; only `run` touches the world.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::Command;

use owo_colors::OwoColorize;

use super::model::Task;
use super::term;

/// Which executable a task needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// This binary, re-invoked with a subcommand.
    Evedoo,
    /// The sibling `cve-db-builder` executable.
    CveDbBuilder,
    /// The sibling `evedoo-gui` executable.
    Gui,
    /// `npm`, for the Studio dev server.
    Npm,
}

/// A command the menu is about to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub program: Program,
    pub args: Vec<String>,
    /// Shown before the command runs, so the user learns the CLI by using the
    /// menu instead of being insulated from it.
    pub note: &'static str,
}

/// Free-text the user must supply before a task can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prompt {
    pub label: &'static str,
    /// Flag the answer is passed as. Empty means it is a bare positional.
    pub flag: &'static str,
}

/// What a task needs in order to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Run this command as-is.
    Ready(Invocation),
    /// Ask for these values first, appending each to the invocation.
    Needs(Invocation, &'static [Prompt]),
}

fn inv(program: Program, note: &'static str, args: &[&str]) -> Invocation {
    Invocation {
        program,
        args: args.iter().map(|s| s.to_string()).collect(),
        note,
    }
}

/// The command behind each menu task.
///
/// `db` is threaded in rather than read from the environment here so the
/// mapping stays a pure function of its inputs.
pub fn plan(task: Task, db: &str) -> Plan {
    use Program::{CveDbBuilder, Gui, Npm, Evedoo};
    use Task as T;

    match task {
        // ---- database ----
        T::DbUpdateIncremental => Plan::Ready(inv(
            CveDbBuilder,
            "Delta feed covers roughly 8 days; older databases fall back to a full sync.",
            &["--output", db, "--update"],
        )),
        T::DbUpdateFull => Plan::Ready(inv(
            CveDbBuilder,
            "Full corpus from the FKIE-CAD mirror. No API key needed.",
            &["--output", db],
        )),
        T::DbEnrichmentOnly => Plan::Ready(inv(
            CveDbBuilder,
            "Refreshes EPSS, CISA KEV and the CPE dictionary without touching CVEs.",
            &["--output", db, "--enrichment-only"],
        )),
        T::DbOptionalFeeds => Plan::Ready(inv(
            CveDbBuilder,
            "Vendor advisories carry their own licence terms and are off by default.",
            &[
                "--output",
                db,
                "--update",
                "--enable-msrc",
                "--enable-ubuntu",
            ],
        )),
        T::DbStatus => Plan::Ready(inv(
            CveDbBuilder,
            "",
            &["--output", db, "--stats"],
        )),

        // ---- scan ----
        T::QuickScan => Plan::Ready(inv(
            Evedoo,
            "Console report with risk tiers.",
            &["scan", "--database", db, "--risk"],
        )),
        T::WebReport => Plan::Ready(inv(
            Evedoo,
            "Serves a token-authenticated report on loopback and opens a browser. Ctrl+C to stop.",
            &["scan", "--database", db, "--format", "html", "--serve", "--risk"],
        )),
        T::Reassess => Plan::Ready(inv(
            Evedoo,
            "Re-correlates the stored inventory against the current database. No host contact.",
            &["reassess", "--database", db],
        )),

        // ---- export ----
        T::ExportCsv => Plan::Ready(inv(
            Evedoo,
            "CSV opens directly in Excel. Cells are neutralised against formula injection.",
            &["scan", "--database", db, "--format", "csv", "--output", "evedoo-report.csv"],
        )),
        T::ExportJson => Plan::Ready(inv(
            Evedoo,
            "",
            &["scan", "--database", db, "--format", "json", "--output", "evedoo-report.json"],
        )),
        T::ExportCycloneDx => Plan::Ready(inv(
            Evedoo,
            "",
            &["scan", "--database", db, "--format", "cyclonedx", "--output", "evedoo-sbom.cdx.json"],
        )),
        T::ExportSpdx => Plan::Ready(inv(
            Evedoo,
            "",
            &["scan", "--database", db, "--format", "spdx", "--output", "evedoo-sbom.spdx.json"],
        )),

        // ---- audit ----
        T::AuditWindows11 => Plan::Ready(inv(Evedoo, "", &["audit", "--benchmark", "windows-11"])),
        T::AuditWindows10 => Plan::Ready(inv(Evedoo, "", &["audit", "--benchmark", "windows-10"])),
        T::AuditServer2022 => Plan::Ready(inv(
            Evedoo,
            "",
            &["audit", "--benchmark", "windows-server-2022"],
        )),
        T::AuditEdge => Plan::Ready(inv(Evedoo, "", &["audit", "--benchmark", "ms-edge"])),
        T::AuditCustomPolicy => Plan::Needs(
            inv(Evedoo, "Custom benchmarks are JSON only; there is no XCCDF parser.", &["audit"]),
            &[Prompt {
                label: "Path to JSON benchmark file",
                flag: "--policy",
            }],
        ),

        // ---- fleet & schedule ----
        T::FleetList => Plan::Ready(inv(Evedoo, "", &["fleet", "list"])),
        T::FleetAdd => Plan::Needs(
            inv(Evedoo, "", &["fleet", "add"]),
            &[
                Prompt { label: "Hostname or IP", flag: "" },
                Prompt { label: "Display name", flag: "--name" },
                Prompt { label: "Tags (comma-separated)", flag: "--tags" },
            ],
        ),
        T::FleetReport => Plan::Ready(inv(
            Evedoo,
            "Ranks upgrades across every scanned host by total risk removed.",
            &["fleet", "report"],
        )),
        T::ScheduleList => Plan::Ready(inv(Evedoo, "", &["schedule", "list"])),
        T::ScheduleCreate => Plan::Needs(
            inv(
                Evedoo,
                "Creates a Windows Task Scheduler entry.",
                &["schedule", "create"],
            ),
            &[
                Prompt { label: "Task name", flag: "--name" },
                Prompt { label: "Frequency (daily/weekly/hourly/onlogon)", flag: "--frequency" },
                Prompt { label: "Start time HH:MM", flag: "--time" },
            ],
        ),
        T::ScheduleRemove => Plan::Needs(
            inv(Evedoo, "", &["schedule", "remove"]),
            &[Prompt { label: "Task name", flag: "" }],
        ),

        // ---- exceptions ----
        T::ExceptionList => Plan::Ready(inv(Evedoo, "", &["exception", "list"])),
        T::ExceptionAdd => Plan::Needs(
            inv(
                Evedoo,
                "An expiry date is required: indefinite suppression is not expressible by design.",
                &["exception", "add"],
            ),
            &[
                Prompt { label: "CVE id (or * for any)", flag: "--cve" },
                Prompt { label: "Software name (or * for any)", flag: "--software" },
                Prompt { label: "Reason", flag: "--reason" },
                Prompt { label: "Owner", flag: "--owner" },
                Prompt { label: "Expires (YYYY-MM-DD)", flag: "--expires" },
            ],
        ),
        T::ExceptionRemove => Plan::Needs(
            inv(Evedoo, "", &["exception", "remove"]),
            &[Prompt { label: "Exception id", flag: "" }],
        ),

        // ---- interfaces ----
        T::LaunchGui => Plan::Ready(inv(Gui, "Launches the egui companion app.", &[])),
        T::LaunchStudio => Plan::Ready(inv(
            Npm,
            "Starts the Vite dev server on loopback. Ctrl+C to stop.",
            &["run", "dev"],
        )),

        // ---- troubleshoot ----
        T::VerifyInstall => Plan::Ready(inv(Evedoo, "", &["--version"])),
        T::ShowPaths => Plan::Ready(inv(Evedoo, "", &["--version"])),
        T::ReachabilityCheck => Plan::Ready(inv(
            Evedoo,
            "Reachability needs elevation to read other processes; a partial sweep is normal unelevated.",
            &["scan", "--database", db, "--risk", "--min-priority", "p1"],
        )),
    }
}

/// Where the CVE database lives, honouring the same env var the CLI does.
pub fn database_path() -> String {
    std::env::var("EVEDOO_DB_PATH").unwrap_or_else(|_| "vulndb.sqlite".to_string())
}

/// Resolve a program to an executable path.
///
/// Sibling binaries are looked for next to this executable first: a release
/// drop ships them side by side, and picking one off `PATH` could run a
/// different build than the menu the user launched.
fn resolve(program: Program) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.to_path_buf();
    let suffix = if cfg!(windows) { ".exe" } else { "" };

    match program {
        Program::Evedoo => Some(exe),
        Program::CveDbBuilder => {
            let sibling = dir.join(format!("cve-db-builder{suffix}"));
            sibling.exists().then_some(sibling)
        }
        Program::Gui => {
            let sibling = dir.join(format!("evedoo-gui{suffix}"));
            sibling.exists().then_some(sibling)
        }
        // npm is a shell shim on Windows, so it has to come off PATH.
        Program::Npm => Some(PathBuf::from(if cfg!(windows) { "npm.cmd" } else { "npm" })),
    }
}

fn missing_program_hint(program: Program) -> &'static str {
    match program {
        Program::CveDbBuilder => {
            "cve-db-builder was not found next to this executable.\n   Build it with:  cargo build --release -p cve-db-builder"
        }
        Program::Gui => {
            "evedoo-gui was not found next to this executable.\n   Build it with:  cargo build --release -p evedoo-gui"
        }
        Program::Npm => {
            "npm was not found on PATH. Node.js is required for Evedoo Studio."
        }
        Program::Evedoo => "This executable could not locate itself.",
    }
}

/// Execute a task, prompting for anything it needs first.
pub fn execute(task: Task) {
    let db = database_path();
    let (mut invocation, prompts) = match plan(task, &db) {
        Plan::Ready(i) => (i, &[][..]),
        Plan::Needs(i, p) => (i, p),
    };

    for prompt in prompts {
        let answer = term::read_line(&format!("   {}: ", prompt.label.bright_cyan()));
        if answer.is_empty() {
            println!("\n   {}", "Cancelled - nothing was run.".bright_yellow());
            return;
        }
        if !prompt.flag.is_empty() {
            invocation.args.push(prompt.flag.to_string());
        }
        invocation.args.push(answer);
    }

    let Some(exe) = resolve(invocation.program) else {
        println!("\n   {}", missing_program_hint(invocation.program).bright_red());
        return;
    };

    if !invocation.note.is_empty() {
        println!("\n   {}", invocation.note.bright_black());
    }
    println!(
        "\n   {} {} {}\n",
        "$".bright_black(),
        exe.file_name().unwrap_or_default().to_string_lossy().bright_cyan(),
        invocation.args.join(" ").bright_black()
    );

    let mut command = Command::new(&exe);
    command.args(&invocation.args);

    // Studio lives in its own directory and npm must run there.
    if invocation.program == Program::Npm {
        command.current_dir("evedoo-studio");
    }

    match command.status() {
        Ok(status) if status.success() => {}
        Ok(status) => println!(
            "\n   {}",
            format!("Command exited with status {status}.").bright_yellow()
        ),
        Err(e) => println!("\n   {}", format!("Could not run {}: {e}", exe.display()).bright_red()),
    }
}

/// Relaunch this executable with an elevation prompt, then ask the current
/// process to exit so two menus are not left driving one console.
pub fn relaunch_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        let Ok(exe) = std::env::current_exe() else {
            println!("\n   {}", "Could not locate this executable.".bright_red());
            return false;
        };

        // ShellExecute with the `runas` verb is what raises the UAC prompt;
        // spawning normally would silently inherit the current token.
        let status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &elevation_command(&exe),
            ])
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("\n   {}", "Elevated menu launched. Closing this one.".bright_green());
                true
            }
            _ => {
                println!(
                    "\n   {}",
                    "Elevation was declined or failed; staying unelevated.".bright_yellow()
                );
                false
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!(
            "\n   {}",
            "Re-run under sudo for full reachability coverage.".bright_yellow()
        );
        false
    }
}

/// The PowerShell command that relaunches the menu elevated.
///
/// The executable path goes inside a single-quoted literal, so it is escaped:
/// a profile directory such as `C:\\Users\\O'Brien` would otherwise end the
/// literal and the remainder would run as script.
// Only the Windows relaunch calls this; it stays compiled and tested everywhere.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn elevation_command(exe: &std::path::Path) -> String {
    format!(
        "Start-Process -FilePath '{}' -ArgumentList 'menu' -Verb RunAs",
        crate::remote::session::ps_escape(&exe.to_string_lossy())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::model::Task;

    fn args_of(task: Task) -> Vec<String> {
        match plan(task, "test.sqlite") {
            Plan::Ready(i) => i.args,
            Plan::Needs(i, _) => i.args,
        }
    }

    #[test]
    fn elevation_command_escapes_quotes_in_the_executable_path() {
        let cmd = elevation_command(std::path::Path::new("C:\\Users\\O'Brien\\evedoo.exe"));
        assert_eq!(
            cmd,
            "Start-Process -FilePath 'C:\\Users\\O''Brien\\evedoo.exe' -ArgumentList 'menu' -Verb RunAs"
        );
        let smart = elevation_command(std::path::Path::new("C:\\x\u{2019}; calc; \u{2018}\\evedoo.exe"));
        assert!(smart.contains("x\u{2019}\u{2019}; calc; \u{2018}\u{2018}"), "{smart}");
    }

    #[test]
    fn every_task_produces_a_plan() {
        // A task with no command behind it is a menu row that does nothing
        // when pressed. `plan` is exhaustive over Task, so this is really a
        // guard that no arm was left pointing at a placeholder.
        for task in ALL_TASKS {
            let args = args_of(*task);
            assert!(
                !args.is_empty() || matches!(plan(*task, "x"), Plan::Ready(Invocation { program: Program::Gui, .. })),
                "{task:?} produced no arguments"
            );
        }
    }

    #[test]
    fn database_tasks_target_the_configured_database() {
        // A task that writes to the default path while the header reports a
        // different one would silently build a second database.
        for task in [
            Task::DbUpdateIncremental,
            Task::DbUpdateFull,
            Task::DbEnrichmentOnly,
            Task::DbOptionalFeeds,
            Task::DbStatus,
        ] {
            let args = args_of(task);
            assert!(
                args.windows(2).any(|w| w[0] == "--output" && w[1] == "test.sqlite"),
                "{task:?} does not write to the configured database: {args:?}"
            );
        }
    }

    #[test]
    fn scan_tasks_read_the_configured_database() {
        for task in [
            Task::QuickScan,
            Task::WebReport,
            Task::Reassess,
            Task::ExportCsv,
            Task::ExportJson,
        ] {
            let args = args_of(task);
            assert!(
                args.windows(2).any(|w| w[0] == "--database" && w[1] == "test.sqlite"),
                "{task:?} does not read the configured database: {args:?}"
            );
        }
    }

    #[test]
    fn each_export_names_its_own_format_and_file() {
        // Two exports sharing an output path would overwrite each other.
        let cases = [
            (Task::ExportCsv, "csv"),
            (Task::ExportJson, "json"),
            (Task::ExportCycloneDx, "cyclonedx"),
            (Task::ExportSpdx, "spdx"),
        ];
        let mut outputs = Vec::new();
        for (task, format) in cases {
            let args = args_of(task);
            assert!(
                args.windows(2).any(|w| w[0] == "--format" && w[1] == format),
                "{task:?} is missing --format {format}: {args:?}"
            );
            let out = args
                .windows(2)
                .find(|w| w[0] == "--output")
                .map(|w| w[1].clone())
                .unwrap_or_else(|| panic!("{task:?} has no --output"));
            outputs.push(out);
        }
        let unique: std::collections::BTreeSet<_> = outputs.iter().collect();
        assert_eq!(unique.len(), outputs.len(), "exports collide: {outputs:?}");
    }

    #[test]
    fn the_web_report_serves_html_rather_than_writing_a_file() {
        let args = args_of(Task::WebReport);
        assert!(args.contains(&"--serve".to_string()), "{args:?}");
        assert!(
            args.windows(2).any(|w| w[0] == "--format" && w[1] == "html"),
            "--serve only works with --format html: {args:?}"
        );
        assert!(
            !args.contains(&"--output".to_string()),
            "--serve writes to the browser, not a file: {args:?}"
        );
    }

    #[test]
    fn each_audit_selects_a_distinct_bundled_benchmark() {
        let mut seen = Vec::new();
        for task in [
            Task::AuditWindows11,
            Task::AuditWindows10,
            Task::AuditServer2022,
            Task::AuditEdge,
        ] {
            let args = args_of(task);
            let bench = args
                .windows(2)
                .find(|w| w[0] == "--benchmark")
                .map(|w| w[1].clone())
                .unwrap_or_else(|| panic!("{task:?} has no --benchmark"));
            seen.push(bench);
        }
        let unique: std::collections::BTreeSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), seen.len(), "benchmarks collide: {seen:?}");
    }

    #[test]
    fn accepting_a_risk_asks_for_an_expiry_date() {
        // FR-68: indefinite suppression is not expressible, so the prompt set
        // has to collect an expiry or the command will always fail.
        let Plan::Needs(_, prompts) = plan(Task::ExceptionAdd, "x") else {
            panic!("ExceptionAdd should prompt");
        };
        assert!(
            prompts.iter().any(|p| p.flag == "--expires"),
            "no expiry prompt: {prompts:?}"
        );
    }

    #[test]
    fn vendor_feeds_are_opt_in_everywhere_except_the_task_that_names_them() {
        // Those feeds carry licence terms; enabling them from a routine update
        // would redistribute data the project is not licensed to redistribute.
        for task in [Task::DbUpdateIncremental, Task::DbUpdateFull, Task::DbEnrichmentOnly] {
            let args = args_of(task);
            assert!(
                !args.iter().any(|a| a.starts_with("--enable-")),
                "{task:?} silently enables a vendor feed: {args:?}"
            );
        }
        assert!(args_of(Task::DbOptionalFeeds)
            .iter()
            .any(|a| a == "--enable-msrc"));
    }

    const ALL_TASKS: &[Task] = &[
        Task::DbUpdateIncremental,
        Task::DbUpdateFull,
        Task::DbEnrichmentOnly,
        Task::DbOptionalFeeds,
        Task::DbStatus,
        Task::QuickScan,
        Task::WebReport,
        Task::Reassess,
        Task::ExportCsv,
        Task::ExportJson,
        Task::ExportCycloneDx,
        Task::ExportSpdx,
        Task::AuditWindows11,
        Task::AuditWindows10,
        Task::AuditServer2022,
        Task::AuditEdge,
        Task::AuditCustomPolicy,
        Task::FleetList,
        Task::FleetAdd,
        Task::FleetReport,
        Task::ScheduleList,
        Task::ScheduleCreate,
        Task::ScheduleRemove,
        Task::ExceptionList,
        Task::ExceptionAdd,
        Task::ExceptionRemove,
        Task::LaunchGui,
        Task::LaunchStudio,
        Task::ShowPaths,
        Task::VerifyInstall,
        Task::ReachabilityCheck,
    ];

    #[test]
    fn the_task_list_under_test_covers_every_menu_task() {
        // If a Task is added to the menu but not here, the coverage tests
        // above quietly stop protecting it.
        use crate::menu::model::{Action, ALL_SCREENS};
        for screen in ALL_SCREENS {
            for item in screen.items() {
                if let Action::Run(task) = item.action {
                    assert!(
                        ALL_TASKS.contains(&task),
                        "{task:?} is reachable from {screen:?} but absent from ALL_TASKS"
                    );
                }
            }
        }
    }
}

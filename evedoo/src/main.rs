//! Evedoo - Windows Vulnerability Scanner
//!
//! SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod aggregate;
pub mod audit;
mod correlate;
mod distro_override;
mod error;
mod exceptions;
mod fleet;
mod history;
mod inventory;
mod matcher;
mod menu;
mod models;
mod msrc_override;
mod normalize;
mod reachability;
mod reconcile;
mod remote;
mod report;
mod risk;
mod scanner;
mod schedule;
mod schema;
mod serve;

use matcher::CveMatcher;
use models::{MatchConfidence, Priority, ScanMode, ScanResult, Severity};
use remote::{RemoteSession, RemoteTarget};
use report::{generate_report, OutputFormat};
use scanner::{
    AppxScanner, ChocolateyScanner, LinuxScanner, MacOsScanner, OsVersionScanner, PackageScanner,
    PeFingerprintScanner, RegistryScanner, ScoopScanner, VersionResolver, WingetScanner,
};

/// Evedoo - Windows Vulnerability Scanner
#[derive(Parser)]
#[command(name = "evedoo")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive menu over every subcommand (no flags to memorise)
    Menu,

    /// Scan system for vulnerabilities
    Scan {
        /// CVE database file path
        #[arg(short, long, env = "EVEDOO_DB_PATH", default_value = "vulndb.sqlite")]
        database: PathBuf,

        /// Output format (json, csv, text, html, cyclonedx, spdx)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file (prints to console if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Filter by severity (comma-separated: critical,high,medium,low)
        #[arg(short, long, value_parser = parse_severity_list)]
        severity: Option<String>,

        /// Minimum match confidence (exact, high, medium, low)
        #[arg(short = 'c', long, default_value = "high", value_parser = parse_min_confidence)]
        min_confidence: String,

        /// Verbose logging
        #[arg(short, long)]
        verbose: bool,

        /// History database path for delta tracking
        #[arg(long, default_value = "scan_history.db")]
        history: PathBuf,

        /// Disable delta tracking (do not read or write history)
        #[arg(long)]
        no_history: bool,

        /// Start a local web server and open the HTML report in the browser
        #[arg(long)]
        serve: bool,

        /// List detected software that resolved to no CPE identity
        /// (coverage diagnostic: distinguishes "no known CVEs" from
        /// "never correlated")
        #[arg(long)]
        show_unmatched: bool,

        /// Show risk score and priority tier in text output (FR-67: machine
        /// formats like CSV/JSON always carry these fields; this only gates
        /// the human-readable text report)
        #[arg(long)]
        risk: bool,

        /// Hide findings below this priority tier (p1, p2, p3, p4).
        /// Findings with no risk assessment are never hidden by this filter.
        #[arg(long, value_parser = parse_min_priority)]
        min_priority: Option<String>,

        /// Show findings suppressed by an active exception (hidden by
        /// default — FR-70)
        #[arg(long)]
        show_excepted: bool,

        /// Sort findings. Default sorts by KEV/EPSS/CVSS/published date;
        /// `--sort risk` sorts by computed priority tier and score instead,
        /// and (FR-67) also turns on `--risk`'s text-report display.
        ///
        /// Restricted to the one recognised value (M3, final whole-branch
        /// review): FR-72's own stated principle is that a typo should be an
        /// error, not a rule that silently never matches — `--sort priorty`
        /// used to silently keep the default order *and* silently decline to
        /// enable `--risk`'s text-report display, with no diagnostic either
        /// way.
        #[arg(long, value_parser = ["risk"])]
        sort: Option<String>,

        /// Skip runtime reachability collection (module enumeration).
        #[arg(long, default_value_t = false)]
        no_reachability: bool,

        /// Target root directory for container image / chroot / offline disk scan
        #[arg(long)]
        rootfs: Option<PathBuf>,

        /// Target OS family (windows, linux, macos). Defaults to host OS (or linux if --rootfs is specified).
        #[arg(long, value_parser = parse_target_os)]
        target_os: Option<String>,
    },

    /// Scan a remote Windows machine via WinRM
    #[command(name = "remote-scan")]
    RemoteScan {
        /// Remote hostname or IP address
        #[arg(short = 't', long)]
        target: String,

        /// WinRM port (5985 for HTTP, 5986 for HTTPS)
        #[arg(short = 'p', long, default_value = "5985")]
        port: u16,

        /// Username for WinRM authentication
        #[arg(short, long)]
        username: String,

        /// Password. Prefer --password-stdin, or the
        /// EVEDOO_REMOTE_PASSWORD env var; a password given here appears in
        /// this process's command line, which Windows process-creation
        /// auditing (event 4688), Sysmon, and EDR agents record.
        // `hide_env_values` is REQUIRED, not cosmetic: without it clap prints
        // the live value of EVEDOO_REMOTE_PASSWORD in `--help` output. That
        // would undo the argv-avoidance the doc comment above recommends — the
        // operator moves the password to an env var precisely to keep it off
        // the command line, and `--help` would then put it on screen anyway,
        // into terminal scrollback, CI logs, and screenshots.
        //
        // Deliberately a plain comment, not a doc comment: this is rationale
        // for the maintainer, and clap would render it into user-facing help.
        #[arg(
            long,
            env = "EVEDOO_REMOTE_PASSWORD",
            hide_env_values = true,
            default_value = ""
        )]
        password: String,

        /// Read the password from the first line of stdin (SEC-5). Most
        /// secure channel: never touches argv, the environment block, or disk.
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,

        /// Use SSL/HTTPS (port 5986)
        #[arg(long)]
        use_ssl: bool,

        /// Skip TLS certificate validation (CA, CN, revocation checks).
        /// WARNING: disables MITM protection — use only in lab/test environments.
        #[arg(long)]
        skip_tls_verify: bool,

        /// CVE database file path
        #[arg(short, long, env = "EVEDOO_DB_PATH", default_value = "vulndb.sqlite")]
        database: PathBuf,

        /// Output format (json, csv, text, html, cyclonedx, spdx)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file (prints to console if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Filter by severity (comma-separated: critical,high,medium,low)
        #[arg(short, long, value_parser = parse_severity_list)]
        severity: Option<String>,

        /// Minimum match confidence (exact, high, medium, low)
        #[arg(short = 'c', long, default_value = "high", value_parser = parse_min_confidence)]
        min_confidence: String,

        /// Verbose logging
        #[arg(short, long)]
        verbose: bool,

        /// History database path for delta tracking
        #[arg(long, default_value = "scan_history.db")]
        history: PathBuf,

        /// Disable delta tracking (do not read or write history)
        #[arg(long)]
        no_history: bool,

        /// Start a local web server and open the HTML report in the browser
        #[arg(long)]
        serve: bool,

        /// Show risk score and priority tier in text output
        #[arg(long)]
        risk: bool,

        /// Hide findings below this priority tier (p1, p2, p3, p4).
        /// Findings with no risk assessment are never hidden by this filter.
        #[arg(long, value_parser = parse_min_priority)]
        min_priority: Option<String>,

        /// Show findings suppressed by an active exception (hidden by
        /// default — FR-70)
        #[arg(long)]
        show_excepted: bool,

        /// Sort findings. Default sorts by KEV/EPSS/CVSS/published date;
        /// `--sort risk` sorts by computed priority tier and score instead,
        /// and (FR-67) also turns on `--risk`'s text-report display.
        ///
        /// Restricted to the one recognised value (M3, final whole-branch
        /// review): FR-72's own stated principle is that a typo should be an
        /// error, not a rule that silently never matches — `--sort priorty`
        /// used to silently keep the default order *and* silently decline to
        /// enable `--risk`'s text-report display, with no diagnostic either
        /// way.
        #[arg(long, value_parser = ["risk"])]
        sort: Option<String>,

        /// Skip runtime reachability collection (module enumeration).
        #[arg(long, default_value_t = false)]
        no_reachability: bool,
    },

    /// Re-correlate the stored inventory against the current CVE database
    /// without contacting the host (FR-58, FR-59)
    Reassess {
        /// CVE database file path
        #[arg(short, long, env = "EVEDOO_DB_PATH", default_value = "vulndb.sqlite")]
        database: PathBuf,

        /// Host whose stored inventory to reassess (default: this machine)
        #[arg(long)]
        host: Option<String>,

        /// Warn when the stored snapshot is older than this many days
        #[arg(long, default_value_t = 7)]
        max_age: i64,

        /// Output format (json, csv, text, html, cyclonedx, spdx)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file (prints to console if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show findings suppressed by an active exception (hidden by
        /// default — FR-70)
        #[arg(long)]
        show_excepted: bool,

        /// Hide findings below this priority tier (p1, p2, p3, p4).
        /// Findings with no risk assessment are never hidden by this filter.
        /// `reassess` shows risk unconditionally (see FR-67's carve-out for
        /// this command in spec.md section 6.2), so unlike `scan` this does
        /// not need to "imply" anything to take effect.
        #[arg(long, value_parser = parse_min_priority)]
        min_priority: Option<String>,

        /// History database path (also holds the stored inventory and
        /// exceptions)
        #[arg(long, default_value = "scan_history.db")]
        history: PathBuf,
    },

    /// Manage accepted-risk exceptions (FR-68..FR-72)
    Exception {
        #[command(subcommand)]
        action: ExceptionCommands,
    },

    /// Manage fleet assets (multi-target scanning)
    #[command(subcommand)]
    Fleet(FleetCommands),

    /// Manage scheduled scans (Windows Task Scheduler)
    #[command(subcommand)]
    Schedule(ScheduleCommands),

    /// Audit Windows configuration against baseline checks derived from DISA STIGs
    Audit {
        /// Bundled benchmark name or alias (windows-11, windows-10, windows-server-2022, ms-edge).
        /// Defaults to the one matching the detected Windows version.
        #[arg(short, long, conflicts_with = "policy")]
        benchmark: Option<String>,

        /// Path to custom JSON benchmark policy file
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Output format (text, json, csv, html)
        #[arg(short = 'f', long, default_value = "text")]
        format: String,

        /// Output file (prints to console if not specified)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ExceptionCommands {
    /// Accept a risk until a given date
    Add {
        /// CVE id, or '*' for any
        #[arg(long)]
        cve: String,

        /// Software name, or '*' for any
        #[arg(long, default_value = "*")]
        software: String,

        /// Host, or '*' for every host. Must be given explicitly — an
        /// estate cannot be silenced by omission (FR-69); defaults to this
        /// machine.
        #[arg(long)]
        host: Option<String>,

        /// Why this risk is accepted
        #[arg(long)]
        reason: String,

        /// Who accepted it
        #[arg(long)]
        owner: String,

        /// Expiry date, YYYY-MM-DD. Required — indefinite suppression is
        /// not expressible by design (FR-68).
        #[arg(long)]
        expires: String,

        #[arg(long, default_value = "scan_history.db")]
        history: String,
    },

    /// List exceptions
    List {
        /// Host to list exceptions for (also shows fleet-wide '*' rules).
        /// Omit to list every rule regardless of host.
        #[arg(long)]
        host: Option<String>,

        #[arg(long)]
        json: bool,

        #[arg(long, default_value = "scan_history.db")]
        history: String,
    },

    /// Remove an exception by id
    Remove {
        id: i64,

        #[arg(long, default_value = "scan_history.db")]
        history: String,
    },
}

#[derive(Subcommand)]
enum FleetCommands {
    /// Register a new asset in the fleet
    Add {
        /// Hostname or IP address
        #[arg()]
        hostname: String,

        /// Display name for the asset
        #[arg(short = 'n', long)]
        name: Option<String>,

        /// Comma-separated tags (e.g. "prod,web,critical")
        #[arg(short, long)]
        tags: Option<String>,

        /// Mark as remote (requires WinRM credentials for scanning)
        #[arg(long)]
        remote: bool,

        /// WinRM port (for remote assets)
        #[arg(short, long, default_value = "5985")]
        port: u16,

        /// Username (for remote assets)
        #[arg(short, long)]
        username: Option<String>,

        /// Use SSL (for remote assets)
        #[arg(long)]
        use_ssl: bool,

        /// History/fleet database path
        #[arg(long, default_value = "scan_history.db")]
        db: PathBuf,
    },

    /// Remove an asset from the fleet
    Remove {
        /// Hostname to remove
        #[arg()]
        hostname: String,

        /// History/fleet database path
        #[arg(long, default_value = "scan_history.db")]
        db: PathBuf,
    },

    /// List registered fleet assets
    List {
        /// Filter by tag
        #[arg(short, long)]
        tag: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// History/fleet database path
        #[arg(long, default_value = "scan_history.db")]
        db: PathBuf,
    },

    /// Add or remove tags on an asset
    Tag {
        /// Hostname to tag
        #[arg()]
        hostname: String,

        /// Tags to add (comma-separated)
        #[arg(short, long)]
        add: Option<String>,

        /// Tags to remove (comma-separated)
        #[arg(short, long)]
        remove: Option<String>,

        /// History/fleet database path
        #[arg(long, default_value = "scan_history.db")]
        db: PathBuf,
    },

    /// Show fleet-level summary
    Summary {
        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// History/fleet database path
        #[arg(long, default_value = "scan_history.db")]
        db: PathBuf,
    },

    /// Rank upgrades by how much risk each removes across the whole fleet
    Report {
        /// CVE database. Risk is derived at report time rather than read from
        /// a stored score (FR-84), so this is required.
        #[arg(short = 'd', long, default_value = "vulndb.sqlite")]
        database: PathBuf,

        /// History/fleet database path
        #[arg(long, default_value = "scan_history.db")]
        db: PathBuf,

        /// Only include assets carrying this fleet tag
        #[arg(long)]
        tag: Option<String>,

        /// Maximum rows to display
        #[arg(long, default_value_t = 20)]
        limit: usize,

        /// Output as JSON (DC-7)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ScheduleCommands {
    /// Create a recurring scan schedule
    Create {
        /// Task name (used as identifier in Task Scheduler)
        #[arg()]
        name: String,

        /// Frequency: daily, weekly, hourly, onlogon
        #[arg(short, long, default_value = "daily")]
        frequency: String,

        /// Start time in HH:MM format (e.g. "02:00")
        #[arg(short, long)]
        time: Option<String>,

        /// Day of week for weekly schedules (MON, TUE, WED, THU, FRI, SAT, SUN)
        #[arg(short, long)]
        day: Option<String>,

        /// Extra arguments to pass to 'evedoo scan' (e.g. "--format json --output report.json")
        #[arg(short, long, default_value = "")]
        args: String,

        /// Run the scheduled task with HIGHEST privileges (required for registry scanning).
        /// WARNING: creates a privilege escalation risk if the executable is in a user-writable path.
        #[arg(long)]
        elevated: bool,
    },

    /// List all evedoo scheduled tasks
    List,

    /// Remove a scheduled scan task
    Remove {
        /// Task name to remove
        #[arg()]
        name: String,
    },
}


/// Reject a filter value that is not one of `allowed` (case-insensitive).
///
/// The filter arguments used to be parsed by infallible `from_str` functions
/// that mapped anything unrecognised to a default, so a typo silently changed
/// what a report showed. They are validated here, when the command line is
/// parsed, and the typed conversion later cannot meet an unknown value.
fn one_of(flag: &str, value: &str, allowed: &[&str]) -> Result<String, String> {
    let v = value.trim();
    if allowed.iter().any(|a| a.eq_ignore_ascii_case(v)) {
        Ok(v.to_string())
    } else {
        Err(format!("'{}' is not a valid {} (expected one of: {})", v, flag, allowed.join(", ")))
    }
}

fn parse_severity_list(value: &str) -> Result<String, String> {
    value
        .split(',')
        .map(|part| one_of("severity", part, &["critical", "high", "medium", "low", "unknown"]))
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join(","))
}

fn parse_min_confidence(value: &str) -> Result<String, String> {
    one_of("confidence", value, &["exact", "high", "medium", "low"])
}

fn parse_min_priority(value: &str) -> Result<String, String> {
    one_of("priority", value, &["p1", "p2", "p3", "p4"])
}

fn parse_target_os(value: &str) -> Result<String, String> {
    one_of("target OS", value, &["windows", "linux", "macos", "darwin"])
}

fn main() -> Result<()> {
    // Configuration comes from flags and the real environment only — no `.env`.
    // dotenvy::dotenv() searched the working directory and every parent for a
    // `.env` and imported every key in it, so anyone able to write one
    // anywhere above the operator's working directory could set
    // EVEDOO_DB_PATH on an often-elevated scanner: a forged CVE database
    // that reports the host clean, or a UNC path that makes the process
    // authenticate to an attacker's SMB server. See tests/env_file.rs.
    let cli = Cli::parse();

    match cli.command {
        Commands::Menu => menu::run(),

        Commands::Scan {
            database,
            format,
            output,
            severity,
            min_confidence,
            verbose,
            history,
            no_history,
            serve,
            show_unmatched,
            risk,
            min_priority,
            show_excepted,
            sort,
            no_reachability,
            rootfs,
            target_os,
        } => {
            // Initialize logging
            let level = if verbose { Level::DEBUG } else { Level::INFO };
            let subscriber = FmtSubscriber::builder()
                .with_max_level(level)
                .with_target(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;

            run_scan(
                database,
                format,
                output,
                severity,
                min_confidence,
                history,
                no_history,
                serve,
                show_unmatched,
                risk,
                min_priority,
                show_excepted,
                sort,
                no_reachability,
                rootfs,
                target_os,
            )?;
        }
        Commands::RemoteScan {
            target,
            port,
            username,
            password,
            password_stdin,
            use_ssl,
            skip_tls_verify,
            database,
            format,
            output,
            severity,
            min_confidence,
            verbose,
            history,
            no_history,
            serve,
            risk,
            min_priority,
            show_excepted,
            sort,
            no_reachability,
        } => {
            let level = if verbose { Level::DEBUG } else { Level::INFO };
            let subscriber = FmtSubscriber::builder()
                .with_max_level(level)
                .with_target(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;

            let password = resolve_remote_password(password, password_stdin)?;

            run_remote_scan(
                target,
                port,
                username,
                password,
                use_ssl,
                skip_tls_verify,
                database,
                format,
                output,
                severity,
                min_confidence,
                history,
                no_history,
                serve,
                risk,
                min_priority,
                show_excepted,
                sort,
                no_reachability,
            )?;
        }
        Commands::Reassess {
            database,
            host,
            max_age,
            format,
            output,
            show_excepted,
            min_priority,
            history,
        } => {
            // B3, final whole-branch review: without this, `reassess` runs
            // with no tracing subscriber installed at all, so every
            // `info!`/`warn!` on this path — including `correlate.rs`'s
            // "Error matching {name}: {err}" — is discarded. A matcher
            // failure then buckets software into `without_cves`
            // indistinguishably from a clean no-match: the report says
            // "Found 0 potential vulnerabilities" with no trace that
            // anything went wrong. `reassess` has no `--verbose` flag (it
            // never gained one), so this always runs at `Level::INFO`,
            // matching `scan`/`remote-scan`'s non-verbose default.
            let subscriber = FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .with_target(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;

            run_reassess(
                database,
                host,
                max_age,
                format,
                output,
                show_excepted,
                min_priority,
                history,
            )?;
        }
        Commands::Exception { action } => {
            run_exception_command(action)?;
        }
        Commands::Fleet(fleet_cmd) => {
            run_fleet_command(fleet_cmd)?;
        }
        Commands::Schedule(schedule_cmd) => {
            run_schedule_command(schedule_cmd)?;
        }
        Commands::Audit {
            benchmark,
            policy,
            format,
            output,
        } => {
            run_audit_command(benchmark, policy, format, output)?;
        }
    }

    Ok(())
}

fn run_audit_command(
    benchmark: Option<String>,
    policy: Option<PathBuf>,
    format: String,
    output: Option<PathBuf>,
) -> Result<()> {
    let host = audit::HostOs::detect();
    let (chosen, note) = audit::resolve_benchmark(benchmark.as_deref(), policy.as_deref(), &host)?;
    if let Some(note) = note {
        eprintln!("{} {}", "!".bright_yellow().bold(), note);
    }

    let summary = audit::run_audit(&chosen);

    let rendered = match format.to_lowercase().as_str() {
        "text" | "txt" => audit::generate_text_report(&summary),
        "json" => {
            let val = audit::generate_json_report(&summary);
            serde_json::to_string_pretty(&val)?
        }
        "csv" => audit::generate_csv_report(&summary),
        "html" | "htm" => audit::generate_html_report(&summary),
        other => anyhow::bail!(
            "Unsupported audit report format: '{}'. Supported formats: text, json, csv, html",
            other
        ),
    };

    if let Some(out_path) = output {
        fs::write(&out_path, &rendered)?;
        println!(
            "{} Compliance audit report written to {}",
            "✓".bright_green().bold(),
            out_path.display()
        );
    } else {
        print!("{}", rendered);
    }

    Ok(())
}

/// State how old the data behind a fleet rollup is.
///
/// A rollup reads STORED findings, so it is only as current as the last scan
/// of each host. Presenting three-month-old findings as a current fleet
/// picture is the same defect `delta_known` and the reachability coverage
/// line exist to prevent, and the first shipped version of `fleet report` had
/// it: the underlying scans were from 2026-05-17 with nothing on screen to
/// say so.
///
/// Both ends of the range are reported when they differ, because the stalest
/// host is the one you have no current information about. No staleness
/// threshold is applied — an arbitrary "old" cutoff would be editorialising;
/// the age is stated and the operator judges it.
fn fleet_report_freshness(
    oldest: &str,
    newest: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let age_days = |s: &str| -> Option<i64> {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|t| (now - t.with_timezone(&chrono::Utc)).num_days())
    };

    match (age_days(oldest), age_days(newest)) {
        (Some(o), Some(n)) if o == n => format!("  scan data: {o} days old"),
        (Some(o), Some(n)) => {
            format!("  scan data: newest {n} days old, oldest {o} days old")
        }
        _ => "  scan data: age unknown (unparseable timestamp)".to_string(),
    }
}

/// FR-87. Say what was not measured, following the reachability coverage
/// line's precedent. A rollup that silently shrank because some CVEs were
/// missing from the database is indistinguishable from a fleet that simply
/// has less risk, so the count is stated rather than swallowed.
/// Pluralise a count for report prose. "1 assets covered" reads as a bug in
/// a document an operator is meant to trust.
fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn fleet_report_header(assets: usize, excluded: usize) -> String {
    if excluded == 0 {
        format!("  {} covered", plural(assets, "asset", "assets"))
    } else {
        format!(
            "  {} covered — {} excluded: CVE not present in the database",
            plural(assets, "asset", "assets"),
            plural(excluded, "finding", "findings")
        )
    }
}

/// FR-81. Disclose collection coverage on every run, complete or not.
///
/// A partial sweep is the NORMAL unelevated case (measured: 161 of 336
/// processes on a real desktop), and FR-74 turns every unreadable process
/// into `Unknown` rather than a false negative — so the reader needs to know
/// how much of the machine was actually observed.
fn reachability_coverage_line(c: crate::reachability::Coverage) -> String {
    if c.readable >= c.total {
        format!(
            "  reachability: {}/{} processes readable",
            c.readable, c.total
        )
    } else {
        format!(
            "  reachability: {}/{} processes readable — run elevated for full coverage",
            c.readable, c.total
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn run_scan(
    database: PathBuf,
    format: String,
    output: Option<PathBuf>,
    severity_filter: Option<String>,
    min_confidence: String,
    history_path: PathBuf,
    no_history: bool,
    serve: bool,
    show_unmatched: bool,
    risk_flag: bool,
    min_priority: Option<String>,
    show_excepted: bool,
    sort: Option<String>,
    no_reachability: bool,
    rootfs: Option<PathBuf>,
    target_os: Option<String>,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║          EVEDOO VULNERABILITY SCANNER              ║".bright_blue()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();

    // Parse output format
    let output_format: OutputFormat = format.parse().map_err(|e: String| anyhow::anyhow!(e))?;

    // Parse severity filter. `correlate()` runs unfiltered (FR-61); this is
    // reapplied as a presentation-layer filter after delta tracking, below,
    // so filtering never affects what is persisted as Resolved.
    let severity_filter: Option<Vec<Severity>> =
        severity_filter.map(|s| s.split(',').map(|s| Severity::from_str(s.trim())).collect());

    // Parse confidence filter
    let min_confidence = MatchConfidence::from_str(&min_confidence);
    println!(
        "{} Minimum confidence: {}",
        "→".bright_blue(),
        min_confidence
    );

    // Open CVE database
    println!("{} Loading CVE database...", "→".bright_blue());
    let (matcher, cve_count, cpe_count) = open_cve_database(&database)?;
    println!(
        "  {} CVEs, {} CPE configurations loaded",
        cve_count, cpe_count
    );
    println!();

    // Determine target operating system
    let target = target_os
        .as_deref()
        .unwrap_or(if rootfs.is_some() { "linux" } else { std::env::consts::OS });

    let mut software = if target.eq_ignore_ascii_case("linux") {
        if let Some(ref root) = rootfs {
            println!(
                "{} Scanning Linux rootfs ({}) for installed packages and software...",
                "→".bright_blue(),
                root.display()
            );
            LinuxScanner::new().scan_rootfs(root)
        } else {
            println!(
                "{} Scanning Linux system for installed packages and software...",
                "→".bright_blue()
            );
            let mut s = LinuxScanner::new().scan();
            let pkg_software = PackageScanner::new().scan();
            if !pkg_software.is_empty() {
                info!("Found {} ecosystem packages (pip/npm/cargo)", pkg_software.len());
            }
            s.extend(pkg_software);
            s
        }
    } else if target.eq_ignore_ascii_case("macos") || target.eq_ignore_ascii_case("darwin") {
        println!(
            "{} Scanning macOS system for applications, bundles, and packages...",
            "→".bright_blue()
        );
        let mut s = MacOsScanner::new().scan();
        let pkg_software = PackageScanner::new().scan();
        if !pkg_software.is_empty() {
            info!("Found {} ecosystem packages (pip/npm/cargo)", pkg_software.len());
        }
        s.extend(pkg_software);
        s
    } else {
        // Windows (default on Windows or explicit windows target)
        println!(
            "{} Scanning Windows Registry for installed software...",
            "→".bright_blue()
        );
        let scanner = RegistryScanner::new();
        let mut s = scanner.scan()?;

        // Extend with pip / npm / cargo packages
        let pkg_software = PackageScanner::new().scan();
        if !pkg_software.is_empty() {
            info!("Found {} ecosystem packages (pip/npm/cargo)", pkg_software.len());
        }
        s.extend(pkg_software);

        // Extend with Windows Store / AppX / MSIX packages
        let appx_software = AppxScanner::new().scan();
        if !appx_software.is_empty() {
            info!("Found {} Windows Store (AppX) packages", appx_software.len());
        }
        s.extend(appx_software);

        // Extend with WinGet-managed packages (covers winget + Store sources)
        let winget_software = WingetScanner::new().scan();
        if !winget_software.is_empty() {
            info!("Found {} WinGet packages", winget_software.len());
        }
        s.extend(winget_software);

        // Extend with Chocolatey packages (filesystem-based, works without choco on PATH)
        let choco_software = ChocolateyScanner::new().scan();
        if !choco_software.is_empty() {
            info!("Found {} Chocolatey packages", choco_software.len());
        }
        s.extend(choco_software);

        // Extend with Scoop packages (filesystem-based, works without scoop shim on PATH)
        let scoop_software = ScoopScanner::new().scan();
        if !scoop_software.is_empty() {
            info!("Found {} Scoop packages", scoop_software.len());
        }
        s.extend(scoop_software);

        // Extend with PE header fingerprints (catches portable tools and
        // toolchains the package managers miss)
        let pe_software = PeFingerprintScanner::new().scan();
        if !pe_software.is_empty() {
            info!(
                "Found {} PE-fingerprinted applications in install roots",
                pe_software.len()
            );
        }
        s.extend(pe_software);

        // The OS itself — correlates against microsoft:windows_* CPEs
        if let Some(os) = OsVersionScanner::new().scan() {
            info!(
                "OS identity: {} ({})",
                os.name,
                os.version.as_deref().unwrap_or("?")
            );
            s.push(os);
        }

        // Python packages from every detected install's own site-packages, not
        // just the environment whose pip is first on PATH (see
        // scanner::packages::site_packages_software). Collapses with any
        // `pip list` duplicates in the dedup pass below.
        let roots: std::collections::BTreeSet<String> =
            s.iter().filter_map(|sw| sw.install_location.clone()).collect();
        let site_pkgs: Vec<_> = roots
            .iter()
            .flat_map(|root| scanner::site_packages_software(std::path::Path::new(root)))
            .collect();
        if !site_pkgs.is_empty() {
            info!("Found {} Python packages in installed site-packages", site_pkgs.len());
        }
        s.extend(site_pkgs);

        // Resolve missing version strings via registry fallbacks and CLI tools
        VersionResolver::new().resolve_missing_versions(&mut s);
        s
    };

    // Deduplicate across all sources by normalised name + version
    {
        let mut seen = std::collections::HashSet::new();
        software.retain(|sw| {
            seen.insert(normalize::names::dedup_key(&sw.name, sw.version.as_deref()))
        });
    }

    println!("  Found {} installed applications", software.len());
    println!();

    // Match software to CVEs
    println!("{} Matching software to CVE database...", "→".bright_blue());

    // Canonicalised (uppercase, trimmed — B2, final whole-branch review) the
    // same way `exceptions`/`fleet` already are: `scan_inventory` and
    // `scan_findings` are looked up with an exact SQL `=`, so a raw
    // `%COMPUTERNAME%` here would still round-trip fine for `scan` itself
    // (it always writes and reads its own case), but would disagree with
    // `remote-scan`'s canonicalisation below and with `reassess --host`'s
    // resolution via `resolve_hostname` if the two ever needed to agree on
    // the same host.
    let host_id = if let Some(ref root) = rootfs {
        root.display().to_string()
    } else {
        resolve_hostname(None)
    };
    let mut result = ScanResult::new(host_id);
    result.total_software = software.len();

    let host_distro = distro_override::HostDistro::from_inventory(&software);
    let outcome = correlate::correlate(software, &matcher);
    result.findings = outcome.findings;
    result.software_without_cves = outcome.without_cves;

    let msrc_outcome = msrc_override::apply(&mut result.findings, matcher.conn());
    if msrc_outcome.suppressed > 0 || msrc_outcome.enriched > 0 {
        info!(
            "MSRC override: {} findings suppressed (patched), {} enriched with KB/build",
            msrc_outcome.suppressed, msrc_outcome.enriched
        );
    }

    let distro_outcome = distro_override::apply(&mut result.findings, matcher.conn(), host_distro.as_ref());
    if distro_outcome.suppressed > 0 || distro_outcome.enriched > 0 {
        info!(
            "Distro advisory override: {} findings suppressed (patched), {} enriched with fixed version/advisory",
            distro_outcome.suppressed, distro_outcome.enriched
        );
    }

    result.total_vulnerabilities = result.findings.len();
    result.sort_findings_by_priority();

    println!(
        "  Found {} potential vulnerabilities",
        result.total_vulnerabilities
    );

    // Coverage diagnostic: split the zero-finding software into "identity
    // resolved, no applicable CVEs" (healthy) and "never correlated"
    // (coverage gap — candidates for curation or naming fixes).
    if show_unmatched {
        let mut unmatched: Vec<&models::DetectedSoftware> = result
            .software_without_cves
            .iter()
            .filter(|sw| matcher.resolves_identity(sw).is_none())
            .collect();
        unmatched.sort_by_key(|sw| sw.name.to_lowercase());

        let resolved_no_cves = result.software_without_cves.len() - unmatched.len();
        let matched_total = result.total_software - unmatched.len();

        println!();
        println!(
            "{} Unmatched software (no CPE identity — never correlated):",
            "→".bright_blue()
        );
        for sw in &unmatched {
            // Registry entries carry raw HKLM/HKCU paths, not a scheme.
            let scheme = if sw.registry_key.contains("://") {
                sw.registry_key.split("://").next().unwrap_or("?")
            } else {
                "registry"
            };
            println!(
                "    {} {} [{}]",
                sw.name,
                sw.version.as_deref().unwrap_or("?"),
                scheme
            );
        }
        println!(
            "  Coverage: {}/{} applications correlated ({:.1}%) — {} matched with no applicable CVEs, {} unmatched",
            matched_total,
            result.total_software,
            100.0 * matched_total as f64 / result.total_software.max(1) as f64,
            resolved_no_cves,
            unmatched.len()
        );
    }

    // --- risk, exceptions, delta tracking, presentation (spec.md section 6) ---
    let history_path_str = history_path.to_str().unwrap_or("scan_history.db").to_string();
    let min_priority = min_priority.as_deref().map(Priority::from_str);

    // Risk (FR-63). Criticality comes from fleet tags when the host is
    // registered; 1.0 otherwise. `--no-history` means "do not read or write
    // history" (its own help text) — FleetManager::open and
    // ExceptionStore::open both route through `crate::schema::open`, which
    // creates and migrates the file, so opening either unconditionally would
    // make `--no-history` write a database anyway. Gate both on the flag;
    // fall back to criticality 1.0 (no fleet lookup) and no exceptions.
    let criticality = if no_history {
        1.0
    } else {
        fleet::FleetManager::open(&history_path_str)
            .ok()
            .and_then(|f| f.tags_for(&result.hostname).ok().flatten())
            .map(|tags| risk::criticality_for(&tags))
            .unwrap_or(1.0)
    };
    let module_map = if no_reachability {
        reachability::ModuleMap::empty_unknown()
    } else {
        let m = reachability::local::collect();
        println!("{}", reachability_coverage_line(m.coverage()));
        m
    };
    for f in &mut result.findings {
        let exploit = matcher
            .has_exploit_reference(&f.vulnerability.cve_id)
            .unwrap_or(false);
        f.reachability = reachability::classify(&f.software, &module_map);
        f.risk = Some(risk::assess(
            &f.vulnerability,
            exploit,
            criticality,
            f.reachability,
        ));
    }

    // `--sort risk` re-sorts by computed priority tier/score instead of the
    // raw KEV/EPSS/CVSS/date ordering above, and (FR-67) also counts as
    // asking to see risk data, same as `--risk` or `--min-priority`.
    let sort_by_risk = sort.as_deref() == Some("risk");
    if sort_by_risk {
        result.sort_findings_by_risk();
    }
    let show_risk = risk_flag || min_priority.is_some() || sort_by_risk;

    // Exceptions (FR-70) — annotate only, never drop. Gated on --no-history
    // for the same reason as fleet lookup above: opening the store creates
    // and migrates scan_history.db even to only read it.
    if !no_history {
        if let Ok(store) = exceptions::ExceptionStore::open(&history_path_str) {
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            if let Ok(n) = store.apply(&mut result.findings, &result.hostname, &today) {
                if n > 0 {
                    println!("  {n} finding(s) suppressed by active exceptions");
                }
            }
        }
    }

    // Delta tracking (reconcile + persist), then presentation filtering —
    // always in that fixed order. `persist_then_present` is the single
    // place this ordering lives; see its doc comment for why the order
    // matters (FR-61).
    let history_arg = if no_history { None } else { Some(history_path_str.as_str()) };
    persist_then_present(
        &mut result,
        history_arg,
        min_confidence,
        severity_filter.as_deref(),
        min_priority,
        show_excepted,
    );

    // Generate report
    let report = generate_report(&result, output_format, show_risk)?;

    // Output report
    match output {
        Some(ref path) => {
            fs::write(path, &report)?;
            println!("{} Report saved to: {}", "✓".bright_green(), path.display());
        }
        None => {
            if !serve {
                println!("{}", report);
            }
        }
    }

    // Serve HTML report in browser if requested
    if serve {
        if output_format == OutputFormat::Html {
            serve::serve_and_open(&report)?;
        } else {
            println!(
                "{} --serve only works with --format html (current: {})",
                "!".bright_yellow(),
                format
            );
        }
    }

    Ok(())
}

/// Resolve the WinRM password from the chosen channel (SEC-5).
///
/// Precedence: `--password-stdin` (most secure — never in argv, the
/// environment block, or on disk), then `--password` / the
/// `EVEDOO_REMOTE_PASSWORD` env var. Clap already rejects passing both.
fn resolve_remote_password(password: String, password_stdin: bool) -> Result<String> {
    if password_stdin {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| anyhow::anyhow!("failed to read password from stdin: {e}"))?;
        // Only the trailing newline is stripped — passwords may legitimately
        // contain leading or trailing spaces.
        let password = line.trim_end_matches(['\r', '\n']).to_string();
        if password.is_empty() {
            anyhow::bail!("--password-stdin was given but stdin provided no password");
        }
        return Ok(password);
    }

    if password.is_empty() {
        anyhow::bail!(
            "no password supplied.\n\n\
             Use --password-stdin (preferred), set EVEDOO_REMOTE_PASSWORD, \
             or pass --password."
        );
    }
    Ok(password)
}

/// This machine's hostname, the same identity a local `scan` stamps onto its
/// `ScanResult` and therefore the same identity `reassess` and
/// `exception add/list` default `--host` to when the operator doesn't name
/// one explicitly.
fn current_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Unknown".to_string())
}

/// Open the CVE database for a run that will pass judgement on a host — and
/// refuse when there is nothing to judge with.
///
/// A missing database used to print "Database not found" and exit 0, so a
/// scheduled scan or CI job recorded success for a run that checked nothing.
/// A database that *exists* but is empty was worse: `evedoo menu` launched
/// from `target\release\` resolved `vulndb.sqlite` against that directory,
/// found a schema-only file an aborted `--enrichment-only` run had created,
/// loaded "0 CVEs, 0 CPE configurations", and printed a green "No known
/// vulnerabilities found!" — indistinguishable from a genuinely clean host.
///
/// Both now fail with a non-zero exit before any report is written. Hints go
/// to stderr so `--json` output on stdout stays parseable. CPE configurations
/// are checked as well as CVEs: a database interrupted after the CVE table
/// filled but before `cpe_matches` did matches nothing either.
fn open_cve_database(database: &std::path::Path) -> Result<(CveMatcher, i64, i64)> {
    let rebuild_hint = || {
        eprintln!();
        eprintln!("Build or point at a populated CVE database:");
        eprintln!("  cve-db-builder --output {}", database.display());
        eprintln!("  or pass --database <path> / set EVEDOO_DB_PATH");
        eprintln!();
    };

    if !database.exists() {
        eprintln!(
            "{} CVE database not found: {}",
            "✗".bright_red(),
            database.display()
        );
        rebuild_hint();
        anyhow::bail!("CVE database not found: {}", database.display());
    }

    let matcher = CveMatcher::new(&database.to_string_lossy())?;
    let (cves, cpes) = matcher.get_stats()?;
    if cves == 0 || cpes == 0 {
        eprintln!(
            "{} CVE database {} contains no CVEs to match against ({} CVEs, {} CPE configurations)",
            "✗".bright_red(),
            database.display(),
            cves,
            cpes
        );
        rebuild_hint();
        anyhow::bail!(
            "refusing to report: CVE database {} contains no CVEs to match against, \
             so an empty result would read as a clean host",
            database.display()
        );
    }

    Ok((matcher, cves, cpes))
}

/// Resolves `--host` (or this machine's hostname) to the canonical form
/// `scan_inventory`, `scan_findings`, and `exceptions` all key on (Task 9b
/// fix round, review item 2). Windows hostnames are case-insensitive, but
/// `InventoryStore::load`/`snapshot_time` compare with an exact SQL `=`, so
/// `reassess --host server01` against a snapshot recorded as `SERVER01`
/// (the conventional `COMPUTERNAME` case) would otherwise bail with "no
/// stored inventory" — telling the operator to rescan a host whose snapshot
/// is already sitting in the table. `exceptions::canonical_hostname` is the
/// same canonicalisation `exception add/list/apply` already use, reused here
/// so every hostname-keyed lookup in the CLI agrees on one case.
fn resolve_hostname(host: Option<String>) -> String {
    exceptions::canonical_hostname(&host.unwrap_or_else(current_hostname))
}

#[allow(clippy::too_many_arguments)]
fn run_remote_scan(
    target: String,
    port: u16,
    username: String,
    password: String,
    use_ssl: bool,
    skip_tls_verify: bool,
    database: PathBuf,
    format: String,
    output: Option<PathBuf>,
    severity_filter: Option<String>,
    min_confidence: String,
    history_path: PathBuf,
    no_history: bool,
    serve: bool,
    risk_flag: bool,
    min_priority: Option<String>,
    show_excepted: bool,
    sort: Option<String>,
    no_reachability: bool,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║       EVEDOO REMOTE VULNERABILITY SCANNER          ║".bright_blue()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();

    println!(
        "{} Target: {}:{} ({})",
        "→".bright_blue(),
        target,
        port,
        if use_ssl { "HTTPS" } else { "HTTP" }
    );
    if !use_ssl {
        // WinRM over HTTP still encrypts the session when Kerberos or NTLM is
        // negotiated, but nothing authenticates the server to the client.
        eprintln!(
            "{} WinRM over HTTP: the remote host's identity is not verified by TLS. \
             Use --use-ssl (port 5986) where an HTTPS listener is available.",
            "!".bright_yellow().bold()
        );
    }
    println!();

    let output_format: OutputFormat = format.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    // See run_scan: `correlate()` runs unfiltered (FR-61); this is reapplied
    // as a presentation-layer filter after delta tracking, below.
    let severity_filter: Option<Vec<Severity>> =
        severity_filter.map(|s| s.split(',').map(|s| Severity::from_str(s.trim())).collect());
    let min_confidence = MatchConfidence::from_str(&min_confidence);

    println!(
        "{} Minimum confidence: {}",
        "→".bright_blue(),
        min_confidence
    );

    // Open CVE database
    println!("{} Loading CVE database...", "→".bright_blue());
    let (matcher, cve_count, cpe_count) = open_cve_database(&database)?;
    println!("  {} CVEs, {} CPE configurations loaded", cve_count, cpe_count);
    println!();

    // Connect to remote host
    println!(
        "{} Connecting to {} via WinRM...",
        "→".bright_blue(),
        target
    );
    if skip_tls_verify {
        println!(
            "{} TLS certificate validation is DISABLED (--skip-tls-verify). Use only in lab/test environments.",
            "⚠".bright_yellow()
        );
    }
    let remote_target = RemoteTarget::with_tls_options(
        target.clone(), port, username, password, use_ssl, skip_tls_verify,
    ).map_err(|e| anyhow::anyhow!("{}", e))?;
    let session = RemoteSession::connect(remote_target)?;
    println!("  {} Connected successfully", "✓".bright_green());
    println!();

    // Run remote scanners
    let mut software = Vec::new();

    println!(
        "{} Scanning remote registry for installed software...",
        "→".bright_blue()
    );
    match remote::scanners::scan_registry(&session) {
        Ok(apps) => {
            info!("Remote registry: {} applications", apps.len());
            software.extend(apps);
        }
        Err(e) => warn!("Remote registry scan failed: {}", e),
    }

    println!("{} Scanning remote AppX packages...", "→".bright_blue());
    match remote::scanners::scan_appx(&session) {
        Ok(apps) => {
            info!("Remote AppX: {} packages", apps.len());
            software.extend(apps);
        }
        Err(e) => warn!("Remote AppX scan failed: {}", e),
    }

    println!("{} Scanning remote WinGet packages...", "→".bright_blue());
    match remote::scanners::scan_winget(&session) {
        Ok(apps) => {
            info!("Remote WinGet: {} packages", apps.len());
            software.extend(apps);
        }
        Err(e) => warn!("Remote WinGet scan failed: {}", e),
    }

    println!(
        "{} Scanning remote Chocolatey packages via SMB...",
        "→".bright_blue()
    );
    match remote::scanners::scan_chocolatey(&session) {
        Ok(apps) => {
            info!("Remote Chocolatey: {} packages", apps.len());
            software.extend(apps);
        }
        Err(e) => warn!("Remote Chocolatey scan failed: {}", e),
    }

    println!(
        "{} Scanning remote Scoop packages via SMB...",
        "→".bright_blue()
    );
    match remote::scanners::scan_scoop(&session) {
        Ok(apps) => {
            info!("Remote Scoop: {} packages", apps.len());
            software.extend(apps);
        }
        Err(e) => warn!("Remote Scoop scan failed: {}", e),
    }

    println!(
        "{} Scanning remote ecosystem packages (pip/npm/cargo)...",
        "→".bright_blue()
    );
    match remote::scanners::scan_packages(&session) {
        Ok(apps) => {
            info!("Remote packages: {} entries", apps.len());
            software.extend(apps);
        }
        Err(e) => warn!("Remote package scan failed: {}", e),
    }

    // Deduplicate
    {
        let mut seen = std::collections::HashSet::new();
        software.retain(|sw| {
            seen.insert(normalize::names::dedup_key(&sw.name, sw.version.as_deref()))
        });
    }

    println!("  Found {} installed applications on remote host", software.len());
    println!();

    // Match software to CVEs
    println!("{} Matching software to CVE database...", "→".bright_blue());

    // Canonicalised (B2, final whole-branch review): `reassess --host`
    // resolves its `--host` through the same `resolve_hostname` /
    // `exceptions::canonical_hostname`, and `scan_inventory`/`scan_findings`
    // compare hostnames with an exact SQL `=`. Writing the raw `--target`
    // string here made `remote-scan --target win-box` followed by `reassess
    // --host win-box` bail with "no stored inventory for WIN-BOX" — advice
    // that cannot work for a remote host, since WIN-BOX was never the key
    // anything was written under. `target` itself (used above to actually
    // connect) is left untouched.
    let mut result = ScanResult::new(exceptions::canonical_hostname(&target));
    result.scan_mode = ScanMode::Remote;
    result.total_software = software.len();

    let host_distro = distro_override::HostDistro::from_inventory(&software);
    let outcome = correlate::correlate(software, &matcher);
    result.findings = outcome.findings;
    result.software_without_cves = outcome.without_cves;

    let msrc_outcome = msrc_override::apply(&mut result.findings, matcher.conn());
    if msrc_outcome.suppressed > 0 || msrc_outcome.enriched > 0 {
        info!(
            "MSRC override: {} findings suppressed (patched), {} enriched with KB/build",
            msrc_outcome.suppressed, msrc_outcome.enriched
        );
    }

    let distro_outcome = distro_override::apply(&mut result.findings, matcher.conn(), host_distro.as_ref());
    if distro_outcome.suppressed > 0 || distro_outcome.enriched > 0 {
        info!(
            "Distro advisory override: {} findings suppressed (patched), {} enriched with fixed version/advisory",
            distro_outcome.suppressed, distro_outcome.enriched
        );
    }

    result.total_vulnerabilities = result.findings.len();
    result.sort_findings_by_priority();

    println!(
        "  Found {} potential vulnerabilities",
        result.total_vulnerabilities
    );

    // --- risk, exceptions, delta tracking, presentation (spec.md section 6) ---
    let history_path_str = history_path.to_str().unwrap_or("scan_history.db").to_string();
    let min_priority = min_priority.as_deref().map(Priority::from_str);

    // Risk (FR-63). Criticality comes from fleet tags when the host is
    // registered; 1.0 otherwise. Gated on --no-history: see run_scan for why
    // (FleetManager::open/ExceptionStore::open create and migrate the DB
    // file even just to read it).
    let criticality = if no_history {
        1.0
    } else {
        fleet::FleetManager::open(&history_path_str)
            .ok()
            .and_then(|f| f.tags_for(&result.hostname).ok().flatten())
            .map(|tags| risk::criticality_for(&tags))
            .unwrap_or(1.0)
    };
    let module_map = if no_reachability {
        reachability::ModuleMap::empty_unknown()
    } else {
        let m = reachability::remote::collect(&session);
        println!("{}", reachability_coverage_line(m.coverage()));
        m
    };
    for f in &mut result.findings {
        let exploit = matcher
            .has_exploit_reference(&f.vulnerability.cve_id)
            .unwrap_or(false);
        f.reachability = reachability::classify(&f.software, &module_map);
        f.risk = Some(risk::assess(
            &f.vulnerability,
            exploit,
            criticality,
            f.reachability,
        ));
    }

    // `--sort risk` re-sorts by computed priority tier/score instead of the
    // raw KEV/EPSS/CVSS/date ordering above, and (FR-67) also counts as
    // asking to see risk data, same as `--risk` or `--min-priority`.
    let sort_by_risk = sort.as_deref() == Some("risk");
    if sort_by_risk {
        result.sort_findings_by_risk();
    }
    let show_risk = risk_flag || min_priority.is_some() || sort_by_risk;

    // Exceptions (FR-70) — annotate only, never drop. Gated on --no-history
    // for the same reason as fleet lookup above.
    if !no_history {
        if let Ok(store) = exceptions::ExceptionStore::open(&history_path_str) {
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            if let Ok(n) = store.apply(&mut result.findings, &result.hostname, &today) {
                if n > 0 {
                    println!("  {n} finding(s) suppressed by active exceptions");
                }
            }
        }
    }

    // Delta tracking (reconcile + persist), then presentation filtering —
    // always in that fixed order. `persist_then_present` is the single
    // place this ordering lives; see its doc comment for why the order
    // matters (FR-61).
    let history_arg = if no_history { None } else { Some(history_path_str.as_str()) };
    persist_then_present(
        &mut result,
        history_arg,
        min_confidence,
        severity_filter.as_deref(),
        min_priority,
        show_excepted,
    );

    // Generate report
    let report = generate_report(&result, output_format, show_risk)?;

    match output {
        Some(ref path) => {
            fs::write(path, &report)?;
            println!("{} Report saved to: {}", "✓".bright_green(), path.display());
        }
        None => {
            if !serve {
                println!("{}", report);
            }
        }
    }

    // Serve HTML report in browser if requested
    if serve {
        if output_format == OutputFormat::Html {
            serve::serve_and_open(&report)?;
        } else {
            println!(
                "{} --serve only works with --format html (current: {})",
                "!".bright_yellow(),
                format
            );
        }
    }

    Ok(())
}

/// `evedoo reassess` (FR-58, FR-59): re-correlate the stored inventory
/// against the current CVE database without contacting the host. Read-only
/// end to end — it never calls `HistoryStore::persist` or
/// `InventoryStore::replace`, because reassessment observes no machine
/// state; there is nothing new to record. `Mode::Reassess` structurally
/// cannot emit `New` or `Resolved` (enforced in `reconcile::reconcile`,
/// covered by that module's own tests), so this never rewrites the
/// inventory it read.
///
/// Unlike `scan`/`remote-scan`, there is no `--risk` flag here: showing risk
/// tier and score is reassessment's entire purpose (FR-63, FR-64), so its
/// report always shows and sorts by risk rather than gating that behind an
/// opt-in flag the way a plain scan does — FR-67's display constraint is
/// explicitly scoped to `scan`/`remote-scan` in spec.md for exactly this
/// reason. `--min-priority` is still offered, to narrow *which* tiers show,
/// same as it does on `scan`.
#[allow(clippy::too_many_arguments)]
fn run_reassess(
    database: PathBuf,
    host: Option<String>,
    max_age: i64,
    format: String,
    output: Option<PathBuf>,
    show_excepted: bool,
    min_priority: Option<String>,
    history_path: PathBuf,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════╗".bright_blue()
    );
    println!(
        "{}",
        "║          EVEDOO REASSESSMENT                       ║".bright_blue()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════╝".bright_blue()
    );
    println!();


    let output_format: OutputFormat = format.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let history_path_str = history_path.to_str().unwrap_or("scan_history.db").to_string();
    // Review item 2: canonicalised the same way `exception add/list/apply`
    // already are, so a differently-cased `--host` (e.g. copied out of
    // `fleet list`) still finds a snapshot a scan wrote under the
    // conventional uppercase `COMPUTERNAME` case.
    let hostname = resolve_hostname(host);
    let min_priority = min_priority.as_deref().map(Priority::from_str);

    // FR-58: re-correlate the stored inventory. Fail with actionable
    // guidance when there is none, rather than emitting an empty report.
    let inv = inventory::InventoryStore::open(&history_path_str)?;
    let stored = inv.load(&hostname)?;
    if stored.is_empty() {
        anyhow::bail!(
            "no stored inventory for {hostname}. Run `evedoo scan` first — \
             reassessment re-correlates a previous scan, it does not collect."
        );
    }

    // FR-59: report the snapshot's age and warn past --max-age, because a
    // reassessment against an old snapshot describes a machine that may
    // have changed since.
    if let Some(ts) = inv.snapshot_time(&hostname)? {
        if let Ok(when) = chrono::DateTime::parse_from_rfc3339(&ts) {
            let age = (chrono::Utc::now() - when.with_timezone(&chrono::Utc)).num_days();
            println!("Inventory observed {age} day(s) ago ({ts})");
            if age > max_age {
                println!(
                    "  {} snapshot is older than {max_age} day(s) — this describes a \
                     machine that may have changed since.",
                    "WARNING:".bright_yellow()
                );
            }
        }
    }
    println!();

    println!("{} Loading CVE database...", "→".bright_blue());
    let (matcher, cve_count, cpe_count) = open_cve_database(&database)?;
    println!("  {} CVEs, {} CPE configurations loaded", cve_count, cpe_count);
    println!();

    println!(
        "{} Re-correlating {} stored item(s) against the CVE database...",
        "→".bright_blue(),
        stored.len()
    );
    // FR-62: the same correlation implementation `scan`/`remote-scan` use,
    // so the three cannot diverge.
    let previous_inventory: std::collections::HashSet<String> =
        stored.iter().map(|s| s.registry_key.clone()).collect();
    let total_software = stored.len();
    let host_distro = distro_override::HostDistro::from_inventory(&stored);
    let outcome = correlate::correlate(stored, &matcher);
    let mut findings = outcome.findings;
    let msrc_outcome = msrc_override::apply(&mut findings, matcher.conn());
    if msrc_outcome.suppressed > 0 || msrc_outcome.enriched > 0 {
        info!(
            "MSRC override: {} findings suppressed (patched), {} enriched with KB/build",
            msrc_outcome.suppressed, msrc_outcome.enriched
        );
    }

    let distro_outcome = distro_override::apply(&mut findings, matcher.conn(), host_distro.as_ref());
    if distro_outcome.suppressed > 0 || distro_outcome.enriched > 0 {
        info!(
            "Distro advisory override: {} findings suppressed (patched), {} enriched with fixed version/advisory",
            distro_outcome.suppressed, distro_outcome.enriched
        );
    }
    println!("  Found {} potential vulnerabilities", findings.len());

    let (result, suppressed) = run_reassess_pipeline(
        &hostname,
        &history_path_str,
        findings,
        total_software,
        outcome.without_cves,
        &previous_inventory,
        &matcher,
        min_priority,
        show_excepted,
    )?;

    // B4, final whole-branch review: `reassess`'s entire justification is
    // separating `NewlyApplicable` ("a CVE was published against what you
    // already had") from `Persisting` ("unchanged since the previous run")
    // — FR-59, FR-60. Without this line that distinction appeared nowhere in
    // the command's own output; an operator had to infer it from the
    // per-finding status field alone. `reconcile::Mode::Reassess` never
    // produces `New` or `Resolved` (enforced in `reconcile::reconcile`), so
    // those two counts are exhaustive here.
    let newly_applicable_count = result
        .findings
        .iter()
        .filter(|f| f.status == models::FindingStatus::NewlyApplicable)
        .count();
    let persisting_count = result
        .findings
        .iter()
        .filter(|f| f.status == models::FindingStatus::Persisting)
        .count();
    println!("  {newly_applicable_count} newly applicable, {persisting_count} persisting");

    if suppressed > 0 {
        println!("  {suppressed} finding(s) suppressed by active exceptions");
    }
    println!();

    let report = generate_report(&result, output_format, true)?;
    match output {
        Some(ref path) => {
            fs::write(path, &report)?;
            println!("{} Report saved to: {}", "✓".bright_green(), path.display());
        }
        None => println!("{}", report),
    }

    Ok(())
}

/// The testable core of `reassess`: risk (FR-63) → exceptions (FR-70) →
/// `reconcile(Mode::Reassess)` (FR-59) → sort → presentation filter. Split
/// out of `run_reassess` (review item 5) so the two properties that make
/// `reassess` safe to run against production data — that it truly passes
/// `Mode::Reassess`, and that nothing here writes to history, the inventory
/// snapshot, or the exceptions table — are pinned by a test that goes red on
/// a regression, not only verified by a one-off manual run. Correlation
/// itself (FR-62) is not included: it is the step shared with `scan`/
/// `remote-scan` and is already covered by `correlate.rs`'s own tests, so
/// this takes already-correlated `findings` rather than calling
/// `correlate::correlate` itself. See `mod tests`'s
/// `reassess_pipeline_uses_reassess_mode_and_writes_nothing_back`.
///
/// Review item 1: a history store that fails to open or read now fails this
/// function outright rather than defaulting to an empty `previous_keys` set.
/// Silently treating "could not read history" as "nothing was ever
/// recorded" would make `reconcile` label every finding `NewlyApplicable` —
/// exactly the false alarm this whole phase exists to raise correctly, not
/// spuriously.
#[allow(clippy::too_many_arguments)]
fn run_reassess_pipeline(
    hostname: &str,
    history_path_str: &str,
    mut findings: Vec<models::Finding>,
    total_software: usize,
    without_cves: Vec<models::DetectedSoftware>,
    previous_inventory: &std::collections::HashSet<String>,
    matcher: &CveMatcher,
    min_priority: Option<Priority>,
    show_excepted: bool,
) -> Result<(ScanResult, usize)> {
    // Risk (FR-63), same as scan.
    let criticality = fleet::FleetManager::open(history_path_str)
        .ok()
        .and_then(|f| f.tags_for(hostname).ok().flatten())
        .map(|tags| risk::criticality_for(&tags))
        .unwrap_or(1.0);
    for f in &mut findings {
        let exploit = matcher
            .has_exploit_reference(&f.vulnerability.cve_id)
            .unwrap_or(false);
        // FR-79: the inventory snapshot was captured at a different moment.
        // Replaying stale reachability as current would be exactly the lie
        // this feature must not tell.
        f.reachability = reachability::Reachability::Unknown;
        f.risk = Some(risk::assess(
            &f.vulnerability,
            exploit,
            criticality,
            reachability::Reachability::Unknown,
        ));
    }

    let mut result = ScanResult::new(hostname.to_string());
    result.total_software = total_software;
    result.findings = findings;
    result.software_without_cves = without_cves;
    result.total_vulnerabilities = result.findings.len();

    // Exceptions (FR-70) — annotate only, never drop.
    let mut suppressed = 0usize;
    if let Ok(store) = exceptions::ExceptionStore::open(history_path_str) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        if let Ok(n) = store.apply(&mut result.findings, hostname, &today) {
            suppressed = n;
        }
    }

    // Reconcile in Reassess mode (FR-59): never New, never Resolved. Read
    // only — `previous_keys` is the last-known (cve_id, software_name) set
    // from history, so a pair already recorded stays Persisting and
    // anything else is NewlyApplicable; nothing here writes back to either
    // store. A failed read is surfaced, not swallowed (review item 1) — see
    // this function's own doc comment.
    let previous_keys = match history::HistoryStore::open(history_path_str)
        .and_then(|s| s.load_previous_keys(hostname))
    {
        Ok(keys) => keys,
        Err(e) => anyhow::bail!(
            "could not read scan history at {history_path_str}: {e}. Reassessment must know \
             which findings were already recorded, or it would mislabel every one of them as \
             newly applicable."
        ),
    };
    reconcile::reconcile(
        &mut result.findings,
        &previous_keys,
        previous_inventory,
        reconcile::Mode::Reassess,
    );
    // Status-honesty fix: this function bails out above (`anyhow::bail!`)
    // whenever `previous_keys` can't be read, so unlike
    // `persist_then_present`'s Mode::Scan path, reconcile here always runs
    // against a real baseline before this point is reached — reassess's
    // statuses are always real. Reports must know that, the same way they
    // know it for a successful `scan`/`remote-scan`.
    result.delta_known = true;

    result.sort_findings_by_risk();
    present::filter(&mut result, MatchConfidence::High, None, min_priority, show_excepted);

    Ok((result, suppressed))
}

/// `evedoo exception add/list/remove` (FR-68..FR-72).
fn run_exception_command(cmd: ExceptionCommands) -> Result<()> {
    match cmd {
        ExceptionCommands::Add {
            cve,
            software,
            host,
            reason,
            owner,
            expires,
            history,
        } => {
            let hostname = host.unwrap_or_else(current_hostname);
            let store = exceptions::ExceptionStore::open(&history)?;

            // Carried Task 8 review item 1: `add()` uses `INSERT OR REPLACE`
            // on (hostname, cve_id, software_name), which silently wipes any
            // prior rule's owner/reason/created_at and reassigns its id —
            // an `ExceptionRef.id` already stamped into a past report would
            // stop resolving, and `remove(old_id)` would report not-found.
            // Detect that collision here and tell the operator what it is
            // about to replace, so the loss is visible instead of silent.
            let existing = store.list(Some(&hostname))?;
            if let Some(prior) = find_replaced_exception(&existing, &hostname, &cve, &software) {
                println!(
                    "{} Replacing existing exception #{} (owner: {}, reason: \"{}\", created: {})",
                    "!".bright_yellow(),
                    prior.id,
                    prior.owner,
                    prior.reason,
                    prior.created_at,
                );
            }

            let id = store.add(exceptions::ExceptionInput {
                hostname,
                cve_id: cve,
                software_name: software,
                reason,
                owner,
                expires_at: expires,
            })?;
            println!("{} Exception #{id} added.", "✓".bright_green());
        }

        ExceptionCommands::List { host, json, history } => {
            let store = exceptions::ExceptionStore::open(&history)?;
            let records = store.list(host.as_deref())?;

            if json {
                println!("{}", serde_json::to_string_pretty(&records).unwrap_or_default());
            } else if records.is_empty() {
                println!("No exceptions recorded.");
            } else {
                println!("\n{}\n", "Exceptions".bright_blue().bold());
                println!(
                    "  {:<5} {:<16} {:<16} {:<16} {:<12} {:<20} Reason",
                    "Id", "Host", "CVE", "Software", "Owner", "Expires"
                );
                println!("  {}", "─".repeat(100));
                for r in &records {
                    println!(
                        "  {:<5} {:<16} {:<16} {:<16} {:<12} {:<20} {}",
                        r.id, r.hostname, r.cve_id, r.software_name, r.owner, r.expires_at, r.reason
                    );
                }
                println!("\n  Total: {} exception(s)\n", records.len());
            }
        }

        ExceptionCommands::Remove { id, history } => {
            let store = exceptions::ExceptionStore::open(&history)?;
            if store.remove(id)? {
                println!("{} Removed exception #{id}", "✓".bright_green());
            } else {
                println!("{} No exception with id {id}", "✗".bright_red());
            }
        }
    }

    Ok(())
}

/// The existing rule (if any) that `exception add` is about to silently
/// destroy: same hostname (after the module's own case-insensitive
/// canonicalisation), cve_id, and software_name — the exact triple
/// `INSERT OR REPLACE` collides on. `existing` is expected to already be
/// scoped to `hostname` via `ExceptionStore::list(Some(hostname))`, which
/// also returns fleet-wide (`*`) rules — those are only a real collision
/// when `hostname` itself is `*`, which the exact-match filter below
/// already handles correctly.
fn find_replaced_exception<'a>(
    existing: &'a [exceptions::ExceptionRecord],
    hostname: &str,
    cve_id: &str,
    software_name: &str,
) -> Option<&'a exceptions::ExceptionRecord> {
    let canonical = exceptions::canonical_hostname(hostname);
    existing
        .iter()
        .find(|r| r.hostname == canonical && r.cve_id == cve_id && r.software_name == software_name)
}

fn run_fleet_command(cmd: FleetCommands) -> Result<()> {
    match cmd {
        FleetCommands::Add {
            hostname,
            name,
            tags,
            remote,
            port,
            username,
            use_ssl,
            db,
        } => {
            let mgr = fleet::FleetManager::open(db.to_str().unwrap_or("scan_history.db"))?;
            let tag_list: Vec<String> = tags
                .map(|t| t.split(',').map(|s| s.trim().to_lowercase()).collect())
                .unwrap_or_default();

            mgr.add_asset(
                &hostname,
                name.as_deref(),
                &tag_list,
                remote,
                port,
                username.as_deref(),
                use_ssl,
            )?;

            println!(
                "{} Added asset: {}{}",
                "✓".bright_green(),
                hostname,
                if remote { " (remote)" } else { " (local)" }
            );
            if !tag_list.is_empty() {
                println!("  Tags: {}", tag_list.join(", "));
            }
        }

        FleetCommands::Remove { hostname, db } => {
            let mgr = fleet::FleetManager::open(db.to_str().unwrap_or("scan_history.db"))?;
            if mgr.remove_asset(&hostname)? {
                println!("{} Removed asset: {}", "✓".bright_green(), hostname);
            } else {
                println!(
                    "{} Asset not found: {}",
                    "✗".bright_red(),
                    hostname
                );
            }
        }

        FleetCommands::List { tag, json, db } => {
            let mgr = fleet::FleetManager::open(db.to_str().unwrap_or("scan_history.db"))?;
            let assets = mgr.list_assets(tag.as_deref())?;

            if json {
                println!("{}", serde_json::to_string_pretty(&assets).unwrap_or_default());
            } else if assets.is_empty() {
                println!("No assets registered. Use 'evedoo fleet add <hostname>' to add one.");
            } else {
                println!(
                    "\n{}\n",
                    "Fleet Assets".bright_blue().bold()
                );
                println!(
                    "  {:<20} {:<15} {:<8} {:<6} {:<25} Tags",
                    "Hostname", "Name", "Type", "Vulns", "Last Scan"
                );
                println!("  {}", "─".repeat(90));
                for asset in &assets {
                    let name_str = asset.display_name.as_deref().unwrap_or("-");
                    let asset_type = if asset.is_remote { "Remote" } else { "Local" };
                    let last_scan = asset
                        .last_scan
                        .as_deref()
                        .map(|s| if s.len() >= 19 { &s[..19] } else { s })
                        .unwrap_or("Never");
                    let tags_str = if asset.tags.is_empty() {
                        "-".to_string()
                    } else {
                        asset.tags.join(", ")
                    };
                    println!(
                        "  {:<20} {:<15} {:<8} {:<6} {:<25} {}",
                        asset.hostname, name_str, asset_type, asset.total_findings, last_scan, tags_str
                    );
                }
                println!("\n  Total: {} asset(s)\n", assets.len());
            }
        }

        FleetCommands::Tag {
            hostname,
            add,
            remove,
            db,
        } => {
            let mgr = fleet::FleetManager::open(db.to_str().unwrap_or("scan_history.db"))?;

            if let Some(add_tags) = add {
                let tags: Vec<String> = add_tags.split(',').map(|s| s.trim().to_string()).collect();
                if mgr.add_tags(&hostname, &tags)? {
                    println!("{} Added tags to {}: {}", "✓".bright_green(), hostname, add_tags);
                } else {
                    println!("{} Asset not found: {}", "✗".bright_red(), hostname);
                }
            }

            if let Some(rm_tags) = remove {
                let tags: Vec<String> = rm_tags.split(',').map(|s| s.trim().to_string()).collect();
                if mgr.remove_tags(&hostname, &tags)? {
                    println!("{} Removed tags from {}: {}", "✓".bright_green(), hostname, rm_tags);
                } else {
                    println!("{} Asset not found: {}", "✗".bright_red(), hostname);
                }
            }
        }

        FleetCommands::Report {
            database,
            db,
            tag,
            limit,
            json,
        } => {
            if !database.exists() {
                println!(
                    "{} CVE database not found at {}. `fleet report` derives risk at\n  \
                     report time (FR-84) rather than reading a stored score, so it needs one.",
                    "✗".bright_red(),
                    database.display()
                );
                return Ok(());
            }

            let db_path = db.to_str().unwrap_or("scan_history.db");
            let mgr = fleet::FleetManager::open(db_path)?;

            // FR-88: with a tag filter, only registered assets carrying it are
            // eligible. Without one, every scanned host counts — an
            // unregistered host was still scanned, so it is still real.
            let host_filter: Option<std::collections::HashSet<String>> = match &tag {
                Some(t) => Some(
                    mgr.list_assets(Some(t))?
                        .into_iter()
                        .map(|a| a.hostname)
                        .collect(),
                ),
                None => None,
            };

            // Criticality is resolved per host (FR-86), so every registered
            // asset's tags are needed, not just the filtered ones.
            let mut tags: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for a in mgr.list_assets(None)? {
                tags.insert(a.hostname.clone(), a.tags.join(","));
            }

            let conn = rusqlite::Connection::open(db_path)?;
            let stored = aggregate::load_stored(&conn, host_filter.as_ref())?;

            let (matcher, _, _) = open_cve_database(&database)?;
            let outcome = aggregate::score_all(&stored, &matcher, &tags);
            let rollups = aggregate::rollup(&outcome.scored);

            let assets: std::collections::HashSet<&String> =
                outcome.scored.iter().map(|f| &f.hostname).collect();

            if json {
                let payload = serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "assets_covered": assets.len(),
                    "findings_excluded": outcome.excluded,
                    "data_oldest_seen": stored.iter().map(|f| f.last_seen.as_str()).min(),
                    "data_newest_seen": stored.iter().map(|f| f.last_seen.as_str()).max(),
                    "remediations": rollups.iter().take(limit).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
                return Ok(());
            }

            println!();
            println!("{}", "Fleet Remediation Report".bright_blue().bold());
            println!("{}", fleet_report_header(assets.len(), outcome.excluded));
            if let (Some(oldest), Some(newest)) = (
                stored.iter().map(|f| f.last_seen.as_str()).min(),
                stored.iter().map(|f| f.last_seen.as_str()).max(),
            ) {
                println!(
                    "{}",
                    fleet_report_freshness(oldest, newest, chrono::Utc::now())
                );
            }
            println!();

            if rollups.is_empty() {
                println!("  No outstanding findings across the selected assets.");
                println!();
                return Ok(());
            }

            for (i, r) in rollups.iter().take(limit).enumerate() {
                let kev = if r.kev_count > 0 {
                    format!(" [{} KEV]", r.kev_count).bright_red().to_string()
                } else {
                    String::new()
                };
                println!(
                    "  {}. {} — {}, {}, risk removed {:.1}{}",
                    i + 1,
                    r.software_name.bright_white(),
                    plural(r.affected_assets, "asset", "assets"),
                    plural(r.cve_count, "CVE", "CVEs"),
                    r.total_risk_removed,
                    kev
                );
                if let Some(cmd) = &r.upgrade_command {
                    println!("     {}", cmd.bright_black());
                }
            }
            println!();
        }
        FleetCommands::Summary { json, db } => {
            let mgr = fleet::FleetManager::open(db.to_str().unwrap_or("scan_history.db"))?;
            let summary = mgr.summary()?;

            if json {
                println!("{}", serde_json::to_string_pretty(&summary).unwrap_or_default());
            } else {
                println!();
                println!(
                    "{}",
                    "╔══════════════════════════════════════════════════════╗".bright_blue()
                );
                println!(
                    "{}",
                    "║             FLEET SUMMARY                            ║".bright_blue()
                );
                println!(
                    "{}",
                    "╚══════════════════════════════════════════════════════╝".bright_blue()
                );
                println!();
                println!("  {} {}", "Total assets:".bright_white(), summary.total_assets);
                println!(
                    "    Local: {}  |  Remote: {}",
                    summary.local_assets, summary.remote_assets
                );
                println!(
                    "  {} {}",
                    "Total vulnerabilities:".bright_white(),
                    summary.total_findings
                );
                println!(
                    "  {} {}",
                    "Never scanned:".bright_yellow(),
                    summary.never_scanned
                );
                if !summary.tags.is_empty() {
                    println!(
                        "  {} {}",
                        "Tags in use:".bright_white(),
                        summary.tags.join(", ")
                    );
                }
                println!();
            }
        }
    }

    Ok(())
}

fn run_schedule_command(cmd: ScheduleCommands) -> Result<()> {
    match cmd {
        ScheduleCommands::Create {
            name,
            frequency,
            time,
            day,
            args,
            elevated,
        } => {
            let freq = schedule::ScheduleFrequency::from_str(&frequency).ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid frequency '{}'. Use: daily, weekly, hourly, onlogon",
                    frequency
                )
            })?;

            println!();
            if elevated {
                println!(
                    "{} Task will run with HIGHEST privileges (--elevated).",
                    "⚠".bright_yellow()
                );
            }
            println!(
                "{} Creating scheduled scan task...",
                "→".bright_blue()
            );

            match schedule::create_schedule(&name, &freq, time.as_deref(), day.as_deref(), &args, elevated) {
                Ok(full_name) => {
                    println!(
                        "{} Scheduled task created: {}",
                        "✓".bright_green(),
                        full_name
                    );
                    println!("  Frequency: {}", freq);
                    if let Some(ref t) = time {
                        println!("  Start time: {}", t);
                    }
                    if let Some(ref d) = day {
                        println!("  Day: {}", d);
                    }
                    if !args.is_empty() {
                        println!("  Scan args: {}", args);
                    }
                    println!();
                    println!("  View in Task Scheduler or run: schtasks /Query /TN {}", full_name);
                }
                Err(e) => {
                    println!("{} Failed to create schedule: {}", "✗".bright_red(), e);
                    println!();
                    println!("  Note: Creating scheduled tasks may require elevated privileges.");
                    println!("  Try running from an Administrator terminal.");
                }
            }
            println!();
        }

        ScheduleCommands::List => {
            println!();
            match schedule::list_schedules() {
                Ok(tasks) if tasks.is_empty() => {
                    println!("No evedoo scheduled tasks found.");
                    println!("Use 'evedoo schedule create <name>' to create one.");
                }
                Ok(tasks) => {
                    println!(
                        "{}\n",
                        "Scheduled Scans".bright_blue().bold()
                    );
                    println!(
                        "  {:<20} {:<12} {:<10} {:<24} Command",
                        "Name", "Schedule", "Status", "Next Run"
                    );
                    println!("  {}", "─".repeat(90));
                    for task in &tasks {
                        println!(
                            "  {:<20} {:<12} {:<10} {:<24} {}",
                            task.display_name,
                            task.schedule_type,
                            task.status,
                            task.next_run,
                            task.command,
                        );
                    }
                    println!("\n  Total: {} task(s)\n", tasks.len());
                }
                Err(e) => {
                    println!("{} Failed to query schedules: {}", "✗".bright_red(), e);
                }
            }
        }

        ScheduleCommands::Remove { name } => {
            println!();
            match schedule::remove_schedule(&name) {
                Ok(true) => {
                    println!(
                        "{} Removed scheduled task: {}{}",
                        "✓".bright_green(),
                        schedule::TASK_PREFIX,
                        name
                    );
                }
                Ok(false) => {
                    println!(
                        "{} Task not found: {}{}",
                        "✗".bright_red(),
                        schedule::TASK_PREFIX,
                        name
                    );
                }
                Err(e) => {
                    println!("{} Failed to remove schedule: {}", "✗".bright_red(), e);
                    println!();
                    println!("  Note: Removing scheduled tasks may require elevated privileges.");
                }
            }
            println!();
        }
    }

    Ok(())
}

/// Builds the inventory snapshot from a scan result's findings and unmatched
/// software, deduplicated by `registry_key`. `result.findings` carries one
/// entry per *finding*, so software with N applicable CVEs would otherwise
/// contribute N identical `registry_key`s to the snapshot — harmless to the
/// stored data (`InventoryStore::replace` collapses duplicates via `INSERT
/// OR IGNORE` regardless) but it would trip that method's collapse warning,
/// which exists to flag a suspected *scanner enumeration bug*, on every
/// ordinary scan that reports more than one CVE against the same software.
fn dedup_snapshot(result: &ScanResult) -> Vec<models::DetectedSoftware> {
    let mut seen = std::collections::HashSet::new();
    result
        .findings
        .iter()
        .map(|f| &f.software)
        .chain(result.software_without_cves.iter())
        .filter(|sw| seen.insert(sw.registry_key.clone()))
        .cloned()
        .collect()
}

/// Runs reconcile + persist (the FR-57/FR-59/FR-60 delta-tracking stage),
/// then the presentation filter — always in that fixed order. This is the
/// single place the FR-61 ordering lives: reconcile/persist must see the
/// complete, unfiltered finding set before anything hides part of it, or a
/// still-present-but-hidden finding gets incorrectly marked `Resolved` in
/// the history DB (the bug this whole task exists to fix). `run_scan` and
/// `run_remote_scan` both call this instead of duplicating the sequence, so
/// there is exactly one place to get the order wrong.
///
/// `history_path` is `None` when `--no-history` was passed; delta tracking
/// (and the inventory snapshot write) is then skipped entirely, but
/// presentation filtering still runs. Opening either store is a diagnostic
/// aid, not something a scan should abort over, so a failure to open is
/// logged (at `warn!`, per M1 — final whole-branch review) and delta
/// tracking is skipped rather than propagated.
///
/// Order within the delta-tracking stage matters too: the previous
/// inventory is read via `InventoryStore::load` *before*
/// `InventoryStore::replace` overwrites it, because `reconcile::reconcile`
/// needs that previous snapshot to distinguish `New` from
/// `NewlyApplicable` — the distinction that write destroys. The inventory
/// write itself now runs unconditionally once both stores are open — not
/// nested inside a successful read of the previous scan-history keys — so a
/// history-read failure alone can no longer also silently skip it (M1: it
/// used to, which meant a locked or unreadable history DB left `reassess`
/// reasoning about a stale snapshot forever, violating FR-57's "every scan"
/// on top of the delta-tracking failure).
///
/// M1 (final whole-branch review): three history/inventory failures used to
/// be swallowed at `info!` — invisible even with a subscriber installed at
/// the default level — and a failure to read the previous scan-history keys
/// specifically left every finding at `correlate()`'s placeholder
/// `FindingStatus::New`, which then got *persisted* as if it were a real
/// delta ("everything is new"), rather than no delta at all. Now: the three
/// failures are `warn!`, and when the previous keys can't be read, `reconcile`
/// and `persist` are both skipped — nothing this run's placeholder statuses
/// touches is written to `scan_findings` — and the console says so plainly,
/// instead of printing a "new/newly applicable/resolved" line built from
/// data that was never actually reconciled.
///
/// Status-honesty fix (found in the scoped re-review of M1/B4 together): M1
/// stopped the *history DB* from recording a fabricated delta, but nothing
/// stopped *reports* from presenting one — `report/text.rs`'s `Status:` line
/// (added by B4) rendered `finding.status` unconditionally, so on
/// `--no-history`, this function's DB-open-failure arm, or its
/// `load_previous_keys`-failure arm, every finding still showed
/// `Status: New` — the exact placeholder M1 refused to persist, presented
/// anyway. `ScanResult::delta_known` now tracks this explicitly: it starts
/// `false` and is set `true` only in the one branch below where
/// `reconcile::reconcile` actually ran against a real `previous_keys` set.
/// Every report format (text, JSON, CSV) consults it before showing a
/// per-finding status. The DB-open-failure arm — previously `warn!`-only —
/// now also prints the same console caveat the `load_previous_keys`-failure
/// arm already had, so both silent-to-the-operator paths are silent no more.
///
/// Returns the number of findings the presentation filter hid (across both
/// `result.findings` and `result.resolved_findings`).
#[allow(clippy::too_many_arguments)]
fn persist_then_present(
    result: &mut ScanResult,
    history_path: Option<&str>,
    min_confidence: MatchConfidence,
    severity_filter: Option<&[Severity]>,
    min_priority: Option<Priority>,
    show_excepted: bool,
) -> usize {
    if let Some(path) = history_path {
        match (history::HistoryStore::open(path), inventory::InventoryStore::open(path)) {
            (Ok(store), Ok(inv)) => {
                // Read the previous inventory BEFORE it is overwritten below —
                // this is the one fact reconcile() needs that the write
                // destroys. A read failure degrades to "nothing known" (New
                // vs NewlyApplicable may be wrong for this one scan) rather
                // than aborting — the actual New/Persisting/Resolved delta
                // status is decided from `previous_keys` below, which this
                // alone cannot fabricate.
                let previous_inventory: std::collections::HashSet<String> =
                    match inv.load(&result.hostname) {
                        Ok(items) => items.into_iter().map(|s| s.registry_key).collect(),
                        Err(e) => {
                            warn!(
                                "Could not load previous inventory for {}: {e}",
                                result.hostname
                            );
                            std::collections::HashSet::new()
                        }
                    };

                // The inventory snapshot write is independent of scan-history
                // tracking below — a different table, and FR-57 requires
                // *every* scan to persist the complete inventory regardless
                // of whether delta tracking below succeeds. Runs first (after
                // the previous snapshot has been captured into
                // `previous_inventory` above, satisfying the read-before-
                // write ordering `reconcile` needs) so a `load_previous_keys`
                // failure below cannot also silently skip it.
                //
                // Deduplicated by registry_key first: `snapshot` is built one
                // entry per *finding*, so software with N CVEs would
                // otherwise contribute N identical registry_keys, and
                // `InventoryStore::replace`'s collapse warning — meant to
                // flag a scanner enumeration bug — would fire on every
                // ordinary scan instead.
                let scan_time = result.scan_time.to_rfc3339();
                let snapshot = dedup_snapshot(result);
                if let Err(e) = inv.replace(&result.hostname, &scan_time, &snapshot) {
                    warn!("Inventory snapshot error: {}", e);
                }

                match store.load_previous_keys(&result.hostname) {
                    Ok(previous_keys) => {
                        reconcile::reconcile(
                            &mut result.findings,
                            &previous_keys,
                            &previous_inventory,
                            reconcile::Mode::Scan,
                        );
                        // Status-honesty fix: reconcile() just replaced
                        // correlate()'s placeholder FindingStatus::New with a
                        // real comparison against `previous_keys`, so every
                        // report format may now present `finding.status`.
                        // This is independent of whether `store.persist`
                        // below succeeds — the statuses in `result.findings`
                        // are real either way; only their durability to disk
                        // is in question.
                        result.delta_known = true;

                        match store.persist(result) {
                            Ok(()) => {
                                let new_count = result
                                    .findings
                                    .iter()
                                    .filter(|f| f.status == models::FindingStatus::New)
                                    .count();
                                let newly_applicable_count = result
                                    .findings
                                    .iter()
                                    .filter(|f| f.status == models::FindingStatus::NewlyApplicable)
                                    .count();
                                let resolved_count = result.resolved_findings.len();
                                if new_count > 0 || newly_applicable_count > 0 || resolved_count > 0 {
                                    println!(
                                        "  {} new, {} newly applicable, {} resolved since last scan",
                                        new_count, newly_applicable_count, resolved_count
                                    );
                                }
                            }
                            Err(e) => warn!("History tracking error: {}", e),
                        }
                    }
                    Err(e) => {
                        // Do NOT reconcile or persist on this path: every
                        // finding is still sitting at correlate()'s
                        // placeholder `FindingStatus::New`, and persisting
                        // that would write a fabricated "everything is new"
                        // delta into history — wrong, not merely absent (M1).
                        // Say so instead of staying silent about it.
                        warn!("Cannot read scan history for {}: {}", result.hostname, e);
                        println!(
                            "  {} delta status unavailable — could not read scan history ({e}); \
                             findings below are not compared against the previous run",
                            "!".bright_yellow()
                        );
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                // Status-honesty fix: this used to warn! only, so a history
                // DB that fails to open (locked, corrupt, unwritable
                // directory) left every finding at correlate()'s placeholder
                // FindingStatus::New with nothing on the console to say the
                // delta below wasn't actually computed — the same defect
                // M1 fixed for the load_previous_keys-failure arm above, just
                // one open() call earlier. `result.delta_known` stays at its
                // default `false` here (reconcile never runs on this path),
                // so every report format already omits/neutralises the
                // per-finding status; this line is the console-visible half
                // of that.
                warn!("Cannot open history DB: {}", e);
                println!(
                    "  {} delta status unavailable — could not open scan history ({e}); \
                     findings below are not compared against the previous run",
                    "!".bright_yellow()
                );
            }
        }
    }
    println!();

    present::filter(result, min_confidence, severity_filter, min_priority, show_excepted)
}

/// The presentation layer (FR-61, FR-70). Nothing in this module may be
/// called before delta tracking has already run against the complete
/// finding set — `persist_then_present`, above, is the only sanctioned
/// caller and owns that ordering.
mod present {
    use crate::models::{Finding, FindingStatus, MatchConfidence, Priority, ScanResult, Severity};

    /// Whether one finding survives the active confidence/severity/priority/
    /// exception filters.
    ///
    /// `resolved_findings` stubs (`status == FindingStatus::Resolved`, built
    /// by `history::load_resolved_finding`) carry placeholder identity, not
    /// real match data: `confidence` is hardcoded `Low` and `severity` is
    /// hardcoded `Unknown`, because nothing was actually re-matched — the
    /// finding is loaded straight back out of history. Filtering on those
    /// placeholders would blame the operator's confidence/severity flags for
    /// hiding resolved findings the flags were never meant to touch, so:
    ///   - the confidence filter is skipped entirely for resolved stubs;
    ///   - the severity filter is applied normally when the stub's severity
    ///     happens to be known, and skipped when it is `Unknown` (which is
    ///     always, today, but this is expressed in terms of "is the data
    ///     real" rather than "is this a stub" so it keeps working if a
    ///     future change starts carrying the real severity through).
    ///
    /// The priority and excepted filters need no special-casing: a resolved
    /// stub always has `risk: None` (it is never run through `risk::assess`,
    /// which only iterates `result.findings`) and always has `excepted:
    /// None` (exceptions are applied to `result.findings` only, before
    /// stubs are loaded back from history) — both filters already treat
    /// missing data as "never hide this", which is the correct behaviour
    /// for a resolved finding: it isn't a live risk to prioritise away, and
    /// it was never suppressed by an exception in *this* scan.
    fn keep(
        f: &Finding,
        min_confidence: MatchConfidence,
        severity_filter: Option<&[Severity]>,
        min_priority: Option<Priority>,
        show_excepted: bool,
    ) -> bool {
        let is_resolved_stub = f.status == FindingStatus::Resolved;
        // A resolved stub's severity filter is skipped only when its
        // severity is the placeholder `Unknown` — normal findings, and any
        // resolved stub that did carry a real severity, are filtered as
        // usual.
        let severity_ok = (is_resolved_stub && f.vulnerability.severity == Severity::Unknown)
            || severity_filter.is_none_or(|s| s.contains(&f.vulnerability.severity));

        (is_resolved_stub || f.confidence <= min_confidence)
            && severity_ok
            && min_priority.is_none_or(|mp| f.risk.as_ref().is_none_or(|r| r.tier <= mp))
            && (show_excepted || f.excepted.is_none())
    }

    /// Hides findings that don't meet the active filters from the
    /// *displayed* sets — both `result.findings` and `result.resolved_findings`,
    /// so e.g. `--severity critical` doesn't leave a resolved section still
    /// showing Low/Medium entries — and recomputes `total_vulnerabilities` to
    /// match, so every report format (text header, JSON field, severity
    /// breakdown) stays internally consistent. Never touches history.
    ///
    /// Excepted findings are hidden by default (FR-70); `show_excepted`
    /// reveals them. This never removes anything from the collections before
    /// this point runs — exceptions only annotate, and persistence has
    /// already happened by the time `persist_then_present` calls this.
    ///
    /// Prints a diagnostic naming the count hidden, without attributing it to
    /// a single cause — confidence, severity, priority and exception status
    /// all feed the same filter, so e.g. `--severity critical` alone must not
    /// be reported as "low-confidence matches". Returns the number hidden.
    pub fn filter(
        result: &mut ScanResult,
        min_confidence: MatchConfidence,
        severity_filter: Option<&[Severity]>,
        min_priority: Option<Priority>,
        show_excepted: bool,
    ) -> usize {
        let before = result.findings.len() + result.resolved_findings.len();
        result
            .findings
            .retain(|f| keep(f, min_confidence, severity_filter, min_priority, show_excepted));
        result
            .resolved_findings
            .retain(|f| keep(f, min_confidence, severity_filter, min_priority, show_excepted));
        result.total_vulnerabilities = result.findings.len();

        let hidden = before - (result.findings.len() + result.resolved_findings.len());
        if hidden > 0 {
            println!(
                "  Filtered {} finding(s) not matching the active confidence/severity/priority/exception filters",
                hidden
            );
        }
        hidden
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::models::{
            Architecture, DetectedSoftware, Remediation, Vulnerability,
        };

        /// Mirrors `history::load_resolved_finding`'s placeholder identity:
        /// `MatchConfidence::Low`, `Severity::Unknown`, no risk, no
        /// exception — the finding was loaded back from history, not
        /// re-matched.
        fn resolved_stub(cve_id: &str, sw_name: &str) -> Finding {
            Finding {
                software: DetectedSoftware {
                    name: sw_name.to_string(),
                    version: Some("1.0.0".to_string()),
                    publisher: None,
                    install_location: None,
                    install_date: None,
                    registry_key: String::new(),
                    architecture: Architecture::Unknown,
                },
                vulnerability: Vulnerability {
                    cve_id: cve_id.to_string(),
                    description: String::new(),
                    cvss_score: None,
                    severity: Severity::Unknown,
                    published_date: None,
                    references: Vec::new(),
                    remediation: Remediation::default(),
                    epss_score: None,
                    epss_percentile: None,
                    in_kev: false,
                    kev_due_date: None,
                    kev_ransomware_use: None,
                },
                confidence: MatchConfidence::Low,
                vendor: None,
                status: FindingStatus::Resolved,
                risk: None,
                excepted: None,
                reachability: Default::default(),
            }
        }

        /// Item 1: filtering `resolved_findings` with the same predicate as
        /// `result.findings` used to delete the whole "resolved" section on
        /// every default-confidence scan — a resolved stub's placeholder
        /// `MatchConfidence::Low` is never `<= MatchConfidence::High`
        /// (`--min-confidence`'s default), so `Low <= High` was false for
        /// every resolved finding, always. This asserts a default-confidence
        /// scan still reports its resolved findings.
        #[test]
        fn default_confidence_scan_still_reports_resolved_findings() {
            let mut result = ScanResult::new("host".into());
            result.resolved_findings.push(resolved_stub("CVE-2024-0001", "Alpha"));
            result.resolved_findings.push(resolved_stub("CVE-2024-0002", "Beta"));

            let hidden = filter(&mut result, MatchConfidence::High, None, None, false);

            assert_eq!(hidden, 0, "resolved findings must not be hidden by the default confidence filter");
            assert_eq!(result.resolved_findings.len(), 2);
        }

        /// A `--severity` filter must not hide resolved findings either —
        /// their severity is always the placeholder `Unknown`, not a real
        /// severity that could legitimately fail to match the filter.
        #[test]
        fn severity_filter_does_not_hide_resolved_findings() {
            let mut result = ScanResult::new("host".into());
            result.resolved_findings.push(resolved_stub("CVE-2024-0001", "Alpha"));

            let hidden = filter(
                &mut result,
                MatchConfidence::High,
                Some(&[Severity::Critical]),
                None,
                false,
            );

            assert_eq!(hidden, 0);
            assert_eq!(result.resolved_findings.len(), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::{
        Architecture, DetectedSoftware, Finding, FindingStatus, Remediation, Vulnerability,
    };

    fn finding_for(cve_id: &str, registry_key: &str) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: "Alpha".into(),
                version: Some("1.0.0".into()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: registry_key.to_string(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: cve_id.to_string(),
                description: String::new(),
                cvss_score: None,
                severity: Severity::High,
                published_date: None,
                references: Vec::new(),
                remediation: Remediation::default(),
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Exact,
            vendor: None,
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        }
    }

    /// Item 5: one piece of software with several applicable CVEs used to
    /// contribute one snapshot entry per finding — N identical
    /// `registry_key`s for N CVEs — which `InventoryStore::replace` would
    /// then report as "collapsed on duplicate registry_key", a warning
    /// meant to flag a scanner enumeration bug, not an ordinary scan. This
    /// asserts the snapshot itself is already deduplicated before it ever
    /// reaches `replace`, so `written == items.len()` always holds for a
    /// snapshot built this way and the collapse warning cannot fire.
    #[test]
    fn dedup_snapshot_collapses_multiple_cves_against_one_software_to_one_entry() {
        let mut result = ScanResult::new("host".into());
        result.findings.push(finding_for("CVE-2024-0001", "pe://alpha.exe"));
        result.findings.push(finding_for("CVE-2024-0002", "pe://alpha.exe"));
        result.findings.push(finding_for("CVE-2024-0003", "pe://alpha.exe"));

        let snapshot = dedup_snapshot(&result);

        assert_eq!(snapshot.len(), 1, "three CVEs against one registry_key must yield one inventory row");
        assert_eq!(snapshot[0].registry_key, "pe://alpha.exe");
    }

    /// Distinct software (distinct `registry_key`s) must not be collapsed
    /// into each other, and unmatched software (no CVEs) must still be
    /// included — FR-57 wants the complete inventory, not just what has
    /// findings.
    #[test]
    fn dedup_snapshot_keeps_distinct_software_and_includes_unmatched() {
        let mut result = ScanResult::new("host".into());
        result.findings.push(finding_for("CVE-2024-0001", "pe://alpha.exe"));
        result.findings.push(finding_for("CVE-2024-0002", "pe://beta.exe"));
        result.software_without_cves.push(DetectedSoftware {
            name: "Gamma".into(),
            version: Some("1.0".into()),
            publisher: None,
            install_location: None,
            install_date: None,
            registry_key: "pe://gamma.exe".into(),
            architecture: Architecture::X64,
        });

        let snapshot = dedup_snapshot(&result);

        assert_eq!(snapshot.len(), 3);
        let keys: std::collections::HashSet<_> =
            snapshot.iter().map(|s| s.registry_key.clone()).collect();
        assert!(keys.contains("pe://alpha.exe"));
        assert!(keys.contains("pe://beta.exe"));
        assert!(keys.contains("pe://gamma.exe"));
    }

    fn exception_record(
        id: i64,
        hostname: &str,
        cve_id: &str,
        software_name: &str,
    ) -> exceptions::ExceptionRecord {
        exceptions::ExceptionRecord {
            id,
            hostname: hostname.into(),
            cve_id: cve_id.into(),
            software_name: software_name.into(),
            reason: "r".into(),
            owner: "o".into(),
            created_at: "2026-08-21T00:00:00Z".into(),
            expires_at: "2099-01-01".into(),
        }
    }

    /// Carried Task 8 review item 1: `exception add` uses `INSERT OR
    /// REPLACE`, which silently destroys a prior rule with the same
    /// (hostname, cve_id, software_name) triple. `find_replaced_exception`
    /// is the CLI-layer detector that lets the operator be told about that
    /// collision before it happens; this pins down exactly which existing
    /// row counts as "the same triple".
    #[test]
    fn find_replaced_exception_matches_the_exact_triple_case_insensitively() {
        let existing = vec![
            exception_record(1, "HOST-01", "CVE-2024-0001", "Alpha"),
            exception_record(2, "*", "CVE-2024-0001", "Alpha"),
        ];

        // Same triple, queried in a different case — must still be found
        // (this module's own hostname canonicalisation is what makes the
        // rule reachable at all; the detector must agree with it).
        let hit = find_replaced_exception(&existing, "host-01", "CVE-2024-0001", "Alpha");
        assert_eq!(hit.map(|r| r.id), Some(1));

        // Different software — no collision.
        assert!(find_replaced_exception(&existing, "HOST-01", "CVE-2024-0001", "Beta").is_none());

        // Querying with the fleet-wide wildcard must match only the
        // wildcard row, not the host-specific one.
        let wildcard_hit = find_replaced_exception(&existing, "*", "CVE-2024-0001", "Alpha");
        assert_eq!(wildcard_hit.map(|r| r.id), Some(2));
    }

    /// Review item 2: `reassess --host` must resolve to the same canonical
    /// case `exception add/list/apply` already use, or an operator-supplied
    /// value in a different case than the stored `COMPUTERNAME` convention
    /// falsely reports "no stored inventory" for a host whose snapshot is
    /// actually in the table.
    #[test]
    fn resolve_hostname_canonicalizes_operator_supplied_host() {
        assert_eq!(resolve_hostname(Some("server01".to_string())), "SERVER01");
        assert_eq!(resolve_hostname(Some("  Server01  ".to_string())), "SERVER01");
        assert_eq!(resolve_hostname(Some("*".to_string())), "*");
    }

    /// M3 (final whole-branch review): `--sort` must reject anything other
    /// than `risk` at the clap layer. Before this, `--sort priorty` parsed
    /// successfully, silently kept the default KEV/EPSS/CVSS/date order, and
    /// silently declined to turn on `--risk`'s text-report display — with no
    /// diagnostic either way, the exact "typo becomes a rule that silently
    /// never matches" failure FR-72 says must be an error instead.
    #[test]
    fn sort_flag_rejects_anything_other_than_risk() {
        let ok = Cli::try_parse_from(["evedoo", "scan", "--sort", "risk"]);
        assert!(ok.is_ok(), "{:?}", ok.err());

        let bad = Cli::try_parse_from(["evedoo", "scan", "--sort", "priorty"]);
        assert!(
            bad.is_err(),
            "a misspelled --sort value must be a parse error, not silently ignored"
        );

        let bad_remote = Cli::try_parse_from([
            "evedoo", "remote-scan", "-t", "host", "-u", "user", "--sort", "priorty",
        ]);
        assert!(bad_remote.is_err(), "remote-scan's --sort must reject typos too");
    }

    /// A mistyped filter value used to be accepted and silently changed what
    /// the report showed: `--severity critcal` became "Unknown severity only",
    /// so a host full of critical findings looked clean. Every filter value is
    /// now validated when the arguments are parsed.
    #[test]
    fn filter_flags_reject_misspelled_values() {
        for args in [
            vec!["evedoo", "scan", "--severity", "critcal"],
            vec!["evedoo", "scan", "--severity", "critical,hgih"],
            vec!["evedoo", "scan", "--severity", ""],
            vec!["evedoo", "scan", "--min-confidence", "hihg"],
            vec!["evedoo", "scan", "--min-priority", "p5"],
            vec!["evedoo", "scan", "--target-os", "windoze"],
            vec!["evedoo", "remote-scan", "-t", "host", "-u", "user", "--severity", "critcal"],
            vec!["evedoo", "remote-scan", "-t", "host", "-u", "user", "--min-confidence", "hihg"],
            vec!["evedoo", "remote-scan", "-t", "host", "-u", "user", "--min-priority", "p0"],
            vec!["evedoo", "reassess", "--min-priority", "urgent"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?} must be a parse error");
        }
    }

    #[test]
    fn filter_flags_accept_every_documented_value_in_any_case() {
        for args in [
            vec!["evedoo", "scan", "--severity", "critical,high,medium,low"],
            vec!["evedoo", "scan", "--severity", "Critical, HIGH"],
            vec!["evedoo", "scan", "--severity", "unknown"],
            vec!["evedoo", "scan", "--min-confidence", "exact"],
            vec!["evedoo", "scan", "--min-confidence", "Medium"],
            vec!["evedoo", "scan", "--min-confidence", "low"],
            vec!["evedoo", "scan", "--min-priority", "p1"],
            vec!["evedoo", "scan", "--min-priority", "P4"],
            vec!["evedoo", "scan", "--target-os", "linux"],
            vec!["evedoo", "scan", "--target-os", "Windows"],
            vec!["evedoo", "scan", "--target-os", "macos"],
            vec!["evedoo", "scan", "--target-os", "darwin"],
            vec!["evedoo", "reassess", "--min-priority", "p2"],
        ] {
            let parsed = Cli::try_parse_from(&args);
            assert!(parsed.is_ok(), "{args:?}: {:?}", parsed.err());
        }
    }

    fn open_history_tables(path: &str) -> rusqlite::Connection {
        rusqlite::Connection::open(path).unwrap()
    }

    fn row_count(conn: &rusqlite::Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    /// Review item 5: the two properties that make `reassess` safe were
    /// previously protected only by a manual end-to-end run. This drives
    /// `run_reassess_pipeline` directly and asserts both:
    ///   1. `Mode::Reassess` is really what reaches `reconcile` — a finding
    ///      against software absent from the previous inventory must come
    ///      back `NewlyApplicable`, never `New` (which `Mode::Scan` would
    ///      produce for the identical input).
    ///   2. nothing the pipeline touches — `scan_findings`, `scan_inventory`,
    ///      `exceptions` — gains or loses a row.
    ///
    /// Mutation check (per the brief, reported in the fix-round report):
    /// swapping `reconcile::Mode::Reassess` for `reconcile::Mode::Scan` in
    /// `run_reassess_pipeline` turns the `NewlyApplicable` assertion below
    /// red (it observes `New` instead), then was reverted.
    #[test]
    fn reassess_pipeline_uses_reassess_mode_and_writes_nothing_back() {
        let dir = std::env::temp_dir().join("evedoo_reassess_pipeline_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.db");
        let path_str = path.to_str().unwrap();
        let hostname = "TEST-HOST";

        // Seed history + inventory the way an ordinary `scan` would: one
        // finding against Alpha (registry_key pe://alpha.exe), recorded once.
        let mut scan1 = ScanResult::new(hostname.to_string());
        scan1.findings = vec![finding_for("CVE-2024-0001", "pe://alpha.exe")];
        crate::persist_then_present(&mut scan1, Some(path_str), MatchConfidence::Low, None, None, false);

        let conn = open_history_tables(path_str);
        let findings_before = row_count(&conn, "scan_findings");
        let inventory_before = row_count(&conn, "scan_inventory");
        let exceptions_before = row_count(&conn, "exceptions");
        drop(conn);

        // Reassess input: the previously-recorded finding (must come back
        // Persisting), plus a second finding whose CVE was never recorded
        // AND whose registry_key was never in the previous inventory —
        // exactly the case where Mode::Reassess (always NewlyApplicable) and
        // Mode::Scan (New, because the software itself is unknown) disagree.
        let matcher = crate::matcher::tests_support::empty_matcher("reassess_writes_nothing");
        let findings = vec![
            finding_for("CVE-2024-0001", "pe://alpha.exe"),
            finding_for("CVE-2024-9999", "pe://zeta.exe"),
        ];
        let previous_inventory: std::collections::HashSet<String> =
            ["pe://alpha.exe".to_string()].into_iter().collect();

        let (result, _suppressed) = run_reassess_pipeline(
            hostname,
            path_str,
            findings,
            2,
            Vec::new(),
            &previous_inventory,
            &matcher,
            None,
            false,
        )
        .expect("a healthy history store must not fail the pipeline");

        let persisting = result
            .findings
            .iter()
            .find(|f| f.vulnerability.cve_id == "CVE-2024-0001")
            .expect("the previously-recorded finding must survive");
        assert_eq!(persisting.status, FindingStatus::Persisting);

        let newly_applicable = result
            .findings
            .iter()
            .find(|f| f.vulnerability.cve_id == "CVE-2024-9999")
            .expect("the unrecorded finding must survive");
        assert_eq!(
            newly_applicable.status,
            FindingStatus::NewlyApplicable,
            "reassess must never mark a finding New, even against software absent from the \
             previous inventory — that is exactly what distinguishes Mode::Reassess from \
             Mode::Scan"
        );

        // Status-honesty fix: `run_reassess_pipeline` bails outright when
        // history is unreadable (see its doc comment and
        // `reassess_pipeline_fails_loudly_when_history_is_unreadable`
        // below), so by the time it returns `Ok`, `reconcile` has always run
        // against a real baseline — its statuses are always real, and
        // `delta_known` must say so.
        assert!(result.delta_known, "reassess's statuses are always real once it returns Ok");

        let conn = open_history_tables(path_str);
        assert_eq!(row_count(&conn, "scan_findings"), findings_before, "reassess must not write to scan_findings");
        assert_eq!(row_count(&conn, "scan_inventory"), inventory_before, "reassess must not write to scan_inventory");
        assert_eq!(row_count(&conn, "exceptions"), exceptions_before, "reassess must not write to exceptions");
        drop(conn);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review item 1: a history store that fails to open (here, a file that
    /// exists but is not a valid SQLite database — the same failure mode as
    /// a half-migrated or locked database) must fail the pipeline outright.
    /// Before this fix, `.unwrap_or_default()` turned that failure into an
    /// empty `previous_keys` set, which made every finding come back
    /// `NewlyApplicable` — a false "a new CVE now affects you" alarm with no
    /// error and no log line.
    #[test]
    fn reassess_pipeline_fails_loudly_when_history_is_unreadable() {
        let dir = std::env::temp_dir().join("evedoo_reassess_unreadable_history_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not_a_database.db");
        std::fs::write(&path, b"this is not a sqlite database").unwrap();
        let path_str = path.to_str().unwrap();

        let matcher = crate::matcher::tests_support::empty_matcher("reassess_unreadable_history");
        let findings = vec![finding_for("CVE-2024-0001", "pe://alpha.exe")];
        let previous_inventory = std::collections::HashSet::new();

        let result = run_reassess_pipeline(
            "TEST-HOST",
            path_str,
            findings,
            1,
            Vec::new(),
            &previous_inventory,
            &matcher,
            None,
            false,
        );

        assert!(
            result.is_err(),
            "an unreadable history store must fail the pipeline, not silently default to \
             \"nothing was ever recorded\""
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M1 (final whole-branch review): the inventory snapshot write must not
    /// live inside the `Ok(previous_keys)` arm of `persist_then_present` — a
    /// failure to read `scan_findings` must not also silently skip writing
    /// `scan_inventory`, or FR-57's "every scan persists the complete
    /// inventory" is violated on top of delta tracking already being
    /// unavailable. `scan_findings` is dropped *after* a full migration (so
    /// re-opening the database does not resurrect it — `schema::open`'s
    /// migration loop only runs below `CURRENT_VERSION`, and the version is
    /// already current), forcing `store.load_previous_keys` to fail while
    /// `scan_inventory` remains perfectly healthy. Before the fix (the
    /// inventory write nested inside `Ok(previous_keys)`), this test's
    /// inventory assertion fails: nothing gets written.
    #[test]
    fn persist_then_present_writes_inventory_even_when_scan_history_is_unreadable() {
        let dir = std::env::temp_dir().join("evedoo_persist_inventory_independent_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.db");
        let path_str = path.to_str().unwrap();

        {
            let conn = rusqlite::Connection::open(path_str).unwrap();
            crate::schema::migrate(&conn).unwrap();
            conn.execute_batch("DROP TABLE scan_findings;").unwrap();
        }

        let mut result = ScanResult::new("TEST-HOST".to_string());
        result.findings = vec![finding_for("CVE-2024-0001", "pe://alpha.exe")];

        // Must not panic despite scan_findings being gone.
        let _hidden = crate::persist_then_present(
            &mut result,
            Some(path_str),
            MatchConfidence::Low,
            None,
            None,
            false,
        );

        let conn = open_history_tables(path_str);
        let inventory_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_inventory WHERE hostname = 'TEST-HOST'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            inventory_rows, 1,
            "the inventory snapshot must be written even though scan_findings is unreadable \
             (FR-57: every scan persists the complete inventory, independent of whether delta \
             tracking against scan_findings succeeded)"
        );
        drop(conn);

        // Status-honesty fix: a `load_previous_keys` failure must leave
        // `reconcile` (and therefore `delta_known`) untouched — every
        // finding here is still sitting at correlate()'s placeholder
        // `FindingStatus::New`, and no report may present that as a real
        // delta.
        assert!(
            !result.delta_known,
            "a load_previous_keys failure must not leave delta_known true"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The primary regression test for the status-honesty fix. Before this
    /// fix, `report/text.rs` rendered `Status: {finding.status}`
    /// unconditionally, so `--no-history` (`history_path: None`, exactly
    /// what this test passes) presented `Status: New` for every finding —
    /// `correlate()`'s placeholder, never replaced because delta tracking
    /// is skipped entirely on this path. This test fails red against the
    /// pre-fix code: `generate_report`'s text output contained "Status:"
    /// even though `persist_then_present` never touched history.
    #[test]
    fn no_history_scan_does_not_present_a_delta_status() {
        let mut result = ScanResult::new("TEST-HOST".to_string());
        result.findings = vec![finding_for("CVE-2024-0001", "pe://alpha.exe")];

        // `history_path: None` is exactly what `run_scan`/`run_remote_scan`
        // pass when `--no-history` was given (see the `history_arg` binding
        // just above each `persist_then_present` call site).
        crate::persist_then_present(&mut result, None, MatchConfidence::Low, None, None, false);

        assert!(
            !result.delta_known,
            "--no-history must never leave delta_known true — reconcile() never ran"
        );

        let report = generate_report(&result, OutputFormat::Text, false)
            .expect("text report must still render");
        assert!(
            !report.contains("Status:"),
            "a --no-history scan must not present a per-finding delta status: {report}"
        );

        let json = generate_report(&result, OutputFormat::Json, false)
            .expect("json report must still render");
        assert!(
            json.contains("\"delta_known\": false") || json.contains("\"delta_known\":false"),
            "the JSON artifact must carry delta_known so a machine consumer can discount \
             finding.status: {json}"
        );
    }

    /// The success-path counterpart: once `reconcile` has actually run
    /// against a real `previous_keys` set, `delta_known` must flip to
    /// `true` and the text report must present the status again.
    #[test]
    fn persist_then_present_marks_delta_known_on_successful_reconcile() {
        let dir = std::env::temp_dir().join("evedoo_delta_known_success_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.db");
        let path_str = path.to_str().unwrap();

        let mut result = ScanResult::new("TEST-HOST".to_string());
        result.findings = vec![finding_for("CVE-2024-0001", "pe://alpha.exe")];

        crate::persist_then_present(
            &mut result,
            Some(path_str),
            MatchConfidence::Low,
            None,
            None,
            false,
        );

        assert!(
            result.delta_known,
            "a healthy history store with a readable previous-keys set must mark the delta known"
        );
        let report = generate_report(&result, OutputFormat::Text, false)
            .expect("text report must render");
        assert!(
            report.contains("Status:"),
            "once the delta is known, the status line must render: {report}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The DB-open-failure arm (`(Err(e), _) | (_, Err(e))` in
    /// `persist_then_present`) used to `warn!` only — no console line, and
    /// (before this fix) `delta_known` did not exist, so a report generated
    /// from this path would have presented the same fabricated `Status: New`
    /// `no_history_scan_does_not_present_a_delta_status` guards against.
    /// Reuses the same "write garbage bytes" technique
    /// `reassess_pipeline_fails_loudly_when_history_is_unreadable` uses to
    /// make `crate::schema::open` fail on an invalid SQLite file.
    #[test]
    fn persist_then_present_leaves_delta_unknown_when_history_db_unopenable() {
        let dir = std::env::temp_dir().join("evedoo_delta_known_db_unopenable_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not_a_database.db");
        std::fs::write(&path, b"this is not a sqlite database").unwrap();
        let path_str = path.to_str().unwrap();

        let mut result = ScanResult::new("TEST-HOST".to_string());
        result.findings = vec![finding_for("CVE-2024-0001", "pe://alpha.exe")];

        crate::persist_then_present(
            &mut result,
            Some(path_str),
            MatchConfidence::Low,
            None,
            None,
            false,
        );

        assert!(
            !result.delta_known,
            "a history DB that fails to open must not leave delta_known true"
        );
        let report = generate_report(&result, OutputFormat::Text, false)
            .expect("text report must still render");
        assert!(
            !report.contains("Status:"),
            "a report built from an unopenable history DB must not present a delta status: {report}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FR-81. Coverage is disclosed on every run, complete or not, so a
    /// reader never has to guess whether the sweep was partial. Measured
    /// unelevated on a real desktop: 161 of 336 processes readable, which
    /// makes the partial case the normal one rather than an edge case.
    #[test]
    fn coverage_line_is_produced_for_complete_and_partial_sweeps() {
        use crate::reachability::Coverage;

        let complete = reachability_coverage_line(Coverage {
            readable: 9,
            total: 9,
        });
        assert!(complete.contains("9/9"));
        assert!(
            !complete.contains("run elevated"),
            "a complete sweep must not nag about elevation"
        );

        let partial = reachability_coverage_line(Coverage {
            readable: 4,
            total: 9,
        });
        assert!(partial.contains("4/9"));
        assert!(
            partial.contains("run elevated"),
            "a partial sweep must say how to get the rest"
        );
    }

    /// FR-87. The excluded count must reach the operator. A rollup that
    /// silently shrank because some CVEs were missing from the database is
    /// indistinguishable from a fleet that simply has less risk.
    #[test]
    fn fleet_report_header_discloses_exclusions_only_when_nonzero() {
        let clean = fleet_report_header(4, 0);
        assert!(clean.contains("4 assets"));
        assert!(
            !clean.contains("excluded"),
            "a complete rollup must not mention exclusions"
        );

        let lossy = fleet_report_header(4, 7);
        assert!(lossy.contains("4 assets"));
        assert!(
            lossy.contains("7 findings excluded"),
            "an incomplete rollup must say exactly how much was dropped"
        );
        assert!(lossy.contains("not present in the database"));
    }

    /// A fleet rollup reads STORED findings, so it is only as current as the
    /// last scan of each host. The report must say how old that data is.
    ///
    /// This was a real miss: the first shipped version presented findings
    /// last seen 2026-05-17 as a current fleet picture with nothing on screen
    /// to say they were three months old — the same "stale presented as
    /// current" defect delta_known and the reachability coverage line exist
    /// to prevent.
    #[test]
    fn fleet_report_freshness_states_the_age_of_the_data() {
        let now: chrono::DateTime<chrono::Utc> = "2026-08-28T00:00:00Z".parse().unwrap();

        // One scan date across the fleet.
        let single = fleet_report_freshness(
            "2026-05-17T12:00:00+00:00",
            "2026-05-17T12:00:00+00:00",
            now,
        );
        assert!(single.contains("102 days old"), "got: {single}");
        assert!(!single.contains("oldest"), "no range to report: {single}");

        // Hosts scanned at different times: both ends must be stated, because
        // the stalest host is the one you have no current information about.
        let ranged = fleet_report_freshness(
            "2026-05-17T12:00:00+00:00",
            "2026-08-20T12:00:00+00:00",
            now,
        );
        assert!(ranged.contains("newest 7 days old"), "got: {ranged}");
        assert!(ranged.contains("oldest 102 days old"), "got: {ranged}");
    }

    /// An unparseable timestamp must say so rather than silently reporting a
    /// plausible-looking age.
    #[test]
    fn fleet_report_freshness_admits_when_it_cannot_tell() {
        let now: chrono::DateTime<chrono::Utc> = "2026-08-28T00:00:00Z".parse().unwrap();
        let out = fleet_report_freshness("not-a-date", "also-not-a-date", now);
        assert!(out.contains("age unknown"), "got: {out}");
    }

    #[test]
    fn test_audit_cli_parsing() {
        let cli = Cli::try_parse_from(["evedoo", "audit"]);
        assert!(cli.is_ok());
        if let Ok(Cli { command: Commands::Audit { benchmark, policy, format, output } }) = cli {
            assert!(benchmark.is_none(), "the default is chosen from the detected OS at run time");
            assert!(policy.is_none());
            assert_eq!(format, "text");
            assert!(output.is_none());
        } else {
            panic!("Expected Commands::Audit");
        }

        let cli_custom = Cli::try_parse_from([
            "evedoo", "audit", "--benchmark", "ms-edge", "-f", "json", "-o", "report.json",
        ]);
        assert!(cli_custom.is_ok());
        if let Ok(Cli { command: Commands::Audit { benchmark, policy, format, output } }) = cli_custom {
            assert_eq!(benchmark.as_deref(), Some("ms-edge"));
            assert!(policy.is_none());
            assert_eq!(format, "json");
            assert_eq!(output, Some(PathBuf::from("report.json")));
        } else {
            panic!("Expected Commands::Audit with options");
        }
    }

    #[test]
    fn test_cross_platform_scan_cli_parsing() {
        let cli = Cli::try_parse_from(["evedoo", "scan", "--rootfs", "/mnt/chroot", "--target-os", "linux"]);
        assert!(cli.is_ok());
        if let Ok(Cli {
            command:
                Commands::Scan {
                    rootfs,
                    target_os,
                    ..
                },
        }) = cli
        {
            assert_eq!(rootfs, Some(PathBuf::from("/mnt/chroot")));
            assert_eq!(target_os, Some("linux".to_string()));
        } else {
            panic!("Expected Commands::Scan with rootfs and target_os");
        }

        let cli_default = Cli::try_parse_from(["evedoo", "scan"]);
        assert!(cli_default.is_ok());
        if let Ok(Cli {
            command:
                Commands::Scan {
                    rootfs,
                    target_os,
                    ..
                },
        }) = cli_default
        {
            assert!(rootfs.is_none());
            assert!(target_os.is_none());
        } else {
            panic!("Expected Commands::Scan default");
        }
    }
}

//! The two facts worth stating before the user picks an action: whether the
//! CVE database is usable, and whether this process can see enough of the
//! system to scan it properly.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use owo_colors::OwoColorize;

/// What the CVE database looks like right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Database {
    /// No file at the configured path.
    Missing,
    /// A file that could not be opened or queried as a CVE database.
    Unreadable(String),
    Ready {
        cves: u64,
        cpe_matches: u64,
        /// Whole days since the last recorded sync, when one is recorded.
        age_days: Option<i64>,
    },
}

/// Status facts shown in the main screen's header band.
#[derive(Debug, Clone)]
pub struct Status {
    pub database: Database,
    pub db_path: String,
    pub elevated: bool,
}

/// A sync older than this is called out. The NVD publishes continuously, so a
/// fortnight-old corpus is quietly missing real findings.
const STALE_AFTER_DAYS: i64 = 14;

impl Status {
    /// Read the current state. Never fails: every problem becomes a `Database`
    /// variant the header can describe, because a menu that refuses to draw
    /// when the database is missing is a menu you cannot use to build one.
    pub fn probe(db_path: &str) -> Self {
        Status {
            database: probe_database(db_path),
            db_path: db_path.to_string(),
            elevated: is_elevated(),
        }
    }

    /// Fixed values for rendering tests, so layout assertions never depend on
    /// what happens to be on the machine running them.
    #[cfg(test)]
    pub fn fixture() -> Self {
        Status {
            database: Database::Ready {
                cves: 383_401,
                cpe_matches: 2_370_054,
                age_days: Some(12),
            },
            db_path: "vulndb.sqlite".to_string(),
            elevated: false,
        }
    }

    /// One line describing the corpus.
    pub fn database_line(&self) -> String {
        match &self.database {
            Database::Missing => format!(
                "{} {} {}",
                "CVE DB:".bright_black(),
                "not found".bright_red(),
                format!("({}) - run [1] to build it", self.db_path).bright_black()
            ),
            Database::Unreadable(why) => format!(
                "{} {} {}",
                "CVE DB:".bright_black(),
                "unreadable".bright_red(),
                format!("({why})").bright_black()
            ),
            Database::Ready {
                cves,
                cpe_matches,
                age_days,
            } => {
                let age = match age_days {
                    Some(d) if *d >= STALE_AFTER_DAYS => {
                        format!("synced {d}d ago - stale").bright_yellow().to_string()
                    }
                    Some(0) => "synced today".bright_green().to_string(),
                    Some(d) => format!("synced {d}d ago").bright_green().to_string(),
                    None => "sync date unknown".bright_yellow().to_string(),
                };
                format!(
                    "{} {} {} {}",
                    "CVE DB:".bright_black(),
                    format!("{} CVEs", thousands(*cves)).white(),
                    format!("- {} CPEs -", thousands(*cpe_matches)).bright_black(),
                    age
                )
            }
        }
    }

    /// One line describing what this process can see.
    ///
    /// Unelevated runs cannot open most process handles, so runtime
    /// reachability degrades to `Unknown` for every finding and silently stops
    /// contributing to risk. Measured on a live scan: 159 of 330 processes
    /// readable. That is worth saying out loud before a scan, not after.
    pub fn session_line(&self) -> String {
        if self.elevated {
            format!(
                "{} {}",
                "Session:".bright_black(),
                "elevated - full reachability coverage".bright_green()
            )
        } else {
            format!(
                "{} {} {}",
                "Session:".bright_black(),
                "not elevated".bright_yellow(),
                "- reachability limited; [T] [E] to relaunch".bright_black()
            )
        }
    }
}

/// Group digits for readability: 383401 reads as 383,401.
///
/// Written as a leading partial group plus fixed chunks rather than testing
/// `% 3 == 0` per digit: the modulo form trips clippy's `manual_is_multiple_of`,
/// and its suggested `is_multiple_of` was only stabilised in Rust 1.87, above
/// this crate's 1.83 MSRV.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    let lead = digits.len() % 3;

    out.push_str(&digits[..lead]);
    for (i, chunk) in digits.as_bytes()[lead..].chunks(3).enumerate() {
        if i > 0 || lead > 0 {
            out.push(',');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out
}

fn probe_database(db_path: &str) -> Database {
    if !Path::new(db_path).exists() {
        return Database::Missing;
    }

    let conn = match rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => return Database::Unreadable(e.to_string()),
    };

    // SQLite integers are signed 64-bit; a COUNT(*) is never negative.
    let cves: u64 = match conn.query_row("SELECT COUNT(*) FROM cves", [], |r| r.get::<_, i64>(0)) {
        Ok(v) => u64::try_from(v).unwrap_or(0),
        Err(e) => return Database::Unreadable(e.to_string()),
    };
    let cpe_matches: u64 = conn
        .query_row("SELECT COUNT(*) FROM cpe_matches", [], |r| r.get::<_, i64>(0))
        .map(|v| u64::try_from(v).unwrap_or(0))
        .unwrap_or(0);

    // sync_metadata carries a single row; an absent or unparseable date is
    // reported as unknown rather than guessed at.
    let last_sync: Option<String> = conn
        .query_row(
            "SELECT last_sync_date FROM sync_metadata ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok();

    let age_days = last_sync
        .as_deref()
        .and_then(parse_sync_date)
        .map(|d| (chrono::Utc::now() - d).num_days());

    Database::Ready {
        cves,
        cpe_matches,
        age_days,
    }
}

/// Parse whatever `sync_metadata.last_sync_date` happens to hold.
///
/// The column has carried RFC 3339 from the API sync path and a bare date from
/// the mirror path, so both are accepted. An unrecognised value yields `None`
/// and the header says the sync date is unknown, which is honest — guessing a
/// date would let a stale corpus present itself as fresh.
fn parse_sync_date(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&chrono::Utc));
    }
    if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(d.and_utc());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
    }
    None
}

/// Does this process hold an elevated token?
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use std::ffi::c_void;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: u32 = 20;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(h_object: *mut c_void) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: *mut c_void,
            desired_access: u32,
            token_handle: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    unsafe {
        let mut token: *mut c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut returned: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TokenElevation>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.token_is_elevated != 0
    }
}

/// On Unix, "elevated" means running as root.
#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    std::env::var("USER").map(|u| u == "root").unwrap_or(false)
        || std::path::Path::new("/proc/self")
            .metadata()
            .map(|_| false)
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_groups_digits() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(383_401), "383,401");
        assert_eq!(thousands(2_370_054), "2,370,054");
    }

    #[test]
    fn a_missing_database_says_how_to_build_one() {
        // The empty-state is the first thing a new user sees; it has to point
        // at the fix rather than just reporting the absence.
        let status = Status {
            database: Database::Missing,
            db_path: "vulndb.sqlite".into(),
            elevated: false,
        };
        let line = strip(&status.database_line());
        assert!(line.contains("not found"), "{line}");
        assert!(line.contains("[1]"), "missing-db line must name the fix: {line}");
    }

    #[test]
    fn a_stale_corpus_is_called_out_but_a_fresh_one_is_not() {
        let stale = ready(Some(STALE_AFTER_DAYS));
        assert!(strip(&stale.database_line()).contains("stale"));

        let fresh = ready(Some(STALE_AFTER_DAYS - 1));
        assert!(!strip(&fresh.database_line()).contains("stale"));
    }

    #[test]
    fn an_unelevated_session_says_what_it_costs() {
        let status = ready(Some(1));
        let line = strip(&status.session_line());
        assert!(line.contains("not elevated"), "{line}");
        assert!(
            line.contains("reachability"),
            "the warning must say what is lost: {line}"
        );
    }

    #[test]
    fn probing_a_path_that_does_not_exist_reports_missing_not_a_panic() {
        // The menu draws before the database exists; probing must never fail.
        let status = Status::probe("this-file-does-not-exist-9f3a.sqlite");
        assert_eq!(status.database, Database::Missing);
    }

    #[test]
    fn sync_dates_parse_in_every_shape_the_column_has_carried() {
        // The API sync path writes RFC 3339; the mirror path writes a bare
        // date. Rejecting either would show "sync date unknown" on a database
        // that is in fact fresh.
        assert!(parse_sync_date("2026-09-11T02:55:10Z").is_some());
        assert!(parse_sync_date("2026-09-11 02:55:10").is_some());
        assert!(parse_sync_date("2026-09-11").is_some());
    }

    #[test]
    fn an_unparseable_sync_date_is_unknown_rather_than_guessed() {
        // Guessing would let a stale corpus present itself as fresh.
        assert!(parse_sync_date("").is_none());
        assert!(parse_sync_date("last tuesday").is_none());
    }

    fn ready(age_days: Option<i64>) -> Status {
        Status {
            database: Database::Ready {
                cves: 1,
                cpe_matches: 1,
                age_days,
            },
            db_path: "vulndb.sqlite".into(),
            elevated: false,
        }
    }

    fn strip(s: &str) -> String {
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
}

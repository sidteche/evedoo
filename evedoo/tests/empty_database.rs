//! A scan must never report a clean result from a CVE database that has
//! nothing in it.
//!
//! Found in the field: `evedoo menu`, launched from `target\release\`,
//! resolved `vulndb.sqlite` against that directory, where an aborted
//! `--enrichment-only` run had just created a schema-only database. The scan
//! loaded "0 CVEs, 0 CPE configurations" and printed a green
//! "✓ No known vulnerabilities found!" — indistinguishable from a genuinely
//! clean host. A security tool that cannot check must say so, not pass.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;

/// The schema `CveMatcher` opens, with no rows — what a fresh or aborted
/// cve-db-builder run leaves behind.
const EMPTY_SCHEMA: &str = "
    CREATE TABLE cves (cve_id TEXT PRIMARY KEY, description TEXT,
        published_date TEXT, modified_date TEXT,
        cvss_v3_score REAL, cvss_v3_vector TEXT, cvss_v2_score REAL,
        cvss_v2_vector TEXT, severity TEXT);
    CREATE TABLE cpe_matches (cve_id TEXT, vendor TEXT, product TEXT,
        version TEXT, version_start_including TEXT, version_start_excluding TEXT,
        version_end_including TEXT, version_end_excluding TEXT, platform TEXT,
        vulnerable INTEGER DEFAULT 1, target_sw TEXT);
    CREATE TABLE cve_references (id INTEGER PRIMARY KEY,
        cve_id TEXT, url TEXT, source TEXT, tags TEXT);
    CREATE TABLE product_mappings (id INTEGER PRIMARY KEY,
        display_name_pattern TEXT, cpe_vendor TEXT, cpe_product TEXT,
        confidence REAL DEFAULT 1.0);
    CREATE TABLE epss (cve_id TEXT PRIMARY KEY, score REAL,
        percentile REAL, fetched_at TEXT);
    CREATE TABLE kev (cve_id TEXT PRIMARY KEY, date_added TEXT,
        due_date TEXT, action TEXT, ransomware_use TEXT);
    CREATE TABLE schema_version (version INTEGER);
";

struct TempDb(PathBuf);

impl TempDb {
    fn empty(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "evedoo-emptydb-{label}-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(EMPTY_SCHEMA).unwrap();
        TempDb(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_evedoo"))
        .args(args)
        .env_remove("EVEDOO_DB_PATH")
        .output()
        .expect("run evedoo");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn a_scan_against_a_database_with_no_cves_fails_instead_of_reporting_clean() {
    let db = TempDb::empty("scan");

    let (ok, out) = run(&[
        "scan",
        "--database",
        db.path().to_str().unwrap(),
        "--no-history",
        "--no-reachability",
    ]);

    assert!(
        !out.contains("No known vulnerabilities found"),
        "an empty CVE database produced a clean verdict:\n{out}"
    );
    assert!(!ok, "a scan that checked nothing must exit non-zero:\n{out}");
    assert!(
        out.contains("contains no CVEs"),
        "the failure must say why, so the operator can fix it:\n{out}"
    );
}

#[test]
fn a_scan_with_no_database_at_all_exits_non_zero() {
    // It printed "Database not found" and then exited 0 — a scheduled scan or
    // CI job would record success for a run that checked nothing.
    let missing = std::env::temp_dir().join(format!(
        "evedoo-emptydb-missing-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing);

    let (ok, out) = run(&[
        "scan",
        "--database",
        missing.to_str().unwrap(),
        "--no-history",
        "--no-reachability",
    ]);

    assert!(!ok, "a scan with no CVE database exited 0:\n{out}");
    assert!(
        !out.contains("No known vulnerabilities found"),
        "a missing database produced a clean verdict:\n{out}"
    );
}

#[test]
fn a_json_scan_against_an_empty_database_writes_no_report() {
    // Machine consumers (CI, SIEM ingest, the Studio bridge) read the report
    // file, not the console. An empty findings array would look like a clean
    // host to every one of them.
    let db = TempDb::empty("json");
    let report = std::env::temp_dir().join(format!(
        "evedoo-emptydb-report-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&report);

    let (ok, out) = run(&[
        "scan",
        "--database",
        db.path().to_str().unwrap(),
        "--format",
        "json",
        "--output",
        report.to_str().unwrap(),
        "--no-history",
        "--no-reachability",
    ]);

    let wrote = report.exists();
    let _ = std::fs::remove_file(&report);
    assert!(!ok, "expected a non-zero exit:\n{out}");
    assert!(!wrote, "a report was written from an empty database:\n{out}");
}

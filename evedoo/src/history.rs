//! Scan history and delta tracking.
//!
//! Persists findings to a local SQLite database so consecutive scans can be
//! compared, and each finding can be tagged New / Persisting / Resolved.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use rusqlite::{params, Connection};
use tracing::debug;

use crate::error::Result;
use crate::models::{Finding, FindingStatus, ScanResult};

pub struct HistoryStore {
    conn: Connection,
}

impl HistoryStore {
    /// Open (or create) the history database at the given path.
    pub fn open(path: &str) -> Result<Self> {
        // Schema and migrations are owned by `crate::schema` (NFR-8).
        let conn = crate::schema::open(path)?;
        Ok(Self { conn })
    }

    /// Writes the already-reconciled findings to history and populates
    /// `result.resolved_findings`. Every finding in `result.findings` must
    /// already carry its `status` (set by `reconcile::reconcile`, which runs
    /// against the same `load_previous_keys` set before this is called) —
    /// this method persists that status, it does not assign it.
    ///
    /// A finding present in the previous scan but absent from the current
    /// set is loaded back as a `Resolved` stub and appended to
    /// `result.resolved_findings`; its row in `scan_findings` is updated to
    /// `Resolved` to match.
    pub(crate) fn persist(&self, result: &mut ScanResult) -> Result<()> {
        let previous = self.load_previous_keys(&result.hostname)?;
        let scan_time = result.scan_time.to_rfc3339();

        let current: HashSet<(String, String)> = result
            .findings
            .iter()
            .map(|f| (f.vulnerability.cve_id.clone(), f.software.name.clone()))
            .collect();

        // Findings that were in the previous scan but are now gone
        let resolved_keys: Vec<_> = previous.difference(&current).cloned().collect();
        debug!("{} resolved finding(s)", resolved_keys.len());

        for (cve_id, software_name) in &resolved_keys {
            if let Some(f) = self.load_resolved_finding(&result.hostname, cve_id, software_name)? {
                result.resolved_findings.push(f);
            }
        }

        // Upsert current findings into the history table
        self.persist_findings(result, &scan_time)?;

        // Mark resolved rows
        for (cve_id, software_name) in &resolved_keys {
            self.conn.execute(
                "UPDATE scan_findings SET status = 'Resolved', last_seen = ?1
                 WHERE hostname = ?2 AND cve_id = ?3 AND software_name = ?4",
                params![scan_time, result.hostname, cve_id, software_name],
            )?;
        }

        Ok(())
    }

    /// `(cve_id, software_name)` pairs recorded for `hostname` on the
    /// previous run (any status short of `Resolved`). Feeds both
    /// `reconcile::reconcile` (status tagging) and `persist`, above (which
    /// re-derives resolved keys from the same set) — `pub(crate)` so the
    /// scan pipeline in `main.rs` can read it before `persist` overwrites
    /// anything.
    pub(crate) fn load_previous_keys(&self, hostname: &str) -> Result<HashSet<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT cve_id, software_name FROM scan_findings
             WHERE hostname = ?1 AND status != 'Resolved'",
        )?;

        let keys = stmt
            .query_map(params![hostname], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(keys)
    }

    fn persist_findings(&self, result: &ScanResult, scan_time: &str) -> Result<()> {
        for finding in &result.findings {
            self.conn.execute(
                "INSERT INTO scan_findings
                    (hostname, cve_id, software_name, software_version,
                     first_seen, last_seen, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(hostname, cve_id, software_name) DO UPDATE SET
                     software_version = excluded.software_version,
                     last_seen        = excluded.last_seen,
                     status           = excluded.status",
                params![
                    result.hostname,
                    finding.vulnerability.cve_id,
                    finding.software.name,
                    finding.software.version,
                    scan_time,
                    scan_time,
                    finding.status.to_string(),
                ],
            )?;
        }
        Ok(())
    }

    fn load_resolved_finding(
        &self,
        hostname: &str,
        cve_id: &str,
        software_name: &str,
    ) -> Result<Option<Finding>> {
        use crate::models::{
            Architecture, DetectedSoftware, MatchConfidence, Remediation, Severity, Vulnerability,
        };

        let row: rusqlite::Result<(Option<String>, String)> = self.conn.query_row(
            "SELECT software_version, first_seen FROM scan_findings
             WHERE hostname = ?1 AND cve_id = ?2 AND software_name = ?3 LIMIT 1",
            params![hostname, cve_id, software_name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        let (version, first_seen) = match row {
            Ok(r) => r,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        Ok(Some(Finding {
            software: DetectedSoftware {
                name: software_name.to_string(),
                version,
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
                published_date: Some(first_seen),
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
        }))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Architecture, DetectedSoftware, MatchConfidence, Remediation, Severity, Vulnerability};

    #[test]
    fn history_open_leaves_a_fully_migrated_db() {
        let dir = std::env::temp_dir().join("evedoo_hist_migrate_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.db");
        let p = path.to_str().unwrap().to_string();

        drop(HistoryStore::open(&p).unwrap());

        let conn = rusqlite::Connection::open(&p).unwrap();
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, crate::schema::CURRENT_VERSION);

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn finding(cve_id: &str, sw_name: &str, severity: Severity) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: sw_name.to_string(),
                version: Some("1.0.0".to_string()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: format!("pe://{sw_name}.exe"),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: cve_id.to_string(),
                description: String::new(),
                cvss_score: None,
                severity,
                published_date: None,
                references: Vec::new(),
                remediation: Remediation::default(),
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::High,
            vendor: None,
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        }
    }

    /// Regression guard for FR-61 (the bug this task exists to fix).
    ///
    /// Before this task, `--severity`/`--min-confidence` filtered findings
    /// *before* delta tracking ran, so on a filtered invocation delta
    /// tracking only ever saw the filtered subset as "current". Any
    /// still-present finding that the filter hid was therefore absent from
    /// `current`, and it was incorrectly marked Resolved in the history DB
    /// even though it had never actually gone away.
    ///
    /// This drives `crate::persist_then_present` directly — the one function
    /// in main.rs that encodes the fix's ordering (reconcile + persist, then
    /// the presentation filter) — rather than replicating that ordering
    /// inline in the test. A test that builds its own correctly-ordered
    /// sequence cannot fail on a regression to the ordering *inside the
    /// thing under test*; driving the real function can, and does (see the
    /// ordering-swap experiment recorded in the fix-round report).
    ///
    /// Two scans of an unchanged three-severity finding set are run through
    /// `persist_then_present`, the second with a `--severity critical`
    /// presentation filter active, then two things are checked: (1) the
    /// in-memory displayed set (`scan2.findings`) is filtered down to the
    /// critical finding, and (2) the persisted history DB — queried
    /// directly, independent of `scan2.findings` — still shows all three
    /// findings as `Persisting`, never `Resolved`.
    #[test]
    fn filtering_after_delta_leaves_history_complete_and_unresolved() {
        let dir = std::env::temp_dir().join("evedoo_severity_filter_ordering_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.db");
        let path_str = path.to_str().unwrap();

        let hostname = "test-host".to_string();

        let complete_set = || {
            vec![
                finding("CVE-2024-0001", "Alpha", Severity::Critical),
                finding("CVE-2024-0002", "Beta", Severity::Medium),
                finding("CVE-2024-0003", "Gamma", Severity::Low),
            ]
        };

        // Scan 1: the complete, unfiltered set goes through the pipeline
        // with no presentation filter active (mirrors an invocation with no
        // --severity flag), establishing "previous" history for scan 2.
        let mut scan1 = ScanResult::new(hostname.clone());
        scan1.findings = complete_set();
        crate::persist_then_present(&mut scan1, Some(path_str), MatchConfidence::Low, None, None, false);

        // Scan 2: nothing actually changed in reality, so correlate() again
        // hands the pipeline the same complete three-finding set — but this
        // invocation has --severity critical active.
        let mut scan2 = ScanResult::new(hostname.clone());
        scan2.findings = complete_set();
        let hidden = crate::persist_then_present(
            &mut scan2,
            Some(path_str),
            MatchConfidence::Low,
            Some(&[Severity::Critical]),
            None,
            false,
        );

        // The in-memory displayed set is filtered down to the critical
        // finding, and total_vulnerabilities is recomputed to match.
        assert_eq!(hidden, 2, "medium + low severity findings hidden by the filter");
        assert_eq!(scan2.findings.len(), 1, "displayed set is filtered to critical only");
        assert_eq!(scan2.findings[0].vulnerability.cve_id, "CVE-2024-0001");
        assert_eq!(
            scan2.total_vulnerabilities, 1,
            "total_vulnerabilities must match the filtered, displayed set"
        );

        // The persisted history is untouched by the display-only filter:
        // query it directly (not via `scan2.findings`, which was just
        // mutated by the filter) and confirm all three rows are still
        // there, still Persisting. This is the actual bug this task fixes —
        // if persist_then_present filtered before reconciling and
        // persisting, the medium/low findings would be absent from the
        // "current" set and would be marked Resolved here instead.
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut stmt = conn
            .prepare("SELECT cve_id, status FROM scan_findings WHERE hostname = ?1 ORDER BY cve_id")
            .unwrap();
        let rows: Vec<(String, String)> = stmt
            .query_map(params![hostname], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(stmt);
        drop(conn);

        assert_eq!(
            rows.len(),
            3,
            "the medium/low findings hidden by the display filter must still be in history: {:?}",
            rows
        );
        assert!(
            rows.iter().all(|(_, status)| status == "Persisting"),
            "no finding may be marked Resolved just because a display filter would hide it: {:?}",
            rows
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression guard for the *other* half of FR-59/FR-60's ordering
    /// requirement: `reconcile()` must run against the previous inventory
    /// snapshot before that snapshot is overwritten, because "was this
    /// software already known" is precisely what distinguishes `New` from
    /// `NewlyApplicable` — see `reconcile.rs`'s own doc comment. Reversed,
    /// the write happens first and the read that follows sees only the
    /// scan's own just-written data.
    ///
    /// Scan 1 establishes Alpha and Beta in the inventory. Scan 2 keeps
    /// their original findings (still `Persisting`) and adds two new ones:
    /// a new CVE against Alpha (already-known software — must come back
    /// `NewlyApplicable`) and a new CVE against Delta, software that has
    /// never appeared before (must come back `New`). Verified by mutation
    /// in the fix-round report: moving the inventory write to run before
    /// the previous snapshot is read turns the Delta assertion red.
    #[test]
    fn reconcile_runs_before_inventory_replace_new_vs_newly_applicable() {
        let dir = std::env::temp_dir().join("evedoo_reconcile_before_replace_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.db");
        let path_str = path.to_str().unwrap();

        let hostname = "test-host".to_string();

        // Scan 1: establishes Alpha and Beta, both in history and in the
        // inventory snapshot.
        let mut scan1 = ScanResult::new(hostname.clone());
        scan1.findings = vec![
            finding("CVE-2024-0001", "Alpha", Severity::Critical),
            finding("CVE-2024-0002", "Beta", Severity::Medium),
        ];
        crate::persist_then_present(&mut scan1, Some(path_str), MatchConfidence::Low, None, None, false);

        // Scan 2: the two original findings persist unchanged, plus two new
        // ones — a new CVE against already-known Alpha, and a new CVE
        // against Delta, software never seen before.
        let mut scan2 = ScanResult::new(hostname.clone());
        scan2.findings = vec![
            finding("CVE-2024-0001", "Alpha", Severity::Critical),
            finding("CVE-2024-0002", "Beta", Severity::Medium),
            finding("CVE-2024-0099", "Alpha", Severity::High),
            finding("CVE-2024-0100", "Delta", Severity::High),
        ];
        crate::persist_then_present(&mut scan2, Some(path_str), MatchConfidence::Low, None, None, false);

        let known_software_new_cve = scan2
            .findings
            .iter()
            .find(|f| f.vulnerability.cve_id == "CVE-2024-0099")
            .expect("CVE-2024-0099 must survive to the displayed set");
        assert_eq!(
            known_software_new_cve.status,
            FindingStatus::NewlyApplicable,
            "a new CVE against software already in the previous inventory must be NewlyApplicable, not New"
        );

        let new_software_new_cve = scan2
            .findings
            .iter()
            .find(|f| f.vulnerability.cve_id == "CVE-2024-0100")
            .expect("CVE-2024-0100 must survive to the displayed set");
        assert_eq!(
            new_software_new_cve.status,
            FindingStatus::New,
            "a CVE against software absent from the previous inventory must be New, not NewlyApplicable"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

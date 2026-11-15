//! Cross-asset remediation aggregation (FR-83..FR-88).
//!
//! Answers "which single upgrade removes the most risk from my fleet" by
//! grouping stored findings across every scanned host. Risk is derived at
//! report time from the current CVE database and never persisted (FR-84) —
//! a ranking frozen at scan time would disagree with `reassess` about the
//! same finding, and would be the wrong one.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::Serialize;

/// One stored finding, scored against the current CVE database.
#[derive(Debug, Clone, Serialize)]
pub struct ScoredFinding {
    pub hostname: String,
    pub cve_id: String,
    pub software_name: String,
    pub software_version: Option<String>,
    pub risk_score: f32,
    pub in_kev: bool,
    pub fixed_version: Option<String>,
    pub upgrade_command: Option<String>,
}

/// One upgrade action, aggregated across every affected asset.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationRollup {
    pub software_name: String,
    pub affected_assets: usize,
    pub affected_hostnames: Vec<String>,
    pub cve_count: usize,
    pub total_risk_removed: f32,
    pub max_risk_score: f32,
    pub kev_count: usize,
    pub versions_seen: Vec<String>,
    pub fixed_version: Option<String>,
    pub upgrade_command: Option<String>,
}

/// Working state while folding findings into one group.
struct Acc {
    display_name: String,
    hosts: BTreeSet<String>,
    cves: HashSet<String>,
    kev_cves: HashSet<String>,
    versions: BTreeSet<String>,
    total_risk: f32,
    max_risk: f32,
    fixed_version: Option<String>,
    upgrade_command: Option<String>,
}

/// One row of `scan_findings`, before scoring.
#[derive(Debug, Clone)]
pub struct StoredFinding {
    pub hostname: String,
    pub cve_id: String,
    pub software_name: String,
    pub software_version: Option<String>,
    /// When this finding was last confirmed present. A rollup is only as
    /// current as its stalest host, and the report must be able to say so.
    pub last_seen: String,
}

/// Read live findings across every host (FR-85).
///
/// `Resolved` and `NoLongerApplicable` are filtered in SQL rather than in
/// Rust so the exclusion cannot be forgotten by a later caller. The strings
/// are exactly what `FindingStatus::to_string()` writes.
///
/// `hosts`, when given, restricts the read — used by `--tag` (FR-88).
pub fn load_stored(
    conn: &rusqlite::Connection,
    hosts: Option<&HashSet<String>>,
) -> crate::error::Result<Vec<StoredFinding>> {
    let mut stmt = conn.prepare(
        "SELECT hostname, cve_id, software_name, software_version, last_seen
           FROM scan_findings
          WHERE status NOT IN ('Resolved', 'NoLongerApplicable')",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(StoredFinding {
            hostname: row.get(0)?,
            cve_id: row.get(1)?,
            software_name: row.get(2)?,
            software_version: row.get(3)?,
            last_seen: row.get(4)?,
        })
    })?;

    let mut out = Vec::new();
    for r in rows {
        let f = r?;
        // Filtered here rather than with a generated IN clause: the host set
        // comes from the fleet table and could be large, and building SQL by
        // interpolation is exactly what the project's SQL rule forbids.
        if let Some(allowed) = hosts {
            if !allowed.contains(&f.hostname) {
                continue;
            }
        }
        out.push(f);
    }
    Ok(out)
}

/// The result of scoring: what could be scored, and how much could not.
pub struct ScoreOutcome {
    pub scored: Vec<ScoredFinding>,
    /// FR-87. Findings whose CVE is absent from the current database.
    /// Counted and reported, never scored as zero and never dropped in
    /// silence: understating a rollup is the failure this project has twice
    /// spent a phase eliminating.
    pub excluded: usize,
}

/// Score every stored finding against the CURRENT CVE database (FR-84, FR-86).
///
/// `tags` maps hostname to that host's fleet tags, so criticality is resolved
/// per host — a finding on a `prod` asset must contribute more than the same
/// finding on a `lab` one, which is the entire point of fleet tags.
///
/// Per-CVE lookups are memoised, including the `None` case: a CVE affecting
/// forty hosts costs one query, and a CVE missing from the database is not
/// re-queried once per host.
pub fn score_all(
    stored: &[StoredFinding],
    matcher: &crate::matcher::CveMatcher,
    tags: &HashMap<String, String>,
) -> ScoreOutcome {
    let mut cve_cache: HashMap<String, Option<crate::models::Vulnerability>> = HashMap::new();
    let mut exploit_cache: HashMap<String, bool> = HashMap::new();
    let mut scored = Vec::new();
    let mut excluded = 0usize;

    for f in stored {
        let vuln = cve_cache
            .entry(f.cve_id.clone())
            .or_insert_with(|| matcher.get_cve_details(&f.cve_id, None).ok().flatten());

        let Some(v) = vuln.as_ref() else {
            excluded += 1;
            continue;
        };

        let exploit = *exploit_cache
            .entry(f.cve_id.clone())
            .or_insert_with(|| matcher.has_exploit_reference(&f.cve_id).unwrap_or(false));

        let criticality = tags
            .get(&f.hostname)
            .map(|t| crate::risk::criticality_for(t))
            .unwrap_or(1.0);

        // Reachability is structurally Unknown: FR-82 forbids persisting it,
        // so a stored finding cannot carry it. Its factor is exactly 1.0
        // (FR-78), so this neither inflates nor deflates the rollup.
        let assessment = crate::risk::assess(
            v,
            exploit,
            criticality,
            crate::reachability::Reachability::Unknown,
        );

        scored.push(ScoredFinding {
            hostname: f.hostname.clone(),
            cve_id: f.cve_id.clone(),
            software_name: f.software_name.clone(),
            software_version: f.software_version.clone(),
            risk_score: assessment.score,
            in_kev: v.in_kev,
            fixed_version: v.remediation.fixed_version.clone(),
            upgrade_command: v.remediation.upgrade_command.clone(),
        });
    }

    ScoreOutcome { scored, excluded }
}

/// Group scored findings into ranked remediation actions (FR-85, FR-86).
///
/// Grouping is by lowercased software name, NOT by (name, version): different
/// hosts run different vulnerable versions of the same product, and one
/// upgrade fixes all of them. Splitting by version would report "47 assets
/// need Chrome" as a dozen separate actions.
pub fn rollup(findings: &[ScoredFinding]) -> Vec<RemediationRollup> {
    let mut groups: HashMap<String, Acc> = HashMap::new();

    for f in findings {
        let key = f.software_name.to_lowercase();
        let acc = groups.entry(key).or_insert_with(|| Acc {
            display_name: f.software_name.clone(),
            hosts: BTreeSet::new(),
            cves: HashSet::new(),
            kev_cves: HashSet::new(),
            versions: BTreeSet::new(),
            total_risk: 0.0,
            max_risk: 0.0,
            fixed_version: None,
            upgrade_command: None,
        });

        acc.hosts.insert(f.hostname.clone());
        acc.cves.insert(f.cve_id.clone());
        if f.in_kev {
            acc.kev_cves.insert(f.cve_id.clone());
        }
        if let Some(v) = &f.software_version {
            acc.versions.insert(v.clone());
        }

        // Summed, not maxed: every finding this upgrade resolves is risk it
        // removes, so a product on many hosts accumulates across all of them.
        acc.total_risk += f.risk_score;
        if f.risk_score > acc.max_risk {
            acc.max_risk = f.risk_score;
        }

        if acc.fixed_version.is_none() {
            acc.fixed_version = f.fixed_version.clone();
        }
        if acc.upgrade_command.is_none() {
            acc.upgrade_command = f.upgrade_command.clone();
        }
    }

    let mut out: Vec<RemediationRollup> = groups
        .into_values()
        .map(|a| RemediationRollup {
            software_name: a.display_name,
            affected_assets: a.hosts.len(),
            affected_hostnames: a.hosts.into_iter().collect(),
            cve_count: a.cves.len(),
            total_risk_removed: a.total_risk,
            max_risk_score: a.max_risk,
            kev_count: a.kev_cves.len(),
            versions_seen: a.versions.into_iter().collect(),
            fixed_version: a.fixed_version,
            upgrade_command: a.upgrade_command,
        })
        .collect();

    // Descending by risk removed; software name breaks ties so the output is
    // deterministic across runs (HashMap iteration order is not).
    out.sort_by(|x, y| {
        y.total_risk_removed
            .partial_cmp(&x.total_risk_removed)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| x.software_name.cmp(&y.software_name))
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sf(host: &str, cve: &str, name: &str, ver: &str, score: f32) -> ScoredFinding {
        ScoredFinding {
            hostname: host.into(),
            cve_id: cve.into(),
            software_name: name.into(),
            software_version: Some(ver.into()),
            risk_score: score,
            in_kev: false,
            fixed_version: Some("999.0".into()),
            upgrade_command: Some("winget upgrade X".into()),
        }
    }

    /// FR-85. One upgrade action fixes every vulnerable version across the
    /// fleet, so three hosts running three different Chrome versions are ONE
    /// remediation, not three. Grouping by (name, version) would split them.
    #[test]
    fn groups_across_hosts_and_versions_by_name() {
        let f = vec![
            sf("host-a", "CVE-1", "Google Chrome", "120.0", 10.0),
            sf("host-b", "CVE-1", "Google Chrome", "121.0", 10.0),
            sf("host-c", "CVE-2", "Google Chrome", "119.0", 10.0),
        ];
        let r = rollup(&f);

        assert_eq!(r.len(), 1, "one product is one remediation action");
        assert_eq!(r[0].software_name, "Google Chrome");
        assert_eq!(r[0].affected_assets, 3);
        assert_eq!(r[0].cve_count, 2, "CVE-1 appears on two hosts but is one CVE");
        assert_eq!(r[0].versions_seen.len(), 3);
    }

    /// Name matching is case-insensitive: the same product recorded with
    /// different capitalisation on two hosts is still one action.
    #[test]
    fn grouping_is_case_insensitive() {
        let f = vec![
            sf("host-a", "CVE-1", "Google Chrome", "120.0", 5.0),
            sf("host-b", "CVE-1", "google chrome", "120.0", 5.0),
        ];
        assert_eq!(rollup(&f).len(), 1);
    }

    /// FR-86, and the reason this view exists separately from the per-asset
    /// Top Solutions tab. Breadth must be able to outrank depth: fifty
    /// moderate findings across fifty hosts is a bigger fleet problem than
    /// one critical finding on one host. Ranking by CVE count or by max
    /// score would invert this.
    #[test]
    fn ranks_by_summed_risk_so_breadth_can_beat_depth() {
        let mut f = vec![sf("host-x", "CVE-BIG", "Deep", "1.0", 90.0)];
        for i in 0..10 {
            f.push(sf(&format!("host-{i}"), "CVE-W", "Wide", "1.0", 20.0));
        }
        let r = rollup(&f);

        assert_eq!(r[0].software_name, "Wide", "200.0 summed must outrank 90.0");
        assert!((r[0].total_risk_removed - 200.0).abs() < 0.01);
        assert_eq!(r[1].software_name, "Deep");
        assert!((r[1].max_risk_score - 90.0).abs() < 0.01);
    }

    /// A host appearing twice for the same product must be counted once.
    #[test]
    fn affected_assets_counts_distinct_hosts() {
        let f = vec![
            sf("host-a", "CVE-1", "App", "1.0", 5.0),
            sf("host-a", "CVE-2", "App", "1.0", 5.0),
            sf("host-b", "CVE-1", "App", "1.0", 5.0),
        ];
        let r = rollup(&f);
        assert_eq!(r[0].affected_assets, 2);
        assert_eq!(r[0].cve_count, 2);
        assert!((r[0].total_risk_removed - 15.0).abs() < 0.01);
    }

    #[test]
    fn kev_count_counts_distinct_kev_cves_not_rows() {
        let mut a = sf("host-a", "CVE-K", "App", "1.0", 5.0);
        a.in_kev = true;
        let mut b = sf("host-b", "CVE-K", "App", "1.0", 5.0);
        b.in_kev = true;
        let c = sf("host-c", "CVE-N", "App", "1.0", 5.0);

        let r = rollup(&[a, b, c]);
        assert_eq!(r[0].kev_count, 1, "one KEV CVE on two hosts is one KEV CVE");
    }

    #[test]
    fn empty_input_produces_no_rollups() {
        assert!(rollup(&[]).is_empty());
    }

    use rusqlite::Connection;

    /// Synthetic multi-host fixture. This machine has one scanned host, so a
    /// synthetic fleet is the only way to exercise cross-asset behaviour at
    /// all. Rows are written exactly as `history::persist_findings` writes
    /// them, including `status` as `FindingStatus::to_string()`.
    fn fixture_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scan_findings (
                 id               INTEGER PRIMARY KEY AUTOINCREMENT,
                 hostname         TEXT    NOT NULL,
                 cve_id           TEXT    NOT NULL,
                 software_name    TEXT    NOT NULL,
                 software_version TEXT,
                 first_seen       TEXT    NOT NULL,
                 last_seen        TEXT    NOT NULL,
                 status           TEXT    NOT NULL DEFAULT 'New',
                 UNIQUE(hostname, cve_id, software_name)
             );",
        )
        .unwrap();

        let rows = [
            ("host-a", "CVE-1", "Google Chrome", "120.0", "Persisting"),
            ("host-b", "CVE-1", "Google Chrome", "121.0", "New"),
            ("host-c", "CVE-2", "Google Chrome", "119.0", "Persisting"),
            ("host-a", "CVE-3", "OldApp", "1.0", "Resolved"),
            ("host-b", "CVE-4", "GoneApp", "2.0", "NoLongerApplicable"),
        ];
        for (h, c, n, v, s) in rows {
            conn.execute(
                "INSERT INTO scan_findings
                   (hostname, cve_id, software_name, software_version,
                    first_seen, last_seen, status)
                 VALUES (?1, ?2, ?3, ?4, '2026-01-01', '2026-01-01', ?5)",
                rusqlite::params![h, c, n, v, s],
            )
            .unwrap();
        }
        conn
    }

    /// FR-85. A resolved finding needs no remediation; including it would
    /// inflate every rollup with work already done.
    #[test]
    fn load_stored_excludes_resolved_and_no_longer_applicable() {
        let conn = fixture_db();
        let rows = load_stored(&conn, None).unwrap();

        assert_eq!(rows.len(), 3, "the two closed-out rows must not load");
        assert!(
            rows.iter().all(|r| r.software_name == "Google Chrome"),
            "only the live Chrome findings should survive the filter"
        );
    }

    /// FR-88. A host filter restricts the read to the named hosts.
    #[test]
    fn load_stored_honours_a_host_filter() {
        let conn = fixture_db();
        let only: std::collections::HashSet<String> =
            ["host-a".to_string()].into_iter().collect();
        let rows = load_stored(&conn, Some(&only)).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hostname, "host-a");
    }

    #[test]
    fn load_stored_on_empty_table_returns_nothing() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scan_findings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL,
                 cve_id TEXT NOT NULL, software_name TEXT NOT NULL,
                 software_version TEXT, first_seen TEXT NOT NULL,
                 last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New');",
        )
        .unwrap();
        assert!(load_stored(&conn, None).unwrap().is_empty());
    }
}

# Cross-Asset Remediation Aggregation Implementation Plan

> **Status: SHIPPED (Historical Plan).** All 23 steps executed and ticked
> (`P21-N7`, closed 2026-08-28). Implemented in `evedoo/src/aggregate.rs` and
> the `evedoo fleet report` subcommand. Live state is tracked in
> `docs/agent-state/tasks.jsonl`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Answer "which single upgrade removes the most risk from my fleet" by grouping stored findings across every scanned host and ranking them by summed risk.

**Architecture:** One new module, `evedoo/src/aggregate.rs`, split into three layers that are testable independently: a pure `rollup()` over already-scored findings, a `load_stored()` + `score_all()` pair that reads `scan_findings` and scores each row against the current CVE database, and a `fleet report` subcommand that renders the result. Risk is derived at report time and never persisted.

**Tech Stack:** Rust 2021, `rusqlite` 0.32 (parameterised queries only), `clap` 4.5 derive, existing `risk::assess` and `FleetManager`. **No new dependencies.**

**Spec:** `docs/superpowers/specs/2026-08-28-cross-asset-remediation-design.md`

> **Status: Completed.** All three tasks implemented, verified, and pushed
> (`725450d`..`9bb7c42`). Verified end to end against the real
> `scan_history.db`. One open concern recorded on the task in
> `docs/agent-state/tasks.jsonl`: display-name aliasing double-counts risk
> (Microsoft Edge and Microsoft Edge Update appear as separate rows with
> identical 221 CVEs / 2509.4 risk).

## Global Constraints

- **Risk is never persisted.** Nothing in this feature writes to `scan_findings` or any other table. It is a read-only view. (FR-84)
- **Parameterised SQL only** — never string concatenation for queries.
- **Unscoreable findings are excluded AND counted**, never scored as zero and never dropped silently. (FR-87)
- **Criticality is resolved per host** from that host's fleet tags, not once for the rollup. (FR-86)
- **Reachability is always `Reachability::Unknown`** — FR-82 forbids persisting it, so a stored finding cannot carry it. Its factor is exactly 1.0 (FR-78), so it neither inflates nor deflates a rollup.
- Status is stored via `FindingStatus::to_string()`, so the excluded values are the exact strings `"Resolved"` and `"NoLongerApplicable"`.
- MSRV Rust 1.83, edition 2021.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass — CI gate.
- Tests live in `#[cfg(test)] mod tests` blocks inside each source file.

---

### Task 1: The rollup — pure grouping and ranking

All the logic that can be wrong, with no database and no CVE lookups.

**Files:**
- Create: `evedoo/src/aggregate.rs`
- Modify: `evedoo/src/main.rs` (add `mod aggregate;` alphabetically, before `mod correlate;`)

**Interfaces:**
- Produces:
  - `pub struct ScoredFinding { pub hostname: String, pub cve_id: String, pub software_name: String, pub software_version: Option<String>, pub risk_score: f32, pub in_kev: bool, pub fixed_version: Option<String>, pub upgrade_command: Option<String> }`
  - `pub struct RemediationRollup { pub software_name: String, pub affected_assets: usize, pub affected_hostnames: Vec<String>, pub cve_count: usize, pub total_risk_removed: f32, pub max_risk_score: f32, pub kev_count: usize, pub versions_seen: Vec<String>, pub fixed_version: Option<String>, pub upgrade_command: Option<String> }` — both `Debug, Clone, Serialize`
  - `pub fn rollup(findings: &[ScoredFinding]) -> Vec<RemediationRollup>`

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/aggregate.rs` containing only the module doc comment and this test block, so the tests fail to compile against absent items:

```rust
//! Cross-asset remediation aggregation (FR-83..FR-88).
//!
//! Answers "which single upgrade removes the most risk from my fleet" by
//! grouping stored findings across every scanned host. Risk is derived at
//! report time from the current CVE database and never persisted (FR-84) —
//! a ranking frozen at scan time would disagree with `reassess` about the
//! same finding, and would be the wrong one.
//!
//! SPDX-License-Identifier: Apache-2.0

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
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p evedoo aggregate`
Expected: FAIL to compile — `cannot find type ScoredFinding`, `cannot find function rollup`.

- [x] **Step 3: Write the implementation**

Insert above the `#[cfg(test)]` block:

```rust
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
```

Add to `evedoo/src/main.rs`, keeping the module list alphabetical:

```rust
mod aggregate;
```

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p evedoo aggregate`
Expected: PASS, 6 tests.

- [x] **Step 5: Mutation-verify the two rules that define this view**

Change the group key from `f.software_name.to_lowercase()` to
`format!("{}|{:?}", f.software_name.to_lowercase(), f.software_version)`.
Run: `cargo test -p evedoo aggregate`
Expected: `groups_across_hosts_and_versions_by_name` FAILS (3 rollups, not 1). Revert.

Change the sort key from `total_risk_removed` to `cve_count`.
Run: `cargo test -p evedoo aggregate`
Expected: `ranks_by_summed_risk_so_breadth_can_beat_depth` FAILS. Revert.

Re-run and confirm PASS after both reverts.

- [x] **Step 6: Commit**

```bash
git add evedoo/src/aggregate.rs evedoo/src/main.rs
git commit -m "P21-N7 Task 1: cross-asset rollup grouping and ranking (FR-85, FR-86)"
```

---

### Task 2: Reading and scoring stored findings

**Files:**
- Modify: `evedoo/src/aggregate.rs`
- Modify: `evedoo/src/matcher/cpe.rs` (`get_cve_details` visibility)

**Interfaces:**
- Consumes: `ScoredFinding` from Task 1; `CpeIndex::get_cve_details(&self, cve_id: &str, fixed_version: Option<&str>) -> Result<Option<Vulnerability>>`; `CpeIndex::has_exploit_reference(&self, cve_id: &str) -> Result<bool>`; `FleetManager::tags_for(&self, hostname: &str) -> Result<Option<String>>`; `risk::assess`, `risk::criticality_for`
- Produces:
  - `pub struct StoredFinding { pub hostname: String, pub cve_id: String, pub software_name: String, pub software_version: Option<String> }`
  - `pub struct ScoreOutcome { pub scored: Vec<ScoredFinding>, pub excluded: usize }`
  - `pub fn load_stored(conn: &rusqlite::Connection, hosts: Option<&std::collections::HashSet<String>>) -> crate::error::Result<Vec<StoredFinding>>`
  - `pub fn score_all(stored: &[StoredFinding], index: &crate::matcher::cpe::CpeIndex, tags: &HashMap<String, String>) -> ScoreOutcome`

- [x] **Step 1: Write the failing tests**

Append to the `mod tests` block in `evedoo/src/aggregate.rs`:

```rust
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
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p evedoo aggregate`
Expected: FAIL to compile — `cannot find function load_stored`.

- [x] **Step 3: Implement `load_stored`**

Add to `evedoo/src/aggregate.rs`:

```rust
/// One row of `scan_findings`, before scoring.
#[derive(Debug, Clone)]
pub struct StoredFinding {
    pub hostname: String,
    pub cve_id: String,
    pub software_name: String,
    pub software_version: Option<String>,
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
    hosts: Option<&std::collections::HashSet<String>>,
) -> crate::error::Result<Vec<StoredFinding>> {
    let mut stmt = conn.prepare(
        "SELECT hostname, cve_id, software_name, software_version
           FROM scan_findings
          WHERE status NOT IN ('Resolved', 'NoLongerApplicable')",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(StoredFinding {
            hostname: row.get(0)?,
            cve_id: row.get(1)?,
            software_name: row.get(2)?,
            software_version: row.get(3)?,
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
```

- [x] **Step 4: Run the load tests**

Run: `cargo test -p evedoo aggregate`
Expected: PASS, 9 tests.

- [x] **Step 5: Make `get_cve_details` reachable**

In `evedoo/src/matcher/cpe.rs`, change:

```rust
    fn get_cve_details(
```

to:

```rust
    pub(crate) fn get_cve_details(
```

This is a visibility change only — the function already returns a complete
`Vulnerability` with CVSS, EPSS, and KEV in one query.

- [x] **Step 6: Implement `score_all`**

Add to `evedoo/src/aggregate.rs`:

```rust
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
    index: &crate::matcher::cpe::CpeIndex,
    tags: &HashMap<String, String>,
) -> ScoreOutcome {
    let mut cve_cache: HashMap<String, Option<crate::models::Vulnerability>> = HashMap::new();
    let mut exploit_cache: HashMap<String, bool> = HashMap::new();
    let mut scored = Vec::new();
    let mut excluded = 0usize;

    for f in stored {
        let vuln = cve_cache
            .entry(f.cve_id.clone())
            .or_insert_with(|| index.get_cve_details(&f.cve_id, None).ok().flatten());

        let Some(v) = vuln.as_ref() else {
            excluded += 1;
            continue;
        };

        let exploit = *exploit_cache
            .entry(f.cve_id.clone())
            .or_insert_with(|| index.has_exploit_reference(&f.cve_id).unwrap_or(false));

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
```

- [x] **Step 7: Run tests and the full gate**

Run: `cargo test --workspace`
Expected: all pass.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [x] **Step 8: Mutation-verify the exclusion filter**

Change the `WHERE` clause to `WHERE status NOT IN ('Resolved')`.
Run: `cargo test -p evedoo aggregate`
Expected: `load_stored_excludes_resolved_and_no_longer_applicable` FAILS with 4 rows, not 3. Revert and confirm PASS.

- [x] **Step 9: Commit**

```bash
git add evedoo/src/aggregate.rs evedoo/src/matcher/cpe.rs
git commit -m "P21-N7 Task 2: read and score stored findings at report time (FR-84, FR-87)"
```

---

### Task 3: The `fleet report` subcommand

**Files:**
- Modify: `evedoo/src/main.rs`

**Interfaces:**
- Consumes: `aggregate::{load_stored, score_all, rollup}`; `FleetManager::list_assets`

- [x] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `evedoo/src/main.rs`:

```rust
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
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p evedoo fleet_report_header`
Expected: FAIL to compile — `cannot find function fleet_report_header`.

- [x] **Step 3: Implement the header**

Add to `evedoo/src/main.rs`:

```rust
/// FR-87. Say what was not measured, following the reachability coverage
/// line's precedent.
fn fleet_report_header(assets: usize, excluded: usize) -> String {
    if excluded == 0 {
        format!("  {assets} assets covered")
    } else {
        format!(
            "  {assets} assets covered — {excluded} findings excluded: CVE not present in the database"
        )
    }
}
```

- [x] **Step 4: Add the subcommand**

Add to `enum FleetCommands` in `evedoo/src/main.rs`:

```rust
    /// Rank upgrades by how much risk each removes across the whole fleet
    Report {
        /// CVE database (risk is derived at report time, never stored)
        #[arg(short = 'd', long, default_value = "vulndb.sqlite")]
        database: PathBuf,

        /// Fleet/history database
        #[arg(long, default_value = "scan_history.db")]
        db: String,

        /// Only include assets carrying this fleet tag
        #[arg(long)]
        tag: Option<String>,

        /// Maximum rows to display
        #[arg(long, default_value_t = 20)]
        limit: usize,

        /// Emit JSON (DC-7)
        #[arg(long)]
        json: bool,
    },
```

- [x] **Step 5: Implement the handler**

Add this arm to `run_fleet_command`:

```rust
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

            let fleet = fleet::FleetManager::open(&db)?;

            // FR-88: with a tag filter, only registered assets carrying it are
            // eligible. Without one, every scanned host counts — an
            // unregistered host was still scanned, so it is still real.
            let host_filter: Option<std::collections::HashSet<String>> = match &tag {
                Some(t) => Some(
                    fleet
                        .list_assets(Some(t))?
                        .into_iter()
                        .map(|a| a.hostname)
                        .collect(),
                ),
                None => None,
            };

            let mut tags: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for a in fleet.list_assets(None)? {
                tags.insert(a.hostname.clone(), a.tags.clone());
            }

            let conn = rusqlite::Connection::open(&db)?;
            let stored = aggregate::load_stored(&conn, host_filter.as_ref())?;

            let index = matcher::cpe::CpeIndex::load(database.to_str().unwrap_or_default())?;
            let outcome = aggregate::score_all(&stored, &index, &tags);
            let rollups = aggregate::rollup(&outcome.scored);

            let assets: std::collections::HashSet<&String> =
                outcome.scored.iter().map(|f| &f.hostname).collect();

            if json {
                let payload = serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "assets_covered": assets.len(),
                    "findings_excluded": outcome.excluded,
                    "remediations": rollups.iter().take(limit).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
                return Ok(());
            }

            println!();
            println!("{}", "Fleet Remediation Report".bright_blue().bold());
            println!("{}", fleet_report_header(assets.len(), outcome.excluded));
            println!();

            if rollups.is_empty() {
                println!("  No outstanding findings across the selected assets.");
                return Ok(());
            }

            for (i, r) in rollups.iter().take(limit).enumerate() {
                let kev = if r.kev_count > 0 {
                    format!(" [{} KEV]", r.kev_count).bright_red().to_string()
                } else {
                    String::new()
                };
                println!(
                    "  {}. {} — {} assets, {} CVEs, risk removed {:.1}{}",
                    i + 1,
                    r.software_name.bright_white(),
                    r.affected_assets,
                    r.cve_count,
                    r.total_risk_removed,
                    kev
                );
                if let Some(cmd) = &r.upgrade_command {
                    println!("     {}", cmd.bright_black());
                }
            }
            println!();
        }
```

- [x] **Step 6: Run tests and the full gate**

Run: `cargo test --workspace`
Expected: all pass.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [x] **Step 7: Verify on real data**

```bash
cargo build --release -p evedoo
target/release/evedoo.exe fleet report -d vulndb.sqlite --db evedoo/scan_history.db
```

Expected: a ranked list for a fleet of one. Confirm the assets-covered count is
1, that the ranking is descending by risk removed, and that if any exclusions
occur the count is stated. A fleet of one is a thin test, which is why Tasks 1
and 2 carry the synthetic multi-host fixture — but this proves the command runs
end to end against a genuine database.

- [x] **Step 8: Commit**

```bash
git add evedoo/src/main.rs
git commit -m "P21-N7 Task 3: fleet report subcommand with tag filter and JSON (FR-83, FR-88, DC-7)"
```

---

## Self-Review

**Spec coverage:**

| Requirement | Task |
|---|---|
| FR-83 fleet-wide rollup ranked by aggregate risk | 1, 3 |
| FR-84 risk derived at report time, never persisted | 2 (nothing writes) |
| FR-85 group by name, exclude Resolved/NoLongerApplicable | 1, 2 (both mutation-verified) |
| FR-86 rank by summed risk, criticality per host | 1 (mutation-verified), 2 |
| FR-87 unscoreable findings excluded and disclosed | 2, 3 |
| FR-88 tag filter, unregistered hosts only when unfiltered | 2, 3 |
| DC-7 JSON shape | 3 |

**Type consistency:** `ScoredFinding`, `RemediationRollup`, `StoredFinding`, `ScoreOutcome`, `rollup`, `load_stored`, `score_all`, `fleet_report_header` are each defined once and referenced with the same name and arity throughout.

**Known gap, stated rather than hidden:** this machine has one scanned host, so Task 3's real-data run exercises a fleet of one. The cross-asset behaviour that matters is covered only by the synthetic fixture in Tasks 1 and 2. That is a real limit on the evidence, not a formality.

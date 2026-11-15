# Operationalisation (N1 + N2 + N4) Implementation Plan

> **Status: Completed (Historical Plan)**
> All 51 steps in this plan have been executed, verified, and retroactively marked complete (`- [x]`). This document is preserved as a historical plan and architecture reference. Live agent state, active tasks, and next steps are maintained in `docs/agent-state/tasks.jsonl` (and rendered in `docs/agent-state/CURRENT.md`).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist scan inventory so findings can be re-correlated without touching the host, score every finding for triage, and let analysts accept risk with an expiring, auditable exception.

**Architecture:** One module takes ownership of the `scan_history.db` schema and versions it via `PRAGMA user_version`. The correlation loop — today duplicated between local and remote scan — is extracted into a single `correlate()` stage that runs **unfiltered**; severity and confidence become presentation concerns. Risk scoring, exception matching, and status reconciliation are annotation stages layered after correlation, so all three entry points (scan, remote-scan, reassess) get them identically and cannot diverge.

**Tech Stack:** Rust 1.83+, `rusqlite` 0.32 (bundled), `clap` 4.6 derive, `chrono` 0.4, `tracing`. **No new dependencies.**

**Spec:** `spec.md` section 6 (FR-57..FR-72), plus NFR-8, DC-3, DC-5.

## Global Constraints

- **Licensing (NFR-1):** Apache 2.0 only; Rust exclusively; no new dependencies in this plan.
- **Platform (NFR-2):** `evedoo` is Windows-only (`winreg` has `compile_error!` elsewhere); MSRV Rust 1.83+.
- **Quality gate (NFR-6):** `cargo clippy --workspace --all-targets -- -D warnings` and the full suite pass on every commit. Suite is **230 tests** at plan start.
- **SQL:** parameterized queries only. Never concatenate user input into SQL.
- **Build output** is `target/release/`, **not** `./target/`. Never commit `.cargo/`.
- **Kill running `evedoo.exe` before building** — a live `--serve` locks the binary, the build fails with "Access is denied (os error 5)", and the old binary is silently kept.
- **DC-3:** new `Finding` fields must be `#[serde(default)]` and additive, with `evedoo-gui/src/models.rs` updated in the same commit.
- **Never rebuild `scan_history.db`** to change its shape (NFR-8) — it holds the delta history and exception audit trail.

---

## File Structure

**Create:**

| File | Responsibility |
|---|---|
| `evedoo/src/schema.rs` | Sole owner of `scan_history.db` structure + migrations (NFR-8) |
| `evedoo/src/inventory.rs` | Read/write the per-host inventory snapshot (FR-57) |
| `evedoo/src/correlate.rs` | The single unfiltered correlation pass (FR-61, FR-62) |
| `evedoo/src/reconcile.rs` | Assigns `FindingStatus`; mode-aware (FR-59, FR-60) |
| `evedoo/src/risk.rs` | Risk score + priority tier (FR-63..FR-66) |
| `evedoo/src/exceptions.rs` | Exception store, wildcard matching, expiry (FR-68..FR-72) |

**Modify:** `models.rs`, `history.rs`, `fleet.rs`, `matcher/cpe.rs`, `main.rs`, `report/csv.rs`, `report/text.rs`, `evedoo-gui/src/models.rs`.

**Task order is dependency order.** Tasks 1–3 are foundation; 4–7 are pipeline stages; 8–9 are user surface.

---

### Task 1: Schema module and migrations

**Files:**
- Create: `evedoo/src/schema.rs`
- Modify: `evedoo/src/main.rs` (add `mod schema;`)

**Interfaces:**
- Consumes: nothing.
- Produces: `schema::open(path: &str) -> rusqlite::Result<Connection>`; `schema::migrate(&Connection) -> rusqlite::Result<()>`; `schema::CURRENT_VERSION: i64` (= 3).

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/schema.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn tables(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.flatten().collect()
    }

    fn version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn fresh_database_migrates_to_current() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        assert_eq!(version(&conn), CURRENT_VERSION);
        let t = tables(&conn);
        for expected in ["exceptions", "fleet_assets", "scan_findings", "scan_inventory"] {
            assert!(t.contains(&expected.to_string()), "missing {expected} in {t:?}");
        }
    }

    #[test]
    fn legacy_database_is_adopted_not_rebuilt() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scan_findings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL,
                 cve_id TEXT NOT NULL, software_name TEXT NOT NULL,
                 software_version TEXT, first_seen TEXT NOT NULL,
                 last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New',
                 UNIQUE(hostname, cve_id, software_name));
             INSERT INTO scan_findings
                 (hostname, cve_id, software_name, first_seen, last_seen)
             VALUES ('HOST','CVE-2024-0001','App','2026-01-01','2026-01-01');",
        )
        .unwrap();
        assert_eq!(version(&conn), 0);

        migrate(&conn).unwrap();

        assert_eq!(version(&conn), CURRENT_VERSION);
        let surviving: i64 = conn
            .query_row("SELECT COUNT(*) FROM scan_findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(surviving, 1, "existing rows must survive migration");
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        assert_eq!(version(&conn), CURRENT_VERSION);
    }

    #[test]
    fn inventory_identity_is_unique_per_host() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let ins = "INSERT INTO scan_inventory
            (hostname, registry_key, name, architecture, scan_time)
            VALUES (?1, ?2, ?3, ?4, ?5)";
        conn.execute(ins, rusqlite::params!["H", "pe://a.exe", "A", "x64", "t"])
            .unwrap();
        let dup = conn.execute(ins, rusqlite::params!["H", "pe://a.exe", "A", "x64", "t"]);
        assert!(dup.is_err(), "(hostname, registry_key) must be unique");
    }
}
```

- [x] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p evedoo schema::`
Expected: FAIL — `migrate`, `CURRENT_VERSION`, `Connection` unresolved.

- [x] **Step 3: Write the implementation**

Prepend to `evedoo/src/schema.rs`:

```rust
//! Sole owner of the `scan_history.db` schema (NFR-8, DC-5).
//!
//! Feature modules own their queries but must not declare tables — every
//! structural change lands here as a numbered migration so an existing
//! database is upgraded in place. This DB holds the delta history and the
//! exception audit trail, the only irreplaceable state the tool owns, so
//! "delete and recreate" is not an available upgrade path.

use rusqlite::{Connection, Result};

/// Bump when adding a migration, and add the matching arm to `apply`.
pub const CURRENT_VERSION: i64 = 3;

/// v1 — baseline. Deliberately idempotent so databases predating versioning
/// are adopted in place rather than rebuilt.
const V1: &str = "
CREATE TABLE IF NOT EXISTS scan_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname         TEXT    NOT NULL,
    cve_id           TEXT    NOT NULL,
    software_name    TEXT    NOT NULL,
    software_version TEXT,
    first_seen       TEXT    NOT NULL,
    last_seen        TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'New',
    UNIQUE(hostname, cve_id, software_name)
);
CREATE INDEX IF NOT EXISTS idx_host ON scan_findings(hostname);
CREATE TABLE IF NOT EXISTS fleet_assets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname       TEXT    NOT NULL UNIQUE,
    display_name   TEXT,
    tags           TEXT    NOT NULL DEFAULT '',
    is_remote      INTEGER NOT NULL DEFAULT 0,
    port           INTEGER NOT NULL DEFAULT 5985,
    username       TEXT,
    use_ssl        INTEGER NOT NULL DEFAULT 0,
    added_at       TEXT    NOT NULL,
    last_scan      TEXT,
    total_findings INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fleet_hostname ON fleet_assets(hostname);
CREATE INDEX IF NOT EXISTS idx_fleet_tags ON fleet_assets(tags);
";

/// v2 — inventory snapshot (FR-57), replaced wholesale per host each scan.
const V2: &str = "
CREATE TABLE IF NOT EXISTS scan_inventory (
    hostname         TEXT NOT NULL,
    registry_key     TEXT NOT NULL,
    name             TEXT NOT NULL,
    version          TEXT,
    publisher        TEXT,
    install_location TEXT,
    install_date     TEXT,
    architecture     TEXT NOT NULL,
    scan_time        TEXT NOT NULL,
    PRIMARY KEY (hostname, registry_key)
);
";

/// v3 — accepted-risk exceptions (FR-68). `reason`, `owner` and `expires_at`
/// are NOT NULL: an exception without attribution or an end date is not an
/// audit trail.
const V3: &str = "
CREATE TABLE IF NOT EXISTS exceptions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname      TEXT NOT NULL,
    cve_id        TEXT NOT NULL,
    software_name TEXT NOT NULL,
    reason        TEXT NOT NULL,
    owner         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    UNIQUE(hostname, cve_id, software_name)
);
CREATE INDEX IF NOT EXISTS idx_exc_host ON exceptions(hostname);
";

fn apply(conn: &Connection, version: i64) -> Result<()> {
    match version {
        1 => conn.execute_batch(V1),
        2 => conn.execute_batch(V2),
        3 => conn.execute_batch(V3),
        _ => Ok(()),
    }
}

/// Bring `conn` up to `CURRENT_VERSION`, one transactional step at a time.
/// A failing step rolls back, leaving the database at its previous version.
pub fn migrate(conn: &Connection) -> Result<()> {
    let mut version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    while version < CURRENT_VERSION {
        let next = version + 1;
        let tx = conn.unchecked_transaction()?;
        apply(&tx, next)?;
        // PRAGMA cannot be parameterized; `next` is a loop counter bounded by
        // CURRENT_VERSION, never user input.
        tx.execute_batch(&format!("PRAGMA user_version = {next};"))?;
        tx.commit()?;
        version = next;
    }
    Ok(())
}

/// Open `path` and migrate it. The only sanctioned way to obtain a connection
/// to the state database.
pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    migrate(&conn)?;
    Ok(conn)
}
```

Add `mod schema;` to `evedoo/src/main.rs` alongside the other module declarations.

- [x] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p evedoo schema::`
Expected: PASS, 4 tests.

- [x] **Step 5: Commit**

```bash
git add evedoo/src/schema.rs evedoo/src/main.rs
git commit -m "schema: version scan_history.db via PRAGMA user_version (NFR-8)"
```

---

### Task 2: Adopt the schema module in history and fleet

**Files:**
- Modify: `evedoo/src/history.rs:22-45`
- Modify: `evedoo/src/fleet.rs:38-63`

**Interfaces:**
- Consumes: `schema::open`.
- Produces: unchanged public APIs — `HistoryStore::open(&str) -> Result<Self>`, `FleetManager::open(&str) -> Result<Self>`.

- [x] **Step 1: Write the failing test**

Append to the tests module in `evedoo/src/history.rs`:

```rust
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
```

- [x] **Step 2: Run it to verify it fails**

Run: `cargo test -p evedoo history_open_leaves`
Expected: FAIL — `user_version` is 0; `history.rs` still creates its own tables.

- [x] **Step 3: Delegate schema ownership**

In `evedoo/src/history.rs`, replace the body of `open` and **delete `init_schema` entirely**:

```rust
    pub fn open(path: &str) -> Result<Self> {
        // Schema and migrations are owned by `crate::schema` (NFR-8).
        let conn = crate::schema::open(path)?;
        Ok(Self { conn })
    }
```

Make the identical change in `evedoo/src/fleet.rs::open`, deleting its local `CREATE TABLE` batch.

- [x] **Step 4: Run the whole suite**

Run: `cargo test -p evedoo`
Expected: PASS. The pre-existing history and fleet tests must pass untouched — that is the evidence this move is behaviour-preserving.

- [x] **Step 5: Commit**

```bash
git add evedoo/src/history.rs evedoo/src/fleet.rs
git commit -m "history,fleet: delegate schema ownership to the schema module"
```

---

### Task 3: Model changes — status vocabulary, risk, exception reference

**Files:**
- Modify: `evedoo/src/models.rs`
- Modify: `evedoo-gui/src/models.rs` (DC-3, same commit)

**Interfaces:**
- Consumes: nothing.
- Produces: `FindingStatus::{New, NewlyApplicable, Persisting, Resolved, NoLongerApplicable}`; `Priority::{P1,P2,P3,P4}` (`Ord`, P1 lowest); `RiskAssessment { score: f32, tier: Priority, epss_known: bool }`; `ExceptionRef { id: i64, owner: String, reason: String, expires_at: String }`; `Finding.risk: Option<RiskAssessment>`; `Finding.excepted: Option<ExceptionRef>`.

- [x] **Step 1: Write the failing tests**

Append to `evedoo/src/models.rs`:

```rust
#[cfg(test)]
mod operationalisation_tests {
    use super::*;

    #[test]
    fn every_status_survives_a_json_round_trip() {
        for s in [
            FindingStatus::New,
            FindingStatus::NewlyApplicable,
            FindingStatus::Persisting,
            FindingStatus::Resolved,
            FindingStatus::NoLongerApplicable,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: FindingStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn priority_sorts_most_urgent_first() {
        let mut v = vec![Priority::P3, Priority::P1, Priority::P4, Priority::P2];
        v.sort();
        assert_eq!(v, vec![Priority::P1, Priority::P2, Priority::P3, Priority::P4]);
    }

    #[test]
    fn json_without_risk_or_excepted_still_parses() {
        // DC-3: new fields are additive, so output from a previous release
        // must still deserialize.
        let legacy = r#"{
            "software": {"name":"App","version":"1.0","publisher":null,
                         "install_location":null,"install_date":null,
                         "registry_key":"pe://app.exe","architecture":"X64"},
            "vulnerability": {"cve_id":"CVE-2024-0001","description":"d",
                              "cvss_score":7.5,"severity":"High",
                              "published_date":null,"references":[],
                              "remediation":{"recommendation":"",
                                             "fixed_version":null,
                                             "vendor_advisory":null}},
            "confidence":"Exact","vendor":"v","status":"New"
        }"#;
        let f: Finding = serde_json::from_str(legacy).expect("legacy JSON must parse");
        assert!(f.risk.is_none());
        assert!(f.excepted.is_none());
    }
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test -p evedoo operationalisation_tests`
Expected: FAIL — `NewlyApplicable`, `Priority`, `risk`, `excepted` do not exist.

- [x] **Step 3: Write the implementation**

Replace `FindingStatus` in `evedoo/src/models.rs` and add the new types:

```rust
/// Why a finding is in the report. `New` and `NewlyApplicable` are distinct on
/// purpose (FR-60): "you installed something vulnerable" and "a CVE was
/// published against what you already had" need different operator responses,
/// and collapsing them makes reassessment pointless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    /// Software was absent from the previous inventory snapshot.
    New,
    /// Software was already known; the CVE data now matches it.
    NewlyApplicable,
    /// Present in the previous run and still present.
    Persisting,
    /// Software removed, or its version now falls outside the affected range.
    Resolved,
    /// CVE data changed such that the match no longer holds.
    NoLongerApplicable,
}

/// Triage bucket. `P1 < P2` so a plain sort puts the most urgent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    P1,
    P2,
    P3,
    P4,
}

/// Risk assessment for one finding (FR-63).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// `[0, 100]`.
    pub score: f32,
    pub tier: Priority,
    /// False when the CVE had no EPSS score: `score` used the corpus median
    /// and `tier` was floored at P3 (FR-66). Reports should mark such a score
    /// provisional rather than presenting it as measured.
    pub epss_known: bool,
}

/// The exception that suppressed a finding (FR-70). Its presence is a change
/// of view, never a change of record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExceptionRef {
    pub id: i64,
    pub owner: String,
    pub reason: String,
    pub expires_at: String,
}
```

> **Do not touch `Remediation`'s derives.** It already has a hand-written
> `impl Default` that sets `recommendation` to a real user-facing string
> ("Update to the latest version or contact vendor for patches."). So
> `Remediation::default()` already works for the Tasks 6/7/8 fixtures, and
> adding `#[derive(Default)]` collides with it (E0119). An earlier revision of
> this plan wrongly instructed adding the derive; that instruction is withdrawn.

Add to `struct Finding`:

```rust
    /// Populated by the risk stage (FR-63); `None` if scoring was skipped.
    #[serde(default)]
    pub risk: Option<RiskAssessment>,
    /// Set when an exception matched (FR-70). The finding stays in the
    /// pipeline and in history regardless.
    #[serde(default)]
    pub excepted: Option<ExceptionRef>,
```

Mirror `Priority`, `RiskAssessment`, `ExceptionRef`, the two `Finding` fields, and the new `FindingStatus` variants in `evedoo-gui/src/models.rs`.

- [x] **Step 4: Fix the fallout, then run everything**

New enum variants break exhaustive `match`, and the new fields break `Finding { .. }` literals.

Run: `cargo build --workspace 2>&1 | grep -B2 -A6 "E0004\|missing field"`
Fix each site: add `risk: None, excepted: None` to literals; add arms for the two new statuses.
Then: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add evedoo/src/models.rs evedoo-gui/src/models.rs
git commit -m "models: split New/NewlyApplicable, add risk and exception fields (FR-60, DC-3)"
```

---

### Task 4: Inventory persistence

**Files:**
- Create: `evedoo/src/inventory.rs`
- Modify: `evedoo/src/main.rs` (add `mod inventory;`)

**Interfaces:**
- Consumes: `schema::open`, `models::DetectedSoftware`, `models::Architecture`.
- Produces: `InventoryStore::open(path: &str) -> Result<Self>`; `InventoryStore::replace(&self, hostname: &str, scan_time: &str, items: &[DetectedSoftware]) -> Result<usize>`; `InventoryStore::load(&self, hostname: &str) -> Result<Vec<DetectedSoftware>>`; `InventoryStore::snapshot_time(&self, hostname: &str) -> Result<Option<String>>`.

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/inventory.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Architecture;

    fn sw(name: &str, key: &str) -> DetectedSoftware {
        DetectedSoftware {
            name: name.to_string(),
            version: Some("1.0".to_string()),
            publisher: Some("Pub".to_string()),
            install_location: None,
            install_date: None,
            registry_key: key.to_string(),
            architecture: Architecture::X64,
        }
    }

    fn store() -> InventoryStore {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::migrate(&conn).unwrap();
        InventoryStore { conn }
    }

    #[test]
    fn round_trips_inventory() {
        let s = store();
        let items = vec![sw("Alpha", "pe://a.exe"), sw("Beta", "winget://b")];
        assert_eq!(s.replace("HOST", "2026-08-21T00:00:00Z", &items).unwrap(), 2);

        let back = s.load("HOST").unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.iter().any(|i| i.name == "Alpha"
            && i.registry_key == "pe://a.exe"
            && i.version.as_deref() == Some("1.0")));
    }

    #[test]
    fn replace_is_wholesale_not_additive() {
        let s = store();
        s.replace("HOST", "t1", &[sw("Alpha", "pe://a.exe")]).unwrap();
        s.replace("HOST", "t2", &[sw("Beta", "pe://b.exe")]).unwrap();

        let back = s.load("HOST").unwrap();
        assert_eq!(back.len(), 1, "old snapshot must be gone, not merged");
        assert_eq!(back[0].name, "Beta");
    }

    #[test]
    fn hosts_are_isolated() {
        let s = store();
        s.replace("A", "t", &[sw("Alpha", "pe://a.exe")]).unwrap();
        s.replace("B", "t", &[sw("Beta", "pe://b.exe")]).unwrap();
        assert_eq!(s.load("A").unwrap().len(), 1);
        assert_eq!(s.load("B").unwrap().len(), 1);
        assert_eq!(s.load("A").unwrap()[0].name, "Alpha");
    }

    #[test]
    fn snapshot_time_reports_when_absent_and_present() {
        let s = store();
        assert_eq!(s.snapshot_time("HOST").unwrap(), None);
        s.replace("HOST", "2026-08-21T00:00:00Z", &[sw("A", "pe://a.exe")]).unwrap();
        assert_eq!(
            s.snapshot_time("HOST").unwrap().as_deref(),
            Some("2026-08-21T00:00:00Z")
        );
    }

    #[test]
    fn duplicate_identity_within_one_batch_does_not_abort_the_scan() {
        // Two scanners can legitimately surface the same identity; the
        // snapshot should keep one rather than failing the whole write.
        let s = store();
        let items = vec![sw("Alpha", "pe://a.exe"), sw("Alpha dup", "pe://a.exe")];
        let n = s.replace("HOST", "t", &items).unwrap();
        assert_eq!(n, 1, "duplicate identity collapses to a single row");
        assert_eq!(s.load("HOST").unwrap().len(), 1);
    }
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test -p evedoo inventory::`
Expected: FAIL — `InventoryStore` does not exist.

- [x] **Step 3: Write the implementation**

Prepend to `evedoo/src/inventory.rs`:

```rust
//! Per-host inventory snapshot (FR-57).
//!
//! Findings alone are not enough to reassess: software that currently matches
//! nothing is exactly the population a newly published CVE will affect, so the
//! *complete* inventory is stored — matched and unmatched alike.

use crate::error::Result;
use crate::models::{Architecture, DetectedSoftware};
use rusqlite::{params, Connection};
use tracing::warn;

pub struct InventoryStore {
    pub(crate) conn: Connection,
}

fn architecture_from(s: &str) -> Architecture {
    match s {
        "X86" => Architecture::X86,
        "X64" => Architecture::X64,
        _ => Architecture::Unknown,
    }
}

impl InventoryStore {
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self { conn: crate::schema::open(path)? })
    }

    /// Replace this host's snapshot wholesale, in one transaction. A scan that
    /// fails partway leaves the previous snapshot intact rather than a blend
    /// of two observations.
    pub fn replace(
        &self,
        hostname: &str,
        scan_time: &str,
        items: &[DetectedSoftware],
    ) -> Result<usize> {
        // Refuse to wipe a good snapshot with nothing. A scanner that
        // degrades to zero results (a partial remote failure that does not
        // itself error) must not destroy the only inventory we hold — it is
        // the sole input to `reassess`, and it cannot be reconstructed
        // without touching the host again.
        if items.is_empty() {
            warn!("refusing to replace {hostname}'s inventory with an empty snapshot");
            return Ok(0);
        }

        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM scan_inventory WHERE hostname = ?1", params![hostname])?;
        let mut written = 0usize;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO scan_inventory
                   (hostname, registry_key, name, version, publisher,
                    install_location, install_date, architecture, scan_time)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for item in items {
                written += stmt.execute(params![
                    hostname,
                    item.registry_key,
                    item.name,
                    item.version,
                    item.publisher,
                    item.install_location,
                    item.install_date,
                    format!("{:?}", item.architecture),
                    scan_time,
                ])?;
            }
        }
        tx.commit()?;
        // FR-57 asks for the *complete* inventory. registry_key is unique per
        // source (DC-2), so a collision inside one batch is more plausibly a
        // scanner enumeration bug than two scanners legitimately agreeing —
        // and a silently dropped item undercuts the completeness guarantee.
        if written < items.len() {
            warn!(
                "inventory for {hostname}: {} of {} items collapsed on duplicate registry_key",
                items.len() - written,
                items.len()
            );
        }
        Ok(written)
    }

    pub fn load(&self, hostname: &str) -> Result<Vec<DetectedSoftware>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, publisher, install_location, install_date,
                    registry_key, architecture
               FROM scan_inventory WHERE hostname = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![hostname], |r| {
            Ok(DetectedSoftware {
                name: r.get(0)?,
                version: r.get(1)?,
                publisher: r.get(2)?,
                install_location: r.get(3)?,
                install_date: r.get(4)?,
                registry_key: r.get(5)?,
                architecture: architecture_from(&r.get::<_, String>(6)?),
            })
        })?;
        Ok(rows.flatten().collect())
    }

    /// RFC3339 timestamp of the stored snapshot, or `None` if this host has
    /// never been scanned. Drives the staleness warning in FR-59.
    pub fn snapshot_time(&self, hostname: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT scan_time FROM scan_inventory WHERE hostname = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![hostname])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }
}
```

Add `mod inventory;` to `evedoo/src/main.rs`.

> **Note on `Architecture`:** the store uses `format!("{:?}")` plus `architecture_from` rather than serde, so the on-disk value stays stable if serde attributes ever change. The enum has exactly three variants — `X64`, `X86`, `Unknown` (verified at `models.rs`) — so any unrecognised string degrades to `Unknown` rather than failing the load.

- [x] **Step 4: Run to verify passing**

Run: `cargo test -p evedoo inventory::`
Expected: PASS, 5 tests.

- [x] **Step 5: Commit**

```bash
git add evedoo/src/inventory.rs evedoo/src/main.rs
git commit -m "inventory: persist the full per-host software snapshot (FR-57)"
```

---

### Task 5: Extract the shared correlation stage

**Files:**
- Create: `evedoo/src/correlate.rs`
- Modify: `evedoo/src/main.rs:564-600` (local loop), `evedoo/src/main.rs:934-968` (remote loop)

**Interfaces:**
- Consumes: `matcher::CveMatcher`, `models::{DetectedSoftware, Finding, FindingStatus}`.
- Produces: `correlate::correlate(inventory: Vec<DetectedSoftware>, matcher: &CveMatcher) -> CorrelationOutcome`; `CorrelationOutcome { findings: Vec<Finding>, without_cves: Vec<DetectedSoftware> }`.

**Why unfiltered (FR-61):** today both loops apply `--severity` and `--min-confidence` *before* `apply_delta` runs, so `scan -s critical` records every still-present medium and low finding as `Resolved` in the history DB. Filtering moves to presentation so persisted state never depends on invocation flags.

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/correlate.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Architecture;

    fn sw(name: &str) -> DetectedSoftware {
        DetectedSoftware {
            name: name.to_string(),
            version: Some("1.2.3".to_string()),
            publisher: None,
            install_location: None,
            install_date: None,
            registry_key: format!("pe://{name}.exe"),
            architecture: Architecture::X64,
        }
    }

    #[test]
    fn outcome_partitions_matched_and_unmatched() {
        // An empty matcher fixture correlates nothing, so every item must land
        // in `without_cves` and none in `findings`.
        let matcher = crate::matcher::tests_support::empty_matcher();
        let out = correlate(vec![sw("Alpha"), sw("Beta")], &matcher);
        assert!(out.findings.is_empty());
        assert_eq!(out.without_cves.len(), 2);
    }

    #[test]
    fn every_finding_starts_unclassified() {
        // Status is assigned later by reconcile(); correlate must not guess.
        let matcher = crate::matcher::tests_support::empty_matcher();
        let out = correlate(vec![sw("Alpha")], &matcher);
        for f in &out.findings {
            assert_eq!(f.status, FindingStatus::New);
            assert!(f.risk.is_none());
            assert!(f.excepted.is_none());
        }
    }
}
```

Add a small fixture helper in `evedoo/src/matcher/mod.rs`:

```rust
#[cfg(test)]
pub(crate) mod tests_support {
    use super::CveMatcher;

    /// A matcher over an empty in-memory CVE database — correlates nothing.
    /// Used by pipeline tests that care about plumbing, not matching.
    pub(crate) fn empty_matcher() -> CveMatcher {
        let dir = std::env::temp_dir().join("evedoo_empty_matcher_fixture");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.sqlite");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cves (cve_id TEXT PRIMARY KEY, description TEXT,
                 cvss_v3_score REAL, cvss_v3_vector TEXT, cvss_v2_score REAL,
                 cvss_v2_vector TEXT, severity TEXT);
             CREATE TABLE IF NOT EXISTS cpe_matches (cve_id TEXT, vendor TEXT, product TEXT,
                 version TEXT, version_start_including TEXT, version_start_excluding TEXT,
                 version_end_including TEXT, version_end_excluding TEXT, platform TEXT,
                 vulnerable INTEGER DEFAULT 1, target_sw TEXT);
             CREATE TABLE IF NOT EXISTS cve_references (id INTEGER PRIMARY KEY,
                 cve_id TEXT, url TEXT, source TEXT, tags TEXT);
             CREATE TABLE IF NOT EXISTS product_mappings (id INTEGER PRIMARY KEY,
                 display_name TEXT, cpe_vendor TEXT, cpe_product TEXT);
             CREATE TABLE IF NOT EXISTS epss (cve_id TEXT PRIMARY KEY, score REAL,
                 percentile REAL, fetched_at TEXT);
             CREATE TABLE IF NOT EXISTS kev (cve_id TEXT PRIMARY KEY, date_added TEXT,
                 due_date TEXT, action TEXT, ransomware_use TEXT);
             CREATE TABLE IF NOT EXISTS schema_version (version INTEGER);",
        )
        .unwrap();
        drop(conn);
        CveMatcher::new(path.to_str().unwrap()).unwrap()
    }
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test -p evedoo correlate::`
Expected: FAIL — `correlate` does not exist.

- [x] **Step 3: Write the implementation**

Prepend to `evedoo/src/correlate.rs`:

```rust
//! The single correlation pass (FR-62).
//!
//! Local scan, remote scan and reassessment all call this, so the three
//! cannot drift apart. It runs **unfiltered** (FR-61): severity and confidence
//! are presentation concerns, because filtering here would make persisted
//! findings and their delta status depend on which flags an invocation used.

use crate::matcher::CveMatcher;
use crate::models::{DetectedSoftware, Finding, FindingStatus};
use tracing::info;

pub struct CorrelationOutcome {
    pub findings: Vec<Finding>,
    /// Items that correlated to no applicable CVE, plus items whose lookup
    /// errored — both are "nothing to report", and the coverage diagnostic
    /// distinguishes them separately.
    pub without_cves: Vec<DetectedSoftware>,
}

pub fn correlate(inventory: Vec<DetectedSoftware>, matcher: &CveMatcher) -> CorrelationOutcome {
    let mut findings = Vec::new();
    let mut without_cves = Vec::new();

    for sw in inventory {
        match matcher.find_vulnerabilities(&sw) {
            Ok(matches) if !matches.is_empty() => {
                for (mut vuln, confidence, vendor) in matches {
                    vuln.remediation.upgrade_command = crate::build_upgrade_command(
                        &sw.registry_key,
                        &sw.name,
                        vuln.remediation.fixed_version.as_deref(),
                    );
                    findings.push(Finding {
                        software: sw.clone(),
                        vulnerability: vuln,
                        confidence,
                        vendor,
                        // Assigned by reconcile(); correlate never guesses.
                        status: FindingStatus::New,
                        risk: None,
                        excepted: None,
                    });
                }
            }
            Ok(_) => without_cves.push(sw),
            Err(e) => {
                info!("Error matching {}: {}", sw.name, e);
                without_cves.push(sw);
            }
        }
    }

    CorrelationOutcome { findings, without_cves }
}
```

Add `mod correlate;` to `main.rs`. `build_upgrade_command` already lives in `matcher/cpe.rs:1475` as a `pub fn` — call it as `crate::matcher::build_upgrade_command`; no visibility change is needed.

- [x] **Step 4: Replace both call sites**

In `run_scan` (~main.rs:564) and the remote path (~main.rs:934), delete the inline loops and substitute:

```rust
    let outcome = correlate::correlate(software, &matcher);
    result.findings = outcome.findings;
    result.software_without_cves = outcome.without_cves;
```

The `skipped_low_confidence` counter moves to the presentation filter added in Task 9; delete its declaration and any references at these two sites.

**Do not leave `--severity` and `--min-confidence` inert.** Filtering must leave
correlation, but it must not vanish: apply it **after** history is written and
**before** the report is generated, at both call sites. That ordering is the
whole point — history receives the complete set (fixing the Resolved
corruption), while the report honours the flags:

```rust
    // Presentation filter (FR-61). Runs AFTER delta tracking so persisted
    // state stays complete and flag-independent; the report sees the filtered
    // view. Task 9 replaces this with the non-mutating `present::filter`,
    // which also handles --min-priority and --show-excepted.
    result.findings.retain(|f| {
        f.confidence <= min_confidence
            && severity_filter
                .as_ref()
                .is_none_or(|s| s.contains(&f.vulnerability.severity))
    });
```

Keep `severity_filter` named without a leading underscore, since it is used.

- [x] **Step 5: Run everything**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS. **The 53+53 accuracy gate must be untouched** — movement there means the extraction changed matching behaviour.

- [x] **Step 6: Commit**

```bash
git add evedoo/src/correlate.rs evedoo/src/main.rs evedoo/src/matcher/mod.rs
git commit -m "correlate: extract one unfiltered correlation stage (FR-61, FR-62)"
```

---

### Task 6: Status reconciliation

**Files:**
- Create: `evedoo/src/reconcile.rs`
- Modify: `evedoo/src/main.rs` (add `mod reconcile;`)

**Interfaces:**
- Consumes: `models::{Finding, FindingStatus, DetectedSoftware}`.
- Produces: `reconcile::Mode::{Scan, Reassess}`; `reconcile::reconcile(findings: &mut [Finding], previous_keys: &HashSet<(String,String)>, previous_inventory: &HashSet<String>, mode: Mode)`.

`previous_keys` holds `(cve_id, software_name)` from the last run; `previous_inventory` holds `registry_key` values from the previous snapshot. Both must be read **before** the new snapshot overwrites them.

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/reconcile.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Architecture, DetectedSoftware, Finding, MatchConfidence,
                        Remediation, Severity, Vulnerability};
    use std::collections::HashSet;

    fn finding(cve: &str, name: &str, key: &str) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: name.to_string(),
                version: Some("1.0".to_string()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: key.to_string(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: cve.to_string(),
                description: String::new(),
                cvss_score: Some(7.5),
                severity: Severity::High,
                published_date: None,
                references: vec![],
                remediation: Remediation::default(),
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Exact,
            vendor: Some("v".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
        }
    }

    fn keys(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs.iter().map(|(c, n)| (c.to_string(), n.to_string())).collect()
    }

    fn inv(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    #[test]
    fn unseen_software_yields_new() {
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[]), &inv(&[]), Mode::Scan);
        assert_eq!(f[0].status, FindingStatus::New);
    }

    #[test]
    fn known_software_with_a_new_cve_yields_newly_applicable() {
        // The software was already in the previous snapshot; only the CVE is
        // new. This is the distinction that makes reassessment worth running.
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[]), &inv(&["pe://a.exe"]), Mode::Scan);
        assert_eq!(f[0].status, FindingStatus::NewlyApplicable);
    }

    #[test]
    fn previously_recorded_finding_persists() {
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[("CVE-1", "Alpha")]), &inv(&["pe://a.exe"]), Mode::Scan);
        assert_eq!(f[0].status, FindingStatus::Persisting);
    }

    #[test]
    fn reassess_never_emits_new() {
        // Reassessment observes no machine state, so it cannot claim software
        // appeared (FR-59) — even when the previous inventory is empty.
        let mut f = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        reconcile(&mut f, &keys(&[]), &inv(&[]), Mode::Reassess);
        assert_eq!(f[0].status, FindingStatus::NewlyApplicable);
        assert_ne!(f[0].status, FindingStatus::New);
    }

    #[test]
    fn filters_do_not_influence_status() {
        // FR-61 regression guard: a previous run that recorded only some
        // findings must not make the rest look New once filtering moves to
        // presentation. Same inputs, same statuses, regardless of severity.
        let mut a = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        let mut b = vec![finding("CVE-1", "Alpha", "pe://a.exe")];
        b[0].vulnerability.severity = Severity::Low;
        let k = keys(&[("CVE-1", "Alpha")]);
        let i = inv(&["pe://a.exe"]);
        reconcile(&mut a, &k, &i, Mode::Scan);
        reconcile(&mut b, &k, &i, Mode::Scan);
        assert_eq!(a[0].status, b[0].status);
    }
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test -p evedoo reconcile::`
Expected: FAIL — `reconcile` and `Mode` do not exist.

- [x] **Step 3: Write the implementation**

Prepend to `evedoo/src/reconcile.rs`:

```rust
//! Assigns `FindingStatus` (FR-59, FR-60).
//!
//! Must run *before* the new inventory snapshot overwrites the old one — the
//! difference between `New` and `NewlyApplicable` is precisely "was this
//! software in the previous snapshot", and that answer is destroyed by the
//! write.

use crate::models::{Finding, FindingStatus};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The host was observed just now.
    Scan,
    /// Stored inventory was re-correlated; nothing was observed.
    Reassess,
}

/// Tag each finding. `previous_keys` is `(cve_id, software_name)` from the
/// last run; `previous_inventory` is the `registry_key` set from the previous
/// snapshot.
pub fn reconcile(
    findings: &mut [Finding],
    previous_keys: &HashSet<(String, String)>,
    previous_inventory: &HashSet<String>,
    mode: Mode,
) {
    for f in findings.iter_mut() {
        let key = (f.vulnerability.cve_id.clone(), f.software.name.clone());
        if previous_keys.contains(&key) {
            f.status = FindingStatus::Persisting;
            continue;
        }
        // The finding is new to the record. Which kind of new depends on
        // whether we already knew about the software.
        let software_known = previous_inventory.contains(&f.software.registry_key);
        f.status = match mode {
            // Reassessment observed nothing, so it can never claim software
            // appeared — every unrecorded finding is newly applicable.
            Mode::Reassess => FindingStatus::NewlyApplicable,
            Mode::Scan if software_known => FindingStatus::NewlyApplicable,
            Mode::Scan => FindingStatus::New,
        };
    }
}
```

Add `mod reconcile;` to `main.rs`.

- [x] **Step 4: Run to verify passing**

Run: `cargo test -p evedoo reconcile::`
Expected: PASS, 5 tests.

- [x] **Step 5: Commit**

```bash
git add evedoo/src/reconcile.rs evedoo/src/main.rs
git commit -m "reconcile: separate New from NewlyApplicable, mode-aware (FR-59, FR-60)"
```

---

### Task 7: Risk scoring

**Files:**
- Create: `evedoo/src/risk.rs`
- Modify: `evedoo/src/matcher/cpe.rs` (add exploit-reference lookup)
- Modify: `evedoo/src/main.rs` (add `mod risk;`)

**Interfaces:**
- Consumes: `models::{Vulnerability, RiskAssessment, Priority}`.
- Produces: `risk::assess(v: &Vulnerability, has_exploit_ref: bool, criticality: f32) -> RiskAssessment`; `risk::criticality_for(tags: &str) -> f32`; `CveMatcher::has_exploit_reference(&self, cve_id: &str) -> Result<bool>`; constants `MEDIAN_EPSS`, `P1_MIN`, `P2_MIN`, `P3_MIN`.

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/risk.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Remediation, Severity, Vulnerability};

    fn vuln(cvss: f32, epss: Option<f32>, kev: bool) -> Vulnerability {
        Vulnerability {
            cve_id: "CVE-2024-0001".into(),
            description: String::new(),
            cvss_score: Some(cvss),
            severity: Severity::High,
            published_date: None,
            references: vec![],
            remediation: Remediation::default(),
            epss_score: epss,
            epss_percentile: None,
            in_kev: kev,
            kev_due_date: None,
            kev_ransomware_use: None,
        }
    }

    #[test]
    fn high_cvss_with_negligible_epss_is_not_urgent() {
        // The premise the whole feature rests on: CVSS 9.8 + EPSS 0.001 is
        // not a fire. A purely additive blend cannot express this.
        let r = assess(&vuln(9.8, Some(0.001), false), false, 1.0);
        assert!(r.score < 9.0, "expected low score, got {}", r.score);
        assert_eq!(r.tier, Priority::P4);
    }

    #[test]
    fn moderate_cvss_in_kev_is_urgent() {
        let r = assess(&vuln(7.5, Some(0.02), true), false, 1.0);
        assert!(r.score > 60.0, "expected high score, got {}", r.score);
        assert_eq!(r.tier, Priority::P1);
    }

    #[test]
    fn kev_forces_p1_regardless_of_score() {
        // Low CVSS keeps the number modest; KEV still means "patch this".
        let r = assess(&vuln(2.0, Some(0.001), true), false, 1.0);
        assert_eq!(r.tier, Priority::P1);
    }

    #[test]
    fn unknown_epss_is_floored_at_p3_and_marked() {
        // Absence of an EPSS score is absence of evidence. A CVSS 10 with no
        // EPSS scores ~5 and would otherwise land in P4 (FR-66).
        let r = assess(&vuln(10.0, None, false), false, 1.0);
        assert!(!r.epss_known);
        assert_eq!(r.tier, Priority::P3);
    }

    #[test]
    fn known_epss_is_marked_known() {
        assert!(assess(&vuln(5.0, Some(0.2), false), false, 1.0).epss_known);
    }

    #[test]
    fn exploit_tag_raises_a_low_epss_finding() {
        let without = assess(&vuln(7.0, Some(0.001), false), false, 1.0).score;
        let with = assess(&vuln(7.0, Some(0.001), false), true, 1.0).score;
        assert!(with > without, "exploit-tagged reference must raise likelihood");
    }

    #[test]
    fn score_is_monotonic_in_both_axes() {
        let a = assess(&vuln(5.0, Some(0.1), false), false, 1.0).score;
        let b = assess(&vuln(9.0, Some(0.1), false), false, 1.0).score;
        let c = assess(&vuln(5.0, Some(0.5), false), false, 1.0).score;
        assert!(b > a, "raising CVSS must not lower the score");
        assert!(c > a, "raising EPSS must not lower the score");
    }

    #[test]
    fn criticality_never_pushes_past_one_hundred() {
        let r = assess(&vuln(10.0, Some(0.99), true), true, 1.25);
        assert!(r.score <= 100.0, "score must clamp, got {}", r.score);
    }

    #[test]
    fn criticality_reads_fleet_tags() {
        assert_eq!(criticality_for("prod,web,critical"), 1.25);
        assert_eq!(criticality_for("prod,web"), 1.15);
        assert_eq!(criticality_for("lab"), 0.85);
        assert_eq!(criticality_for(""), 1.0);
        assert_eq!(criticality_for("unrelated,tags"), 1.0);
    }
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test -p evedoo risk::`
Expected: FAIL — `assess` and `criticality_for` do not exist.

- [x] **Step 3: Write the implementation**

Prepend to `evedoo/src/risk.rs`:

```rust
//! Risk score and priority tier (FR-63..FR-66).
//!
//! The form is multiplicative, not a weighted sum: an additive blend cannot
//! express that a CVSS 9.8 with EPSS 0.001 is not urgent — it floors such a
//! finding around 40 no matter how the weights are chosen.
//!
//! Thresholds are calibrated against the CVE corpus rather than chosen by
//! taste. At P1 >= 60 / P2 >= 15 / P3 >= 9 the corpus splits 2.0% / 8.6% /
//! 14.9% / 74.5%, which is a usable triage pyramid. Earlier guesses of
//! 70/40/15 put 86% of CVEs in P4 using raw EPSS, and 92% in P1+P2 using the
//! percentile — both useless.

use crate::models::{Priority, RiskAssessment, Vulnerability};

/// Median EPSS across scored CVEs, used when a CVE has none (FR-66).
/// Re-derive whenever the thresholds below are recalibrated.
pub const MEDIAN_EPSS: f32 = 0.00696;

pub const P1_MIN: f32 = 60.0;
pub const P2_MIN: f32 = 15.0;
pub const P3_MIN: f32 = 9.0;

/// Likelihood floor applied when a reference carries NVD's `Exploit` tag.
/// Deliberately small: the tag covers 23.1% of the corpus, so it corroborates
/// rather than proves.
const EXPLOIT_FLOOR: f32 = 0.10;
/// Likelihood floor for CISA KEV membership — confirmed exploitation.
const KEV_FLOOR: f32 = 0.90;

/// Multiplier derived from an asset's fleet tags (FR-65). 1.0 for an
/// unregistered host, which is the normal single-machine case.
pub fn criticality_for(tags: &str) -> f32 {
    let lower = tags.to_ascii_lowercase();
    let has = |t: &str| lower.split(',').any(|x| x.trim() == t);
    if has("critical") {
        1.25
    } else if has("prod") || has("production") {
        1.15
    } else if has("lab") || has("test") || has("dev") {
        0.85
    } else {
        1.0
    }
}

pub fn assess(v: &Vulnerability, has_exploit_ref: bool, criticality: f32) -> RiskAssessment {
    let epss_known = v.epss_score.is_some();
    let mut likelihood = v.epss_score.unwrap_or(MEDIAN_EPSS);
    if v.in_kev {
        likelihood = likelihood.max(KEV_FLOOR);
    }
    if has_exploit_ref {
        likelihood = likelihood.max(EXPLOIT_FLOOR);
    }

    let impact = (v.cvss_score.unwrap_or(0.0) / 10.0).clamp(0.0, 1.0);
    let score =
        (100.0 * impact.powf(0.4) * likelihood.powf(0.6) * criticality).clamp(0.0, 100.0);

    let mut tier = if score >= P1_MIN {
        Priority::P1
    } else if score >= P2_MIN {
        Priority::P2
    } else if score >= P3_MIN {
        Priority::P3
    } else {
        Priority::P4
    };

    // Confirmed in-the-wild exploitation outranks the arithmetic.
    if v.in_kev {
        tier = Priority::P1;
    }
    // An unknown likelihood must not be presented as a low one (FR-66).
    if !epss_known && tier == Priority::P4 {
        tier = Priority::P3;
    }

    RiskAssessment { score, tier, epss_known }
}
```

Add `mod risk;` to `main.rs`.

- [x] **Step 4: Add the exploit-reference lookup**

The existing reference query in `matcher/cpe.rs:1373` carries `LIMIT 10`, so an `Exploit` tag on reference #15 is invisible. Add a separate exact check — `idx_ref_cve` makes it ~0.007 ms, about 6 ms across 900 findings:

```rust
    /// True when any reference for `cve_id` carries NVD's `Exploit` tag
    /// (FR-63). Deliberately separate from `get_cve_references_with_kb`, whose LIMIT 10
    /// would hide the tag on a later reference.
    pub fn has_exploit_reference(&self, cve_id: &str) -> Result<bool> {
        let found: i64 = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM cve_references
                            WHERE cve_id = ?1 AND tags LIKE '%\"Exploit\"%')",
            params![cve_id],
            |r| r.get(0),
        )?;
        Ok(found == 1)
    }
```

Add a test in `matcher/cpe.rs`:

```rust
    #[test]
    fn exploit_reference_is_detected_beyond_the_first_ten() {
        let db = build_expanded_gate_db("exploit_ref_probe");
        let conn = rusqlite::Connection::open(&db).unwrap();
        for i in 0..12 {
            let tags = if i == 11 { r#"["Exploit"]"# } else { r#"["Patch"]"# };
            conn.execute(
                "INSERT INTO cve_references (cve_id, url, source, tags)
                 VALUES ('CVE-GATE-0000', ?1, 's', ?2)",
                rusqlite::params![format!("https://example.test/{i}"), tags],
            )
            .unwrap();
        }
        drop(conn);
        let matcher = CveMatcher::new(&db).unwrap();
        assert!(
            matcher.has_exploit_reference("CVE-GATE-0000").unwrap(),
            "the Exploit tag sits past LIMIT 10 and must still be found"
        );
    }
```

- [x] **Step 5: Run to verify passing**

Run: `cargo test -p evedoo risk:: && cargo test -p evedoo exploit_reference`
Expected: PASS, 9 risk tests + 1 matcher test.

- [x] **Step 6: Validate calibration against real data**

The thresholds come from the whole corpus, but real findings are a biased sample — widely deployed desktop software skews toward higher EPSS. Check the on-machine distribution:

```bash
cargo build --release -p evedoo
"target/release/evedoo.exe" scan \
  -d cve-db-builder/vulndb.sqlite -f json -o /tmp/risk-check.json --no-history
python -c "
import json,collections
d=json.load(open('/tmp/risk-check.json'))
c=collections.Counter(f['risk']['tier'] for f in d['findings'] if f.get('risk'))
n=sum(c.values())
for t in ('P1','P2','P3','P4'): print(f'{t} {c[t]:5} {100*c[t]/n:5.1f}%')
"
```

Expected: P1 is a short list — roughly 1–10%. **If P1 exceeds ~25%, the thresholds are miscalibrated for real inventory**: raise `P1_MIN` until P1 is actionable, and record the new value and its measured distribution in the `risk.rs` doc comment and in spec.md FR-64.

- [x] **Step 7: Commit**

```bash
git add evedoo/src/risk.rs evedoo/src/matcher/cpe.rs evedoo/src/main.rs
git commit -m "risk: corpus-calibrated score and priority tier (FR-63..FR-66)"
```

---

### Task 8: Exceptions store and matching

**Files:**
- Create: `evedoo/src/exceptions.rs`
- Modify: `evedoo/src/main.rs` (add `mod exceptions;`)

**Interfaces:**
- Consumes: `schema::open`, `models::{Finding, ExceptionRef}`.
- Produces: `ExceptionStore::open(&str) -> Result<Self>`; `add(&self, ExceptionInput) -> Result<i64>`; `list(&self, host: Option<&str>) -> Result<Vec<ExceptionRecord>>`; `remove(&self, id: i64) -> Result<bool>`; `apply(&self, findings: &mut [Finding], hostname: &str, now: &str) -> Result<usize>`; `is_valid_cve_id(&str) -> bool`; `ExceptionInput { hostname, cve_id, software_name, reason, owner, expires_at }`; `ExceptionRecord { id, hostname, cve_id, software_name, reason, owner, created_at, expires_at }`.

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/exceptions.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Architecture, DetectedSoftware, Finding, FindingStatus,
                        MatchConfidence, Remediation, Severity, Vulnerability};

    fn store() -> ExceptionStore {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::migrate(&conn).unwrap();
        ExceptionStore { conn }
    }

    fn input(host: &str, cve: &str, sw: &str, expires: &str) -> ExceptionInput {
        ExceptionInput {
            hostname: host.into(),
            cve_id: cve.into(),
            software_name: sw.into(),
            reason: "compensating control".into(),
            owner: "sid".into(),
            expires_at: expires.into(),
        }
    }

    fn finding(cve: &str, name: &str) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: name.into(), version: Some("1.0".into()), publisher: None,
                install_location: None, install_date: None,
                registry_key: format!("pe://{name}.exe"),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: cve.into(), description: String::new(),
                cvss_score: Some(7.5), severity: Severity::High,
                published_date: None, references: vec![],
                remediation: Remediation::default(), epss_score: None,
                epss_percentile: None, in_kev: false, kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Exact, vendor: Some("v".into()),
            status: FindingStatus::New, risk: None, excepted: None,
        }
    }

    #[test]
    fn exact_match_suppresses() {
        let s = store();
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2099-01-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 1);
        assert!(f[0].excepted.is_some());
    }

    #[test]
    fn wildcards_match_on_every_axis() {
        let s = store();
        s.add(input("*", "CVE-2024-0001", "*", "2099-01-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Anything")];
        assert_eq!(s.apply(&mut f, "ANY-HOST", "2026-08-21").unwrap(), 1);
    }

    #[test]
    fn non_matching_exception_leaves_the_finding_alone() {
        let s = store();
        s.add(input("HOST", "CVE-2024-9999", "Alpha", "2099-01-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 0);
        assert!(f[0].excepted.is_none());
    }

    #[test]
    fn expired_exception_does_not_suppress() {
        let s = store();
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2026-01-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 0);
        assert!(f[0].excepted.is_none(), "an expired rule must stop suppressing");
    }

    #[test]
    fn excepted_findings_stay_in_the_collection() {
        // FR-70: exceptions annotate, never remove. The finding must still be
        // present so delta tracking and history keep recording it.
        let s = store();
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2099-01-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        s.apply(&mut f, "HOST", "2026-08-21").unwrap();
        assert_eq!(f.len(), 1, "the finding must not be dropped");
    }

    #[test]
    fn exception_ref_carries_the_audit_fields() {
        let s = store();
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2099-01-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        s.apply(&mut f, "HOST", "2026-08-21").unwrap();
        let e = f[0].excepted.as_ref().unwrap();
        assert_eq!(e.owner, "sid");
        assert_eq!(e.reason, "compensating control");
        assert_eq!(e.expires_at, "2099-01-01");
    }

    #[test]
    fn list_and_remove_round_trip() {
        let s = store();
        let id = s.add(input("HOST", "CVE-2024-0001", "Alpha", "2099-01-01")).unwrap();
        assert_eq!(s.list(Some("HOST")).unwrap().len(), 1);
        assert!(s.remove(id).unwrap());
        assert!(s.list(Some("HOST")).unwrap().is_empty());
        assert!(!s.remove(id).unwrap(), "removing twice reports not-found");
    }

    #[test]
    fn cve_id_validation_accepts_canonical_and_wildcard_only() {
        assert!(is_valid_cve_id("CVE-2024-0001"));
        assert!(is_valid_cve_id("CVE-2024-1234567"));
        assert!(is_valid_cve_id("*"));
        assert!(!is_valid_cve_id("cve-2024-0001"));
        assert!(!is_valid_cve_id("CVE-24-0001"));
        assert!(!is_valid_cve_id("CVE-2024-12"));
        assert!(!is_valid_cve_id("not a cve"));
        assert!(!is_valid_cve_id(""));
    }
}
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test -p evedoo exceptions::`
Expected: FAIL — `ExceptionStore` does not exist.

- [x] **Step 3: Write the implementation**

Prepend to `evedoo/src/exceptions.rs`:

```rust
//! Accepted-risk exceptions (FR-68..FR-72).
//!
//! An exception **annotates** a finding; it never removes it. Excepted
//! findings still reach delta tracking and history, so the exception list is
//! an audit trail rather than a place findings go to disappear. Reports do the
//! hiding, and `--show-excepted` undoes it.

use crate::error::{Result, ScanError};
use crate::models::{ExceptionRef, Finding};
use rusqlite::{params, Connection};

pub struct ExceptionStore {
    pub(crate) conn: Connection,
}

pub struct ExceptionInput {
    pub hostname: String,
    pub cve_id: String,
    pub software_name: String,
    pub reason: String,
    pub owner: String,
    pub expires_at: String,
}

pub struct ExceptionRecord {
    pub id: i64,
    pub hostname: String,
    pub cve_id: String,
    pub software_name: String,
    pub reason: String,
    pub owner: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Canonical `CVE-YYYY-NNNN+`, or the `*` wildcard (FR-72). Rejecting a typo
/// at entry beats storing a rule that silently never matches.
///
/// `expires_at` is validated the same way, for a sharper reason: expiry is
/// compared lexicographically, so a malformed date like "soon" sorts above
/// every real date and the rule never expires — turning a typo into the
/// permanent suppression FR-68 exists to make inexpressible.
pub fn is_valid_cve_id(s: &str) -> bool {
    if s == "*" {
        return true;
    }
    let rest = match s.strip_prefix("CVE-") {
        Some(r) => r,
        None => return false,
    };
    let mut parts = rest.split('-');
    let (year, seq) = match (parts.next(), parts.next(), parts.next()) {
        (Some(y), Some(n), None) => (y, n),
        _ => return false,
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && seq.len() >= 4
        && seq.bytes().all(|b| b.is_ascii_digit())
}

fn matches(rule: &str, actual: &str) -> bool {
    rule == "*" || rule == actual
}

impl ExceptionStore {
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self { conn: crate::schema::open(path)? })
    }

    pub fn add(&self, input: ExceptionInput) -> Result<i64> {
        if !is_valid_cve_id(&input.cve_id) {
            return Err(ScanError::SerializationError(format!(
                "not a valid CVE id: {} (expected CVE-YYYY-NNNN or *)",
                input.cve_id
            )));
        }
        for (field, value) in [
            ("reason", &input.reason),
            ("owner", &input.owner),
            ("expires_at", &input.expires_at),
        ] {
            if value.trim().is_empty() {
                return Err(ScanError::SerializationError(format!(
                    "{field} is required — an exception without it is not an audit trail"
                )));
            }
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO exceptions
               (hostname, cve_id, software_name, reason, owner, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                input.hostname,
                input.cve_id,
                input.software_name,
                input.reason,
                input.owner,
                chrono::Utc::now().to_rfc3339(),
                input.expires_at,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list(&self, host: Option<&str>) -> Result<Vec<ExceptionRecord>> {
        let mut stmt = match host {
            Some(_) => self.conn.prepare(
                "SELECT id, hostname, cve_id, software_name, reason, owner,
                        created_at, expires_at
                   FROM exceptions WHERE hostname = ?1 OR hostname = '*' ORDER BY id",
            )?,
            None => self.conn.prepare(
                "SELECT id, hostname, cve_id, software_name, reason, owner,
                        created_at, expires_at
                   FROM exceptions ORDER BY id",
            )?,
        };
        let map = |r: &rusqlite::Row| -> rusqlite::Result<ExceptionRecord> {
            Ok(ExceptionRecord {
                id: r.get(0)?,
                hostname: r.get(1)?,
                cve_id: r.get(2)?,
                software_name: r.get(3)?,
                reason: r.get(4)?,
                owner: r.get(5)?,
                created_at: r.get(6)?,
                expires_at: r.get(7)?,
            })
        };
        let rows = match host {
            Some(h) => stmt.query_map(params![h], map)?.flatten().collect(),
            None => stmt.query_map([], map)?.flatten().collect(),
        };
        Ok(rows)
    }

    pub fn remove(&self, id: i64) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM exceptions WHERE id = ?1", params![id])? > 0)
    }

    /// Annotate matching findings. `now` is an ISO date (`YYYY-MM-DD` or
    /// RFC3339); lexicographic comparison is correct for both. Returns how
    /// many findings were suppressed.
    pub fn apply(&self, findings: &mut [Finding], hostname: &str, now: &str) -> Result<usize> {
        let rules = self.list(Some(hostname))?;
        let mut hits = 0usize;
        for f in findings.iter_mut() {
            for r in &rules {
                if r.expires_at.as_str() <= now {
                    continue; // expired (FR-71)
                }
                if matches(&r.hostname, hostname)
                    && matches(&r.cve_id, &f.vulnerability.cve_id)
                    && matches(&r.software_name, &f.software.name)
                {
                    f.excepted = Some(ExceptionRef {
                        id: r.id,
                        owner: r.owner.clone(),
                        reason: r.reason.clone(),
                        expires_at: r.expires_at.clone(),
                    });
                    hits += 1;
                    break;
                }
            }
        }
        Ok(hits)
    }
}
```

Add `mod exceptions;` to `main.rs`.

- [x] **Step 4: Run to verify passing**

Run: `cargo test -p evedoo exceptions::`
Expected: PASS, 8 tests.

- [x] **Step 5: Commit**

```bash
git add evedoo/src/exceptions.rs evedoo/src/main.rs
git commit -m "exceptions: expiring, auditable accepted-risk rules (FR-68..FR-72)"
```

---

### Task 9: Wire the pipeline, add both subcommands, update reports and docs

**Files:**
- Modify: `evedoo/src/main.rs` (pipeline wiring, `Reassess` + `Exception` subcommands, presentation filters)
- Modify: `evedoo/src/report/csv.rs` (two columns), `evedoo/src/report/text.rs` (`--risk`)
- Modify: `PARAMETERS.md`, `spec.md` (mark section 6 implemented), `evedoo/IMPROVEMENT_ROADMAP.md` (Phase 20)

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Produces: `evedoo reassess`, `evedoo exception {add,list,remove}`, `--risk`, `--sort risk`, `--min-priority`, `--show-excepted`, `--max-age`.

- [x] **Step 1: Write the failing tests**

Add to `evedoo/src/report/csv.rs` tests:

```rust
    #[test]
    fn csv_carries_risk_columns_unconditionally() {
        // FR-67: machine formats always include the fields, so pipelines can
        // use them without anyone passing a flag.
        let result = sample_scan_result();
        let csv = generate_csv(&result).unwrap();
        let header = csv.lines().next().unwrap();
        assert!(header.contains("Risk Score"), "header was: {header}");
        assert!(header.contains("Priority"), "header was: {header}");
    }
```

Add to `evedoo/src/report/text.rs` tests:

```rust
    #[test]
    fn text_report_hides_risk_unless_asked() {
        // FR-67: default text output must not change.
        let result = sample_scan_result();
        let plain = generate_text(&result, false);
        assert!(!plain.contains("Priority:"), "risk must be opt-in in text output");
        let with_risk = generate_text(&result, true);
        assert!(with_risk.contains("Priority:"));
    }
```

- [x] **Step 2: Run to verify failure**

Run: `cargo test -p evedoo report::`
Expected: FAIL — columns absent; `generate_text` takes one argument.

- [x] **Step 3: Wire the pipeline in `run_scan`**

Replace the correlate/delta region of `run_scan` with the full ordered pipeline. Read previous state **before** writing the new snapshot:

```rust
    // --- pipeline (spec.md section 6) -----------------------------------
    let outcome = correlate::correlate(software, &matcher);
    result.findings = outcome.findings;
    result.software_without_cves = outcome.without_cves;

    let scan_time = result.scan_time.to_rfc3339();
    let history_path_str = history_path.to_str().unwrap_or("scan_history.db").to_string();

    // Risk (FR-63). Criticality comes from fleet tags when the host is
    // registered; 1.0 otherwise.
    let criticality = fleet::FleetManager::open(&history_path_str)
        .ok()
        .and_then(|f| f.tags_for(&result.hostname).ok().flatten())
        .map(|tags| risk::criticality_for(&tags))
        .unwrap_or(1.0);
    for f in &mut result.findings {
        let exploit = matcher
            .has_exploit_reference(&f.vulnerability.cve_id)
            .unwrap_or(false);
        f.risk = Some(risk::assess(&f.vulnerability, exploit, criticality));
    }

    // Exceptions (FR-70) — annotate only.
    let mut expired_note = None;
    if let Ok(store) = exceptions::ExceptionStore::open(&history_path_str) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        if let Ok(n) = store.apply(&mut result.findings, &result.hostname, &today) {
            if n > 0 {
                expired_note = Some(n);
            }
        }
    }

    // Reconcile + persist (FR-57, FR-60). Previous state must be read before
    // the snapshot is overwritten.
    if !no_history {
        if let Ok(inv) = inventory::InventoryStore::open(&history_path_str) {
            let previous_inventory: std::collections::HashSet<String> = inv
                .load(&result.hostname)
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.registry_key)
                .collect();

            if let Ok(store) = history::HistoryStore::open(&history_path_str) {
                let previous_keys = store.load_previous_keys(&result.hostname)?;
                reconcile::reconcile(
                    &mut result.findings,
                    &previous_keys,
                    &previous_inventory,
                    reconcile::Mode::Scan,
                );
                store.persist(&mut result)?;
            }

            let mut snapshot: Vec<_> =
                result.findings.iter().map(|f| f.software.clone()).collect();
            snapshot.extend(result.software_without_cves.iter().cloned());
            let _ = inv.replace(&result.hostname, &scan_time, &snapshot);
        }
    }
    if let Some(n) = expired_note {
        println!("  {n} finding(s) suppressed by active exceptions");
    }

    // Presentation filtering already happens inside `persist_then_present`,
    // which Task 5 added and both call sites already use. Do NOT recreate it.
```

`HistoryStore::apply_delta` is split into `load_previous_keys` (already private — make it `pub(crate)`) and a new `persist(&self, result: &mut ScanResult)` that writes rows and computes `resolved_findings`, without assigning statuses. Add `FleetManager::tags_for(&self, hostname: &str) -> Result<Option<String>>` returning the `tags` column.

**`mod present` and `persist_then_present` already exist — Task 5 built them.**
Do not create them. `persist_then_present(result, store, min_confidence, severity)`
lives in `main.rs`, encodes the ordering (delta tracking on the complete set,
then presentation filtering), prints the hidden-count diagnostic, and is called
from both `run_scan` and `run_remote_scan`. `history::tests` has a guard test
that fails if that ordering is swapped — verified by deliberate experiment.

Your job here is to **extend** what exists, not rebuild it:

1. Add `min_priority: Option<Priority>` and `show_excepted: bool` to the filter,
   keeping the existing confidence and severity behaviour intact.
2. Filter `result.resolved_findings` as well as `result.findings`. Today only
   the latter is filtered, so `scan -s critical` shows a Critical-only active
   list beside a resolved section still carrying Low and Medium entries.
3. Fix the diagnostic wording. It currently reads "Filtered N low-confidence
   matches" for what is now a combined confidence+severity+priority+excepted
   count, so `--severity critical` alone can blame low confidence. Report the
   count accurately without attributing a single cause.
4. Keep the ordering guard passing. If you change the shape of
   `persist_then_present`, the test in `history.rs` must still fail when the
   ordering is swapped — re-run the swap experiment and report it.



- [x] **Step 4: Add the two subcommands**

In `enum Commands`, add:

```rust
    /// Re-correlate the stored inventory against the current CVE database
    /// without contacting the host
    Reassess {
        /// CVE database file path
        #[arg(short, long, default_value = "vulndb.sqlite")]
        database: String,
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
        output: Option<String>,
        /// Show findings suppressed by an exception
        #[arg(long)]
        show_excepted: bool,
        /// History database path
        #[arg(long, default_value = "scan_history.db")]
        history: String,
    },

    /// Manage accepted-risk exceptions
    Exception {
        #[command(subcommand)]
        action: ExceptionCommands,
    },
```

```rust
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
        /// Host, or '*' for every host (must be explicit)
        #[arg(long)]
        host: Option<String>,
        /// Why this risk is accepted
        #[arg(long)]
        reason: String,
        /// Who accepted it
        #[arg(long)]
        owner: String,
        /// Expiry date, YYYY-MM-DD. Required — indefinite suppression is not
        /// expressible by design.
        #[arg(long)]
        expires: String,
        #[arg(long, default_value = "scan_history.db")]
        history: String,
    },
    /// List exceptions
    List {
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
```

The `Reassess` handler loads inventory, errors clearly when absent, warns on staleness, and runs the pipeline with `Mode::Reassess`:

```rust
        Commands::Reassess { database, host, max_age, format, output, show_excepted, history } => {
            let hostname = host.unwrap_or_else(current_hostname);
            let inv = inventory::InventoryStore::open(&history)?;
            let stored = inv.load(&hostname)?;
            if stored.is_empty() {
                anyhow::bail!(
                    "no stored inventory for {hostname}. Run `evedoo scan` first — \
                     reassessment re-correlates a previous scan, it does not collect."
                );
            }
            if let Some(ts) = inv.snapshot_time(&hostname)? {
                if let Ok(when) = chrono::DateTime::parse_from_rfc3339(&ts) {
                    let age = (chrono::Utc::now() - when.with_timezone(&chrono::Utc)).num_days();
                    println!("Inventory observed {age} day(s) ago ({ts})");
                    if age > max_age {
                        println!(
                            "  WARNING: snapshot is older than {max_age} days — this describes \
                             a machine that may have changed since."
                        );
                    }
                }
            }
            // ...correlate → risk → exceptions → reconcile(Mode::Reassess) → report.
            // Inventory is NOT rewritten: nothing was observed.
        }
```

- [x] **Step 5: Add the CSV columns and the text flag**

In `report/csv.rs`, append `"Risk Score"` and `"Priority"` to the header record and, for each of the three `write_record` sites, append the corresponding values (`""` twice where a record has no finding):

```rust
            f.risk.as_ref().map(|r| format!("{:.1}", r.score)).unwrap_or_default(),
            f.risk.as_ref().map(|r| format!("{:?}", r.tier)).unwrap_or_default(),
```

In `report/text.rs`, add a `show_risk: bool` parameter to `generate_text` and, when true, print `Priority: P2 (score 41.3)` per finding — appending ` (provisional — no EPSS)` when `!epss_known`. Update every caller.

- [x] **Step 6: Run everything, then verify end to end**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
taskkill //IM evedoo.exe //F 2>/dev/null || true
cargo build --release -p evedoo
cd evedoo
"target/release/evedoo.exe" scan -d ../cve-db-builder/vulndb.sqlite --no-history -f text | tail -5
"target/release/evedoo.exe" scan -d ../cve-db-builder/vulndb.sqlite -f text | tail -5
"target/release/evedoo.exe" reassess -d ../cve-db-builder/vulndb.sqlite | head -20
"target/release/evedoo.exe" exception add --cve CVE-2024-0001 \
  --reason "test" --owner sid --expires 2027-01-01
"target/release/evedoo.exe" exception list
```

Expected: the second scan writes an inventory snapshot; `reassess` reports the snapshot age and finds the same findings with **no `New` statuses**; `exception add` then `list` round-trips.

**Then the FR-61 regression check by hand:**

```bash
"target/release/evedoo.exe" scan -d ../cve-db-builder/vulndb.sqlite -s critical
"target/release/evedoo.exe" scan -d ../cve-db-builder/vulndb.sqlite | tail -3
```
Expected: the second run reports **0 new findings**. Before this plan it reported hundreds, because the filtered scan had marked them Resolved.

- [x] **Step 7: Update the docs**

- `PARAMETERS.md`: document `reassess`, `exception {add,list,remove}`, and the new `--risk`, `--sort risk`, `--min-priority`, `--show-excepted`, `--max-age` flags.
- `spec.md`: change the header line to say section 6 is implemented, and update the test count.
- `evedoo/IMPROVEMENT_ROADMAP.md`: add **Phase 20: Operationalisation (N1+N2+N4)** with problem, solution, the measured tier distribution, the FR-61 bug it fixed, and the final test count. Move N1/N2/N4 out of "What's next".

- [x] **Step 8: Commit**

```bash
git add -A
git commit -m "operationalisation: reassess, risk tiers, exceptions (FR-57..FR-72)"
```

---

## Self-Review

**Spec coverage:** FR-57 T4 · FR-58 T9 · FR-59 T6,T9 · FR-60 T3,T6 · FR-61 T5,T9 · FR-62 T5 · FR-63 T7 · FR-64 T7 · FR-65 T7 · FR-66 T7 · FR-67 T9 · FR-68 T8 · FR-69 T9 · FR-70 T8 · FR-71 T8 · FR-72 T8 · NFR-8 T1,T2 · DC-3 T3 · DC-5 T1. No gaps.

**Type consistency:** `RiskAssessment { score, tier, epss_known }`, `ExceptionRef { id, owner, reason, expires_at }`, and `Priority::{P1..P4}` are defined in Task 3 and used with those exact names in Tasks 7, 8 and 9. `InventoryStore::{replace, load, snapshot_time}` (Task 4) match their Task 9 call sites. `reconcile(findings, previous_keys, previous_inventory, mode)` (Task 6) matches Task 9.

**Known refactors this plan requires**, called out so they are not a surprise mid-task:
- `HistoryStore::apply_delta` splits into `load_previous_keys` (visibility widened) + `persist` — Task 9.
- `build_upgrade_command` needs no change — it is already `pub` in `matcher/cpe.rs`.
- `FleetManager::tags_for` is new — Task 9.
- `generate_text` gains a parameter — Task 9.

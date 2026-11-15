// SPDX-License-Identifier: Apache-2.0

//! Sole owner of the `scan_history.db` schema (NFR-8, DC-5).
//!
//! Feature modules own their queries but must not declare tables — every
//! structural change lands here as a numbered migration so an existing
//! database is upgraded in place. This DB holds the delta history and the
//! exception audit trail, the only irreplaceable state the tool owns, so
//! "delete and recreate" is not an available upgrade path.

use rusqlite::{Connection, Result};

/// Bump when adding a migration, and add the matching arm to `apply`.
pub const CURRENT_VERSION: i64 = 5;

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

/// v4 — Task 9b fix round, carried item 6. `exceptions::add/list/apply`
/// started canonicalising hostnames (uppercase, trimmed) to a case-insensitive
/// comparison partway through this same unreleased phase. A row written by
/// the earlier, case-sensitive `add()` — e.g. `hostname = 'host-01'` — would
/// otherwise sit in the table forever, silently unreachable by every query
/// after the fix, since none of them compare against that literal case again.
/// `TRIM` before `UPPER` mirrors `exceptions::canonical_hostname`'s own
/// `.trim().to_uppercase()`; `'*'` (the fleet-wide wildcard) is unaffected by
/// either operation.
///
/// `OR REPLACE` (M4, final whole-branch review): a plain `UPDATE` here can
/// violate `UNIQUE(hostname, cve_id, software_name)` if a pre-fix lowercase
/// row and a post-fix uppercase row already exist for the same CVE and
/// software — canonicalising the first collides it into the second. A plain
/// `UPDATE` would then fail this migration step, and `migrate()` rolls a
/// failing step back, leaving the database stuck below `CURRENT_VERSION`
/// forever: `schema::open` — and therefore every command — fails on every
/// subsequent run. `OR REPLACE` resolves the collision by keeping one row
/// instead of failing shut.
const V4: &str = "
UPDATE OR REPLACE exceptions SET hostname = UPPER(TRIM(hostname));
";

/// v5 — final whole-branch review, findings B1 and B2. `fleet.rs`'s
/// `add_asset`/`tags_for`/`get_asset`/`remove_asset`/`add_tags`/
/// `remove_tags`/`record_scan`, and `main.rs`'s local- and remote-scan
/// pipelines, started canonicalising hostnames (uppercase, trimmed) the same
/// way `exceptions` already did as of V4 — but only for writes made *after*
/// that fix landed. A `fleet_assets`, `scan_inventory` or `scan_findings` row
/// written before it — e.g. `hostname = 'prod-web-01'` from an earlier
/// `fleet add`, or `hostname = 'win-box'` from an earlier `remote-scan
/// --target win-box` — would otherwise sit unreachable forever: `tags_for`
/// silently returns `None` (criticality falls back to 1.0 instead of the
/// intended tag-driven multiplier — FR-65, the wrong direction to fail), and
/// `reassess --host` bails with "no stored inventory" even though a snapshot
/// is sitting in the table under the old case (FR-58).
///
/// `OR REPLACE` for the same reason V4 needed it (M4): a hostname-case
/// collision here must not fail this migration step and take delta tracking
/// and inventory persistence down with it for every future run.
const V5: &str = "
UPDATE OR REPLACE fleet_assets SET hostname = UPPER(TRIM(hostname));
UPDATE OR REPLACE scan_inventory SET hostname = UPPER(TRIM(hostname));
UPDATE OR REPLACE scan_findings SET hostname = UPPER(TRIM(hostname));
";

fn apply(conn: &Connection, version: i64) -> Result<()> {
    match version {
        1 => conn.execute_batch(V1),
        2 => conn.execute_batch(V2),
        3 => conn.execute_batch(V3),
        4 => conn.execute_batch(V4),
        5 => conn.execute_batch(V5),
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

    /// Carried item 6 (Task 9b fix round): a row written by the pre-fix,
    /// case-sensitive `exceptions::add()` must not be left behind as a dead
    /// rule once the app itself only ever writes and queries uppercase
    /// hostnames.
    #[test]
    fn v4_migration_upgrades_existing_exception_hostnames_to_canonical_case() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn, 1).unwrap();
        apply(&conn, 2).unwrap();
        apply(&conn, 3).unwrap();
        conn.execute_batch("PRAGMA user_version = 3;").unwrap();
        conn.execute(
            "INSERT INTO exceptions
                (hostname, cve_id, software_name, reason, owner, created_at, expires_at)
             VALUES ('host-01', 'CVE-2024-0001', 'App', 'r', 'o', 't', '2099-01-01')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO exceptions
                (hostname, cve_id, software_name, reason, owner, created_at, expires_at)
             VALUES ('*', 'CVE-2024-0002', 'App', 'r', 'o', 't', '2099-01-01')",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();

        assert_eq!(version(&conn), CURRENT_VERSION);
        let hostname: String = conn
            .query_row(
                "SELECT hostname FROM exceptions WHERE cve_id = 'CVE-2024-0001'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            hostname, "HOST-01",
            "pre-existing lowercase hostnames must be upgraded to canonical case"
        );
        let wildcard: String = conn
            .query_row(
                "SELECT hostname FROM exceptions WHERE cve_id = 'CVE-2024-0002'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(wildcard, "*", "the fleet-wide wildcard must survive the migration unchanged");
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

    /// M4: a plain `UPDATE` in a hostname-canonicalising migration can
    /// violate the table's own uniqueness constraint when a pre-fix and a
    /// post-fix row collide after canonicalisation, and a failing migration
    /// step rolls back — leaving `schema::open` (and therefore every
    /// command) failing forever. Two `exceptions` rows for the same CVE and
    /// software that only differ by hostname case are exactly that
    /// collision. Before the `OR REPLACE` fix, this test fails: `migrate`
    /// returns `Err` instead of collapsing the collision.
    #[test]
    fn v4_migration_does_not_fail_permanently_on_a_hostname_case_collision() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn, 1).unwrap();
        apply(&conn, 2).unwrap();
        apply(&conn, 3).unwrap();
        conn.execute_batch("PRAGMA user_version = 3;").unwrap();
        for hostname in ["host-01", "HOST-01"] {
            conn.execute(
                "INSERT INTO exceptions
                    (hostname, cve_id, software_name, reason, owner, created_at, expires_at)
                 VALUES (?1, 'CVE-2024-0001', 'App', 'r', 'o', 't', '2099-01-01')",
                [hostname],
            )
            .unwrap();
        }

        let result = migrate(&conn);
        assert!(
            result.is_ok(),
            "a hostname-case collision must not fail the migration permanently: {result:?}"
        );
        assert_eq!(version(&conn), CURRENT_VERSION);

        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM exceptions WHERE cve_id = 'CVE-2024-0001'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            remaining, 1,
            "the colliding rows must collapse to one row, not fail the whole migration"
        );
    }

    /// B1/B2: a `fleet_assets`, `scan_inventory` or `scan_findings` row
    /// written before `fleet.rs`/`main.rs` started canonicalising hostnames
    /// must be folded into canonical case too, or it sits unreachable by
    /// every query written after the fix — the same defect V4 already fixed
    /// for `exceptions`, now extended to the tables B1 and B2 identify.
    #[test]
    fn v5_migration_upgrades_fleet_scan_inventory_and_scan_findings_hostnames() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn, 1).unwrap();
        apply(&conn, 2).unwrap();
        apply(&conn, 3).unwrap();
        apply(&conn, 4).unwrap();
        conn.execute_batch("PRAGMA user_version = 4;").unwrap();

        conn.execute(
            "INSERT INTO fleet_assets (hostname, tags, added_at)
             VALUES ('prod-web-01', 'critical', 't')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO scan_inventory (hostname, registry_key, name, architecture, scan_time)
             VALUES ('prod-web-01', 'pe://a.exe', 'App', 'x64', 't')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO scan_findings (hostname, cve_id, software_name, first_seen, last_seen)
             VALUES ('prod-web-01', 'CVE-2024-0001', 'App', 't', 't')",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();
        assert_eq!(version(&conn), CURRENT_VERSION);

        let fleet_host: String = conn
            .query_row("SELECT hostname FROM fleet_assets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fleet_host, "PROD-WEB-01");
        let inv_host: String = conn
            .query_row("SELECT hostname FROM scan_inventory", [], |r| r.get(0))
            .unwrap();
        assert_eq!(inv_host, "PROD-WEB-01");
        let findings_host: String = conn
            .query_row("SELECT hostname FROM scan_findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(findings_host, "PROD-WEB-01");
    }

    /// Same collision-must-not-fail-permanently property as V4's own test,
    /// pinned for V5's `fleet_assets` (single-column `UNIQUE(hostname)`,
    /// the tightest constraint of the three tables V5 touches).
    #[test]
    fn v5_migration_does_not_fail_permanently_on_a_fleet_hostname_case_collision() {
        let conn = Connection::open_in_memory().unwrap();
        apply(&conn, 1).unwrap();
        apply(&conn, 2).unwrap();
        apply(&conn, 3).unwrap();
        apply(&conn, 4).unwrap();
        conn.execute_batch("PRAGMA user_version = 4;").unwrap();

        conn.execute("INSERT INTO fleet_assets (hostname, added_at) VALUES ('host1', 't')", [])
            .unwrap();
        conn.execute("INSERT INTO fleet_assets (hostname, added_at) VALUES ('HOST1', 't')", [])
            .unwrap();

        let result = migrate(&conn);
        assert!(
            result.is_ok(),
            "a fleet hostname-case collision must not fail the migration permanently: {result:?}"
        );
        assert_eq!(version(&conn), CURRENT_VERSION);

        let remaining: i64 =
            conn.query_row("SELECT COUNT(*) FROM fleet_assets", [], |r| r.get(0)).unwrap();
        assert_eq!(remaining, 1);
    }
}

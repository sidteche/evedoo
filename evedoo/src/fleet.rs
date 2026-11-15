//! Fleet management — asset tagging and multi-target orchestration.
//!
//! Stores registered assets (local or remote) with tags and connection
//! metadata in the same SQLite history database. Enables fleet-level
//! views and batch scanning across multiple hosts.
//!
//! SPDX-License-Identifier: Apache-2.0

use chrono::Utc;
use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::Result;

/// A registered fleet asset (machine to scan).
#[derive(Debug, Clone, Serialize)]
pub struct Asset {
    pub id: i64,
    pub hostname: String,
    pub display_name: Option<String>,
    pub tags: Vec<String>,
    pub is_remote: bool,
    pub port: u16,
    pub username: Option<String>,
    pub use_ssl: bool,
    pub added_at: String,
    pub last_scan: Option<String>,
    pub total_findings: i64,
}

/// Fleet manager backed by the scan history SQLite database.
pub struct FleetManager {
    conn: Connection,
}

/// Canonicalises `hostname` the same way `exceptions::canonical_hostname` and
/// every other hostname-keyed store in this crate does (B1, final
/// whole-branch review). Windows hostnames are case-insensitive, but every
/// query in this module is an exact SQL `=`. Without this, `fleet add
/// prod-web-01` followed by a scan reporting `PROD-WEB-01` (the conventional
/// `COMPUTERNAME` case) makes `tags_for` return `None` — silently defeating
/// FR-65's criticality lookup in the insecure direction: risk scores land
/// ~20% low, findings drop a tier, and `--min-priority` can hide them, with
/// no diagnostic anywhere because the caller treats "not in the fleet" as a
/// normal, silent case (`.ok().and_then(...).unwrap_or(1.0)` in main.rs).
/// Applied at every public method that takes a hostname, so callers never
/// need to think about case themselves.
fn canon(hostname: &str) -> String {
    crate::exceptions::canonical_hostname(hostname)
}

impl FleetManager {
    /// Open the fleet database (same file as scan history).
    pub fn open(path: &str) -> Result<Self> {
        // Schema and migrations are owned by `crate::schema` (NFR-8).
        let conn = crate::schema::open(path)?;
        Ok(Self { conn })
    }

    /// Register a new asset in the fleet.
    #[allow(clippy::too_many_arguments)]
    pub fn add_asset(
        &self,
        hostname: &str,
        display_name: Option<&str>,
        tags: &[String],
        is_remote: bool,
        port: u16,
        username: Option<&str>,
        use_ssl: bool,
    ) -> Result<i64> {
        let hostname = canon(hostname);
        let now = Utc::now().to_rfc3339();
        let tags_str = tags.join(",");

        self.conn.execute(
            "INSERT INTO fleet_assets
                (hostname, display_name, tags, is_remote, port, username, use_ssl, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![hostname, display_name, tags_str, is_remote, port, username, use_ssl, now],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Remove an asset by hostname.
    pub fn remove_asset(&self, hostname: &str) -> Result<bool> {
        let hostname = canon(hostname);
        let affected = self.conn.execute(
            "DELETE FROM fleet_assets WHERE hostname = ?1",
            params![hostname],
        )?;
        Ok(affected > 0)
    }

    /// List all registered assets, optionally filtered by tag.
    pub fn list_assets(&self, tag_filter: Option<&str>) -> Result<Vec<Asset>> {
        let query = match tag_filter {
            Some(_) => {
                "SELECT id, hostname, display_name, tags, is_remote, port, username,
                        use_ssl, added_at, last_scan, total_findings
                 FROM fleet_assets WHERE tags LIKE ?1 ORDER BY hostname"
            }
            None => {
                "SELECT id, hostname, display_name, tags, is_remote, port, username,
                        use_ssl, added_at, last_scan, total_findings
                 FROM fleet_assets ORDER BY hostname"
            }
        };

        let mut stmt = self.conn.prepare(query)?;
        let rows = if let Some(tag) = tag_filter {
            stmt.query_map(params![format!("%{}%", tag)], Self::row_to_asset)?
        } else {
            stmt.query_map([], Self::row_to_asset)?
        };

        let mut assets = Vec::new();
        for row in rows.flatten() {
            assets.push(row);
        }
        Ok(assets)
    }

    /// Get a single asset by hostname.
    pub fn get_asset(&self, hostname: &str) -> Result<Option<Asset>> {
        let hostname = canon(hostname);
        let result = self.conn.query_row(
            "SELECT id, hostname, display_name, tags, is_remote, port, username,
                    use_ssl, added_at, last_scan, total_findings
             FROM fleet_assets WHERE hostname = ?1",
            params![hostname],
            Self::row_to_asset,
        );

        match result {
            Ok(asset) => Ok(Some(asset)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Comma-separated tags for a registered asset, or `None` if the host
    /// isn't in the fleet — the normal single-machine case, where risk
    /// scoring falls back to criticality 1.0 (FR-65).
    pub fn tags_for(&self, hostname: &str) -> Result<Option<String>> {
        let hostname = canon(hostname);
        let result = self.conn.query_row(
            "SELECT tags FROM fleet_assets WHERE hostname = ?1",
            params![hostname],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(tags) => Ok(Some(tags)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Add tags to an existing asset (append, no duplicates).
    pub fn add_tags(&self, hostname: &str, new_tags: &[String]) -> Result<bool> {
        let hostname = canon(hostname);
        let current = match self.get_asset(&hostname)? {
            Some(a) => a,
            None => return Ok(false),
        };

        let mut tags = current.tags;
        for t in new_tags {
            let normalized = t.trim().to_lowercase();
            if !normalized.is_empty() && !tags.contains(&normalized) {
                tags.push(normalized);
            }
        }

        let tags_str = tags.join(",");
        self.conn.execute(
            "UPDATE fleet_assets SET tags = ?1 WHERE hostname = ?2",
            params![tags_str, hostname],
        )?;
        Ok(true)
    }

    /// Remove specific tags from an asset.
    pub fn remove_tags(&self, hostname: &str, remove_tags: &[String]) -> Result<bool> {
        let hostname = canon(hostname);
        let current = match self.get_asset(&hostname)? {
            Some(a) => a,
            None => return Ok(false),
        };

        let remove_set: Vec<String> = remove_tags.iter().map(|t| t.trim().to_lowercase()).collect();
        let tags: Vec<String> = current
            .tags
            .into_iter()
            .filter(|t| !remove_set.contains(t))
            .collect();

        let tags_str = tags.join(",");
        self.conn.execute(
            "UPDATE fleet_assets SET tags = ?1 WHERE hostname = ?2",
            params![tags_str, hostname],
        )?;
        Ok(true)
    }

    /// Update the last_scan timestamp and finding count for an asset.
    /// Called after each scan completes (local or remote) to keep fleet stats current.
    #[allow(dead_code)]
    pub fn record_scan(&self, hostname: &str, finding_count: i64) -> Result<()> {
        let hostname = canon(hostname);
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE fleet_assets SET last_scan = ?1, total_findings = ?2 WHERE hostname = ?3",
            params![now, finding_count, hostname],
        )?;
        Ok(())
    }

    /// Get fleet-level summary statistics.
    pub fn summary(&self) -> Result<FleetSummary> {
        let total_assets: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM fleet_assets", [], |row| row.get(0))?;

        let remote_assets: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM fleet_assets WHERE is_remote = 1",
            [],
            |row| row.get(0),
        )?;

        let total_findings: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(total_findings), 0) FROM fleet_assets",
            [],
            |row| row.get(0),
        )?;

        let never_scanned: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM fleet_assets WHERE last_scan IS NULL",
            [],
            |row| row.get(0),
        )?;

        // Get unique tags
        let mut stmt = self.conn.prepare("SELECT tags FROM fleet_assets WHERE tags != ''")?;
        let tag_rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut all_tags: Vec<String> = Vec::new();
        for row in tag_rows.flatten() {
            for tag in row.split(',') {
                let t = tag.trim().to_string();
                if !t.is_empty() && !all_tags.contains(&t) {
                    all_tags.push(t);
                }
            }
        }
        all_tags.sort();

        Ok(FleetSummary {
            total_assets,
            local_assets: total_assets - remote_assets,
            remote_assets,
            total_findings,
            never_scanned,
            tags: all_tags,
        })
    }

    fn row_to_asset(row: &rusqlite::Row) -> rusqlite::Result<Asset> {
        let tags_str: String = row.get(3)?;
        let tags: Vec<String> = if tags_str.is_empty() {
            Vec::new()
        } else {
            tags_str.split(',').map(|s| s.trim().to_string()).collect()
        };

        Ok(Asset {
            id: row.get(0)?,
            hostname: row.get(1)?,
            display_name: row.get(2)?,
            tags,
            is_remote: row.get::<_, i64>(4)? != 0,
            port: row.get::<_, i64>(5)? as u16,
            username: row.get(6)?,
            use_ssl: row.get::<_, i64>(7)? != 0,
            added_at: row.get(8)?,
            last_scan: row.get(9)?,
            total_findings: row.get(10)?,
        })
    }
}

/// Fleet-level summary statistics.
#[derive(Debug, Clone, Serialize)]
pub struct FleetSummary {
    pub total_assets: i64,
    pub local_assets: i64,
    pub remote_assets: i64,
    pub total_findings: i64,
    pub never_scanned: i64,
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> FleetManager {
        FleetManager::open(":memory:").unwrap()
    }

    #[test]
    fn add_and_list_assets() {
        let mgr = temp_db();
        mgr.add_asset("server01", Some("Web Server"), &["prod".into(), "web".into()], true, 5986, Some("admin"), true).unwrap();
        mgr.add_asset("localhost", None, &[], false, 5985, None, false).unwrap();

        let assets = mgr.list_assets(None).unwrap();
        assert_eq!(assets.len(), 2);
        // Stored canonicalised (uppercase, trimmed) per B1 — see `canon`.
        assert_eq!(assets[0].hostname, "LOCALHOST");
        assert_eq!(assets[1].hostname, "SERVER01");
        assert_eq!(assets[1].display_name, Some("Web Server".to_string()));
        assert_eq!(assets[1].tags, vec!["prod", "web"]);
        assert!(assets[1].is_remote);
        assert_eq!(assets[1].port, 5986);
        assert!(assets[1].use_ssl);
    }

    #[test]
    fn filter_by_tag() {
        let mgr = temp_db();
        mgr.add_asset("web1", None, &["prod".into(), "web".into()], true, 5985, None, false).unwrap();
        mgr.add_asset("db1", None, &["prod".into(), "database".into()], true, 5985, None, false).unwrap();
        mgr.add_asset("dev1", None, &["dev".into()], true, 5985, None, false).unwrap();

        let prod = mgr.list_assets(Some("prod")).unwrap();
        assert_eq!(prod.len(), 2);

        let db = mgr.list_assets(Some("database")).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(db[0].hostname, "DB1");
    }

    #[test]
    fn add_and_remove_tags() {
        let mgr = temp_db();
        mgr.add_asset("host1", None, &["web".into()], false, 5985, None, false).unwrap();

        mgr.add_tags("host1", &["prod".into(), "critical".into()]).unwrap();
        let asset = mgr.get_asset("host1").unwrap().unwrap();
        assert_eq!(asset.tags, vec!["web", "prod", "critical"]);

        // No duplicates
        mgr.add_tags("host1", &["web".into()]).unwrap();
        let asset = mgr.get_asset("host1").unwrap().unwrap();
        assert_eq!(asset.tags.len(), 3);

        // Remove
        mgr.remove_tags("host1", &["web".into()]).unwrap();
        let asset = mgr.get_asset("host1").unwrap().unwrap();
        assert_eq!(asset.tags, vec!["prod", "critical"]);
    }

    #[test]
    fn remove_asset() {
        let mgr = temp_db();
        mgr.add_asset("gone", None, &[], false, 5985, None, false).unwrap();
        assert!(mgr.remove_asset("gone").unwrap());
        assert!(!mgr.remove_asset("gone").unwrap()); // already gone
        assert_eq!(mgr.list_assets(None).unwrap().len(), 0);
    }

    #[test]
    fn record_scan_updates_stats() {
        let mgr = temp_db();
        mgr.add_asset("host1", None, &[], false, 5985, None, false).unwrap();
        mgr.record_scan("host1", 42).unwrap();

        let asset = mgr.get_asset("host1").unwrap().unwrap();
        assert_eq!(asset.total_findings, 42);
        assert!(asset.last_scan.is_some());
    }

    #[test]
    fn fleet_summary() {
        let mgr = temp_db();
        mgr.add_asset("local1", None, &["dev".into()], false, 5985, None, false).unwrap();
        mgr.add_asset("remote1", None, &["prod".into()], true, 5986, Some("admin"), true).unwrap();
        mgr.add_asset("remote2", None, &["prod".into(), "web".into()], true, 5985, None, false).unwrap();

        mgr.record_scan("local1", 5).unwrap();
        mgr.record_scan("remote1", 12).unwrap();

        let summary = mgr.summary().unwrap();
        assert_eq!(summary.total_assets, 3);
        assert_eq!(summary.local_assets, 1);
        assert_eq!(summary.remote_assets, 2);
        assert_eq!(summary.total_findings, 17);
        assert_eq!(summary.never_scanned, 1);
        assert_eq!(summary.tags, vec!["dev", "prod", "web"]);
    }

    #[test]
    fn get_nonexistent_asset_returns_none() {
        let mgr = temp_db();
        assert!(mgr.get_asset("nope").unwrap().is_none());
    }

    #[test]
    fn tags_for_reads_the_tags_column() {
        let mgr = temp_db();
        mgr.add_asset("host1", None, &["prod".into(), "critical".into()], false, 5985, None, false).unwrap();
        assert_eq!(mgr.tags_for("host1").unwrap().as_deref(), Some("prod,critical"));
        assert_eq!(mgr.tags_for("unregistered-host").unwrap(), None);
    }

    #[test]
    fn duplicate_hostname_rejected() {
        let mgr = temp_db();
        mgr.add_asset("dup", None, &[], false, 5985, None, false).unwrap();
        assert!(mgr.add_asset("dup", None, &[], false, 5985, None, false).is_err());
    }

    /// B1 (final whole-branch review): `fleet add prod-web-01 --tags
    /// critical` followed by a scan on that machine, where `COMPUTERNAME`
    /// reports `PROD-WEB-01`, must still find the tags — `tags_for`
    /// returning `None` here means `risk::criticality_for` never runs and
    /// risk scores land ~20% low with no diagnostic anywhere (main.rs
    /// swallows the miss via `.ok().and_then(...).unwrap_or(1.0)`). This is
    /// the round-trip invariant no single task's own tests covered.
    #[test]
    fn a_differently_cased_hostname_round_trips_through_fleet() {
        let mgr = temp_db();
        mgr.add_asset("prod-web-01", None, &["critical".into()], false, 5985, None, false).unwrap();

        assert_eq!(
            mgr.tags_for("PROD-WEB-01").unwrap().as_deref(),
            Some("critical"),
            "a scan reporting the conventional uppercase COMPUTERNAME must still find tags \
             registered in a different case"
        );
        assert!(mgr.get_asset("PROD-WEB-01").unwrap().is_some());

        // And the reverse direction: registered uppercase, queried lowercase.
        let mgr2 = temp_db();
        mgr2.add_asset("PROD-WEB-01", None, &["critical".into()], false, 5985, None, false).unwrap();
        assert_eq!(mgr2.tags_for("prod-web-01").unwrap().as_deref(), Some("critical"));
    }

    #[test]
    fn add_tags_remove_tags_and_record_scan_are_case_insensitive() {
        let mgr = temp_db();
        mgr.add_asset("host-01", None, &[], false, 5985, None, false).unwrap();

        assert!(mgr.add_tags("HOST-01", &["prod".into()]).unwrap());
        assert_eq!(mgr.get_asset("host-01").unwrap().unwrap().tags, vec!["prod"]);

        assert!(mgr.remove_tags("Host-01", &["prod".into()]).unwrap());
        assert!(mgr.get_asset("host-01").unwrap().unwrap().tags.is_empty());

        mgr.record_scan("HOST-01", 9).unwrap();
        let asset = mgr.get_asset("host-01").unwrap().unwrap();
        assert_eq!(asset.total_findings, 9);
        assert!(asset.last_scan.is_some());
    }

    #[test]
    fn remove_asset_is_case_insensitive() {
        let mgr = temp_db();
        mgr.add_asset("gone", None, &[], false, 5985, None, false).unwrap();
        assert!(mgr.remove_asset("GONE").unwrap());
        assert_eq!(mgr.list_assets(None).unwrap().len(), 0);
    }
}
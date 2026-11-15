// SPDX-License-Identifier: Apache-2.0

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
    ///
    /// Refuses the write and returns `Ok(0)` if `items` is empty, rather than
    /// wiping a good snapshot with nothing — a degraded scan that returns
    /// zero results must not destroy the sole input `reassess` has. Callers
    /// must not treat `Ok(0)` as an ordinary "wrote nothing" success; it
    /// means the write was refused and the prior snapshot (if any) survives
    /// untouched, including its `scan_time`.
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
    /// never been scanned. Drives the staleness warning in FR-59, surfaced
    /// by `evedoo reassess`.
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

    #[test]
    fn empty_batch_preserves_the_prior_snapshot() {
        // A scanner that degrades to zero results (a partial remote failure
        // that does not itself error) must not destroy the only inventory we
        // hold: it is the sole input to `reassess`.
        let s = store();
        s.replace("HOST", "t1", &[sw("Alpha", "pe://a.exe")]).unwrap();

        let n = s.replace("HOST", "t2", &[]).unwrap();
        assert_eq!(n, 0);

        let back = s.load("HOST").unwrap();
        assert_eq!(back.len(), 1, "prior snapshot must survive an empty batch");
        assert_eq!(back[0].name, "Alpha");
        assert_eq!(
            s.snapshot_time("HOST").unwrap().as_deref(),
            Some("t1"),
            "scan_time must not be touched by the refused empty write either"
        );
    }

    #[test]
    fn architecture_round_trips_x86_and_unknown() {
        let s = store();
        let mut x86 = sw("X86App", "pe://x86.exe");
        x86.architecture = Architecture::X86;
        let mut unknown = sw("UnknownApp", "pe://unknown.exe");
        unknown.architecture = Architecture::Unknown;

        s.replace("HOST", "t", &[x86, unknown]).unwrap();
        let back = s.load("HOST").unwrap();

        let x86_back = back.iter().find(|i| i.name == "X86App").unwrap();
        assert_eq!(x86_back.architecture, Architecture::X86);
        let unknown_back = back.iter().find(|i| i.name == "UnknownApp").unwrap();
        assert_eq!(unknown_back.architecture, Architecture::Unknown);
    }
}

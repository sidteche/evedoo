//! CVE matching module.
//!
//! SPDX-License-Identifier: Apache-2.0

mod cpe;
mod dict;
mod index;

pub use cpe::{build_upgrade_command, CveMatcher};

#[cfg(test)]
pub(crate) mod tests_support {
    use super::CveMatcher;

    /// A matcher over an empty in-memory CVE database — correlates nothing.
    /// Used by pipeline tests that care about plumbing, not matching.
    ///
    /// `name` must be unique per caller: tests run in parallel, and a shared
    /// fixture directory means one test's `remove_dir_all` below can delete
    /// the directory — or the open SQLite file inside it — out from under
    /// another test that is opening or using it (see cpe.rs's
    /// `build_expanded_gate_db`, which has the same requirement for the same
    /// reason). The process id is folded in too, so two concurrent `cargo
    /// test` invocations on one machine (e.g. a manual run overlapping CI)
    /// don't collide on the same path either.
    pub(crate) fn empty_matcher(name: &str) -> CveMatcher {
        let dir = std::env::temp_dir()
            .join(format!("evedoo_empty_matcher_{name}_{}", std::process::id()));
        // Fresh directory every run: `CREATE TABLE IF NOT EXISTS` below would
        // otherwise silently reuse a leftover fixture from an earlier schema,
        // so a schema edit here takes effect on CI but not on a developer
        // machine that already ran the tests once (see history.rs's own
        // fixtures, which already remove_dir_all first). Per-caller naming
        // (above) means this only ever removes this test's own leftovers.
        let _ = std::fs::remove_dir_all(&dir);
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
                 display_name_pattern TEXT, cpe_vendor TEXT, cpe_product TEXT,
                 confidence REAL DEFAULT 1.0);
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

//! In-memory CPE index for sub-second scans.
//!
//! Phase 4: loads every row of `cpe_matches` once at matcher startup and
//! builds two hash indices:
//!
//! * `by_vendor_product` — keyed on `(vendor, product)` for the strict
//!   curated-mapping and publisher-correlation lookups
//! * `by_product` — keyed on `product` alone for the Layer 3 fallback path
//!
//! Each index stores `u32` offsets into a flat `rows: Vec<IndexedCpe>` so we
//! only pay for the row data once, regardless of how many indices reference it.
//!
//! Memory footprint (measured against the 3M-row production DB): ~240 MB,
//! one-shot ~8 s startup cost, traded against a ~2-order-of-magnitude drop in
//! per-software lookup latency (SQLite prepared statements → `HashMap::get`).
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::Instant;

use rusqlite::Connection;
use tracing::info;

use crate::error::Result;
use crate::models::CpeMatchRecord;

/// A single row from `cpe_matches`, held in memory.
///
/// Intentionally kept in the same shape as [`CpeMatchRecord`] so the matcher
/// can clone an `IndexedCpe` into an owned record with no further mapping.
#[derive(Debug, Clone)]
pub struct IndexedCpe {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    pub version_start_including: Option<String>,
    pub version_end_excluding: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub target_sw: Option<String>,
}

impl IndexedCpe {
    fn to_record(&self) -> CpeMatchRecord {
        CpeMatchRecord {
            cve_id: self.cve_id.clone(),
            version: self.version.clone(),
            version_start_including: self.version_start_including.clone(),
            version_end_excluding: self.version_end_excluding.clone(),
            version_start_excluding: self.version_start_excluding.clone(),
            version_end_including: self.version_end_including.clone(),
            target_sw: self.target_sw.clone(),
        }
    }
}

/// Flat row store plus the two lookup indices.
pub struct CpeIndex {
    rows: Vec<IndexedCpe>,
    by_vendor_product: HashMap<(String, String), Vec<u32>>,
    by_product: HashMap<String, Vec<u32>>,
}

impl CpeIndex {
    /// Stream every row of `cpe_matches` into memory and build the indices.
    ///
    /// This is a one-shot cost at matcher construction time. Uses a streaming
    /// `query_map` so we never materialise the full result set twice.
    pub fn build(conn: &Connection) -> Result<Self> {
        let start = Instant::now();

        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cpe_matches", [], |row| row.get(0))
            .unwrap_or(0);
        info!(
            "Loading {} CPE configurations into in-memory index...",
            row_count
        );

        // Applicability filters (Phase: correlation precision):
        // - vulnerable = 1: NVD AND-configurations mark the "running on"
        //   side with vulnerable=0 — those rows are context, not findings.
        // - platform: this is a Windows scanner; rows scoped to linux/macos
        //   builds can never apply. NULL/windows/anything-else stays in.
        const FILTER: &str =
            " FROM cpe_matches
             WHERE vulnerable = 1
               AND (platform IS NULL OR platform NOT IN ('linux', 'macos'))";

        // target_sw only exists in databases built after the column was
        // added; fall back to selecting without it so older DBs keep working
        // (rows then carry target_sw = NULL, which gates permissively).
        let with_target_sw = format!(
            "SELECT cve_id, vendor, product, version,
                    version_start_including, version_end_excluding,
                    version_start_excluding, version_end_including, target_sw{}",
            FILTER
        );
        let without_target_sw = format!(
            "SELECT cve_id, vendor, product, version,
                    version_start_including, version_end_excluding,
                    version_start_excluding, version_end_including, NULL{}",
            FILTER
        );

        let mut stmt = match conn.prepare(&with_target_sw) {
            Ok(s) => s,
            Err(_) => {
                info!("cpe_matches has no target_sw column — rebuild the DB with cve-db-builder to enable ecosystem gating");
                conn.prepare(&without_target_sw)?
            }
        };

        let iter = stmt.query_map([], |row| {
            Ok(IndexedCpe {
                cve_id: row.get(0)?,
                // Decode CPE 2.3 escapes (`notepad\+\+` -> `notepad++`) so
                // names from databases built before cve-db-builder decoded
                // them still match. See normalize::cpe_name.
                vendor: crate::normalize::cpe_name::unescape(&row.get::<_, String>(1)?)
                    .into_owned(),
                product: crate::normalize::cpe_name::unescape(&row.get::<_, String>(2)?)
                    .into_owned(),
                version: row.get(3)?,
                version_start_including: row.get(4)?,
                version_end_excluding: row.get(5)?,
                version_start_excluding: row.get(6)?,
                version_end_including: row.get(7)?,
                target_sw: row.get(8)?,
            })
        })?;

        let capacity = row_count.max(0) as usize;
        let mut rows: Vec<IndexedCpe> = Vec::with_capacity(capacity);
        let mut by_vendor_product: HashMap<(String, String), Vec<u32>> =
            HashMap::with_capacity(16_384);
        let mut by_product: HashMap<String, Vec<u32>> = HashMap::with_capacity(16_384);

        for row in iter {
            let row = row?;
            let idx = rows.len() as u32;
            by_vendor_product
                .entry((row.vendor.clone(), row.product.clone()))
                .or_default()
                .push(idx);
            by_product
                .entry(row.product.clone())
                .or_default()
                .push(idx);
            rows.push(row);
        }

        let elapsed = start.elapsed();
        info!(
            "CPE index ready: {} rows, {} (vendor,product) keys, {} products ({} ms)",
            rows.len(),
            by_vendor_product.len(),
            by_product.len(),
            elapsed.as_millis()
        );

        Ok(Self {
            rows,
            by_vendor_product,
            by_product,
        })
    }

    /// Strict lookup — returns every row matching `(vendor, product)` exactly.
    pub fn find_strict(&self, vendor: &str, product: &str) -> Vec<CpeMatchRecord> {
        // Two-string allocation per call is fine — this is called O(apps)
        // times per scan, not per row. If profiling ever shows this as hot,
        // switch to a `Borrow`-based key wrapper.
        let key = (vendor.to_string(), product.to_string());
        match self.by_vendor_product.get(&key) {
            Some(indices) => indices
                .iter()
                .map(|&i| self.rows[i as usize].to_record())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Product-only fallback — every row whose product matches, regardless
    /// of vendor. Used by Layer 3 of the matcher.
    pub fn find_by_product(&self, product: &str) -> Vec<CpeMatchRecord> {
        match self.by_product.get(product) {
            Some(indices) => indices
                .iter()
                .map(|&i| self.rows[i as usize].to_record())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Total row count — exposed for logging / stats.
    pub fn len(&self) -> usize {
        self.rows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE cpe_matches (
                cve_id TEXT, vendor TEXT, product TEXT, version TEXT,
                version_start_including TEXT, version_end_excluding TEXT,
                version_start_excluding TEXT, version_end_including TEXT,
                platform TEXT, vulnerable INTEGER
            );
            INSERT INTO cpe_matches VALUES
                ('CVE-2024-0001', 'google',  'chrome',  '1.0', NULL, NULL, NULL, NULL, NULL, 1),
                ('CVE-2024-0002', 'google',  'chrome',  NULL,  '1.0', '2.0', NULL, NULL, NULL, 1),
                ('CVE-2024-0003', 'mozilla', 'firefox', '90.0', NULL, NULL, NULL, NULL, NULL, 1),
                ('CVE-2024-0004', 'oracle',  'chrome',  '50.0', NULL, NULL, NULL, NULL, NULL, 1),
                -- "running on" half of an AND-configuration: not a finding
                ('CVE-2024-0005', 'google',  'chrome',  '1.0', NULL, NULL, NULL, NULL, NULL, 0),
                -- linux-only build: can never apply on a Windows scanner
                ('CVE-2024-0006', 'google',  'chrome',  '1.0', NULL, NULL, NULL, NULL, 'linux', 1);
            "#,
        )
        .unwrap();
        conn
    }

    #[test]
    fn strict_lookup_matches_vendor_and_product() {
        let conn = mem_db();
        let index = CpeIndex::build(&conn).unwrap();

        // google+chrome has two rows (CVE-2024-0001, CVE-2024-0002).
        // oracle+chrome (CVE-2024-0004) must NOT leak into strict results.
        let hits = index.find_strict("google", "chrome");
        let ids: std::collections::HashSet<_> =
            hits.iter().map(|r| r.cve_id.clone()).collect();
        assert_eq!(hits.len(), 2);
        assert!(ids.contains("CVE-2024-0001"));
        assert!(ids.contains("CVE-2024-0002"));
        assert!(!ids.contains("CVE-2024-0004"));
    }

    #[test]
    fn strict_lookup_returns_empty_on_miss() {
        let conn = mem_db();
        let index = CpeIndex::build(&conn).unwrap();

        assert!(index.find_strict("nobody", "nothing").is_empty());
        assert!(index.find_strict("google", "firefox").is_empty());
    }

    #[test]
    fn product_only_lookup_crosses_vendors() {
        let conn = mem_db();
        let index = CpeIndex::build(&conn).unwrap();

        // "chrome" appears under both google AND oracle in the fixture.
        // Product-only lookup must return all three rows regardless of vendor.
        let hits = index.find_by_product("chrome");
        let ids: std::collections::HashSet<_> =
            hits.iter().map(|r| r.cve_id.clone()).collect();
        assert_eq!(hits.len(), 3);
        assert!(ids.contains("CVE-2024-0001")); // google
        assert!(ids.contains("CVE-2024-0002")); // google
        assert!(ids.contains("CVE-2024-0004")); // oracle
    }

    #[test]
    fn preserves_range_fields_through_index() {
        let conn = mem_db();
        let index = CpeIndex::build(&conn).unwrap();

        let hits = index.find_strict("google", "chrome");
        // CVE-2024-0002 has a version_start_including = "1.0"
        let ranged = hits.iter().find(|r| r.cve_id == "CVE-2024-0002").unwrap();
        assert_eq!(ranged.version_start_including.as_deref(), Some("1.0"));
        assert_eq!(ranged.version_end_excluding.as_deref(), Some("2.0"));
    }

    #[test]
    fn row_count_matches_input() {
        let conn = mem_db();
        let index = CpeIndex::build(&conn).unwrap();
        // 6 inserted; vulnerable=0 and platform='linux' rows are excluded.
        assert_eq!(index.len(), 4);
    }

    #[test]
    fn excludes_non_vulnerable_and_foreign_platform_rows() {
        let conn = mem_db();
        let index = CpeIndex::build(&conn).unwrap();
        let ids: std::collections::HashSet<_> = index
            .find_strict("google", "chrome")
            .iter()
            .map(|r| r.cve_id.clone())
            .collect();
        assert!(
            !ids.contains("CVE-2024-0005"),
            "vulnerable=0 row must be excluded"
        );
        assert!(
            !ids.contains("CVE-2024-0006"),
            "linux-only row must be excluded"
        );
    }

    /// Load-and-query regression test: 50k rows across 200 synthetic products
    /// must build and serve 1,000 strict lookups in under the ceiling. The
    /// ceiling is deliberately loose (5 s) — we are guarding against
    /// *order-of-magnitude* regressions (e.g. someone reintroduces a linear
    /// scan per lookup), not measuring absolute throughput. Production DBs
    /// run ~60× bigger and finish in ~1.5 s on a developer laptop.
    #[test]
    fn build_and_lookup_scale_under_ceiling() {
        use std::time::Instant;

        const ROWS: usize = 50_000;
        const PRODUCTS: usize = 200;
        const LOOKUPS: usize = 1_000;
        const CEILING_MS: u128 = 5_000;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE cpe_matches (
                cve_id TEXT, vendor TEXT, product TEXT, version TEXT,
                version_start_including TEXT, version_end_excluding TEXT,
                version_start_excluding TEXT, version_end_including TEXT,
                platform TEXT, vulnerable INTEGER
            );
            "#,
        )
        .unwrap();

        // Batch insert in one transaction to keep fixture build time reasonable.
        let tx = conn.unchecked_transaction().unwrap();
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO cpe_matches VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, 1)",
                )
                .unwrap();
            for i in 0..ROWS {
                let vendor = format!("vendor{}", i % PRODUCTS);
                let product = format!("product{}", i % PRODUCTS);
                let cve_id = format!("CVE-9999-{:05}", i);
                stmt.execute(rusqlite::params![cve_id, vendor, product]).unwrap();
            }
        }
        tx.commit().unwrap();

        let start = Instant::now();
        let index = CpeIndex::build(&conn).unwrap();
        let build_ms = start.elapsed().as_millis();

        assert_eq!(index.len(), ROWS);

        let start = Instant::now();
        let mut total_hits = 0usize;
        for i in 0..LOOKUPS {
            let vendor = format!("vendor{}", i % PRODUCTS);
            let product = format!("product{}", i % PRODUCTS);
            total_hits += index.find_strict(&vendor, &product).len();
        }
        let lookup_ms = start.elapsed().as_millis();

        // Every lookup must return the same number of rows (ROWS / PRODUCTS).
        assert_eq!(total_hits, LOOKUPS * (ROWS / PRODUCTS));

        let elapsed = build_ms + lookup_ms;
        assert!(
            elapsed < CEILING_MS,
            "CpeIndex build + {} lookups took {} ms (build {} + lookup {}), \
             ceiling {} ms — suspected perf regression",
            LOOKUPS, elapsed, build_ms, lookup_ms, CEILING_MS,
        );
    }
}

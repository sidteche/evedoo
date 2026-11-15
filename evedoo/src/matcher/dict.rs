//! CPE dictionary matching layer (correlation engine Phase C).
//!
//! Loads the `cpe_dictionary` table (built by cve-db-builder from the
//! official NVD CPE Dictionary) into an inverted token index and scores
//! software display names against product titles. Sits between the curated
//! mapping table (Layer 1) and publisher correlation (Layer 2): broad
//! coverage, but gated behind a stricter score threshold than curated
//! entries because the titles are not hand-verified.
//!
//! Databases built before Phase C have no `cpe_dictionary` table; the index
//! then loads empty and the layer is a no-op.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use rusqlite::Connection;
use tracing::info;

use crate::normalize::tokens::tokenize;

use super::cpe::score_curated_match;

/// Minimum score for a dictionary match. Stricter than the curated table's
/// 0.60: a bare token-subset match (0.70) is not enough — the match must be
/// corroborated by publisher→vendor agreement or the vendor appearing in
/// the display name.
pub(crate) const DICT_MIN_SCORE: f32 = 0.75;

/// Tokens mapping to more rows than this are too generic to seed candidate
/// lookups (e.g. "server", "client"). They still participate in scoring.
const MAX_ROWS_PER_TOKEN: usize = 2_000;

struct DictRow {
    vendor: String,
    product: String,
    /// Tokenised title, e.g. ["videolan", "vlc", "media", "player"].
    title_tokens: Vec<String>,
    /// Title tokens minus the vendor's own tokens — display names often
    /// omit the vendor prefix that NVD titles carry.
    title_minus_vendor: Vec<String>,
}

/// Inverted token index over CPE dictionary titles.
pub struct DictIndex {
    rows: Vec<DictRow>,
    token_map: HashMap<String, Vec<u32>>,
}

impl DictIndex {
    /// Load application entries (`part = 'a'`) from `cpe_dictionary`.
    /// Returns an empty index when the table doesn't exist (pre-Phase-C
    /// databases) so the caller never has to special-case it.
    pub fn build(conn: &Connection) -> Self {
        let mut rows: Vec<DictRow> = Vec::new();

        let mut stmt = match conn
            .prepare("SELECT vendor, product, title FROM cpe_dictionary WHERE part = 'a'")
        {
            Ok(s) => s,
            Err(_) => {
                info!("No cpe_dictionary table — dictionary matching disabled (rebuild the DB with cve-db-builder to enable)");
                return Self {
                    rows,
                    token_map: HashMap::new(),
                };
            }
        };

        let mapped = stmt.query_map([], |row| {
            // Vendor/product decoded exactly as the CPE index decodes them
            // (normalize::cpe_name), so a dictionary hit names a key the index
            // actually holds.
            Ok((
                crate::normalize::cpe_name::unescape(&row.get::<_, String>(0)?).into_owned(),
                crate::normalize::cpe_name::unescape(&row.get::<_, String>(1)?).into_owned(),
                row.get::<_, String>(2)?,
            ))
        });

        if let Ok(iter) = mapped {
            for item in iter.flatten() {
                let (vendor, product, title) = item;
                let title_tokens = tokenize(&title);
                if title_tokens.is_empty() {
                    continue;
                }
                let vendor_tokens = tokenize(&vendor.replace(['_', '-'], " "));
                let title_minus_vendor: Vec<String> = title_tokens
                    .iter()
                    .filter(|t| !vendor_tokens.contains(t))
                    .cloned()
                    .collect();
                rows.push(DictRow {
                    vendor,
                    product,
                    title_tokens,
                    title_minus_vendor,
                });
            }
        }

        let mut token_map: HashMap<String, Vec<u32>> = HashMap::new();
        for (i, row) in rows.iter().enumerate() {
            for token in &row.title_tokens {
                token_map.entry(token.clone()).or_default().push(i as u32);
            }
        }
        // Generic tokens seed too many candidates to be useful.
        token_map.retain(|_, ids| ids.len() <= MAX_ROWS_PER_TOKEN);

        info!(
            "CPE dictionary index ready: {} identities, {} candidate tokens",
            rows.len(),
            token_map.len()
        );
        Self { rows, token_map }
    }

    /// Number of loaded dictionary identities (0 = layer disabled).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Find the best dictionary identity for a software name. Reuses the
    /// curated scorer with the title as the pattern, trying both the full
    /// title and the vendor-stripped title, and keeps the best candidate
    /// at or above `DICT_MIN_SCORE`.
    pub fn lookup(
        &self,
        name_tokens: &[String],
        publisher_vendor: Option<&str>,
    ) -> Option<(f32, &str, &str)> {
        if self.rows.is_empty() || name_tokens.is_empty() {
            return None;
        }

        // Candidate rows: any row sharing at least one non-generic token
        // with the name.
        let mut candidates: Vec<u32> = Vec::new();
        for token in name_tokens {
            if let Some(ids) = self.token_map.get(token) {
                candidates.extend_from_slice(ids);
            }
        }
        candidates.sort_unstable();
        candidates.dedup();

        let mut best: Option<(f32, u32)> = None;
        for id in candidates {
            let row = &self.rows[id as usize];
            let full = score_curated_match(
                name_tokens,
                &row.title_tokens,
                publisher_vendor,
                &row.vendor,
            );
            let stripped = if row.title_minus_vendor.is_empty() {
                0.0
            } else {
                score_curated_match(
                    name_tokens,
                    &row.title_minus_vendor,
                    publisher_vendor,
                    &row.vendor,
                )
            };
            let score = full.max(stripped);
            if score >= DICT_MIN_SCORE
                && score > best.map(|(s, _)| s).unwrap_or(0.0)
            {
                best = Some((score, id));
            }
        }

        best.map(|(score, id)| {
            let row = &self.rows[id as usize];
            (score, row.vendor.as_str(), row.product.as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE cpe_dictionary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                part TEXT NOT NULL,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                title TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            );
            INSERT INTO cpe_dictionary (part, vendor, product, title, fetched_at) VALUES
                ('a', 'videolan', 'vlc_media_player', 'VideoLAN VLC media player', 'now'),
                ('a', 'irfanview', 'irfanview', 'IrfanView', 'now'),
                ('a', 'dominik_reichl', 'keepass', 'Dominik Reichl KeePass', 'now'),
                ('o', 'microsoft', 'windows_11', 'Microsoft Windows 11', 'now');
            "#,
        )
        .unwrap();
        conn
    }

    #[test]
    fn build_skips_os_entries() {
        let index = DictIndex::build(&dict_conn());
        assert_eq!(index.len(), 3, "part='o' rows must be excluded");
    }

    #[test]
    fn build_without_table_is_empty_not_error() {
        let conn = Connection::open_in_memory().unwrap();
        let index = DictIndex::build(&conn);
        assert_eq!(index.len(), 0);
        assert!(index.lookup(&tokenize("VLC media player"), None).is_none());
    }

    #[test]
    fn lookup_with_publisher_corroboration() {
        let index = DictIndex::build(&dict_conn());
        // Vendor-stripped title {vlc, media, player} ⊆ name, publisher
        // matches vendor: 0.70 + 0.25 = 0.95.
        let hit = index.lookup(&tokenize("VLC media player"), Some("videolan"));
        let (score, vendor, product) = hit.expect("must match with publisher");
        assert_eq!(vendor, "videolan");
        assert_eq!(product, "vlc_media_player");
        assert!(score >= DICT_MIN_SCORE);
    }

    #[test]
    fn lookup_rejects_without_corroboration() {
        let index = DictIndex::build(&dict_conn());
        // Same tokens but no publisher and vendor not in name: 0.70 < 0.75.
        assert!(
            index.lookup(&tokenize("VLC media player"), None).is_none(),
            "bare subset match must not clear the dictionary threshold"
        );
    }

    #[test]
    fn lookup_vendor_in_name_clears_threshold() {
        let index = DictIndex::build(&dict_conn());
        // "IrfanView" name == title == vendor: 0.70 + 0.05 vendor-in-name
        // = 0.75 exactly.
        let hit = index.lookup(&tokenize("IrfanView"), None);
        let (score, _, product) = hit.expect("vendor-in-name must corroborate");
        assert_eq!(product, "irfanview");
        assert!(score >= DICT_MIN_SCORE);
    }

    #[test]
    fn lookup_unrelated_name_misses() {
        let index = DictIndex::build(&dict_conn());
        assert!(index
            .lookup(&tokenize("Totally Unknown App"), Some("videolan"))
            .is_none());
    }
}

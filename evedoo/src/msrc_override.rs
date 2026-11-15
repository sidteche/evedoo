//! MSRC verdict override (FR-91, FR-92).
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::normalize::version::Version;

#[derive(Debug, Clone)]
pub struct MsrcVerdict {
    pub kb_article: Option<String>,
    pub fixed_build: Option<String>,
}

/// `Some(true)` when the installed build is at or above the fix, `Some(false)`
/// when it is below, and `None` when either side could not be parsed.
///
/// `None` is NOT "patched". The caller must leave the NVD finding standing,
/// because treating "I could not compare" as "fixed" deletes real findings
/// (FR-92).
pub fn is_patched(installed: &str, fixed_build: &str) -> Option<bool> {
    if installed.trim().is_empty() || fixed_build.trim().is_empty() {
        return None;
    }
    let a = Version::parse(installed)?;
    let b = Version::parse(fixed_build)?;
    Some(a >= b)
}

/// Look up MSRC's verdict for one (CVE, product) pair. `None` means MSRC has
/// nothing to say, and the NVD match stands unchanged (FR-91).
pub fn lookup(
    conn: &rusqlite::Connection,
    cve_id: &str,
    vendor: &str,
    product: &str,
) -> Option<MsrcVerdict> {
    let mut stmt = conn
        .prepare(
            "SELECT f.kb_article, f.fixed_build
               FROM msrc_fixes f
               JOIN msrc_products p ON p.product_id = f.product_id
              WHERE f.cve_id = ?1 AND p.vendor = ?2 AND p.product = ?3
              ORDER BY f.fixed_build DESC
              LIMIT 1",
        )
        .ok()?;

    stmt.query_row(
        rusqlite::params![cve_id, vendor.to_ascii_lowercase(), product.to_ascii_lowercase()],
        |r| {
            Ok(MsrcVerdict {
                kb_article: r.get(0)?,
                fixed_build: r.get(1)?,
            })
        },
    )
    .ok()
}

#[derive(Debug, Default)]
pub struct OverrideOutcome {
    pub suppressed: usize,
    pub enriched: usize,
}

/// Apply MSRC verdicts (FR-91, FR-92, FR-93).
///
/// Only a SUCCESSFUL comparison against `fixed_build` may remove a finding.
/// A missing MSRC row, a missing fixed build, or an unparseable version on
/// either side all leave the NVD finding standing — absence of evidence never
/// deletes a finding.
pub fn apply(
    findings: &mut Vec<crate::models::Finding>,
    conn: &rusqlite::Connection,
) -> OverrideOutcome {
    let mut out = OverrideOutcome::default();

    findings.retain_mut(|f| {
        let Some(vendor) = f.vendor.as_deref() else { return true };
        let product = f.software.name.to_ascii_lowercase();

        let Some(v) = lookup(conn, &f.vulnerability.cve_id, vendor, &product) else {
            return true;
        };
        let Some(fixed) = v.fixed_build.as_deref() else { return true };
        let Some(installed) = f.software.version.as_deref() else { return true };

        match is_patched(installed, fixed) {
            Some(true) => {
                out.suppressed += 1;
                false
            }
            _ => {
                // Below the fix, or not comparable: keep it, and enrich with
                // the exact KB and build MSRC gave us.
                if let Some(kb) = v.kb_article.clone() {
                    if !f.vulnerability.remediation.kb_articles.contains(&kb) {
                        f.vulnerability.remediation.kb_articles.push(kb);
                    }
                }
                f.vulnerability.remediation.fixed_version = Some(fixed.to_string());
                out.enriched += 1;
                true
            }
        }
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-92. The comparison is the whole point: at or above the fixed build
    /// the finding is gone, below it the finding stands.
    #[test]
    fn patched_only_at_or_above_the_fixed_build() {
        assert_eq!(is_patched("10.0.26200.9168", "10.0.26200.9168"), Some(true));
        assert_eq!(is_patched("10.0.26200.9200", "10.0.26200.9168"), Some(true));
        assert_eq!(is_patched("10.0.26200.9000", "10.0.26200.9168"), Some(false));
        assert_eq!(is_patched("10.0.22000.1", "10.0.26200.9168"), Some(false));
    }

    /// FR-92, and the safety property of this whole feature: an unparseable
    /// version yields None, and the caller must then LEAVE THE FINDING
    /// STANDING. Treating "I could not compare" as "patched" would delete real
    /// findings, which is the failure mode this project has twice spent a
    /// phase eliminating.
    #[test]
    fn unparseable_versions_yield_none_never_patched() {
        assert_eq!(is_patched("", "10.0.26200.9168"), None);
        assert_eq!(is_patched("not-a-version", "10.0.26200.9168"), None);
        assert_eq!(is_patched("10.0.26200.9168", ""), None);
        assert_eq!(is_patched("10.0.26200.9168", "garbage"), None);
    }

    use crate::models::*;

    fn finding(cve: &str, name: &str, version: &str) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: name.into(),
                version: Some(version.into()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: format!("registry://{name}"),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: cve.into(),
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
            vendor: Some("microsoft".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        }
    }

    fn db_with(cve: &str, vendor: &str, product: &str, kb: &str, build: &str)
        -> rusqlite::Connection
    {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE msrc_products (product_id TEXT PRIMARY KEY, name TEXT NOT NULL,
                 cpe TEXT, vendor TEXT, product TEXT);
             CREATE TABLE msrc_fixes (cve_id TEXT NOT NULL, product_id TEXT NOT NULL,
                 kb_article TEXT, fixed_build TEXT, document_id TEXT NOT NULL,
                 PRIMARY KEY (cve_id, product_id, kb_article));",
        ).unwrap();
        c.execute(
            "INSERT INTO msrc_products VALUES ('1','p',NULL,?1,?2)",
            rusqlite::params![vendor, product],
        ).unwrap();
        c.execute(
            "INSERT INTO msrc_fixes VALUES (?1,'1',?2,?3,'2026-Aug')",
            rusqlite::params![cve, kb, build],
        ).unwrap();
        c
    }

    /// FR-91. Where MSRC says the installed build is at or above the fix, the
    /// finding is suppressed — this is the precision win.
    #[test]
    fn msrc_suppresses_a_finding_that_is_actually_patched() {
        let conn = db_with("CVE-1", "microsoft", "windows_11_25h2", "5121003",
                           "10.0.26200.9168");
        let mut f = vec![finding("CVE-1", "windows_11_25h2", "10.0.26200.9200")];
        let out = apply(&mut f, &conn);

        assert_eq!(out.suppressed, 1);
        assert!(f.is_empty());
    }

    /// Below the fixed build the finding stands AND carries the exact KB
    /// (FR-93) — the thing NVD cannot tell you.
    #[test]
    fn msrc_enriches_a_finding_that_is_genuinely_unpatched() {
        let conn = db_with("CVE-1", "microsoft", "windows_11_25h2", "5121003",
                           "10.0.26200.9168");
        let mut f = vec![finding("CVE-1", "windows_11_25h2", "10.0.26200.9000")];
        let out = apply(&mut f, &conn);

        assert_eq!(out.suppressed, 0);
        assert_eq!(out.enriched, 1);
        assert_eq!(f.len(), 1);
        assert!(f[0].vulnerability.remediation.kb_articles.contains(&"5121003".to_string()));
        assert_eq!(
            f[0].vulnerability.remediation.fixed_version.as_deref(),
            Some("10.0.26200.9168")
        );
    }

    /// FR-91's safety property. MSRC having nothing to say must leave the NVD
    /// finding exactly as it was — absence of data can never delete a finding.
    #[test]
    fn no_msrc_row_leaves_the_finding_untouched() {
        let conn = db_with("CVE-OTHER", "microsoft", "something_else", "1", "1.0");
        let mut f = vec![finding("CVE-1", "windows_11_25h2", "10.0.26200.9000")];
        let out = apply(&mut f, &conn);

        assert_eq!(out.suppressed, 0);
        assert_eq!(out.enriched, 0);
        assert_eq!(f.len(), 1, "a finding MSRC knows nothing about must survive");
    }
}

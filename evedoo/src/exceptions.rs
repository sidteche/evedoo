// SPDX-License-Identifier: Apache-2.0

//! Accepted-risk exceptions (FR-68..FR-72).
//!
//! An exception **annotates** a finding; it never removes it. Excepted
//! findings still reach delta tracking and history, so the exception list is
//! an audit trail rather than a place findings go to disappear. Reports do the
//! hiding, and `--show-excepted` undoes it.

use crate::error::{Result, ScanError};
use crate::models::{ExceptionRef, Finding};
use rusqlite::{params, Connection};
use serde::Serialize;

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

/// `Serialize` backs `evedoo exception list --json`; this is not part of
/// the `Finding` JSON contract DC-3 governs (that's `ExceptionRef`, a
/// separate, smaller struct), so no GUI change is implied by this derive.
#[derive(Serialize)]
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

/// Canonical form for hostname matching (carried Task 8 review item 2):
/// Windows hostnames are case-insensitive, but `matches()` above is a plain
/// string comparison, so an exception filed for `host-01` would otherwise
/// never fire against a scan reporting `HOST-01` (the conventional case for
/// `COMPUTERNAME`) — a silently-dead rule, the same class of mistake FR-72
/// exists to prevent for `cve_id`. Applied at every boundary that stores or
/// compares a hostname (`add`, `list`, `apply`) so callers never need to
/// think about case themselves. `*` (the fleet-wide wildcard) passes through
/// unchanged — it is a sentinel, not a hostname.
pub(crate) fn canonical_hostname(h: &str) -> String {
    if h == "*" {
        "*".to_string()
    } else {
        h.trim().to_uppercase()
    }
}

/// A zero-padded `YYYY-MM-DD` that is also a real calendar date.
///
/// Expiry is compared lexicographically against `now` in `apply()`, so a
/// typo like `"soon"` would sort *above* every genuine date — `"soon" <=
/// now` is never true — and the rule would never expire. That silently
/// converts a data-entry mistake into exactly the permanent suppression
/// FR-68 was written to make inexpressible, so this is validated at entry
/// the same way `is_valid_cve_id` guards `cve_id`.
fn is_valid_expiry_date(s: &str) -> bool {
    let bytes = s.as_bytes();
    let shape_ok = bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit);
    shape_ok && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

/// The furthest out an exception is allowed to expire: two years from the
/// moment it is created.
///
/// M2 (final whole-branch review): FR-68 states indefinite suppression "is
/// not expressible by design", but a syntactically valid `9999-12-31` was
/// accepted by `is_valid_expiry_date` above — expressible in four characters,
/// which defeats the entire feature's premise that accepted risk expires.
/// Rejecting (rather than merely warning) matches how this module already
/// treats every other entry-time mistake (`is_valid_cve_id`,
/// `is_valid_expiry_date` itself): fail the `add`, tell the operator why, and
/// never let a bad rule reach the audit trail in the first place. Two years
/// is generous for any realistic remediation or compensating-control
/// timeline; an exception that still needs to exist after that should be
/// re-filed with a fresh, deliberate expiry rather than inherited from
/// whatever was typed once, long ago.
const MAX_EXPIRY_HORIZON_DAYS: i64 = 730;

/// Whether `s` (already confirmed well-formed by `is_valid_expiry_date`)
/// expires no more than `MAX_EXPIRY_HORIZON_DAYS` from today.
fn is_within_horizon(s: &str) -> bool {
    match chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        Ok(date) => {
            let horizon = chrono::Utc::now().date_naive()
                + chrono::Duration::days(MAX_EXPIRY_HORIZON_DAYS);
            date <= horizon
        }
        // Format is validated separately (is_valid_expiry_date); an
        // unparseable date here has already been rejected by the time this
        // matters, but fail conservatively rather than assume it's fine.
        Err(_) => false,
    }
}

/// How narrowly a rule is scoped: the number of fields pinned to a concrete
/// value rather than `*`. When several rules match one finding, the most
/// specific wins — the alternative is creation order, which would let a
/// broad rule written months ago silently attribute a suppression to the
/// wrong owner, reason and expiry date.
fn specificity(r: &ExceptionRecord) -> u8 {
    (r.hostname != "*") as u8 + (r.cve_id != "*") as u8 + (r.software_name != "*") as u8
}

impl ExceptionStore {
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self { conn: crate::schema::open(path)? })
    }

    pub fn add(&self, input: ExceptionInput) -> Result<i64> {
        if !is_valid_cve_id(&input.cve_id) {
            return Err(ScanError::ValidationError(format!(
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
                return Err(ScanError::ValidationError(format!(
                    "{field} is required — an exception without it is not an audit trail"
                )));
            }
        }
        if !is_valid_expiry_date(&input.expires_at) {
            return Err(ScanError::ValidationError(format!(
                "not a valid expiry date: {} (expected YYYY-MM-DD)",
                input.expires_at
            )));
        }
        if !is_within_horizon(&input.expires_at) {
            return Err(ScanError::ValidationError(format!(
                "expiry date {} is more than {} days out — FR-68 requires an exception to \
                 expire on a realistic horizon, not function as permanent suppression by way \
                 of a date far enough in the future to never matter",
                input.expires_at, MAX_EXPIRY_HORIZON_DAYS
            )));
        }
        let hostname = canonical_hostname(&input.hostname);
        self.conn.execute(
            "INSERT OR REPLACE INTO exceptions
               (hostname, cve_id, software_name, reason, owner, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                hostname,
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
        let canonical = host.map(canonical_hostname);
        let mut stmt = match canonical {
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
        let rows = match canonical {
            Some(h) => stmt.query_map(params![h], map)?.flatten().collect(),
            None => stmt.query_map([], map)?.flatten().collect(),
        };
        Ok(rows)
    }

    pub fn remove(&self, id: i64) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM exceptions WHERE id = ?1", params![id])? > 0)
    }

    /// Annotate matching findings. `now` is an ISO date (`YYYY-MM-DD` or
    /// RFC3339); lexicographic comparison is correct for both. When more
    /// than one unexpired rule matches a finding, the most specific rule
    /// wins (see `specificity`), tie-broken by lowest `id` so the result is
    /// deterministic. The expiry check (`expires_at > now`) is exclusive of
    /// the expiry date itself: a rule created with `expires_at =
    /// "2026-12-31"` stops suppressing at the first instant of
    /// 2026-12-31, not after it — the fail-secure direction. This method
    /// is total over `findings`: a finding that matches no unexpired rule
    /// has `excepted` set to `None`, even if it arrived already carrying a
    /// stale value (e.g. from a rule that has since expired or been
    /// removed), so suppression never outlives the rule that granted it.
    /// Returns how many findings were suppressed.
    pub fn apply(&self, findings: &mut [Finding], hostname: &str, now: &str) -> Result<usize> {
        let hostname = canonical_hostname(hostname);
        let rules = self.list(Some(&hostname))?;
        let mut hits = 0usize;
        for f in findings.iter_mut() {
            let best = rules
                .iter()
                .filter(|r| r.expires_at.as_str() > now) // not expired (FR-71)
                .filter(|r| {
                    matches(&r.hostname, &hostname)
                        && matches(&r.cve_id, &f.vulnerability.cve_id)
                        && matches(&r.software_name, &f.software.name)
                })
                .max_by_key(|r| (specificity(r), std::cmp::Reverse(r.id)));
            if best.is_some() {
                hits += 1;
            }
            f.excepted = best.map(|r| ExceptionRef {
                id: r.id,
                owner: r.owner.clone(),
                reason: r.reason.clone(),
                expires_at: r.expires_at.clone(),
            });
        }
        Ok(hits)
    }
}

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
            reachability: Default::default(),
        }
    }

    #[test]
    fn exact_match_suppresses() {
        let s = store();
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2028-06-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 1);
        assert!(f[0].excepted.is_some());
    }

    #[test]
    fn wildcards_match_on_every_axis() {
        let s = store();
        s.add(input("*", "CVE-2024-0001", "*", "2028-06-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Anything")];
        assert_eq!(s.apply(&mut f, "ANY-HOST", "2026-08-21").unwrap(), 1);
    }

    #[test]
    fn non_matching_exception_leaves_the_finding_alone() {
        let s = store();
        s.add(input("HOST", "CVE-2024-9999", "Alpha", "2028-06-01")).unwrap();
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
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2028-06-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        s.apply(&mut f, "HOST", "2026-08-21").unwrap();
        assert_eq!(f.len(), 1, "the finding must not be dropped");
    }

    #[test]
    fn exception_ref_carries_the_audit_fields() {
        let s = store();
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2028-06-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        s.apply(&mut f, "HOST", "2026-08-21").unwrap();
        let e = f[0].excepted.as_ref().unwrap();
        assert_eq!(e.owner, "sid");
        assert_eq!(e.reason, "compensating control");
        assert_eq!(e.expires_at, "2028-06-01");
    }

    #[test]
    fn list_and_remove_round_trip() {
        let s = store();
        let id = s.add(input("HOST", "CVE-2024-0001", "Alpha", "2028-06-01")).unwrap();
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

    #[test]
    fn add_rejects_malformed_expiry_date() {
        let s = store();
        // "soon" is the sharp case: it sorts lexicographically above every
        // real YYYY-MM-DD date, so if it slipped past validation the
        // exception would never expire — the exact permanent suppression
        // FR-68 forbids.
        assert!(
            s.add(input("HOST", "CVE-2024-0001", "Alpha", "soon")).is_err(),
            "\"soon\" must be rejected as an expiry date"
        );
        for bad in ["2026/08/21", "08-21-2026", "2026-13-01", "2026-02-30", "2026-8-1", ""] {
            assert!(
                s.add(input("HOST", "CVE-2024-0001", "Alpha", bad)).is_err(),
                "{bad:?} must be rejected as an expiry date"
            );
        }
        // Sanity: a well-formed date is still accepted.
        assert!(s.add(input("HOST", "CVE-2024-0001", "Alpha", "2028-06-01")).is_ok());
    }

    /// M2 (final whole-branch review): FR-68 says indefinite suppression "is
    /// not expressible by design", but `9999-12-31` is a syntactically valid
    /// `YYYY-MM-DD` and was accepted by the old format-only check — expressible
    /// in four characters, defeating the entire feature's premise that
    /// accepted risk expires. `add` must reject any expiry beyond a sane
    /// (two-year) horizon, the same way it already rejects a malformed date.
    #[test]
    fn add_rejects_expiry_beyond_two_year_horizon() {
        let s = store();
        let err = s
            .add(input("HOST", "CVE-2024-0001", "Alpha", "9999-12-31"))
            .unwrap_err();
        assert!(
            matches!(err, ScanError::ValidationError(_)),
            "expected ValidationError, got {err:?}"
        );

        // A near-future date comfortably inside the horizon is still fine.
        let ok_expiry = (chrono::Utc::now().date_naive() + chrono::Duration::days(400))
            .format("%Y-%m-%d")
            .to_string();
        assert!(
            s.add(input("HOST", "CVE-2024-0002", "Alpha", &ok_expiry)).is_ok(),
            "an expiry well inside the two-year horizon must still be accepted"
        );

        // Exactly on the horizon boundary is accepted; one day past is not.
        let on_horizon = (chrono::Utc::now().date_naive() + chrono::Duration::days(730))
            .format("%Y-%m-%d")
            .to_string();
        assert!(s.add(input("HOST", "CVE-2024-0003", "Alpha", &on_horizon)).is_ok());

        let past_horizon = (chrono::Utc::now().date_naive() + chrono::Duration::days(731))
            .format("%Y-%m-%d")
            .to_string();
        assert!(
            s.add(input("HOST", "CVE-2024-0004", "Alpha", &past_horizon)).is_err(),
            "one day past the two-year horizon must be rejected"
        );
    }

    #[test]
    fn most_specific_matching_rule_wins() {
        // A broad `*` rule created first must not permanently mask a
        // narrower, more specific rule created later for the same finding.
        // If it did, the ExceptionRef stamped onto the finding — owner,
        // reason, expiry — would misattribute the audit trail to the wrong
        // rule. Under the old first-match-by-id behaviour this test fails,
        // because the broad rule (added first, lower id) is returned first
        // by `list()`'s `ORDER BY id` and wins by being first in iteration
        // order, regardless of specificity.
        let s = store();
        let mut broad = input("*", "CVE-2024-0001", "*", "2028-06-01");
        broad.owner = "broad_owner".into();
        s.add(broad).unwrap();

        let mut narrow = input("HOST", "CVE-2024-0001", "Alpha", "2028-06-01");
        narrow.owner = "narrow_owner".into();
        s.add(narrow).unwrap();

        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 1);
        assert_eq!(
            f[0].excepted.as_ref().unwrap().owner,
            "narrow_owner",
            "the more specific rule must win over the earlier, broader one"
        );
    }

    #[test]
    fn apply_clears_a_stale_excepted_when_nothing_matches() {
        // A finding can arrive with `excepted` already set — e.g. read back
        // from a JSON report, or (from Task 9 onward) re-scanned after its
        // exception rule expired or was deleted. `apply()` must be total:
        // if no unexpired rule matches, the finding must come out clean,
        // not keep whatever suppression it walked in with.
        let s = store();
        // No rules stored at all.
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        f[0].excepted = Some(ExceptionRef {
            id: 999,
            owner: "stale_owner".into(),
            reason: "stale reason".into(),
            expires_at: "2028-06-01".into(),
        });
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 0);
        assert!(
            f[0].excepted.is_none(),
            "a stale `excepted` must be cleared when no rule matches"
        );
    }

    #[test]
    fn expiry_boundary_is_exclusive_of_the_expiry_date() {
        // expires_at == now must NOT suppress: expiry takes effect at the
        // first instant of the expiry date, not after it.
        let s = store();
        s.add(input("HOST", "CVE-2024-0001", "Alpha", "2026-08-21")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 0);
        assert!(
            f[0].excepted.is_none(),
            "a rule must not suppress on its own expiry date"
        );
    }

    #[test]
    fn expired_specific_rule_does_not_shadow_active_broad_rule() {
        // Expiry is filtered before specificity is considered. An expired
        // specific rule must not shadow — nor even be selectable over — an
        // active broad rule for the same finding.
        let s = store();
        let mut specific = input("HOST", "CVE-2024-0001", "Alpha", "2026-01-01"); // expired
        specific.owner = "specific_owner".into();
        s.add(specific).unwrap();

        let mut broad = input("*", "CVE-2024-0001", "*", "2028-06-01"); // active
        broad.owner = "broad_owner".into();
        s.add(broad).unwrap();

        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 1);
        assert_eq!(
            f[0].excepted.as_ref().unwrap().owner,
            "broad_owner",
            "an expired specific rule must not shadow an active broad rule"
        );
    }

    /// Carried Task 8 review item 2: hostname matching was case-sensitive, so
    /// an exception filed for "host-01" silently never fired against a scan
    /// reporting "HOST-01" (Windows COMPUTERNAME is conventionally
    /// uppercase). Fails safe (the finding is shown) but is a silently-dead
    /// rule — the same class of mistake FR-72 exists to prevent for cve_id.
    #[test]
    fn hostname_matching_is_case_insensitive() {
        let s = store();
        s.add(input("host-01", "CVE-2024-0001", "Alpha", "2028-06-01")).unwrap();
        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(
            s.apply(&mut f, "HOST-01", "2026-08-21").unwrap(),
            1,
            "a rule filed in one case must still suppress a scan reporting a different case"
        );
        assert!(f[0].excepted.is_some());
    }

    /// `exception list --host` must find rules regardless of the case the
    /// operator queries with, for the same reason.
    #[test]
    fn list_by_host_is_case_insensitive() {
        let s = store();
        s.add(input("HOST-01", "CVE-2024-0001", "Alpha", "2028-06-01")).unwrap();
        assert_eq!(s.list(Some("host-01")).unwrap().len(), 1);
    }

    /// Carried Task 8 review item 3: validation failures used to surface as
    /// `Serialization error: not a valid expiry date: soon`, misdescribing a
    /// rejected operator input as an internal serialization failure.
    #[test]
    fn invalid_input_reports_validation_error_not_serialization_error() {
        let s = store();
        let err = s.add(input("HOST", "CVE-2024-0001", "Alpha", "soon")).unwrap_err();
        assert!(
            matches!(err, ScanError::ValidationError(_)),
            "expected ValidationError, got {err:?}"
        );
        assert!(
            !err.to_string().starts_with("Serialization error:"),
            "message was: {err}"
        );
    }

    #[test]
    fn equal_specificity_ties_break_to_the_lowest_id() {
        // Two rules with different (hostname, cve_id, software_name)
        // triples — so both are stored, unlike two rules with an identical
        // triple, which `INSERT OR REPLACE` would collapse into one row —
        // but equal specificity (2 concrete fields each) and both matching
        // the same finding. The earlier-created (lower id) rule must win.
        let s = store();
        let mut first = input("HOST", "CVE-2024-0001", "*", "2028-06-01");
        first.owner = "first_owner".into();
        s.add(first).unwrap();

        let mut second = input("HOST", "*", "Alpha", "2028-06-01");
        second.owner = "second_owner".into();
        s.add(second).unwrap();

        let mut f = vec![finding("CVE-2024-0001", "Alpha")];
        assert_eq!(s.apply(&mut f, "HOST", "2026-08-21").unwrap(), 1);
        assert_eq!(
            f[0].excepted.as_ref().unwrap().owner,
            "first_owner",
            "with equal specificity, the lowest id (earliest-created) rule must win"
        );
    }
}

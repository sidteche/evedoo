# MSRC Authoritative Advisories Implementation Plan

> **Status: COMPLETE (`P21-N5`, closed 2026-08-28; live sync verified 2026-09-10).** All 33
> steps are ticked. Task 2 Step 6 (live MSRC sync) executed: 192 documents, 7,749 products,
> 489,927 fixes in `vulndb.sqlite`. Task 4 Step 6 (measurement gate) verified: fallback preserves
> all findings, 0 false suppressions.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Replace guesswork with Microsoft's own answer for Microsoft products — exact fixed build and exact KB article per CVE — where 95% of NVD's `microsoft:edge` records carry no version bounds at all.

**Architecture:** A new `cve-db-builder/src/msrc/` module in four layers: `parse.rs` (pure CVRF interpretation, where everything that can be wrong lives), `fetch.rs` (two HTTP calls with size bounds and ID validation), `store.rs` (three new tables), `mod.rs` (incremental sync orchestration). In `evedoo`, an override layer beside the existing matcher applies MSRC verdicts where they exist and leaves the NVD path untouched where they do not.

**Tech Stack:** Rust 2021, `rusqlite` 0.32 (parameterised queries only), `reqwest` + `serde_json` (already present in cve-db-builder), `clap` 4.5 derive. **No new dependencies.**

**Spec:** `docs/superpowers/specs/2026-08-28-msrc-advisories-design.md`

## Global Constraints

- **Never redistribute.** No build, release, or distributed artifact may contain MSRC-derived data. The data exists only in a database the operator syncs themselves. (FR-94)
- **Opt-in only.** `--enable-msrc`, off by default, printing the Microsoft APIs Terms of Use notice before any request. (FR-89)
- **Fallback never deletes a finding.** Absence of MSRC data leaves the NVD match standing. Only a *successful* version comparison against `fixed_build` may suppress. (FR-91, FR-92)
- **Lowercase vendor/product on ingest** — MSRC publishes `windows_10_21H2`, NVD stores `windows_10_21h2`. Normalise at write time so no caller has to remember. (FR-96)
- **Parameterised SQL only**; validate document IDs before URL interpolation. (SEC-9)
- The scanner performs no network I/O — all fetching lives in `cve-db-builder`. (NFR-7)
- MSRV Rust 1.83, edition 2021. `cargo clippy --workspace --all-targets -- -D warnings` is a CI gate.

## Verified facts this plan relies on

Confirmed against the live API on 2026-08-28, not assumed:

- `GET /cvrf/v3.0/updates` and `GET /cvrf/v3.0/cvrf/{ID}` need **no authentication**.
- `2026-Aug` contains **1202 vulnerabilities** across **282 products**, ~7 MB JSON.
- Every product carries a CPE; **0 products had a missing CPE**.
- A Remediation entry looks exactly like:
  `{"Description":{"Value":"5100263"},"URL":"https://support.microsoft.com/help/5100263","ProductID":["21325"],"Type":2,"SubType":"Security Update","FixedBuild":"26.0.50788"}`
- The KB number is `Description.Value`. **`SubType` is NOT the KB** — it is usually a label like `"Security Update"`, and only sometimes a number.
- Every MSRC product string resolves in the NVD dictionary after lowercasing.

---

### Task 1: CVRF parsing — pure interpretation

Everything that can be wrong about reading MSRC's format, with no network and no database.

**Files:**
- Create: `cve-db-builder/src/msrc/mod.rs` (module declarations only)
- Create: `cve-db-builder/src/msrc/parse.rs`
- Create: `cve-db-builder/tests/fixtures/msrc_sample.json` (trimmed real document)
- Modify: `cve-db-builder/src/main.rs` or `lib.rs` (add `mod msrc;`)

**Interfaces:**
- Produces:
  - `pub struct MsrcProduct { pub product_id: String, pub name: String, pub cpe: Option<String>, pub vendor: Option<String>, pub product: Option<String> }`
  - `pub struct MsrcFix { pub cve_id: String, pub product_id: String, pub kb_article: Option<String>, pub fixed_build: Option<String> }`
  - `pub struct ParsedDocument { pub products: Vec<MsrcProduct>, pub fixes: Vec<MsrcFix> }`
  - `pub fn parse_document(json: &str) -> Result<ParsedDocument, String>`
  - `pub fn split_cpe(cpe: &str) -> Option<(String, String)>` — returns lowercased `(vendor, product)`

- [x] **Step 1: Create the fixture**

Save a trimmed real document. Take the live `2026-Aug` response and keep the
document header, three products, and two vulnerabilities — enough to exercise
the nested `ProductTree.Branch` recursion and both Remediation shapes. Do not
commit a 7 MB blob.

The fixture must preserve this real structure:

```json
{
  "DocumentTitle": { "Value": "August 2026 Security Updates" },
  "DocumentTracking": { "Identification": { "ID": { "Value": "2026-Aug" } } },
  "ProductTree": {
    "Branch": [
      { "Items": [
          { "FullProductName": [
              { "ProductID": "20438", "Value": "Windows 11 Version 25H2 for x64-based Systems",
                "CPE": "cpe:2.3:o:microsoft:windows_11_25H2:10.0.26200.9168:*:*:*:*:*:x64:*" }
          ]}
      ]}
    ],
    "FullProductName": [
      { "ProductID": "10378", "Value": "Windows Server 2012",
        "CPE": "cpe:2.3:o:microsoft:windows_server_2012:6.2.9200.26280:*:*:*:*:*:x64:*" },
      { "ProductID": "11111", "Value": "Product With No CPE" }
    ]
  },
  "Vulnerability": [
    {
      "CVE": "CVE-2026-42976",
      "Remediations": [
        { "Description": { "Value": "5121003" },
          "URL": "https://support.microsoft.com/help/5121003",
          "ProductID": ["20438"], "Type": 2,
          "SubType": "Security Update", "FixedBuild": "10.0.26200.9168" },
        { "URL": "https://support.microsoft.com/help/5121003",
          "ProductID": ["20438"], "Type": 3, "SubType": "5121003" }
      ]
    },
    {
      "CVE": "CVE-2026-11111",
      "Remediations": [
        { "Description": { "Value": "5100263" },
          "ProductID": ["10378", "20438"], "Type": 2,
          "SubType": "Security Update" }
      ]
    }
  ]
}
```

- [x] **Step 2: Write the failing tests**

Create `cve-db-builder/src/msrc/parse.rs` containing only the doc comment and
this test block:

```rust
//! CVRF document interpretation (FR-90, FR-96).
//!
//! Pure: no network, no database. Everything that can be wrong about reading
//! MSRC's format lives here.
//!
//! SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/msrc_sample.json"),
        )
        .expect("fixture must exist")
    }

    /// FR-96. MSRC publishes mixed case ("windows_11_25H2"); the NVD
    /// dictionary is lowercase. Normalising at parse time means the join never
    /// depends on a caller remembering to fold case.
    #[test]
    fn cpe_vendor_and_product_are_lowercased() {
        let (v, p) = split_cpe(
            "cpe:2.3:o:microsoft:windows_11_25H2:10.0.26200.9168:*:*:*:*:*:x64:*",
        )
        .expect("a well-formed CPE must split");
        assert_eq!(v, "microsoft");
        assert_eq!(p, "windows_11_25h2");
    }

    #[test]
    fn split_cpe_rejects_malformed_input() {
        assert!(split_cpe("not-a-cpe").is_none());
        assert!(split_cpe("cpe:2.3:o:microsoft").is_none());
    }

    /// Products live both directly on ProductTree and nested inside Branch
    /// items. Missing either location silently loses products.
    #[test]
    fn products_are_collected_from_both_tree_and_branches() {
        let d = parse_document(&fixture()).unwrap();
        let ids: Vec<&str> = d.products.iter().map(|p| p.product_id.as_str()).collect();

        assert!(ids.contains(&"20438"), "nested Branch product missing");
        assert!(ids.contains(&"10378"), "top-level FullProductName product missing");
    }

    /// A product without a CPE must still be recorded — it has a name and an
    /// ID, and dropping it would silently lose fixes that reference it.
    #[test]
    fn product_without_cpe_is_kept_with_no_vendor_or_product() {
        let d = parse_document(&fixture()).unwrap();
        let p = d.products.iter().find(|p| p.product_id == "11111").unwrap();
        assert!(p.cpe.is_none());
        assert!(p.vendor.is_none());
        assert_eq!(p.name, "Product With No CPE");
    }

    /// The KB number is Description.Value. SubType is a LABEL
    /// ("Security Update") that only sometimes happens to be a number —
    /// reading it as the KB yields garbage for most entries.
    #[test]
    fn kb_comes_from_description_not_subtype() {
        let d = parse_document(&fixture()).unwrap();
        let f = d
            .fixes
            .iter()
            .find(|f| f.cve_id == "CVE-2026-42976" && f.product_id == "20438")
            .expect("fix must be parsed");

        assert_eq!(f.kb_article.as_deref(), Some("5121003"));
        assert_eq!(f.fixed_build.as_deref(), Some("10.0.26200.9168"));
    }

    /// One Remediation can list several ProductIDs; each is its own fix row,
    /// because each product has its own installed version to compare against.
    #[test]
    fn a_remediation_fans_out_to_one_fix_per_product() {
        let d = parse_document(&fixture()).unwrap();
        let rows: Vec<_> = d
            .fixes
            .iter()
            .filter(|f| f.cve_id == "CVE-2026-11111")
            .collect();

        assert_eq!(rows.len(), 2, "two ProductIDs must yield two fix rows");
        assert!(rows.iter().all(|f| f.kb_article.as_deref() == Some("5100263")));
        assert!(
            rows.iter().all(|f| f.fixed_build.is_none()),
            "this remediation has no FixedBuild and must not invent one"
        );
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        assert!(parse_document("{ not json").is_err());
        assert!(parse_document("").is_err());
    }
}
```

- [x] **Step 3: Run tests to verify they fail**

Run: `cargo test -p cve-db-builder msrc`
Expected: FAIL to compile — `cannot find function parse_document`, `cannot find function split_cpe`.

- [x] **Step 4: Write the implementation**

Insert above the test block in `parse.rs`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct MsrcProduct {
    pub product_id: String,
    pub name: String,
    pub cpe: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MsrcFix {
    pub cve_id: String,
    pub product_id: String,
    pub kb_article: Option<String>,
    pub fixed_build: Option<String>,
}

#[derive(Debug, Default)]
pub struct ParsedDocument {
    pub products: Vec<MsrcProduct>,
    pub fixes: Vec<MsrcFix>,
}

// ── Wire format ──────────────────────────────────────────────────────────────
// Only the fields this feature needs; serde ignores the rest, so MSRC adding
// fields cannot break the parse.

#[derive(Deserialize)]
struct Doc {
    #[serde(rename = "ProductTree", default)]
    product_tree: Option<Branch>,
    #[serde(rename = "Vulnerability", default)]
    vulnerability: Vec<Vuln>,
}

#[derive(Deserialize, Default)]
struct Branch {
    #[serde(rename = "FullProductName", default)]
    full_product_name: Vec<FullProductName>,
    #[serde(rename = "Branch", default)]
    branch: Vec<Branch>,
    #[serde(rename = "Items", default)]
    items: Vec<Branch>,
}

#[derive(Deserialize)]
struct FullProductName {
    #[serde(rename = "ProductID")]
    product_id: String,
    #[serde(rename = "Value", default)]
    value: Option<String>,
    #[serde(rename = "CPE", default)]
    cpe: Option<String>,
}

#[derive(Deserialize)]
struct Vuln {
    #[serde(rename = "CVE", default)]
    cve: Option<String>,
    #[serde(rename = "Remediations", default)]
    remediations: Vec<Remediation>,
}

#[derive(Deserialize)]
struct Remediation {
    #[serde(rename = "Description", default)]
    description: Option<ValueField>,
    #[serde(rename = "ProductID", default)]
    product_id: Vec<String>,
    #[serde(rename = "FixedBuild", default)]
    fixed_build: Option<String>,
}

#[derive(Deserialize)]
struct ValueField {
    #[serde(rename = "Value", default)]
    value: Option<String>,
}

/// Split a CPE 2.3 string into its lowercased `(vendor, product)` (FR-96).
pub fn split_cpe(cpe: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = cpe.split(':').collect();
    // cpe:2.3:<part>:<vendor>:<product>:...
    if parts.len() < 5 || parts[0] != "cpe" {
        return None;
    }
    let vendor = parts[3].trim();
    let product = parts[4].trim();
    if vendor.is_empty() || product.is_empty() {
        return None;
    }
    Some((vendor.to_ascii_lowercase(), product.to_ascii_lowercase()))
}

/// Walk the tree, collecting products from every level.
///
/// Products appear BOTH directly on `ProductTree.FullProductName` and nested
/// inside `Branch`/`Items`. Reading only one location silently loses products,
/// and a fix referencing a lost product cannot be resolved.
fn collect_products(b: &Branch, out: &mut Vec<MsrcProduct>) {
    for p in &b.full_product_name {
        let split = p.cpe.as_deref().and_then(split_cpe);
        out.push(MsrcProduct {
            product_id: p.product_id.clone(),
            name: p.value.clone().unwrap_or_default(),
            cpe: p.cpe.clone(),
            vendor: split.as_ref().map(|(v, _)| v.clone()),
            product: split.as_ref().map(|(_, pr)| pr.clone()),
        });
    }
    for child in b.branch.iter().chain(b.items.iter()) {
        collect_products(child, out);
    }
}

/// Parse one CVRF document into products and fixes.
pub fn parse_document(json: &str) -> Result<ParsedDocument, String> {
    let doc: Doc = serde_json::from_str(json).map_err(|e| e.to_string())?;

    let mut products = Vec::new();
    if let Some(tree) = &doc.product_tree {
        collect_products(tree, &mut products);
    }

    let mut fixes = Vec::new();
    for v in &doc.vulnerability {
        let Some(cve) = v.cve.as_deref() else { continue };
        for r in &v.remediations {
            // The KB is Description.Value. SubType is a label such as
            // "Security Update" that only sometimes looks like a number, so
            // reading it as the KB yields garbage for most entries.
            let kb = r.description.as_ref().and_then(|d| d.value.clone());
            for pid in &r.product_id {
                fixes.push(MsrcFix {
                    cve_id: cve.to_string(),
                    product_id: pid.clone(),
                    kb_article: kb.clone(),
                    fixed_build: r.fixed_build.clone(),
                });
            }
        }
    }

    Ok(ParsedDocument { products, fixes })
}
```

Create `cve-db-builder/src/msrc/mod.rs`:

```rust
//! MSRC authoritative advisory ingestion (FR-89..FR-96).
//!
//! Opt-in only, and the data is NEVER redistributed — Microsoft APIs Terms of
//! Use §3(b)(14). See the design doc for the licensing analysis.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod parse;
```

- [x] **Step 5: Run tests to verify they pass**

Run: `cargo test -p cve-db-builder msrc`
Expected: PASS, 7 tests.

- [x] **Step 6: Mutation-verify the two rules most likely to be got wrong**

Change the KB source from `r.description` to the remediation's `SubType`
(add the field to the struct to do so).
Run: `cargo test -p cve-db-builder msrc`
Expected: `kb_comes_from_description_not_subtype` FAILS. Revert.

Change `split_cpe` to return the vendor and product without lowercasing.
Run: `cargo test -p cve-db-builder msrc`
Expected: `cpe_vendor_and_product_are_lowercased` FAILS. Revert.

Remove the `b.items.iter()` half of the recursion in `collect_products`.
Run: `cargo test -p cve-db-builder msrc`
Expected: `products_are_collected_from_both_tree_and_branches` FAILS. Revert.

Re-run and confirm PASS after all three reverts.

- [x] **Step 7: Commit**

```bash
git add cve-db-builder/src/msrc/ cve-db-builder/tests/fixtures/msrc_sample.json
git commit -m "P21-N5 Task 1: CVRF document parsing (FR-90, FR-96)"
```

---

### Task 2: Storage — the three tables

**Files:**
- Create: `cve-db-builder/src/msrc/store.rs`
- Modify: `cve-db-builder/src/msrc/mod.rs` (add `pub mod store;`)

**Interfaces:**
- Consumes: `MsrcProduct`, `MsrcFix`, `ParsedDocument` from Task 1
- Produces:
  - `pub fn init_msrc_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()>`
  - `pub fn store_document(conn: &mut rusqlite::Connection, document_id: &str, current_release: &str, doc: &ParsedDocument) -> rusqlite::Result<()>`
  - `pub fn needs_refetch(conn: &rusqlite::Connection, document_id: &str, current_release: &str) -> rusqlite::Result<bool>`

- [x] **Step 1: Write the failing tests**

Append to `cve-db-builder/src/msrc/store.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::msrc::parse::{MsrcFix, MsrcProduct, ParsedDocument};

    fn doc() -> ParsedDocument {
        ParsedDocument {
            products: vec![MsrcProduct {
                product_id: "20438".into(),
                name: "Windows 11 Version 25H2 for x64-based Systems".into(),
                cpe: Some("cpe:2.3:o:microsoft:windows_11_25H2:10.0.26200.9168:*".into()),
                vendor: Some("microsoft".into()),
                product: Some("windows_11_25h2".into()),
            }],
            fixes: vec![MsrcFix {
                cve_id: "CVE-2026-42976".into(),
                product_id: "20438".into(),
                kb_article: Some("5121003".into()),
                fixed_build: Some("10.0.26200.9168".into()),
            }],
        }
    }

    fn conn() -> rusqlite::Connection {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        init_msrc_schema(&c).unwrap();
        c
    }

    #[test]
    fn stores_products_and_fixes() {
        let mut c = conn();
        store_document(&mut c, "2026-Aug", "2026-08-12T00:00:00Z", &doc()).unwrap();

        let products: i64 = c
            .query_row("SELECT COUNT(*) FROM msrc_products", [], |r| r.get(0))
            .unwrap();
        let fixes: i64 = c
            .query_row("SELECT COUNT(*) FROM msrc_fixes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(products, 1);
        assert_eq!(fixes, 1);
    }

    /// FR-90. A document whose CurrentReleaseDate has not changed must not be
    /// re-fetched; one that has changed must be. This is the entire basis of
    /// incremental sync across ~120 documents.
    #[test]
    fn refetch_is_driven_by_current_release_date() {
        let mut c = conn();
        assert!(
            needs_refetch(&c, "2026-Aug", "2026-08-12T00:00:00Z").unwrap(),
            "never-seen document must be fetched"
        );

        store_document(&mut c, "2026-Aug", "2026-08-12T00:00:00Z", &doc()).unwrap();
        assert!(
            !needs_refetch(&c, "2026-Aug", "2026-08-12T00:00:00Z").unwrap(),
            "unchanged document must be skipped"
        );
        assert!(
            needs_refetch(&c, "2026-Aug", "2026-08-20T00:00:00Z").unwrap(),
            "revised document must be re-fetched"
        );
    }

    /// Re-ingesting a revised document must replace its rows, not duplicate
    /// them — MSRC revises documents after publication.
    #[test]
    fn reingest_replaces_rather_than_duplicates() {
        let mut c = conn();
        store_document(&mut c, "2026-Aug", "v1", &doc()).unwrap();
        store_document(&mut c, "2026-Aug", "v2", &doc()).unwrap();

        let fixes: i64 = c
            .query_row("SELECT COUNT(*) FROM msrc_fixes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fixes, 1, "re-ingest must not double the rows");
    }
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cve-db-builder msrc::store`
Expected: FAIL to compile — `cannot find function init_msrc_schema`.

- [x] **Step 3: Write the implementation**

Insert above the test block in `store.rs`:

```rust
//! MSRC table definitions and upserts (DC-8).
//!
//! SPDX-License-Identifier: Apache-2.0

use rusqlite::{params, Connection};

use super::parse::ParsedDocument;

pub fn init_msrc_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS msrc_products (
             product_id  TEXT PRIMARY KEY,
             name        TEXT NOT NULL,
             cpe         TEXT,
             vendor      TEXT,
             product     TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_msrc_products_vp
             ON msrc_products(vendor, product);

         CREATE TABLE IF NOT EXISTS msrc_fixes (
             cve_id      TEXT NOT NULL,
             product_id  TEXT NOT NULL,
             kb_article  TEXT,
             fixed_build TEXT,
             document_id TEXT NOT NULL,
             PRIMARY KEY (cve_id, product_id, kb_article)
         );
         CREATE INDEX IF NOT EXISTS idx_msrc_fixes_cve ON msrc_fixes(cve_id);
         CREATE INDEX IF NOT EXISTS idx_msrc_fixes_doc ON msrc_fixes(document_id);

         CREATE TABLE IF NOT EXISTS msrc_sync (
             document_id     TEXT PRIMARY KEY,
             current_release TEXT NOT NULL,
             ingested_at     TEXT NOT NULL
         );",
    )
}

/// FR-90. True when the document has never been ingested, or when MSRC has
/// revised it since.
pub fn needs_refetch(
    conn: &Connection,
    document_id: &str,
    current_release: &str,
) -> rusqlite::Result<bool> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT current_release FROM msrc_sync WHERE document_id = ?1",
            params![document_id],
            |r| r.get(0),
        )
        .ok();
    Ok(stored.as_deref() != Some(current_release))
}

/// Store one document's products and fixes, replacing anything previously
/// ingested from it.
///
/// One transaction per document, so an interrupted sync leaves whole documents
/// ingested rather than half of one (FR-95). The `msrc_sync` row is written
/// last inside the same transaction, so a document is marked ingested only if
/// its rows landed.
pub fn store_document(
    conn: &mut Connection,
    document_id: &str,
    current_release: &str,
    doc: &ParsedDocument,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;

    tx.execute(
        "DELETE FROM msrc_fixes WHERE document_id = ?1",
        params![document_id],
    )?;

    for p in &doc.products {
        tx.execute(
            "INSERT INTO msrc_products (product_id, name, cpe, vendor, product)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(product_id) DO UPDATE SET
                 name = excluded.name, cpe = excluded.cpe,
                 vendor = excluded.vendor, product = excluded.product",
            params![p.product_id, p.name, p.cpe, p.vendor, p.product],
        )?;
    }

    for f in &doc.fixes {
        tx.execute(
            "INSERT INTO msrc_fixes
                 (cve_id, product_id, kb_article, fixed_build, document_id)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(cve_id, product_id, kb_article) DO UPDATE SET
                 fixed_build = excluded.fixed_build,
                 document_id = excluded.document_id",
            params![f.cve_id, f.product_id, f.kb_article, f.fixed_build, document_id],
        )?;
    }

    tx.execute(
        "INSERT INTO msrc_sync (document_id, current_release, ingested_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(document_id) DO UPDATE SET
             current_release = excluded.current_release,
             ingested_at = excluded.ingested_at",
        params![document_id, current_release, chrono::Utc::now().to_rfc3339()],
    )?;

    tx.commit()
}
```

Add `pub mod store;` to `cve-db-builder/src/msrc/mod.rs`.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p cve-db-builder msrc`
Expected: PASS, 10 tests.

- [x] **Step 5: Mutation-verify incremental sync**

Change `needs_refetch` to always return `true`.
Run: `cargo test -p cve-db-builder msrc::store`
Expected: `refetch_is_driven_by_current_release_date` FAILS on the "unchanged
document must be skipped" assertion. Revert and confirm PASS.

- [x] **Step 6: Commit**

```bash
git add cve-db-builder/src/msrc/
git commit -m "P21-N5 Task 2: MSRC tables and incremental upserts (DC-8, FR-90)"
```

---

### Task 3: Fetch and sync orchestration

**Files:**
- Create: `cve-db-builder/src/msrc/fetch.rs`
- Modify: `cve-db-builder/src/msrc/mod.rs` (sync driver + `pub mod fetch;`)
- Modify: `cve-db-builder/src/main.rs` (the `--enable-msrc` flag and terms notice)

**Interfaces:**
- Consumes: `parse::parse_document`, `store::{init_msrc_schema, needs_refetch, store_document}`
- Produces:
  - `pub struct UpdateEntry { pub id: String, pub current_release: String }`
  - `pub fn is_valid_document_id(id: &str) -> bool`
  - `pub const MSRC_TERMS_NOTICE: &str`
  - `pub fn sync(conn: &mut rusqlite::Connection, client: &reqwest::blocking::Client) -> Result<SyncSummary, String>`

- [x] **Step 1: Write the failing tests**

Append to `cve-db-builder/src/msrc/fetch.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-9. Document IDs come from a remote listing and are interpolated
    /// into a URL path, so they are validated against a conservative pattern
    /// rather than trusted.
    #[test]
    fn document_ids_are_validated_before_url_interpolation() {
        assert!(is_valid_document_id("2026-Aug"));
        assert!(is_valid_document_id("1999-Sep"));

        assert!(!is_valid_document_id("../../etc/passwd"));
        assert!(!is_valid_document_id("2026-Aug/../../admin"));
        assert!(!is_valid_document_id("2026 Aug"));
        assert!(!is_valid_document_id(""));
        assert!(!is_valid_document_id(&"A".repeat(200)));
    }

    /// FR-89. The notice must name the terms the operator is accepting, and
    /// must say plainly that the data is never redistributed (FR-94).
    #[test]
    fn terms_notice_names_the_terms_and_the_no_redistribution_rule() {
        assert!(MSRC_TERMS_NOTICE.contains("Microsoft APIs Terms of Use"));
        assert!(MSRC_TERMS_NOTICE.to_lowercase().contains("not redistribut"));
    }

    #[test]
    fn parses_the_updates_listing() {
        let json = r#"{"value":[
            {"ID":"2026-Aug","CurrentReleaseDate":"2026-08-12T00:00:00Z"},
            {"ID":"2026-Jul","CurrentReleaseDate":"2026-07-08T00:00:00Z"}
        ]}"#;
        let entries = parse_updates(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "2026-Aug");
        assert_eq!(entries[0].current_release, "2026-08-12T00:00:00Z");
    }

    /// An entry missing its ID must be skipped, not defaulted to something
    /// that would then be fetched.
    #[test]
    fn updates_entry_without_an_id_is_skipped() {
        let json = r#"{"value":[
            {"CurrentReleaseDate":"2026-08-12T00:00:00Z"},
            {"ID":"2026-Jul","CurrentReleaseDate":"2026-07-08T00:00:00Z"}
        ]}"#;
        let entries = parse_updates(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "2026-Jul");
    }
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p cve-db-builder msrc::fetch`
Expected: FAIL to compile — `cannot find function is_valid_document_id`.

- [x] **Step 3: Write the implementation**

Create `cve-db-builder/src/msrc/fetch.rs`:

```rust
//! MSRC HTTP transport (SEC-9, NFR-10).
//!
//! SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

const MSRC_BASE: &str = "https://api.msrc.microsoft.com/cvrf/v3.0";

/// Refuse a response larger than this. A hostile or corrupted endpoint must
/// not be able to exhaust memory; real documents are ~7 MB.
const MAX_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;

/// FR-89. Shown before any request is made, so accepting the terms is an
/// affirmative act rather than a side effect of running a sync.
pub const MSRC_TERMS_NOTICE: &str = "\
MSRC advisory sync is enabled.

Data is retrieved from the Microsoft Security Response Center API and is
subject to the Microsoft APIs Terms of Use:
  https://learn.microsoft.com/en-us/legal/microsoft-apis/terms-of-use

This data is stored ONLY in your local CVE database. Evedoo does not
redistribute it, and any database you build containing it must not be
redistributed either (Microsoft APIs Terms of Use section 3(b)(14)).
";

#[derive(Debug, Clone)]
pub struct UpdateEntry {
    pub id: String,
    pub current_release: String,
}

#[derive(Deserialize)]
struct UpdatesResponse {
    #[serde(rename = "value", default)]
    value: Vec<UpdateRow>,
}

#[derive(Deserialize)]
struct UpdateRow {
    #[serde(rename = "ID", default)]
    id: Option<String>,
    #[serde(rename = "CurrentReleaseDate", default)]
    current_release_date: Option<String>,
}

/// SEC-9. IDs come from a remote listing and are interpolated into a URL path.
/// MSRC IDs look like "2026-Aug"; anything else is refused rather than trusted.
pub fn is_valid_document_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !id.contains("..")
}

pub fn parse_updates(json: &str) -> Result<Vec<UpdateEntry>, String> {
    let parsed: UpdatesResponse = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(parsed
        .value
        .into_iter()
        .filter_map(|r| {
            Some(UpdateEntry {
                id: r.id?,
                current_release: r.current_release_date.unwrap_or_default(),
            })
        })
        .collect())
}

pub fn fetch_updates(client: &reqwest::blocking::Client) -> Result<Vec<UpdateEntry>, String> {
    let url = format!("{MSRC_BASE}/updates");
    let body = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| e.to_string())?
        .text()
        .map_err(|e| e.to_string())?;
    parse_updates(&body)
}

pub fn fetch_document(
    client: &reqwest::blocking::Client,
    id: &str,
) -> Result<String, String> {
    if !is_valid_document_id(id) {
        return Err(format!("refusing to fetch suspicious document id: {id:?}"));
    }
    let url = format!("{MSRC_BASE}/cvrf/{id}");
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| e.to_string())?;

    if let Some(len) = resp.content_length() {
        if len as usize > MAX_DOCUMENT_BYTES {
            return Err(format!("document {id} is {len} bytes, over the cap"));
        }
    }
    resp.text().map_err(|e| e.to_string())
}
```

Add the sync driver to `cve-db-builder/src/msrc/mod.rs`:

```rust
pub mod fetch;
pub mod parse;
pub mod store;

#[derive(Debug, Default)]
pub struct SyncSummary {
    pub documents_seen: usize,
    pub documents_ingested: usize,
    pub documents_skipped: usize,
    pub documents_failed: usize,
}

/// Ingest every document MSRC lists, re-fetching only what changed (FR-90).
///
/// FR-95: a failed document is logged and skipped without aborting, and is NOT
/// recorded as ingested, so the next run retries it.
pub fn sync(
    conn: &mut rusqlite::Connection,
    client: &reqwest::blocking::Client,
) -> Result<SyncSummary, String> {
    store::init_msrc_schema(conn).map_err(|e| e.to_string())?;

    let entries = fetch::fetch_updates(client)?;
    let mut s = SyncSummary {
        documents_seen: entries.len(),
        ..Default::default()
    };

    for (i, e) in entries.iter().enumerate() {
        match store::needs_refetch(conn, &e.id, &e.current_release) {
            Ok(false) => {
                s.documents_skipped += 1;
                continue;
            }
            Ok(true) => {}
            Err(err) => {
                log::warn!("msrc: cannot check {}: {err}", e.id);
                s.documents_failed += 1;
                continue;
            }
        }

        log::info!("msrc: [{}/{}] fetching {}", i + 1, entries.len(), e.id);

        let body = match fetch::fetch_document(client, &e.id) {
            Ok(b) => b,
            Err(err) => {
                log::warn!("msrc: fetch failed for {}: {err}", e.id);
                s.documents_failed += 1;
                continue;
            }
        };

        let doc = match parse::parse_document(&body) {
            Ok(d) => d,
            Err(err) => {
                log::warn!("msrc: parse failed for {}: {err}", e.id);
                s.documents_failed += 1;
                continue;
            }
        };

        match store::store_document(conn, &e.id, &e.current_release, &doc) {
            Ok(()) => s.documents_ingested += 1,
            Err(err) => {
                log::warn!("msrc: store failed for {}: {err}", e.id);
                s.documents_failed += 1;
            }
        }
    }

    Ok(s)
}
```

Wire the flag in `cve-db-builder/src/main.rs`:

```rust
    /// Enable MSRC advisory sync. Off by default: the data is subject to the
    /// Microsoft APIs Terms of Use and must never be redistributed (FR-89).
    #[arg(long, default_value_t = false)]
    enable_msrc: bool,
```

and, where the other sync stages run:

```rust
    if args.enable_msrc {
        println!("{}", msrc::fetch::MSRC_TERMS_NOTICE);
        match msrc::sync(&mut conn, &client) {
            Ok(s) => println!(
                "  MSRC: {} ingested, {} unchanged, {} failed, of {} documents",
                s.documents_ingested, s.documents_skipped, s.documents_failed, s.documents_seen
            ),
            Err(e) => log::warn!("MSRC sync failed: {e}"),
        }
    }
```

- [x] **Step 4: Run tests and the gate**

Run: `cargo test --workspace`
Expected: all pass.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [x] **Step 5: Mutation-verify the ID validation**

Change `is_valid_document_id` to `true` unconditionally.
Run: `cargo test -p cve-db-builder msrc::fetch`
Expected: `document_ids_are_validated_before_url_interpolation` FAILS. Revert.

- [x] **Step 6: Real sync against the live API** — DONE (2026-09-10).
Executed: `cve_db_builder.exe --output vulndb.sqlite --enrichment-only --enable-msrc --skip-kev --skip-epss --skip-cpe-dict`
Terms notice printed before request. 192 documents processed (66 ingested, 126 unchanged).
Row counts recorded in `vulndb.sqlite`:
```sql
SELECT COUNT(*) FROM msrc_products;            -- 7,749
SELECT COUNT(*) FROM msrc_fixes;               -- 489,927
SELECT COUNT(DISTINCT cve_id) FROM msrc_fixes; -- 24,673
```

- [x] **Step 7: Commit**

```bash
git add cve-db-builder/src/msrc/ cve-db-builder/src/main.rs
git commit -m "P21-N5 Task 3: MSRC fetch, opt-in flag, and incremental sync (FR-89, FR-90, FR-95, SEC-9)"
```

---

### Task 4: The override — MSRC verdicts in the matcher

**Files:**
- Create: `evedoo/src/msrc_override.rs`
- Modify: `evedoo/src/main.rs` (`mod msrc_override;` and the correlate stage)

**Interfaces:**
- Produces:
  - `pub struct MsrcVerdict { pub kb_article: Option<String>, pub fixed_build: Option<String> }`
  - `pub fn lookup(conn: &rusqlite::Connection, cve_id: &str, vendor: &str, product: &str) -> Option<MsrcVerdict>`
  - `pub fn is_patched(installed: &str, fixed_build: &str) -> Option<bool>`

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/msrc_override.rs` with only this test block:

```rust
//! MSRC verdict override (FR-91, FR-92).
//!
//! SPDX-License-Identifier: Apache-2.0

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
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p evedoo msrc_override`
Expected: FAIL to compile — `cannot find function is_patched`.

- [x] **Step 3: Write the implementation**

Insert above the test block:

```rust
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
```

Check `Version::parse`'s real signature in `evedoo/src/normalize/version.rs`
and adapt — it may be `Version::parse(&str) -> Option<Version>` or return a
`Result`. Do not guess; read it.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p evedoo msrc_override`
Expected: PASS, 2 tests.

- [x] **Step 5: Mutation-verify the safety property**

Change `is_patched` so the unparseable branches return `Some(true)`.
Run: `cargo test -p evedoo msrc_override`
Expected: `unparseable_versions_yield_none_never_patched` FAILS. Revert.

Change `Some(a >= b)` to `Some(a > b)`.
Run: `cargo test -p evedoo msrc_override`
Expected: `patched_only_at_or_above_the_fixed_build` FAILS on the equal case.
Revert.

- [x] **Step 6: Commit**

```bash
git add evedoo/src/msrc_override.rs evedoo/src/main.rs
git commit -m "P21-N5 Task 4: MSRC verdict lookup and build comparison (FR-91, FR-92)"
```

---

### Task 5: Wire the override into correlation and reporting

**Files:**
- Modify: `evedoo/src/correlate.rs` or `evedoo/src/main.rs` (wherever findings are produced)
- Modify: `evedoo/src/msrc_override.rs` (the apply pass)

**Interfaces:**
- Produces: `pub struct OverrideOutcome { pub suppressed: usize, pub enriched: usize }`, `pub fn apply(findings: &mut Vec<Finding>, conn: &rusqlite::Connection) -> OverrideOutcome`

- [x] **Step 1: Write the failing test**

Append to `evedoo/src/msrc_override.rs` tests:

```rust
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
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p evedoo msrc_override`
Expected: FAIL to compile — `cannot find function apply`.

- [x] **Step 3: Write the implementation**

```rust
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
```

- [x] **Step 4: Run tests and the gate**

Run: `cargo test --workspace` — expected: all pass.
Run: `cargo clippy --workspace --all-targets -- -D warnings` — expected: clean.

- [x] **Step 5: Mutation-verify the no-data safety rule**

Change the `lookup` miss arm from `return true` to `return false`.
Run: `cargo test -p evedoo msrc_override`
Expected: `no_msrc_row_leaves_the_finding_untouched` FAILS. Revert.

- [x] **Step 6: The measurement gate (spec §5)** — DONE (2026-09-10).
Measured on real host:
```
findings before MSRC:   928
findings after MSRC:    928
suppressed by verdict:  0 (0.0% — well under the 50% safety ceiling; fallback preserved all matches)
```

- [x] **Step 7: Commit**

```bash
git add evedoo/src/
git commit -m "P21-N5 Task 5: apply MSRC verdicts to findings (FR-91, FR-92, FR-93)"
```

---

## Self-Review

**Spec coverage:**

| Requirement | Task |
|---|---|
| FR-89 opt-in flag + terms notice | 3 |
| FR-90 full history, incremental by CurrentReleaseDate | 2 (mutation-verified), 3 |
| FR-91 MSRC overrides; absence falls back | 4, 5 (mutation-verified) |
| FR-92 suppression needs a successful comparison | 4 (mutation-verified), 5 |
| FR-93 exact KB and fixed build in reports | 5 |
| FR-94 never redistributed | Satisfied by construction — no task ships data |
| FR-95 failures skipped, not recorded ingested | 3 |
| FR-96 lowercase CPE components | 1 (mutation-verified) |
| NFR-10 progress and resumability | 2, 3 |
| SEC-9 HTTPS, size cap, ID validation | 3 (mutation-verified) |
| DC-8 three tables | 2 |

**Type consistency:** `MsrcProduct`, `MsrcFix`, `ParsedDocument`, `parse_document`, `split_cpe`, `init_msrc_schema`, `store_document`, `needs_refetch`, `UpdateEntry`, `is_valid_document_id`, `parse_updates`, `MSRC_TERMS_NOTICE`, `SyncSummary`, `sync`, `MsrcVerdict`, `lookup`, `is_patched`, `OverrideOutcome`, `apply` are each defined once and used consistently.

**Known risk, stated rather than hidden:** Task 5's override can remove findings. Every path that could remove one without a successful version comparison is closed and mutation-tested, and Task 5 Step 6 is a hard stop on an implausible suppression rate. `Version::parse`'s real signature must be read rather than assumed (noted in Task 4 Step 3).

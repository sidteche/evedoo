# Phase 1.5: Reducing False Positives in CVE Matching

> **HISTORICAL CASE STUDY.** This documents the Phase 1.5 work (10,938 → 67
> findings) as it stood in April 2026. The precision mechanisms have since been
> extended considerably — the CPE dictionary layer, negative-mapping vetoes,
> companion-artifact vetoes, `target_sw` gating, runtime reachability, and MSRC
> overrides all came later, and the finding counts here are not current. The
> algorithm design reasoning is still the best write-up of *why* the matcher
> works the way it does. For the current architecture see
> [docs/architecture.md](../architecture.md) §2.3.

## A Case Study in Algorithm Design for Vulnerability Scanners

This document explains how we reduced false positive CVE matches from **10,938 to 67** (99.4% reduction) in the Evedoo vulnerability scanner. It serves as a system design reference for CPE-based vulnerability matching.

---

## Table of Contents

1. [The Problem](#the-problem)
2. [Root Cause Analysis](#root-cause-analysis)
3. [Phase 1 — Original Implementation (Baseline)](#phase-1--original-implementation-baseline)
4. [Phase 1.5 v1 — Strict Vendor/Product Matching](#phase-15-v1--strict-vendorproduct-matching)
5. [Phase 1.5 v2 — Version Range Filtering](#phase-15-v2--version-range-filtering)
6. [Results Summary](#results-summary)
7. [Lessons Learned](#lessons-learned)

---

## The Problem

The scanner reads the Windows Registry to find installed software, then queries a local SQLite database of 331,723 CVEs (from NIST NVD) to find known vulnerabilities. The database contains 3,004,888 CPE (Common Platform Enumeration) configuration entries that map CVEs to affected products.

**The challenge**: How do you accurately match a Windows registry entry like `"Microsoft Edge (x64)"` to the correct CPE product `cpe:2.3:a:microsoft:edge_chromium:*` — without also matching it to unrelated products like `edge_gateway`, `edgemarc`, `cutting_edge_cms`, etc.?

### The Numbers

| Metric | Value |
|--------|-------|
| Installed software detected | 134 |
| CVEs in database | 331,723 |
| CPE entries in database | 3,004,888 |
| **Phase 1 findings (before)** | **10,938** |
| **Phase 1.5 findings (after)** | **67** |

An enterprise security team receiving a report with 10,938 findings for 134 apps would immediately lose trust in the tool. The false positive rate was ~99%.

---

## Root Cause Analysis

We identified **three independent root causes** that compounded to create the problem:

### Root Cause 1: Substring SQL Matching

The SQL query used `LIKE '%pattern%'` which matches any product containing the search term as a substring.

**Example**: Searching for "edge" (from "Microsoft Edge") would match:

| CPE Product | Vendor | Relevant? |
|-------------|--------|-----------|
| `edge_chromium` | microsoft | ✅ Yes |
| `edge` | microsoft | ✅ Yes |
| `edgemarc` | edgewater_networks | ❌ No |
| `edge_gateway` | dell | ❌ No |
| `knowledge_edge` | knowledgetree | ❌ No |
| `cutting_edge_cms` | cuttingedgecms | ❌ No |
| `leading_edge` | ibm | ❌ No |

One legitimate product vs. 5+ false matches — and each false product could have dozens of CVEs.

### Root Cause 2: No Vendor Verification

The query completely ignored the `vendor` column in the CPE database. Even when the product name matched correctly, there was no check that "Microsoft Edge" should only match `vendor = 'microsoft'`.

**Example**: A product named "Python" would match:
- `python` by vendor `python` ✅
- `python` by vendor `fedoraproject` ❌
- `python` by vendor `debian` ❌

### Root Cause 3: Version-less CPE Entries Matching Everything

Many CPE entries in the NVD database have **no version range constraints** (all four version fields are NULL). These represent "all versions affected" declarations. The original code treated these as "match everything", inflating the count dramatically.

**Example CPE entry with no version range**:
```
cve_id: CVE-2009-XXXX
vendor: mozilla
product: firefox
version_start_including: NULL
version_end_excluding: NULL
→ Matches Firefox 149.0.2 (2026) for a CVE from 2009
```

---

## Phase 1 — Original Implementation (Baseline)

**Result: 10,938 findings**

### Architecture

```
Registry Entry → Normalize Name → LIKE '%name%' SQL → All Matches → Report
```

### Code: Name Normalization (Phase 1)

The normalize function used a small hardcoded mapping and fell back to taking the first 1-2 words:

```rust
fn normalize_name(&self, name: &str) -> String {
    let name = name.to_lowercase();
    let name = name
        .replace(" (x64)", "")
        .replace(" (x86)", "")
        .replace(" (64-bit)", "")
        .replace(" (32-bit)", "")
        .replace(" - ", " ")
        .trim()
        .to_string();

    let parts: Vec<&str> = name.split_whitespace().collect();

    // Small hardcoded mapping
    match parts.first().map(|s| *s) {
        Some("google") if parts.get(1) == Some(&"chrome") => "chrome".to_string(),
        Some("mozilla") if parts.get(1) == Some(&"firefox") => "firefox".to_string(),
        Some("microsoft") => {
            if parts.contains(&"edge") {
                "edge".to_string()  // ← Too generic! Matches edge_gateway, edgemarc, etc.
            } else {
                parts.get(1).unwrap_or(&"microsoft").to_string()
            }
        }
        _ => {
            // Fallback: first 1-2 words joined with underscore
            parts.iter().take(2).map(|s| *s)
                .collect::<Vec<_>>().join("_")
        }
    }
}
```

**Problems**:
- `"edge"` is too generic
- `"visual"` from "Visual Studio" matches `visual_calendar`, `visual_form_mail`, etc.
- Fallback of "first 2 words" creates names like `"update_for"`, `"microsoft_windows"` — way too broad

### Code: SQL Query (Phase 1)

```rust
fn find_cpe_matches(&self, normalized_name: &str) -> Result<Vec<CpeMatchRecord>> {
    let mut stmt = self.conn.prepare(
        "SELECT cve_id, vendor, product,
                version_start_including, version_end_excluding,
                version_start_excluding, version_end_including
         FROM cpe_matches
         WHERE LOWER(product) LIKE ?1
         LIMIT 1000"
    )?;

    let pattern = format!("%{}%", normalized_name);  // ← SUBSTRING match
    // ...
}
```

**Problems**:
- `LIKE '%edge%'` matches everything containing "edge"
- No vendor filter at all
- `LIMIT 1000` caps results but still returns hundreds of false matches
- Vendor column is fetched but never used

### Code: Version Check (Phase 1)

```rust
fn is_version_vulnerable(&self, version: &str, cpe_match: &CpeMatchRecord) -> bool {
    if version.is_empty() {
        return true;  // ← Assumes vulnerable if no version info!
    }
    // Check version ranges...
    // If no range fields are set, falls through to:
    true  // ← ALL CPE entries without version ranges match!
}
```

**Problems**:
- Missing version = assume vulnerable (should be the opposite)
- CPE entries with no version constraints match everything

---

## Phase 1.5 v1 — Strict Vendor/Product Matching

**Result: 4,480 findings (59% reduction)**

### Architecture

```
Registry Entry → 3-Layer Lookup → Exact SQL → Version Check → Report
                     ↓
          Layer 1: Curated Mapping Table
          Layer 2: Publisher → Vendor Correlation
          Layer 3: Exact Product Name Match
```

### Key Design Decision: Three-Layer Matching

Instead of one fuzzy path, we use three progressively less-confident matching layers:

```
┌─────────────────────────────────────────────────────┐
│ Layer 1: CURATED MAPPING TABLE                      │
│ "Microsoft Edge" → vendor:microsoft, product:edge_  │
│ chromium                                            │
│ Confidence: EXACT                                   │
│ Coverage: ~50 common apps                           │
├─────────────────────────────────────────────────────┤
│ Layer 2: PUBLISHER → VENDOR CORRELATION             │
│ Publisher "Google LLC" → vendor "google"             │
│ Then exact product name query                       │
│ Confidence: HIGH                                    │
├─────────────────────────────────────────────────────┤
│ Layer 3: EXACT PRODUCT NAME (fallback)              │
│ WHERE product = 'exact_name' (no LIKE, no vendor)   │
│ Confidence: MEDIUM                                  │
└─────────────────────────────────────────────────────┘
```

### Code: Curated Mapping Table

A static lookup table maps Windows registry display names to exact CPE (vendor, product) pairs:

```rust
/// (display_name_contains, cpe_vendor, cpe_product)
const KNOWN_MAPPINGS: &[(&str, &str, &str)] = &[
    // Browsers
    ("Google Chrome", "google", "chrome"),
    ("Mozilla Firefox", "mozilla", "firefox"),
    ("Microsoft Edge", "microsoft", "edge_chromium"),

    // Microsoft products
    ("Microsoft Office", "microsoft", "office"),
    ("Microsoft Visual Studio Code", "microsoft", "visual_studio_code"),
    ("Visual C++ 2013 Redistributable", "microsoft", "visual_c%2b%2b"),
    ("Microsoft .NET Framework", "microsoft", ".net_framework"),

    // Development tools
    ("Git ", "git-scm", "git"),
    ("Python", "python", "python"),
    ("Node.js", "nodejs", "node.js"),

    // Common apps
    ("7-Zip", "7-zip", "7-zip"),
    ("VLC media player", "videolan", "vlc_media_player"),
    ("Discord", "discord", "discord"),
    ("Steam", "valvesoftware", "steam_client"),
    // ... ~95 entries total
];
```

**Why this works**: The CPE naming scheme is not intuitive. "Google Chrome" is `google:chrome`, not `google:google_chrome`. "7-Zip" is `7-zip:7-zip`. "Node.js" is `nodejs:node.js`. Without a curated table, you can't derive these programmatically.

### Code: Publisher → Vendor Correlation

The Windows Registry provides a `Publisher` field (e.g., "Microsoft Corporation"). We map this to CPE vendor names:

```rust
const PUBLISHER_VENDORS: &[(&str, &str)] = &[
    ("Microsoft Corporation", "microsoft"),
    ("Google LLC", "google"),
    ("Mozilla", "mozilla"),
    ("Adobe Inc.", "adobe"),
    ("Oracle Corporation", "oracle"),
    ("Valve Corporation", "valvesoftware"),
    ("Python Software Foundation", "python"),
    ("The Git Development Community", "git-scm"),
    // ... ~45 entries
];

fn resolve_vendor(&self, publisher: &str) -> Option<&'static str> {
    let publisher_lower = publisher.to_lowercase();
    for (pub_pattern, vendor) in PUBLISHER_VENDORS {
        if publisher_lower.contains(&pub_pattern.to_lowercase()) {
            return Some(vendor);
        }
    }
    None
}
```

### Code: SQL Queries (v1)

The critical change — replacing `LIKE '%x%'` with exact matches:

```rust
/// Layer 1/2: Exact vendor + exact product (no substring!)
fn find_cpe_strict(&self, vendor: &str, product: &str) -> Result<Vec<CpeMatchRecord>> {
    let mut stmt = self.conn.prepare(
        "SELECT cve_id, vendor, product,
                version_start_including, version_end_excluding,
                version_start_excluding, version_end_including
         FROM cpe_matches
         WHERE vendor = ?1 AND product = ?2"  // ← EXACT match on BOTH fields
    )?;
    let matches = stmt.query_map(params![vendor, product], ...)?;
    // ...
}

/// Layer 3 fallback: Exact product only (no vendor filter)
fn find_cpe_product_only(&self, product: &str) -> Result<Vec<CpeMatchRecord>> {
    let mut stmt = self.conn.prepare(
        "SELECT ...
         FROM cpe_matches
         WHERE product = ?1    // ← Exact match, NOT LIKE '%x%'
         LIMIT 500"
    )?;
    // ...
}
```

### Code: Version Check (v1)

Changed the behavior for missing version info:

```rust
fn is_version_vulnerable(&self, version: &str, cpe_match: &CpeMatchRecord) -> bool {
    if version.is_empty() {
        return false;  // ← Changed from true to false!
    }
    // ... version range checks unchanged
    true
}
```

### Why v1 Still Had 4,480 Matches

While substring matching was eliminated, CPE entries **without any version range** still matched everything. For example, Firefox has ~2,000 CPE entries in the database. Many old ones have no version constraints, so they all matched Firefox 149.0.2.

---

## Phase 1.5 v2 — Version Range Filtering

**Result: 67 findings (99.4% total reduction)**

### The Insight

In the NVD database, CPE entries come in two forms:

**Type A — Version-ranged** (reliable):
```
vendor: mozilla, product: firefox
version_start_including: 115.0
version_end_excluding: 115.23
```
Meaning: "Firefox versions 115.0 through 115.22 are vulnerable."

**Type B — No range** (unreliable):
```
vendor: mozilla, product: firefox
version_start_including: NULL
version_end_excluding: NULL
version_start_excluding: NULL
version_end_including: NULL
```
Meaning: "All versions of Firefox" — but this is typically from old CVEs (2005-2015) that predate NVD's version-range system. They inflate counts massively.

### Code: The v2 Fix

A single guard clause that filters out range-less CPE entries:

```rust
fn is_version_vulnerable(&self, version: &str, cpe_match: &CpeMatchRecord) -> bool {
    if version.is_empty() {
        return false;
    }

    // NEW in v2: Skip CPE entries with no version range at all.
    // These are vague "all versions" entries that cause massive false positives.
    let has_any_range = cpe_match.version_start_including.is_some()
        || cpe_match.version_end_excluding.is_some()
        || cpe_match.version_start_excluding.is_some()
        || cpe_match.version_end_including.is_some();

    if !has_any_range {
        return false;  // ← This one check eliminated ~4,400 false matches
    }

    // ... normal version range checks
    let version = self.parse_version(version);
    // check start_including, start_excluding, end_excluding, end_including
    true
}
```

### Trade-off Analysis

Skipping range-less entries **could** miss legitimate vulnerabilities where "all versions" is truly affected. However:

1. Modern NVD entries (2018+) almost always include version ranges
2. Old entries without ranges are usually superseded by newer CVEs
3. The signal-to-noise ratio improvement (67 vs 10,938) far outweighs the risk
4. Users can lower the threshold with `--min-confidence low` if needed

---

## Results Summary

| Phase | Findings | Reduction | Key Change |
|-------|----------|-----------|------------|
| Phase 1 (baseline) | 10,938 | — | `LIKE '%name%'`, no vendor check |
| Phase 1.5 v1 | 4,480 | -59% | Exact matching, vendor verification, publisher correlation |
| Phase 1.5 v2 | **67** | **-99.4%** | Skip CPE entries with no version range |

### Severity Breakdown (Final — 67 findings)

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 22 |
| Medium | 36 |
| Low | 3 |
| Unknown | 3 |

These 67 findings are legitimate CVEs with proper version ranges matching actually-installed software (Firefox, Chrome, Node.js, PostgreSQL, Git, Steam, 7-Zip, Rust).

---

## Lessons Learned

### 1. Never Use Substring Matching for Security Identifiers
`LIKE '%pattern%'` in SQL is a code smell for any security tool. CPE identifiers are structured data — treat them as such. Always use exact matches or structured lookups.

### 2. Vendor Verification is Essential
Product names alone are ambiguous. "Python" exists under multiple vendors in NVD. Always correlate with vendor information — the Windows Registry `Publisher` field is a free signal.

### 3. Absent Data ≠ Positive Match
The old code assumed "no version info → vulnerable" and "no version range → all versions affected." Both assumptions are wrong for a practical scanner. Conservative defaults (skip unknowns) produce far better results than aggressive ones (assume vulnerable).

### 4. Curated Mappings Beat Heuristics
The ~95-entry curated mapping table was more effective than any algorithmic name normalization. CPE naming conventions vary wildly across vendors — you can't derive `edge_chromium` from "Microsoft Edge" or `visual_c%2b%2b` from "Visual C++ Redistributable" algorithmically.

### 5. Most False Positives Come from a Single Root Cause
Despite identifying three root causes, the version range filter (v2) alone eliminated ~4,400 of the remaining 4,480 matches. In practice, one fix often accounts for 80%+ of the improvement. Ship the fix, measure, then decide if you need more.

### 6. Confidence Scoring Enables User Control
Rather than hardcoding a single threshold, we exposed match confidence (Exact/High/Medium/Low) as both a report column and a CLI filter (`--min-confidence`). This lets enterprise users tune the tool for their needs: security auditors want `low` (see everything), operations teams want `exact` (only verified matches).

---

## Architecture Diagram

```
┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│  Windows Registry │     │  CVE Database     │     │  Report Output   │
│                  │     │  (SQLite)         │     │                  │
│  HKLM\Uninstall  │     │  331,723 CVEs     │     │  CSV (25 cols)   │
│  HKLM\WOW6432    │     │  3M CPE entries   │     │  JSON            │
│  HKCU\Uninstall  │     │  product_mappings │     │  Colored Text    │
└────────┬─────────┘     └────────┬──────────┘     └────────▲─────────┘
         │                        │                         │
         ▼                        ▼                         │
┌──────────────────┐     ┌───────────────────┐              │
│  Registry Scanner │     │  CPE Matcher      │              │
│                  │     │                   │              │
│  134 apps with:  │────▶│  Layer 1: Curated │──────────────┘
│  - DisplayName   │     │  Layer 2: Pub→Ven │
│  - Version       │     │  Layer 3: Exact   │
│  - Publisher     │     │                   │
│  - InstallLoc    │     │  Version Range    │
│  - Architecture  │     │  Filtering        │
└──────────────────┘     │                   │
                         │  Confidence Score │
                         └───────────────────┘
```

---

*Document created: April 2026*
*Project: Evedoo Vulnerability Scanner*
*License: Apache 2.0*

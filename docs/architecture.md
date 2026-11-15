# Evedoo — Knowledge Transfer & System Design Document

**Author:** Siddharth Naman
**Last Updated:** 2026-09-10

> **Read this first.** This document was written before the public release,
> when the project was called Toonable, and is not maintained line by line.
> It remains a useful map of how the pieces fit together. Where it disagrees
> with the [README](../README.md) or the code, they are right. In particular:
> Linux and macOS support is newer and less tested than it reads here; the
> only distribution advisory source is experimental Ubuntu notices (there is
> no Red Hat feed); the audit checks are derived from DISA STIGs, not DISA's
> text; and test counts quoted below are historical.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture & Design](#2-system-architecture--design)
3. [Project Management & Development History](#3-project-management--development-history)
4. [Codebase Navigation & Operations](#4-codebase-navigation--operations)

---

## 1. Executive Summary

**Evedoo** is a high-performance, offline-first, agentless vulnerability scanner and compliance auditor for Windows. It inventories installed software from eight sources (Registry, AppX/MSIX, WinGet, Chocolatey, Scoop, PE headers — including bundled library DLLs — language ecosystems, and the Windows OS itself), then correlates every entry against a local NIST NVD SQLite database — overridden where authoritative Microsoft MSRC advisories have a verdict — in sub-second time. It also audits host configuration against Public Domain DISA STIG / NIST SP 800-53 baselines (§2.7).

### Core Value Proposition

| Capability | Detail |
|---|---|
| **Offline-first** | No cloud round-trips. The CVE database lives locally as SQLite. Scan results never leave the machine. |
| **Sub-second matching** | In-memory `CpeIndex` (`HashMap<(vendor, product), Vec<u32>>`) replaces per-call SQL with O(1) lookups against a flat row store. |
| **Agentless** | Single binary, no installation, no services, no kernel drivers. Drop it on a machine and run. |
| **Enterprise reports** | 25-column CSV (Rapid7/Tenable-compatible), interactive self-contained HTML triage surface, JSON for pipelines, CycloneDX 1.6 + SPDX 2.3 SBOMs, colored terminal text. |
| **Delta tracking** | SQLite-backed history tags every finding `New`, `NewlyApplicable`, `Persisting`, `Resolved`, or `NoLongerApplicable` between runs (`models::FindingStatus`). |
| **Real-world prioritisation** | EPSS exploitation probability + CISA KEV known-exploited flag. Reports sort by actual risk, not just CVSS. |
| **Precision matching** | Three-layer cascade with token-based scoring, applicability enforcement, and explicit vetoes. Original reduction was 10,938 → 67 on the first test host; the mechanisms behind that are documented in §2.3. |
| **Honest coverage** | `--show-unmatched` separates "no published CVEs" from "never correlated", so a clean report can be distinguished from a blind spot. |

**Scale on a real host** (545 applications inventoried, database of 378,067
CVEs / 3.16M CPE rows): **901 findings**. That number is the outcome of a long
sequence of precision work — 940 → 916 → 1,432 → 822 → 3,287 → 901 — where each
move is traceable to a specific mechanism in §2.3 and §3.2. The 3,287 spike and
its collapse back to 901 is the single most instructive episode in this project
and is written up as Challenge 5.

### Target Users

- Enterprise security teams running host-level vulnerability assessments
- MSPs scanning client machines without deploying agents
- Sysadmins needing repeatable, offline vulnerability posture checks
- Compliance teams generating evidence for audits (CSV export)

### Technology Stack

| Component | Choice |
|---|---|
| Language | Rust 1.83+ / edition 2021 (`evedoo`, `cve-db-builder`, `evedoo-gui`); Rust 1.88+ / edition 2024 (`evedoo-taskstate`, driven by `rmcp`) |
| Database | SQLite via `rusqlite` 0.32 (bundled, no system dependency) |
| Async runtime | `tokio` (cve-db-builder, evedoo-taskstate) |
| HTTP client | `reqwest` 0.12 (cve-db-builder only) — the scanner makes no network calls |
| CLI framework | `clap` 4.5 with derive macros |
| GUI framework | `egui` / `eframe` 0.31 (evedoo-gui only) |
| MCP server | `rmcp` 3.1 over stdio, file locking via `fs4` (evedoo-taskstate only) |
| Web workspace | React 18 + TypeScript 5.7 + Vite 6 + Tailwind 3.4 (evedoo-studio only) |
| Terminal colour | `owo-colors` 4.2 (MIT) — replaced `colored` to remove MPL-2.0 |
| Logging | `tracing` + `tracing-subscriber` (the `log` crate is **not** used) |
| Serialization | `serde` + `serde_json` + `csv` |
| Platform | Windows 10/11, Windows Server 2019/2022 (scanner); cross-platform for `cve-db-builder` and `evedoo-taskstate` |

---

## 2. System Architecture & Design

### 2.1 High-Level Data Flow

```
                     ┌───────────────────────────────────────┐
                     │             cve-db-builder            │
                     │       (run once, refresh weekly)      │
                     │                                       │
 FKIE mirror ───────►│  CVE + CPE ingest ─────┐              │
 (NVD API fallback)  │                        │              │
 CPE Products API ──►│  CPE dictionary ───────┤              │
 EPSS CSV.gz ───────►│  EPSS scores ──────────┤              │
 CISA KEV JSON ─────►│  KEV catalog ──────────┘              │
                     └───────────────────┬───────────────────┘
                                         │
                                         ▼  vulndb.sqlite (file on disk)
                     ┌───────────────────────────────────────┐
                     │                evedoo               │
                     │             (run per scan)            │
                     │                                       │
 Registry ──────────►│  Software Inventory                   │
 AppX/MSIX ─────────►│         │                             │
 WinGet ────────────►│  Version Resolver                     │
 Chocolatey ────────►│         │                             │
 Scoop ─────────────►│  CpeIndex + Matcher                   │
 PE + bundled DLLs ─►│         │                             │
 pip/npm/cargo ─────►│  Applicability Filters                │
 Windows OS ────────►│         │                             │
                     │  Version Check                        │
                     │         │                             │
                     │  Enrichment (EPSS + KEV)              │
                     │         │                             │
                     │  Delta Tracking                       │
                     │  (scan_history.db)                    │
                     │         │                             │
                     │         ▼                             │
                     │  Report: text · json · csv · html     │
                     │          cyclonedx · spdx             │
                     │                                       │
                     │  Also in this binary:                 │
                     │   remote-scan (WinRM) · fleet         │
                     │   schedule · --serve                  │
                     │   --show-unmatched                    │
                     └───────────────────┬───────────────────┘
                                         │
                                         ▼  wraps via std::process::Command
                     ┌───────────────────────────────────────┐
                     │              evedoo-gui             │
                     │          (egui companion app)         │
                     │                                       │
                     │  Local Scan  ──► evedoo scan        │
                     │  Remote Scan ──► evedoo remote-scan │
                     │  Update DB   ──► cve-db-builder       │
                     │  Settings    ──► %APPDATA%/config.json│
                     │                                       │
                     │  After scan: auto CSV export +        │
                     │  HTML report opens in browser         │
                     └───────────────────────────────────────┘
```

### 2.2 Component Breakdown

#### 2.2.1 cve-db-builder (NVD Sync Tool)

**Purpose:** Downloads the entire NIST NVD database and enrichment feeds into a local SQLite file.

**Source files:**

| File | Purpose |
|---|---|
| `src/main.rs` | CLI entry point, orchestrates full/incremental/enrichment-only sync |
| `src/mirror.rs` | **Primary CVE source** — FKIE-CAD bulk feed fetcher (`.json.xz` per year + `CVE-Modified` delta) |
| `src/nvd_client.rs` | NVD API 2.0 client with async semaphore-based rate limiting (fallback path) |
| `src/cpe_dict.rs` | NVD Products API 2.0 client for the CPE dictionary (~1.8M products → ~148k identities) |
| `src/database.rs` | SQLite operations — CVE upsert, CPE match insertion, schema migration, canonical CVE-ID validation at ingest |
| `src/models.rs` | Serde models for NVD JSON responses (shared by the mirror and API paths — the mirror republishes the exact API 2.0 CVE object shape) |
| `src/epss.rs` | EPSS CSV.gz feed fetcher and parser (source: `https://epss.cyentia.com/epss_scores-current.csv.gz` from FIRST.org/Cyentia, updated daily, columns: `cve, epss, percentile`) |
| `src/kev.rs` | CISA KEV JSON catalog fetcher (source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) |

**Rate limiting design** (applies to the API fallback and the CPE dictionary,
not to the mirror path):

```
Rate limiter: async semaphore with 50 permits
Each API request acquires 1 permit
Permit released after 30-second window
When all 50 permits consumed → blocks until a permit frees

With API key:    50 requests / 30 seconds
Without API key:  5 requests / 30 seconds
```

**SQLite schema (9 tables).** Row counts are measured from the live database
(~1 GB on disk) and are useful as sanity checks after a sync:

```sql
cves              -- CVE metadata, CVSS v2/v3, severity, attack vectors    378,067
cpe_matches       -- Affected products with version ranges (vendor,      3,164,642
                  --   product, version_start/end, platform,
                  --   vulnerable, target_sw)
cve_references    -- Advisory URLs, patch links, vendor bulletins       1,234,544
cpe_dictionary    -- Official NVD product identities + titles             148,356
epss              -- EPSS scores (probability, percentile) per CVE        360,218
kev               -- CISA Known Exploited Vulnerabilities catalog           1,665
product_mappings  -- Display name → CPE rules, seeded by the scanner          138
sync_metadata     -- Last sync timestamp for incremental updates
schema_version    -- Migration tracking
```

Schema changes are **additive and guarded**, so an older database keeps working
and gains new columns on its next sync. This has a failure mode worth knowing:
if any process holds the database open — a running scan, or a long-lived
`--serve` report server — the guards cannot apply and **the sync appears to
succeed while changing nothing**. Close readers before syncing.

**Feed integrity.** Every mirror feed ships a `.meta` sidecar carrying the
`sha256` and byte size of the *decompressed* JSON. Both are verified before a
single row is parsed; a mismatch aborts that feed, a missing sidecar warns and
proceeds, and a malformed one is a hard error (that being the shape tampering
would take). This proves the payload matches what the mirror published — it does
**not** prove authorship. Defending against a fully compromised mirror needs
detached signatures, which the project does not publish.

**Mirror-first CVE sync.** The NVD API is a poor bulk-transfer channel (~180
paginated requests, frequent truncated responses under load). The primary
source is now the [FKIE-CAD NVD mirror](https://github.com/fkie-cad/nvd-json-data-feeds),
which republishes the full corpus daily as one `.json.xz` per CVE year plus a
`CVE-Modified` delta — in the exact API 2.0 CVE object shape, so the same
models parse both. The API client remains as automatic fallback.

**Sync modes:**

| Mode | Flag | API Key | Duration |
|---|---|---|---|
| Full sync (mirror) | *(default)* | No | **~1.5 min** — 28 year feeds, 1999–2026 |
| Incremental (mirror delta) | `--update` | No | ~30 s (falls back to a full mirror sync when the last sync predates the feed's 8-day window) |
| Enrichment only | `--enrichment-only` | No\* | ~30 s for KEV + EPSS |
| CPE dictionary refresh | *(automatic)* | No\* | **~2.5 hours**, at most every 30 days |
| Force API path | `--no-mirror` | Yes | ~hours (legacy fallback) |

\* The CPE dictionary uses the NVD Products API; a key raises its rate limit
from 5 to 50 req/30 s. It is a one-time ~1.8M-product pull that collapses to
148,356 stored identities, and it refreshes only when older than 30 days
(`--skip-cpe-dict` to defer explicitly), so routine syncs never pay its cost.
The 30-day rule is the reason a "quick update" is quick — remove it and every
sync becomes an overnight job.

#### 2.2.2 evedoo (Scanner Binary)

**Purpose:** Inventories all installed software on the local Windows machine and matches each entry against the CVE database.

**Eight scanner sources:**

| Scanner | Module | Detection Method | Covers |
|---|---|---|---|
| **Registry** | `registry.rs` | `HKLM`/`HKCU` 32+64-bit Uninstall keys | Most MSI/EXE installers (~79% of detections) |
| **AppX/MSIX** | `appx.rs` | `Get-AppxPackage` via PowerShell | Windows Store apps, with CamelCase→human-readable normalisation |
| **WinGet** | `winget.rs` | `winget list` column parsing | Win32 + Store apps managed by WinGet |
| **Chocolatey** | `chocolatey.rs` | `.nuspec` XML under `%ChocolateyInstall%\lib\` | Chocolatey packages (filesystem-based, no `choco` on PATH needed) |
| **Scoop** | `scoop.rs` | `manifest.json` under `%SCOOP%\apps\` | Scoop apps (filesystem-based, no `scoop` shim needed) |
| **PE Fingerprint** | `pe_fingerprint.rs` | `GetFileVersionInfoW`/`VerQueryValueW` via FFI to `version.dll` | Portable tools under ProgramFiles/LocalAppData that package managers miss, **plus 30 known bundled library DLLs** (`libcurl`, `libssl`, `zlib`, `sqlite3`, …) shipped inside applications |
| **pip/npm/cargo** | `packages.rs` | CLI invocation (`pip list --format json`, etc.) | Python, Node, Rust global packages |
| **Windows OS** | `os_version.rs` | Registry `CurrentBuildNumber` + `UBR` | The operating system itself, emitted as `os://windows/<build>.<ubr>` |

**Why bundled DLLs matter.** An application that statically ships a vulnerable
`libcurl` is invisible to every package-manager source — the app's own version
says nothing about the library inside it. Enumerating those DLLs is where a
large share of *genuine* findings now come from, and also the largest remaining
noise class (one real host carried three cURL copies and several OpenSSL
copies). Grouping duplicates and attributing them to a parent app is recorded as
future work.

**Why the OS is a scanner source.** `ProductName` in the registry still reads
"Windows 10" on Windows 11 machines. Identity is therefore derived from the
build number — **build ≥ 22000 means Windows 11** — because the field that looks
authoritative is the one that lies.

**Updater/staging suppression.** `is_updater_staging_dir()` discards binaries
found under updater and staging directories. These carry the parent product's
name with an entirely unrelated version stream, and would otherwise report every
CVE fixed between the staged version and the installed one. Note that this
catches them by *path*; the same class arriving by *name* is handled separately
by the artifact veto in §2.3.

**After inventory:** `VersionResolver` fills missing version strings via registry fallbacks (`Version`, `MajorVersion`+`MinorVersion`+`BuildVersion` keys) and a CLI whitelist (`git --version`, `python --version`, `node --version`, `rustc --version`, `go version`, `ruby --version`, `php --version`).

**Deduplication:** All entries are deduped on normalised `name|version` before matching.

### 2.3 The Matching Engine (Core Algorithm)

The matcher uses a cascading three-layer architecture. Each layer provides progressively lower confidence. Matching stops at the first layer that produces results.

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: CURATED MAPPING TABLE                             │
│  558 display-name aliases over 520 CPE identities           │
│  (CuratedMapping — one identity, one or more aliases)       │
│  Token-based subset scoring with publisher verification,    │
│  qualifier-aware penalties, and companion-artifact veto     │
│  Confidence: Exact (score >= 0.90) or High (score >= 0.75)  │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1.5: CPE DICTIONARY TITLE MATCH (Phase 13C)          │
│  148,356 product identities + titles from the Products API  │
│  Same scorer, stricter threshold (0.75): requires publisher │
│  corroboration or vendor-in-name. Confidence capped at High │
│  Inert when the DB predates the cpe_dictionary table        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: PUBLISHER → VENDOR CORRELATION                    │
│  131 publisher-to-vendor mappings                           │
│  Uses Registry Publisher field to deduce vendor             │
│  Then exact product name lookup in CpeIndex                 │
│  Confidence: High                                           │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: EXACT PRODUCT-ONLY MATCH (fallback)               │
│  No vendor filter — product name only                       │
│  Confidence: Medium                                         │
└─────────────────────────────────────────────────────────────┘
```

Cutting across all layers: **8 negative mappings** veto known-bad pairings, and
three applicability filters gate every surviving candidate row (below).

**Why curated mappings?** CPE naming conventions are not algorithmic. You cannot derive that:
- `"Google Chrome"` → `google:chrome` (not `google:google_chrome`)
- `"Node.js"` → `nodejs:node.js`
- `"7-Zip"` → `7-zip:7-zip`
- `"Visual C++ 2013 Redistributable"` → `microsoft:visual_c%2b%2b`
- `"Microsoft Edge"` → `microsoft:edge_chromium` (not `microsoft:edge`)

A curated table is the only reliable approach. It currently covers **558 display-name aliases across 520 CPE identities** (each `CuratedMapping` entry carries one CPE identity and one or more aliases, e.g. "Adobe Acrobat Reader DC" / "Adobe Reader" / "Acrobat Reader" → `adobe:acrobat_reader_dc`). Every vendor/product pair is verified to exist in the live CPE data before inclusion, and the table grows as new software is encountered.

**Does the curated table limit coverage to known software?** No — it is the
*precision* layer, not the coverage layer. A product released tomorrow is
matched by Layer 1.5 against the CPE dictionary or by Layers 2–3 on
publisher/product name, and its CVEs arrive with the next database sync without
any code change. What the curated table buys is confident, high-precision
identification of the software people actually run. `--show-unmatched` is the
instrument for measuring the gap: it lists what resolved to no CPE identity at
all, which is the natural worklist for extending the table.

#### Token-Based Scoring (`score_curated_match`)

Each curated mapping is scored against the detected software:

```
1. Tokenise both strings: split on non-alphanumeric, lowercase
   "Google Chrome" → ["google", "chrome"]
   "Python 3.13.2" → ["python", "3", "13", "2"]

2. Subset check: all pattern tokens must appear in name tokens
   Pattern ["python"] ⊂ name ["python", "3", "13", "2"] → proceed
   Pattern ["python"] ⊄ name ["java", "runtime"] → score = 0.0

3. Artifact veto (Phase 18) — checked BEFORE scoring:
   If any extra token is ARTIFACT-class (installer, setup, updater,
   update, uninstall, uninstaller, helper, bootstrapper, launcher)
   → return 0.0 immediately. No score can rescue it.

   "Extra" is load-bearing here. The word only vetoes when it is in the
   software name but NOT in the matched pattern, so products genuinely
   named that way are unaffected: "Epic Games Launcher" still matches
   epicgames:launcher, because "launcher" is then part of the pattern.

4. Weighted score (extra tokens are classified — Phase 13A):
   base_score = 0.70
   - 0.25 per extra CORE token       (identity word: "server", "sdk")
   - 0.05 per extra QUALIFIER token  (edition word: "pro", "enterprise", "dc")
   -  0.0 per extra NOISE token      (packaging: "redistributable", "x64")
     (numeric-only extra tokens are ignored)
   + 0.25 if publisher vendor matches CPE vendor
   + 0.05 if CPE vendor name appears in name tokens
   Clamped to [0.0, 1.0]

   Classification lives in normalize/tokens.rs (classify_token, with
   17 QUALIFIERS, 7 NOISE, 9 ARTIFACT words) so the scorer, the
   dictionary layer, and any future layer share one source of truth.

5. Score → Confidence:
   >= 0.90 → Exact
   >= 0.75 → High
   >= 0.55 → Medium
   <  0.55 → Low
   
   Minimum threshold: 0.60 (CURATED_MIN_SCORE)
```

**Examples:**

| Software | Pattern Match | Score | Confidence |
|---|---|---|---|
| `"Google Chrome"` + publisher Google LLC | `"Google Chrome"` | 1.00 | Exact |
| `"Adobe Acrobat Reader DC"` + publisher Adobe | `"Adobe Acrobat Reader DC"` (alias) | 1.00 | Exact |
| `"VLC media player"` + publisher VideoLAN | `"VLC media player"` (+0.25 publisher) | 0.95 | Exact |
| `"Microsoft Office Professional Plus"` + publisher Microsoft | `"Microsoft Office"` (2 qualifiers, −0.10) | 0.90 | Exact |
| `"Python 3.13"` | `"Python"` (digits ignored) | 0.75 | High |
| `"Google Chrome Installer"` + publisher Google LLC | `"Google Chrome"` — **artifact veto** | 0.00 | Rejected |
| `"Python Launcher"` | `"Python"` — **artifact veto** | 0.00 | Rejected |

The last two rows are the entire content of Phase 18, and they are worth
internalising: without the veto, the Chrome installer scores a **perfect 1.00**
with publisher confirmation, and its stale bundled version then matches every
Chrome CVE fixed since. One name produced 2,385 false findings that way.

#### Applicability Filters (Precision Layer)

Three NVD signals gate every candidate row before version comparison:

```
1. vulnerable = 1  (index load time)
   NVD AND-configurations mark the "running on" side as vulnerable=0 —
   context, not findings. ~25% of raw rows are excluded here.

2. platform ∉ {linux, macos}  (index load time)
   Rows scoped to non-Windows builds can never apply.

3. target_sw compatibility  (per candidate row)
   The CPE ecosystem field gates on detection source:
     pip://   → python | wildcard      cargo:// → rust | wildcard
     npm://   → node.js | wildcard     desktop  → never ecosystem-scoped
   Kills wordpress-plugin / python-library CPEs matching desktop exes
   that share a product name (and vice versa).
```

Negative mappings add an explicit veto layer: `("Microsoft Edge Update",
"microsoft", "*")` blocks a whole vendor for updater-class tools whose own
version stream is wrong against every product the vendor ships.

#### Coverage Diagnostic (`--show-unmatched`)

`CveMatcher::resolves_identity()` walks the same layer cascade and reports
whether *any* layer lands on a CPE identity backed by index rows. This
separates "no published CVEs" (healthy) from "never correlated" (a coverage
gap), turning correlation coverage into a per-scan number and producing the
natural worklist for future curation.

#### In-Memory CpeIndex (Performance Layer)

```rust
struct CpeIndex {
    rows: Vec<CpeRow>,                              // flat row store
    by_vendor_product: HashMap<(String, String), Vec<u32>>,  // (vendor, product) → row indices
    by_product: HashMap<String, Vec<u32>>,           // product-only → row indices (fallback)
}
```

- Built once at startup from SQLite (~8s for a production 3M-row database)
- All subsequent lookups are O(1) HashMap operations
- A perf regression test guards against accidental reintroduction of linear scans

### 2.4 Version Resolution & Comparison

#### The Version Struct

```rust
struct Version {
    release: Vec<u32>,          // [1, 2, 3] for "1.2.3"
    letter: Option<char>,       // 'a' for "1.0a"
    pre: Option<PreRelease>,    // alpha < beta < rc < release
    build: Option<String>,      // ignored in comparisons
}
```

**Parser handles:**
- Standard semver: `1.2.3`
- Leading `v`: `v1.2.3`
- 4-component Windows versions: `1.2.3.4`
- Calendar versions: `2023.10.5`
- Pre-release tags: `1.2.3-beta`, `1.2.3-rc.1`, `1.2.3-alpha.2`
- Letter suffixes: `1.0a`, `1.0b`
- Build metadata: `1.0.0+build.5` (parsed, ignored in comparison)

**Comparison order (Ord implementation):**

```
1. Release components (numeric, zero-padded to equal length)
   [1,2,3] vs [1,2,3,0] → equal
   [2,0,0] > [1,9,9]

2. Letter suffix (if present)
   1.0a < 1.0b < 1.0 (letter present sorts before absent)

3. Pre-release tag (if present)
   1.0.0-beta < 1.0.0 (pre-release sorts before release)
   Ordering: Dev < Alpha < Beta < RC < Other < Post
   Within kind: numeric suffix compared (beta.1 < beta.2)

4. Build metadata — ignored
```

#### Version Vulnerability Checking

```
Input: software version string + CPE match record (with optional range fields)

1. If version is empty → return false (conservative)

2. If no range fields exist:
   a. If cpe_match.version == "*" or "-" → return true (wildcard)
   b. If cpe_match.version == parsed(software_version) → return true (exact pin)
   c. Otherwise → return false

3. If range fields exist, check all constraints:
   - version_start_including: software_version >= start
   - version_start_excluding: software_version > start
   - version_end_excluding:   software_version < end
   - version_end_including:   software_version <= end
   All constraints must pass → return true
```

### 2.5 Delta Tracking

SQLite table `scan_findings` in `scan_history.db`:

```sql
CREATE TABLE scan_findings (
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
```

**Delta algorithm (`apply_delta`):**

```
1. Load all previous findings for this hostname (status != 'Resolved')
2. For each current finding:
   - If (cve_id, software_name) existed in previous scan → tag "Persisting"
   - Otherwise → tag "New"
3. For each previous finding NOT in current scan:
   - Mark as "Resolved" in database
   - Include in report under resolved section
4. Upsert all current findings with updated last_seen timestamp
```

### 2.6 Report Formats

| Format | File | Purpose |
|---|---|---|
| **Text** | `report/text.rs` | Colored terminal output grouped by severity, with remediation advice |
| **CSV** | `report/csv.rs` | 25-column enterprise format, compatible with Rapid7/Tenable import |
| **JSON** | `report/json.rs` | Full `ScanResult` serialization for pipelines and custom tooling |
| **HTML** | `report/html.rs` | Self-contained interactive triage surface (below) |
| **CycloneDX** | `report/cyclonedx.rs` | CycloneDX 1.6 SBOM including VEX vulnerability data with exploitable/resolved status |
| **SPDX** | `report/spdx.rs` | SPDX 2.3 inventory-only SBOM, per standard practice |

Both SBOM formats are hand-serialized with `serde_json` rather than pulling in
the `cyclonedx-bom` crate — consistent with the project's preference for direct
implementation over heavy dependencies.

**Report sorting order:** KEV status (descending) → EPSS score (descending) → CVSS severity (descending) → published date (descending). This surfaces "patch these first" items at the top rather than just listing everything CVSS 9+.

#### The HTML report (Phase 19)

A single self-contained file with no external assets, built on a token-driven
design system in the macOS/Material language: Apple's dark system palette,
Material elevation (`--e1`…`--e4`), vibrancy via `backdrop-filter` on the
header, sticky table head and modal, capsule chips, a segmented tab control, and
a print stylesheet that flattens elevation for PDF sharing.

It opens on **Top Solutions** — findings grouped by software and ranked by
impact (CVE count × max CVSS), each card carrying a severity breakdown, the
fixed version, a copyable upgrade command, KB links, and a KEV badge. **All
Findings** is the second tab, with KEV and Has-Fix filter chips that AND with the
severity group, a live row counter, sort-direction arrows, sqrt-scaled EPSS
magnitude bars, and per-row detail sheets.

**Escaping model — the part most likely to be got wrong.** Text nodes and
attributes need *different* escaping. The client-side `esc()` uses a
`textContent → innerHTML` round-trip, which escapes `& < >` but **not quotes**;
using it in an attribute position is a vulnerability, not a nicety, because the
browser HTML-decodes `data-*` values before JS ever reads them — so `esc()` in an
attribute actively *undoes* the correct Rust-side escaping. Attributes therefore
go through `escAttr()`, and any URL through the `safeUrl()` http/https allowlist.
A regression test walks every rendered row's `data-*` values and fails if any
contains markup.

### 2.7 Configuration & Compliance Auditing (`evedoo audit`)

**Purpose:** Automated hardening assessment against authoritative **DISA STIG (Defense Information Systems Agency Security Technical Implementation Guides)** and **NIST SP 800-53** security controls.

**Source files (`evedoo/src/audit/`):**

| File | Purpose |
|---|---|
| `policy.rs` | Data models (`Benchmark`, `BenchmarkRule`, `CheckAssertion`, `RuleResult`, `AuditSummary`) and comparison operator evaluation |
| `evaluator.rs` | Direct Winreg FFI evaluation across HKLM/HKCU/HKU and Windows service startup types |
| `builtin.rs` | Bundled baseline checks derived from DISA STIGs (Windows 11 V1R4, Windows 10 V2R8, Windows Server 2022 V1R3, Microsoft Edge V1R2) |
| `report.rs` | Text (`owo-colors`), JSON, CSV, and interactive HTML compliance report generators |
| `mod.rs` | Top-level audit coordinator (`run_audit`) supporting bundled and custom policy files |

**Licensing Standard:**
The bundled rules are Evedoo's own wording (Apache-2.0) of a small sample of each STIG; they are not DISA's text and Evedoo is not an official DISA product.

**Evaluation Capabilities:**
- **Registry Check Assertions:** Supports DWORD, QWORD, String, ExpandString, MultiString, and Binary keys.
- **Comparison Operators:** `Equals`, `NotEquals`, `GreaterThanOrEqual`, `LessThanOrEqual`, `BitwiseAnd` bitmasks, `Exists`, `NotExists`, and `Contains`.
- **Severity Classification:** `CatI` (High severity / immediate compromise), `CatII` (Medium severity / defense in depth), `CatIII` (Low severity / administrative).
- **Compliance Score Calculation:** Percentage pass rate (`passed_rules / total_applicable * 100.0`) with CAT I/II/III breakdowns.

---

### 2.8 Runtime Module Reachability

**Purpose:** Inspects active process memory and loaded dynamic link libraries (DLLs) via Toolhelp32 Win32 FFI to determine if vulnerable libraries are actively loaded in memory.

**Source files (`evedoo/src/reachability/`):**

| File | Purpose |
|---|---|
| `mod.rs` | `Reachability` enum (`Loaded`, `NotObserved`, `Unknown`), `ModuleMap`, software classification, and safety scoring |
| `local.rs` | Toolhelp32 snapshot FFI (`CreateToolhelp32Snapshot`, `Process32FirstW`, `Module32FirstW`, `TH32CS_SNAPMODULE32`) |

**Safety Guard (FR-74 & FR-76):**
- When process coverage is incomplete (`readable < total`), all unobserved findings are forced to `Unknown` (never claiming `NotObserved` without proof).
- Reachability multipliers are strictly `>= 1.0` (active services can be prioritized, but dormant code is never demoted on a transient sample).

---

### 2.9 Authoritative Vendor Advisories (MSRC)

**Purpose:** Ingests official Microsoft Security Response Center CVRF JSON advisories to obtain exact KB article IDs, identify patched Windows builds, and suppress false-positive OS/component CVEs.

**Source files:**
- `cve-db-builder/src/msrc/`: CVRF parsing, SQLite tables (`msrc_products`, `msrc_fixes`, `msrc_sync`), and HTTPS sync client behind `--enable-msrc`.
- `evedoo/src/msrc_override.rs`: `is_patched(installed, fixed_build)` version comparison and match override pipeline.

---

### 2.10 Cross-Asset Fleet Remediation Aggregation

**Purpose:** `evedoo fleet report` groups stored scan findings across all registered hosts in `scan_history.db` to rank software upgrades by total fleet risk reduction.

**Source files (`evedoo/src/aggregate.rs`):**
- Computes risk scores at report time from the live CVE database (`FR-84`).
- Filters out resolved findings and groups by software product to surface top enterprise patch actions.

---

### 2.11 Agent Task State Coordination (`evedoo-taskstate`)

**Purpose:** Cross-runtime agent coordination server & CLI facilitating seamless task handoffs and state persistence between Claude Code and Antigravity.

**Architecture:**
- Append-only event ledger: `docs/agent-state/tasks.jsonl`.
- Advisory locking: `fs4` cross-platform file locks (`docs/agent-state/.lock`).
- Pure fold derivation: `fold(&[Record]) -> State` deriving task lifecycles, review queues, and next actions.
- 8 MCP tools exposed over stdio via `rmcp`: `task_state`, `task_declare`, `task_start`, `task_finish`, `task_review`, `task_ruling`, `task_history`, `task_handoff`.
- Auto-generated markdown view: `docs/agent-state/CURRENT.md`.

---

### 2.12 Evedoo Studio (`evedoo-studio`)

**Purpose:** Modern dual-target (Desktop + Web) SecOps workspace combining Apple Human Interface Guidelines (clean frosted glass, refined typography, minimal elevation) and Google Material 3 (expressive status chips, tonal palettes).

**Key Features:**
- **First-Class Dark & Light Modes:** OLED Dark (`#090a0f`) and Crisp Light (`#f8f9fa`) with theme toggle and persistence.
- **Live Scanner Engine Bridge:** Custom Vite middleware connecting directly to `evedoo.exe scan -f json` and `docs/agent-state/tasks.jsonl`.
- **Views:** Command Center (KPI metrics, CISA KEV threat radar, pipeline visualizer), Triage & Findings table with flyout detail drawer, Fleet Asset Grid, Accepted-Risk Rules Manager, Software Inventory (SBOM), Agent Task State, and Settings.
- **Technology Stack:** React 18, TypeScript, Vite, Tailwind CSS, Lucide React icons.

---

## 3. Project Management & Development History

### 3.1 Phase Roadmap

`docs/roadmap.md` is the single source of truth for phase
numbering and carries the full write-up of each. Summary below.

**Core phases** — execution order **#1 → #2 → #3 → #5 → #4 → #6** (EPSS/KEV was
prioritised before the in-memory index):

| Phase | Description | Status | Effort | Key Change |
|---|---|---|---|---|
| **#0** | CVE Database Builder | Done | — | NVD API client, SQLite schema, rate limiting |
| **#1** | Structured version comparison | Done | 2-3h | `Version` type with `Ord` for semver/calver/pre-release/letter suffix |
| **#2** | Exact-version CPE fallback | Done | 1h | Catch CPE entries pinning a single version with no range fields |
| **#3** | Token matching + curated mapping | Done | 4-6h | Subset-based token scoring, weighted confidence, `KNOWN_MAPPINGS` |
| **#5** | EPSS + CISA KEV enrichment | Done | 3-4h | Priority sort by real-world exploitation signal |
| **#4** | In-memory CPE index | Done | 2h | `(vendor, product)` HashMap over flat row store |
| **#6** | Normalisation module | Done | 2h | Consolidated tokenisation, version parsing, name cleanup |

**Capability phases:**

| Phase | Description | Status | Key Change |
|---|---|---|---|
| **#7–8** | SBOM export | Done | CycloneDX 1.6 with VEX + SPDX 2.3, hand-serialized |
| **#9** | Remote scanning | Done | Agentless WinRM via PowerShell `Invoke-Command` |
| **#10B** | Patch recommendations | Done | Fixed versions, KB articles, per-source upgrade commands |
| **#10C** | Fleet management | Done | Asset registry with tagging, scan tracking, summaries |
| **#10D** | Scheduled scanning | Done | Windows Task Scheduler via `schtasks.exe` |
| **#11** | Security hardening | Done | TLS default-on, privilege opt-in, path-traversal rejection, `--serve` token auth, credential zeroization |
| **#12** | GUI companion app | Done | egui desktop app wrapping the CLI |

**Correlation-quality phases** — where most of the recent work went:

| Phase | Description | Status | Key Change |
|---|---|---|---|
| **#13 (A–C)** | Correlation engine overhaul | Done | `CuratedMapping` alias struct, qualifier-aware scoring, negative-mapping vetoes, CPE dictionary layer, expanded accuracy gate |
| **#14** | Detection expansion + applicability | Done | Bundled library DLLs, the Windows OS itself, updater/staging suppression, `vulnerable`/platform/`target_sw` enforcement |
| **#15** | Mirror-first CVE sync | Done | FKIE-CAD bulk feeds as primary source — hours → ~1.5 min, no API key |
| **#16** | Coverage diagnostic | Done | `--show-unmatched` separates "no known CVEs" from "never correlated" |
| **#17** | Security remediation (SEC-1…7) | Done | Context-correct escaping, credentials off argv onto stdin, CVE-ID ingest validation, feed integrity, binary-planting fix |
| **#18** | Companion-artifact veto | Done | `TokenClass::Artifact` — one FP class was 73% of a real scan |
| **#19** | Report design system | Done | macOS/Material language plus filter chips, row counter, sort indicators, EPSS bars, detail sheets, copyable commands, print stylesheet |

**Operationalisation and enterprise-accuracy phases** — the N1–N7 backlog, now
fully shipped:

| Phase | Item | Description | Status | Key Change |
|---|---|---|---|---|
| **#20** | N1 | Reassess without rescanning | Done | `evedoo reassess` re-correlates persisted inventory snapshots offline (FR-57–FR-62) |
| **#20** | N2 | Unified risk scoring | Done | `100 · impact^0.4 · likelihood^0.6 · criticality`, P1–P4 tiers, KEV override (FR-63–FR-67) |
| **#20** | N4 | Expiring accepted-risk exceptions | Done | Scoped `(hostname, cve_id, software_name)` rules, mandatory owner/reason, 730-day cap (FR-68–FR-72) |
| **#21** | N3 | Runtime module reachability | Done | Toolhelp32 FFI; `Loaded` / `NotObserved` / `Unknown`, multiplier floor of 1.0 (FR-73–FR-82) |
| **#21** | N7 | Cross-asset remediation aggregation | Done | `evedoo fleet report` ranks upgrades by total fleet risk removed (FR-83–FR-88) |
| **#21** | N5 | Authoritative MSRC advisories | Done | Opt-in `--enable-msrc` CVRF sync; exact KB + fixed build overrides NVD (FR-89–FR-96) |
| **#21** | N6 | Configuration & compliance auditing | Done | `evedoo audit` against baseline checks derived from DISA STIGs, mapped to NIST SP 800-53 (FR-97–FR-105) |
| **#21** | — | Evedoo Studio | Done | React 18 + TS + Tailwind SecOps workspace with a live engine bridge |
| **#21** | — | Dependency cleanliness | Done | `colored` → `owo-colors`, `directories`/`option-ext` removed: zero MPL-2.0 |

**Cross-cutting, no phase number:** CI with `clippy -D warnings` as a gate and a
`CpeIndex` perf-ceiling test; the frozen-fixture accuracy gate, since expanded to
53 true positives, 53 true negatives, and wrong-product identity negatives
generated from `GATE_CASES`; and `evedoo-taskstate`, the cross-runtime agent
coordination ledger described in §2.11.

**What's next** is recorded at the end of `docs/roadmap.md`: native
Universal Linux and macOS scanners (implementation plans already authored under
`docs/superpowers/plans/`), ticketing integration driven off CISA KEV due dates,
historical risk burn-down trends, and dry-run-gated automated remediation.

**One ruling worth knowing before you touch reachability** (recorded in
`docs/agent-state/CURRENT.md`): because FR-74 forces every non-match to
`Unknown` whenever coverage is incomplete, `NotObserved` is unreachable in
practice on an unelevated scan — measured at 159 of 332 processes readable, 6
findings `Loaded`, 0 `NotObserved`, 982 `Unknown`. The feature therefore
promotes loaded findings but cannot currently report a finding as dormant. That
is deliberate, and `is_complete()` was left strict on purpose.

### 3.2 Key Technical Challenges & Resolutions

#### Challenge 1: The 10,938 False Positive Problem

**Symptom:** First scan of a machine with 134 installed apps returned 10,938 CVE findings. An enterprise security team would immediately lose trust in the tool.

**Root causes (three independent, compounding):**

1. **Substring SQL matching** — `LIKE '%edge%'` matched `edge_chromium` (correct), but also `edgemarc`, `edge_gateway`, `cutting_edge_cms`, `knowledge_edge` (all wrong). Each false product match multiplied by dozens of CVEs.

2. **No vendor verification** — `"Python"` matched `python` by vendor `python` (correct), but also `python` by vendor `fedoraproject` and `debian` (wrong). The vendor column was fetched from SQLite but never checked.

3. **Version-less CPE entries matching everything** — Many CPE entries (especially pre-2018) have all four version range fields as NULL, meaning "all versions affected." The original code treated these as matches, so Firefox 149.0.2 (2026) would match CVE-2009-XXXX.

**Resolution (two iterations):**

| Iteration | Findings | Change |
|---|---|---|
| Phase 1 (baseline) | 10,938 | `LIKE '%name%'`, no vendor check |
| Phase 1.5 v1 | 4,480 (-59%) | Three-layer matching with exact SQL, vendor verification, publisher correlation |
| Phase 1.5 v2 | 67 (-99.4%) | Skip CPE entries with no version range fields |

The single most impactful fix was the version range guard — one `if !has_any_range { return false; }` clause eliminated ~4,400 false matches.

**Trade-off:** Skipping range-less CPEs could miss vulnerabilities where "all versions" is truly affected. However, modern NVD entries (2018+) always include ranges, and old entries are typically superseded. Users can lower the threshold with `--min-confidence low` to recover recall.

#### Challenge 2: The NVD Date Format Bug

**Symptom:** The NVD API rejected requests with `lastModStartDate` parameter, returning HTTP 400.

**Root cause:** The NVD API 2.0 requires ISO-8601 dates with second precision (`2026-01-01T00:00:00.000`). The code was sending nanosecond precision from Rust's `chrono::Utc::now()`, which NVD's parser rejected.

**Fix:** Truncated timestamps to millisecond precision before sending to the API.

#### Challenge 3: The Two-Database Problem

**Symptom:** Users had to manually copy `vulndb.sqlite` to the scanner's working directory, or remember the exact path every time.

**Resolution:** The scanner accepts the database path via three mechanisms with clear precedence:

```
CLI flag (-d, --database)  >  Environment variable (EVEDOO_DB_PATH)  >  Default ("vulndb.sqlite")
```

The `EVEDOO_DB_PATH` environment variable allows enterprise deployments to set the path once system-wide.

#### Challenge 4: PE Header Case Sensitivity

**Symptom:** Some portable executables returned empty version strings despite having valid `VS_VERSION_INFO` resources.

**Root cause:** The `VerQueryValueW` API's StringFileInfo path uses a translation table (language ID + code page) formatted as hex. Some executables use uppercase hex (`04B00000`), others lowercase (`04b00000`).

**Fix:** `query_string()` tries uppercase hex first (`{:04X}`), then falls back to lowercase (`{:04x}`).

#### Challenge 5: One name, 2,385 false positives

**Symptom:** A routine database update took a scan from 901 findings to 3,287.
The obvious suspect — new CVEs in the feed — was wrong.

**Root cause:** **2,385 of the 3,287 findings (73%) came from a single detected
entry**: "Google Chrome Installer v127.0.6512.0". The installer stub carries the
product's name but its own, much older version, so it matched `google:chrome`
and inherited every Chrome CVE fixed between v127 and the actually-installed
v151.

The uncomfortable part is that this was **self-inflicted by an earlier phase**.
Phase 13 had placed `installer` in the NOISE token list, meaning *zero penalty*
— so the name scored a perfect 1.00 with publisher confirmation. Phase 14's
updater-directory suppression would have caught this class by *path*; this one
arrived by *name* and walked straight through.

**Fix:** `TokenClass::Artifact` and a hard veto (§2.3), taking the scan back to
901 with genuine findings intact.

**Lessons worth keeping:**
- A large finding-count jump after a *data* update usually indicates a *matching*
  bug, not new vulnerabilities. Check the distribution before believing the total.
- Classifying a token as harmless is an assertion about every product name
  containing it. `installer` was not harmless.
- Two suppression mechanisms covering "the same" class by different keys (path
  vs name) do not imply coverage. Enumerate the keys.

#### Challenge 6: An off-by-three-years constant that dropped 4,378 CVEs

**Symptom:** None. Nothing failed, no test broke, no warning appeared.

**Root cause:** `FIRST_FEED_YEAR` in the mirror client was `2002`, with a comment
asserting that pre-2002 CVEs were folded into the 2002 feed. That assertion was
simply false — the mirror publishes a feed per year from **1999**. Every fresh
database build silently omitted **4,378 CVEs**.

**Fix:** `FIRST_FEED_YEAR = 1999` (28 feeds, 1999–2026).

**Lesson:** the dangerous constants are the ones with a confident comment
explaining why they are right. This one was found by counting rows against the
feed listing, not by any test — completeness of an external feed is not
something unit tests can assert.

#### Challenge 7: An attribute that ate the findings table

**Symptom:** The entire All Findings table vanished from the HTML report.

**Root cause:** `data-epss` was bound to a variable that had been repurposed to
hold rendered *markup* rather than the raw score. The embedded `class="epss"`
quote terminated the attribute early, and every following row was parsed as
garbage.

**Fix:** bind `data-epss` to the raw score, plus a regression test
(`data_attributes_never_contain_markup`) that walks every rendered row's `data-*`
values and fails if any contains markup. A sibling bug in the same pass: the
filter JS toggled a `.hidden` class that no stylesheet ever defined, so filtering
silently did nothing.

**Lesson:** generated HTML needs tests that parse the output, not just tests that
assert a substring appears in it. Both bugs produced perfectly valid-looking
strings.

#### Challenge 8: CI "broke" at a commit that changed nothing relevant

**Symptom:** GitHub Actions failed from commit `bc77db0`; the last green run was
`9ddc465`. The obvious conclusion was that `bc77db0` introduced the breakage.

**Root cause:** **Toolchain drift.** Local clippy was 0.1.93 (January 2026); CI
runs `stable`, by then 1.98.0 (August 2026), which had added lints. The commit
was innocent.

**The tell:** clippy flagged `version_resolver.rs`, a file `bc77db0` never
touched. When a failure implicates files outside the diff, suspect the
environment, not the change.

**Fix:** `rustup update stable` locally, then fix the three new lints
(`question_mark`, `unnecessary_sort_by`, `field_reassign_with_default`).

**Lesson:** with `-D warnings` as a CI gate, a floating `stable` toolchain means
CI can break with no commit at all. Update the local toolchain before debugging
a clippy failure you cannot reproduce.

### 3.3 Delta Tracking Mechanism

The SQLite `scan_history.db` persists findings across runs. Each finding is keyed on `(hostname, cve_id, software_name)`.

**State transitions:**

```
First scan:      All findings           → "New"
Subsequent run:  Found again            → "Persisting"  (last_seen updated)
                 Software newly seen    → "New"         (inserted)
                 Software already known,
                   CVE data now matches → "NewlyApplicable"     (FR-59, FR-60)
                 Software gone, or version
                   now outside range    → "Resolved"
                 CVE data changed so the
                   match no longer holds→ "NoLongerApplicable"
```

`New` vs `NewlyApplicable` is the distinction that makes a delta trustworthy:
the first means the host changed, the second means the *database* changed.
Reconciliation is mode-aware (`Scan` vs `Reassess`, FR-59) and filtering runs
**after** delta tracking (FR-61, FR-62), so a severity or confidence filter can
never manufacture a false `Resolved`.

This enables:
- **Trend reporting** — track how many open vulnerabilities over time
- **Remediation verification** — confirm patches resolved specific CVEs
- **Regression detection** — catch re-introduced vulnerabilities after rollbacks

---

## 4. Codebase Navigation & Operations

### 4.1 Directory Structure

```
evedoo/                              (repo root)
├── cve-db-builder/                    NVD → SQLite sync tool
│   ├── Cargo.toml                     Dependencies: reqwest, tokio, rusqlite, clap
│   ├── src/
│   │   ├── main.rs                    CLI + sync orchestration
│   │   ├── mirror.rs                  ◄ PRIMARY CVE source: FKIE-CAD bulk feeds
│   │   │                                (.json.xz per year + .meta sha256 verify)
│   │   ├── nvd_client.rs              NVD API 2.0 client + rate limiting (fallback)
│   │   ├── cpe_dict.rs                ◄ NVD Products API → cpe_dictionary table
│   │   ├── database.rs                SQLite ops (CVE upsert, schema init,
│   │   │                                canonical CVE-ID validation)
│   │   ├── models.rs                  Serde structs for NVD JSON (shared by both paths)
│   │   ├── epss.rs                    EPSS CSV.gz fetcher
│   │   ├── kev.rs                     CISA KEV JSON fetcher
│   │   └── msrc/                      OPT-IN Microsoft advisories (--enable-msrc)
│   │       ├── fetch.rs               CVRF document listing + retrieval
│   │       ├── parse.rs               CVRF -> products/fixes, lowercased CPEs (FR-96)
│   │       └── store.rs               msrc_products, msrc_fixes, msrc_sync tables
│   └── migrations/
│       ├── 001_initial_schema.sql     Core tables (cves, cpe_matches, references)
│       ├── 002_epss_kev.sql           Enrichment tables (epss, kev)
│       └── 003_cpe_dictionary.sql     CPE dictionary table
│
├── evedoo/                          Scanner binary (Windows-only)
│   ├── Cargo.toml                     Dependencies: winreg, rusqlite, clap, serde
│   └── src/
│       ├── main.rs                    CLI entry point, scan orchestration
│       ├── models.rs                  DetectedSoftware, Vulnerability, Finding,
│       │                                FindingStatus, PriorityTier
│       ├── error.rs                   Error types
│       ├── schema.rs                  scan_history.db migrations (PRAGMA user_version)
│       ├── history.rs                 Delta tracking (scan_history.db)
│       ├── inventory.rs               Per-host software snapshot persistence (FR-57)
│       ├── correlate.rs               The single unfiltered correlation stage (FR-61)
│       ├── reconcile.rs               Mode-aware delta reconciliation (FR-59, FR-62)
│       ├── risk.rs                    Impact x Likelihood scoring, P1-P4 tiers (FR-63)
│       ├── exceptions.rs              Expiring accepted-risk rules (FR-68-FR-72)
│       ├── aggregate.rs               Fleet remediation rollups (FR-83-FR-88)
│       ├── msrc_override.rs           MSRC verdict override, is_patched() (FR-89-FR-96)
│       ├── fleet.rs                   Asset registry: tags, scan tracking, summaries
│       ├── schedule.rs                Task Scheduler integration (schtasks.exe)
│       ├── serve.rs                   Local HTTP report server, random-token auth
│       ├── audit/                     Compliance auditing (FR-97-FR-105)
│       │   ├── policy.rs              Benchmark models, ComparisonOperator::evaluate()
│       │   ├── evaluator.rs           Winreg + service-startup assertion evaluation
│       │   ├── builtin.rs             Baseline checks derived from DISA STIGs (35)
│       │   └── report.rs              text / json / csv / html compliance reports
│       ├── reachability/              Runtime module reachability (FR-73-FR-82)
│       │   ├── mod.rs                 Reachability enum, ModuleMap, classify()
│       │   ├── local.rs               Toolhelp32 FFI sweep (incl. TH32CS_SNAPMODULE32)
│       │   └── remote.rs              Fixed non-interpolated WinRM blocks (SEC-8)
│       ├── remote/
│       │   ├── session.rs             WinRM session, input validation, ps_escape(),
│       │   │                            credential zeroization, TLS on by default
│       │   └── scanners.rs            Per-source remote scanner variants
│       ├── scanner/
│       │   ├── mod.rs                 Module exports
│       │   ├── registry.rs            ◄ Windows Registry scanner
│       │   ├── appx.rs                ◄ AppX/MSIX (Windows Store) scanner
│       │   ├── winget.rs              ◄ WinGet package scanner
│       │   ├── chocolatey.rs          ◄ Chocolatey scanner (filesystem)
│       │   ├── scoop.rs               ◄ Scoop scanner (filesystem)
│       │   ├── pe_fingerprint.rs      ◄ PE header fingerprinter (FFI), bundled
│       │   │                            library DLLs, updater/staging suppression
│       │   ├── packages.rs            ◄ pip/npm/cargo scanner
│       │   ├── os_version.rs          ◄ Windows OS identity → windows_* CPEs
│       │   └── version_resolver.rs    Version fallback (registry + CLI)
│       ├── matcher/
│       │   ├── mod.rs                 CveMatcher struct + find_vulnerabilities()
│       │   ├── cpe.rs                 ◄ KNOWN_MAPPINGS, PUBLISHER_VENDORS,
│       │   │                            NEGATIVE_MAPPINGS, scoring, version check,
│       │   │                            resolves_identity(), GATE_CASES
│       │   ├── dict.rs                ◄ Layer 1.5 CPE dictionary matcher
│       │   └── index.rs               ◄ CpeIndex + applicability filters at load
│       ├── normalize/
│       │   ├── mod.rs                 Re-exports
│       │   ├── version.rs             ◄ Version struct + Ord impl
│       │   ├── names.rs               AppX CamelCase splitting, name cleanup
│       │   └── tokens.rs              ◄ Tokenisation + TokenClass (Core/Qualifier/
│       │                                Noise/Artifact), classify_token()
│       └── report/
│           ├── mod.rs                 Format dispatcher
│           ├── text.rs                Terminal output
│           ├── csv.rs                 Enterprise 25-column CSV
│           ├── json.rs                Machine-readable JSON
│           ├── html.rs                Interactive HTML report + design system
│           ├── cyclonedx.rs           CycloneDX 1.6 SBOM with VEX
│           └── spdx.rs                SPDX 2.3 SBOM
│
├── evedoo-gui/                      egui GUI companion app
│   └── src/
│       ├── main.rs                    eframe entry point
│       ├── app.rs                     Tab routing, command polling, results display
│       ├── config.rs                  Persistent settings (%APPDATA%/evedoo-gui/config.json)
│       ├── command.rs                 Background CLI execution via std::thread + mpsc
│       ├── models.rs                  Serde structs mirroring evedoo's JSON output
│       ├── results_table.rs           Sortable findings table with severity colors
│       └── tabs/                      local_scan, remote_scan, update_db, settings
│
├── evedoo-taskstate/                Agent task coordination MCP server (cross-platform)
│   ├── Cargo.toml                     edition 2024, MSRV 1.88+ — rmcp, fs4, tokio
│   ├── src/
│   │   ├── main.rs                    CLI: serve | render | validate
│   │   ├── lib.rs                     Store + TaskStateServer exports
│   │   ├── model.rs                   Record/event and State types
│   │   ├── store.rs                   Append-only JSONL + fs4 advisory locking
│   │   ├── fold.rs                    Pure fold(&[Record]) -> State
│   │   ├── tools.rs                   The 8 MCP tools
│   │   └── render.rs                  CURRENT.md generation
│   └── tests/concurrency.rs           Structural invariants under concurrent writers
│
├── evedoo-studio/                   React 18 + TS + Tailwind SecOps workspace (npm)
│   ├── vite.config.ts                 Dev-server middleware = the live engine bridge
│   └── src/
│       ├── api/adapter.ts             Transport adapter (live|demo|tauri|rest|mock)
│       ├── api/mockData.ts            Fallback dataset for static builds
│       ├── types/                     scanner.ts, taskstate.ts
│       └── components/                command-center, triage, fleet, sbom,
│                                        exceptions, agent-state, settings, layout
│
├── docs/
│   ├── agent-state/tasks.jsonl        Append-only agent ledger (source of truth)
│   ├── agent-state/CURRENT.md         AUTO-GENERATED — never edit by hand
│   └── superpowers/{specs,plans}/     Per-feature design specs and execution plans
│
├── Cargo.toml                         Workspace manifest (members: evedoo,
│                                        cve-db-builder, evedoo-gui, evedoo-taskstate)
├── .cargo/config.toml                 GIT-IGNORED, machine-local — see §4.3
├── .mcp.json                          Claude Code MCP config (taskstate)
├── .agents/mcp_config.json            Antigravity MCP config (taskstate)
├── .github/workflows/ci.yml           CI: evedoo on Windows; cve-db-builder and
│                                        evedoo-taskstate on Windows + Linux
├── README.md                          Project documentation
├── CLAUDE.md / GEMINI.md              Project rules for AI assistants
├── skill.md                           Pointer to CLAUDE.md
├── LICENSE                            Apache 2.0
└── docs/
    ├── spec.md                        Spec-Driven Development requirements
    │                                    (FR-01…105, NFR-1…9, SEC-1…10, DC-1…9)
    ├── architecture.md                This document
    ├── cli-reference.md               Full CLI / API / MCP reference
    ├── license-audit.md               Dependency license audit (Cargo + npm)
    ├── roadmap.md                     Shipped phases + what's next
    ├── security/appsec-review-2026-08.md  Application security review (historical)
    ├── design/false-positive-reduction.md Case study, 10,938 → 67 (historical)
    ├── history/                       AI-assisted development logs (historical)
    └── superpowers/                   Design specs and implementation plans
```

### 4.2 Common Developer Tasks

#### Adding a New Scanner Source

1. Create `evedoo/src/scanner/my_scanner.rs`
2. Implement a struct with a `scan() -> Vec<DetectedSoftware>` method
3. Use a scheme prefix for `registry_key`: `"mysource://name"`
4. Add `mod my_scanner;` and `pub use my_scanner::MyScanner;` to `scanner/mod.rs`
5. In `main.rs`, add a scan block after the existing scanners:
   ```rust
   info!("Scanning MySource...");
   let my_scanner = MyScanner::new();
   software.extend(my_scanner.scan());
   ```
6. Add tests in `#[cfg(test)] mod tests` within the new file

**Design preference:** Filesystem-based detection over CLI shelling when possible (see Chocolatey/Scoop as models).

#### Adding a New Report Format

1. Create `evedoo/src/report/my_format.rs`
2. Implement a function taking `&ScanResult` and returning formatted output
3. Wire it into `report/mod.rs` format dispatcher
4. Add the format string to the `--format` CLI flag handling in `main.rs`

#### Adding to KNOWN_MAPPINGS (Curated Table)

In `evedoo/src/matcher/cpe.rs`, add a `CuratedMapping` entry via the `m()`
constructor. One CPE identity can carry several display-name aliases — list
the most specific first:

```rust
const KNOWN_MAPPINGS: &[CuratedMapping] = &[
    // ... existing entries ...
    m(&["Display Name", "Alternate Name"], "cpe_vendor", "cpe_product"),
];
```

**How to find the correct CPE vendor/product:**
1. Search [NVD CPE Dictionary](https://nvd.nist.gov/products/cpe/search) for the software
2. The CPE URI `cpe:2.3:a:VENDOR:PRODUCT:*` gives you the exact strings
3. Verify the pair exists in the local DB:
   `sqlite3 vulndb.sqlite "SELECT 1 FROM cpe_matches WHERE vendor='V' AND product='P' LIMIT 1"`
4. Add the entry and run `cargo test` to verify no regressions
   (`no_duplicate_known_mappings` catches duplicate aliases)

#### Adding to PUBLISHER_VENDORS

In the same file, add to the `PUBLISHER_VENDORS` array:

```rust
const PUBLISHER_VENDORS: &[(&str, &str)] = &[
    // ... existing entries ...
    ("Publisher Name from Registry", "cpe_vendor"),
];
```

### 4.3 Build & Test

```powershell
# Whole workspace (preferred)
cargo test --workspace                                  # 521 tests
cargo clippy --workspace --all-targets -- -D warnings   # CI gate (must pass)

# Individual packages
cargo build --release -p evedoo           # multi-platform scanner & audit CLI
cargo build --release -p cve-db-builder     # NVD/MSRC sync tool (cross-platform)
cargo build --release -p evedoo-gui       # GUI companion (Windows only)
cargo build --release -p evedoo-taskstate # agent task state MCP server (cross-platform)

# Studio is npm, not a Cargo workspace member
cd evedoo-studio; npm install; npm run build
```

Test totals by package: **458** `evedoo` · **34** `cve-db-builder` ·
**26** `evedoo-taskstate` (23 unit + 3 in `tests/concurrency.rs`) ·
**3** `evedoo-gui`.

**MSRV: Rust 1.83+** for the three original crates, driven by `icu_*`
transitive dependencies in cve-db-builder. **`evedoo-taskstate` needs Rust
1.88+** and edition 2024, driven by `rmcp`.

**CI pipeline:** GitHub Actions runs `build` + `clippy -D warnings` + `test` on every push. Evedoo runs on Windows only (`winreg` emits `compile_error!` on other platforms). cve-db-builder runs on Windows + Linux.

> **Toolchain drift is a real failure mode here.** CI tracks `stable`; with
> `-D warnings` as a gate, a newly-stabilised lint can turn CI red with no commit
> at all. If clippy fails in CI on files your change never touched, run
> `rustup update stable` locally before debugging the diff. See Challenge 8.

#### Machine-local build hazard (history)

Builds use cargo's default `./target/` — compiled binaries are at
**`./target/release/`**.

It used to live inside a **OneDrive-synced folder**, where OneDrive syncing
`target/` while cargo wrote to it intermittently corrupted build artifacts — a
half-synced `thiserror` once produced "no `Error` in the root" plus 84 cascading
errors on a completely clean tree. The workaround was a git-ignored
`.cargo/config.toml` redirecting `build.target-dir` to
`C:/cargo-target/evedoo`; the checkout has since moved out of OneDrive and the
redirect has been removed. Keep checkouts out of synced folders.

Still worth knowing:

- **Never commit `.cargo/`** — an absolute Windows path breaks Linux and CI
- Inexplicable import or proc-macro errors on a clean tree usually mean a stale
  artifact: `cargo clean -p <crate>` fixes it
- A running `evedoo.exe` (especially a long-lived `--serve` server) **locks the
  binary**, and the build then fails with "Access is denied (os error 5)". The
  build failure is easy to miss, and the next run silently uses the *old* binary.
  Kill it first, then build, then regenerate.

**Key test categories:**

| Test Type | Location | Count | Purpose |
|---|---|---|---|
| Version comparison | `normalize/version.rs` | ~15 | Semver, calver, pre-release, letter suffix edge cases |
| Token matching | `normalize/tokens.rs` | ~12 | Subset checks, stopword filtering, `TokenClass` assignment |
| Curated scoring | `matcher/cpe.rs` | ~20 | Score thresholds, confidence mapping, artifact veto |
| Version vulnerability | `matcher/cpe.rs` | ~15 | Range checks, exact pins, wildcards |
| Accuracy gate (frozen) | `matcher/cpe.rs` | 1 | Frozen fixture DB, EPSS/KEV round-trip |
| Accuracy gate (expanded) | `matcher/cpe.rs` | 1 | **53 true positives + 53 true negatives** generated from `GATE_CASES`, plus wrong-product identity negatives |
| Table invariants | `matcher/cpe.rs` | ~3 | ≥500 aliases, ≥120 publisher vendors, no duplicate aliases |
| CPE dictionary layer | `matcher/dict.rs` | ~6 | Threshold behaviour; inert when the table is absent |
| CpeIndex perf | `matcher/index.rs` | 1 | Performance regression guard |
| Chocolatey parsing | `scanner/chocolatey.rs` | 5 | Nuspec XML, whitespace, dependency disambiguation |
| Scoop parsing | `scanner/scoop.rs` | 5 | JSON, missing fields, malformed input |
| PE fingerprinting | `scanner/pe_fingerprint.rs` | 9 | OS component filtering, walker bounds, extension/size filters |
| AppX normalisation | `scanner/appx.rs` | ~5 | CamelCase splitting, publisher prefix stripping |
| OS identity | `scanner/os_version.rs` | ~4 | Build-number → display-name mapping |
| History delta | `history.rs` | ~5 | New/Persisting/Resolved state transitions |
| HTML report | `report/html.rs` | ~8 | Theme/UX affordances, and `data_attributes_never_contain_markup` — walks every row's `data-*` for markup |
| Remote session | `remote/session.rs` | ~8 | Hostname/username validation, injection rejection, `ps_escape()` |
| Fleet + schedule | `fleet.rs`, `schedule.rs` | ~15 | Registry CRUD, tag ops, summaries, arg metacharacter rejection |

**The gate to watch is `accuracy_gate_expanded`.** It generates a synthetic CVE
per `GATE_CASES` product and asserts both directions: v1.2.3 must find its own
CVE (true positive) and v9.9.9 must not (true negative), plus that a *different*
product's name never resolves to that identity. Any change to scoring, token
classification, or the alias table is checked against all 53 products at once —
which is what makes precision work safe to attempt.

### 4.4 CLI Usage Examples

```powershell
# Basic scan with text output
evedoo.exe scan

# HTML dashboard report
evedoo.exe scan -f html -o scan_results.html

# Enterprise CSV for SIEM ingest
evedoo.exe scan -f csv -o findings.csv

# Critical + High severity only, exact confidence
evedoo.exe scan -s critical,high -c exact

# Custom database path
evedoo.exe scan -d C:\security\vulndb.sqlite

# JSON for pipeline consumption
evedoo.exe scan -f json -o findings.json

# Verbose debug output
evedoo.exe scan -v

# Disable delta tracking
evedoo.exe scan --no-history

# Generate the HTML report and open it in a browser via a token-authed
# local server (only meaningful with -f html)
evedoo.exe scan -f html --serve

# Coverage diagnostic: list software that resolved to NO CPE identity.
# Separates "no known CVEs" (healthy) from "never correlated" (a gap).
evedoo.exe scan --show-unmatched

# Full combination
evedoo.exe scan -d .\vulndb.sqlite -f csv -s critical,high -c high -o report.csv -v

# SBOM export
evedoo.exe scan -f cyclonedx -o sbom.cdx.json
evedoo.exe scan -f spdx -o sbom.spdx.json

# Risk-first triage: show scores/tiers, sort by them, hide anything below P2.
# Reachability collection is ON by default -- --no-reachability opts out.
evedoo.exe scan --risk --sort risk --min-priority p2
evedoo.exe scan --no-reachability

# Reveal findings currently suppressed by an accepted-risk rule
evedoo.exe scan --show-excepted
```

**Reassess without touching the host** (FR-58) — re-correlate a stored
inventory snapshot against a freshly synced CVE database:

```powershell
evedoo.exe reassess
evedoo.exe reassess --host SERVER01 --min-priority p1 -f html -o server01.html
evedoo.exe reassess --max-age 30        # widen the stale-snapshot warning
```

**Configuration & compliance audit** (FR-97–FR-105):

```powershell
evedoo.exe audit                                   # defaults to windows-11
evedoo.exe audit -b ms-edge -f html -o edge.html
evedoo.exe audit -p .\custom_benchmark.json -f json -o audit.json
```

`--policy` takes **JSON only** — it deserializes straight into the `Benchmark`
model in `audit/policy.rs`. There is no XCCDF/XML parser; licensed XCCDF
content must be converted to that JSON shape first.

**Accepted-risk exceptions** (FR-68–FR-72). Owner, reason, and an expiry
capped at 730 days are all mandatory:

```powershell
# --expires takes an ABSOLUTE date (YYYY-MM-DD), not a duration, and must be
# within 730 days of today. There is no --expires-in form.
evedoo.exe exception add --cve CVE-2024-1234 --software "OpenSSL" `
    --reason "Vendor patch scheduled for Q4" --owner "sec-team" --expires 2026-12-31
evedoo.exe exception list --json
evedoo.exe exception remove 7
```

**Remote scanning.** Pass the password on **stdin**, never as an argument —
argv is recorded by Windows process-creation auditing (event 4688), Sysmon
event 1, and EDR agents, and is then shipped to a SIEM:

```powershell
# Correct: password never touches argv, the environment block, or disk.
# The target flag is --target / -t (there is no --host on remote-scan).
"P@ssw0rd" | evedoo.exe remote-scan -t SERVER01 -u admin --password-stdin

# Also acceptable
$env:EVEDOO_REMOTE_PASSWORD = "P@ssw0rd"
evedoo.exe remote-scan -t SERVER01 -u admin

# --password exists but exposes the credential; the CLI help says so
```

TLS validation is enforced by default; `--skip-tls-verify` disables MITM
protection and is for lab environments only.

**A subtlety worth knowing if you add a credential flag.** clap's `env` feature
renders the *live value* of the environment variable into `--help` output. Both
credential arguments therefore set `hide_env_values = true`
(`cve-db-builder --api-key` / `NVD_API_KEY`, and
`evedoo remote-scan --password` / `EVEDOO_REMOTE_PASSWORD`). Without it, an
operator who moved the secret to an env var precisely to keep it off argv would
have `--help` print it to the terminal anyway — into scrollback, CI logs, and
screenshots. The variable *name* is still shown, which is the useful half.

**Fleet and scheduling:**

Hostnames and task names are **positional**, not flags:

```powershell
evedoo.exe fleet add WEB01 --name "Web Server 1" --tags prod,web
evedoo.exe fleet list --tag prod
evedoo.exe fleet tag WEB01 --add critical --remove lab
evedoo.exe fleet summary
evedoo.exe fleet remove WEB01

evedoo.exe schedule create weekly --frequency weekly --args "-f html"
evedoo.exe schedule list
evedoo.exe schedule remove weekly
```

**Cross-asset remediation rollup** (FR-83–FR-88) — "which single upgrade
removes the most risk across the fleet?":

```powershell
evedoo.exe fleet report                              # text table, top 20
evedoo.exe fleet report --tag prod --limit 50 --json # DC-7 JSON
```

`fleet report` has no `--format`; use `--json`. Risk is recomputed at report
time from the live CVE database and never read from a stored score (FR-84), so
`vulndb.sqlite` must be present — point at it with `-d` if it is not in the
working directory.

Scheduled tasks run at normal privilege unless `--elevated` is passed
explicitly. `docs/cli-reference.md` is the full reference.

### 4.5 Key File Quick Reference

Line numbers drift with every edit; the symbol names do not. Search for the
symbol, and treat the line number as a hint.

| "I want to..." | Look at... |
|---|---|
| Understand the matching algorithm | `matcher/cpe.rs` → `score_curated_match()` (~1545) and `find_vulnerabilities()` (~992) |
| Add a curated software mapping | `matcher/cpe.rs` → `KNOWN_MAPPINGS` (~73), `m()` alias entries |
| Veto a bad pairing | `matcher/cpe.rs` → `NEGATIVE_MAPPINGS` (~732), `is_negated()` |
| Add a publisher→vendor mapping | `matcher/cpe.rs` → `PUBLISHER_VENDORS` (~776) |
| Change how extra tokens are penalised | `normalize/tokens.rs` → `classify_token()`, `QUALIFIERS` / `NOISE` / `ARTIFACT` |
| Suppress an installer/updater false positive | `normalize/tokens.rs` → `ARTIFACT`, and `pe_fingerprint.rs` → `is_updater_staging_dir()` for the path-based variant |
| Fix version comparison bugs | `normalize/version.rs` → `parse()` (~94), `impl Ord` (~139) |
| Understand applicability filtering | `matcher/index.rs` (load-time `vulnerable`/platform filter) and `matcher/cpe.rs` → `target_sw_applies()` |
| Diagnose a coverage gap | `matcher/cpe.rs` → `resolves_identity()` (~1082), behind `--show-unmatched` |
| Add a new scanner source | `evedoo/src/scanner/` (see `chocolatey.rs` as template) |
| Add a new report format | `evedoo/src/report/` (see `csv.rs` as template) |
| Change the HTML report | `report/html.rs` — read the escaping model in §2.6 first |
| Change enrichment feeds | `cve-db-builder/src/epss.rs` or `kev.rs` |
| Change the CVE feed source | `cve-db-builder/src/mirror.rs` (`FIRST_FEED_YEAR`, `.meta` verification) |
| Modify the CVE database schema | `cve-db-builder/migrations/` |
| Change the CLI interface | `evedoo/src/main.rs` → `enum Commands` (~45) |
| Understand delta tracking | `evedoo/src/history.rs` → `apply_delta()` (~49) |
| Check the accuracy gate | `matcher/cpe.rs` test module → `accuracy_gate_frozen_fixture` (~2165), `accuracy_gate_expanded` (~2380), `GATE_CASES` (~2285) |
| Change compliance rules or add a benchmark | `evedoo/src/audit/builtin.rs` → `list_bundled_benchmarks()`, `get_bundled_benchmark()` |
| Change how a compliance check is evaluated | `evedoo/src/audit/evaluator.rs` → `CheckAssertion::Registry` / `::Service` arms |
| Change the custom-policy schema | `evedoo/src/audit/policy.rs` → `Benchmark`, `CheckAssertion`, `ComparisonOperator::evaluate()` |
| Change reachability classification | `evedoo/src/reachability/mod.rs` → `classify()`, `is_complete()` (read the FR-74 ruling in §3.1 first) |
| Change the Toolhelp32 sweep | `evedoo/src/reachability/local.rs` → `collect()`, `collect_modules_for_pid()` |
| Change how MSRC overrides NVD | `evedoo/src/msrc_override.rs` → `is_patched()` |
| Change MSRC ingest or its tables | `cve-db-builder/src/msrc/` → `parse.rs`, `store.rs`, `fetch.rs` |
| Change fleet rollup ranking | `evedoo/src/aggregate.rs` |
| Change risk scoring or priority tiers | `evedoo/src/risk.rs` |
| Change agent task state or MCP tools | `evedoo-taskstate/src/tools.rs`, `fold.rs` |
| See what to build next | `docs/roadmap.md` → "What's next" |

---

*Document created: May 2026 · Last revised: 2026-08-29*
*Project: Evedoo Vulnerability Scanner*
*License: Apache 2.0*
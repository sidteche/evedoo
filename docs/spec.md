# Evedoo — Unified Specification & Architecture Ledger

**Project:** Evedoo (Windows-Native Vulnerability Scanner & Compliance Auditor)  
**License:** Apache-2.0 (Strictly Permissive Dependencies Only — Zero Copyleft)  
**Language:** Rust — edition 2021 / MSRV 1.83+ for `evedoo`, `cve-db-builder`, `evedoo-gui`; edition 2024 / MSRV 1.88+ for `evedoo-taskstate` (driven by `rmcp`)  
**Status:** Living specification (updated through Phase 21)  
**Verified against:** commit `971a817` — 441 tests passing, `clippy -D warnings` clean  

---

## 1. Vision & Core Principles

Evedoo is an offline-capable, host-level vulnerability scanner and compliance auditor. It inventories software across all Windows installation surfaces, correlates findings against NIST NVD + MSRC offline in sub-second time, performs runtime module reachability analysis, and audits system configurations against DISA STIG / NIST SP 800-53 public domain baselines.

1. **Sub-second matching**: In-memory O(1) indexed lookups.
2. **Offline guarantee**: Zero network I/O during scan execution; data is synced via local builder.
3. **Status honesty**: Never claim state or safety that observation did not prove.
4. **Zero copyleft**: permissive licences only (Apache-2.0, MIT, BSD and similar), enforced by `deny.toml`.

---

## 2. Functional Requirements — Inventory & Discovery

- **FR-01** Registry scanner: Walk 32-bit and 64-bit `Uninstall` keys across HKLM and HKCU.
- **FR-02** AppX / MSIX scanner: Enumerate Windows Store packages via Windows AppX management API.
- **FR-03** WinGet scanner: Enumerate WinGet-managed packages.
- **FR-04** Chocolatey scanner: Enumerate Chocolatey packages from local lib metadata.
- **FR-05** Scoop scanner: Enumerate Scoop apps from local manifests.
- **FR-06** PE Fingerprint scanner: Walk Program Files / binary paths, inspect PE headers, and detect bundled library DLLs (OpenSSL, zlib, libcurl, sqlite3).
- **FR-07** Package scanner: Enumerate language ecosystems (`pip://`, `npm://`, `cargo://`, `go://`).
- **FR-08** OS Version scanner: Detect exact Windows 10/11 and Windows Server builds and UBR revisions (`os://windows/<build>.<ubr>`).

---

## 3. Functional Requirements — Matcher & Correlation

- **FR-10** In-memory `CpeIndex`: O(1) keyed lookup on `(vendor, product)`.
- **FR-11** Curated aliases & token-based fuzzy matching.
- **FR-12** CPE dictionary integration for automatic vendor/product resolution.
- **FR-13** Applicability & platform enforcement (vulnerable flag, target_sw, Windows platform gating).
- **FR-14** Companion-artifact vetoes (prevent updaters/installers from overmatching parent product CVEs).
- **FR-15** Negative-mapping veto list.
- **FR-16** Version comparison: Structured `Version` type supporting semver, calver, Windows 4-part builds, pre-release tags, and letter suffixes.
- **FR-17** Version range boundary evaluation.
- **FR-18** Windows OS release-specific product resolution (`windows_11_25h2`).
- **FR-19** `--show-unmatched` diagnostic and coverage calculation.

---

## 4. Functional Requirements — Reporting & Operations

- **FR-30** Output formats: `text` (rendered with `owo-colors`), `json`, `csv` (enterprise columns), `html` (interactive self-contained dashboard), `cyclonedx` (1.6 with VEX), `spdx` (2.3).
- **FR-31** EPSS score/percentile and CISA KEV exploitation enrichment.
- **FR-32** Remediation recommendations: Fixed versions, KB article links, and CLI upgrade commands.
- **FR-33** Delta tracking against SQLite history DB (`New`, `NewlyApplicable`, `Persisting`, `Resolved`).
- **FR-34** Local `--serve` token-authenticated HTTP server (`std::net` only; random per-run token in the URL query string; `--serve` is rejected for any format other than `html`).
- **FR-35** WinRM remote scanning with TLS default-on, credential zeroization, and stdin password channel.
- **FR-36** Fleet asset registry and Windows Task Scheduler integration.

---

## 5. Functional Requirements — Database Builder

- **FR-50** Mirror-first NVD sync via FKIE-CAD JSON feeds with API fallback.
- **FR-51** Incremental delta feed updates.
- **FR-52** Key-free operation for primary mirror sync.
- **FR-53** NVD CPE Dictionary ingestion and deduplication.
- **FR-54** CISA KEV catalog and EPSS probability feed ingestion.
- **FR-55** Bounded retry and SHA-256 sidecar validation.
- **FR-56** Parameterized SQL schema with PRAGMA versioning.

---

## 6. Functional Requirements — Operationalisation & Risk Scoring

- **FR-57** Per-host full inventory snapshot persistence.
- **FR-58** `evedoo reassess` offline correlation against stored snapshots.
- **FR-59** Mode-aware delta reconciliation (`Scan` vs `Reassess`).
- **FR-60** Finding status vocabulary (`New`, `NewlyApplicable`, `Persisting`, `Resolved`).
- **FR-61** Single unfiltered correlation stage before delta tracking.
- **FR-62** Post-reconciliation filtering to prevent false Resolved transitions.
- **FR-63** Corpus-calibrated risk scoring (Impact × Likelihood).
- **FR-64** Priority tiers (`P1`, `P2`, `P3`, `P4`) with KEV top-tier override.
- **FR-65** Fleet host criticality multipliers (`critical` 1.25, `prod` 1.15, `lab` 0.85).
- **FR-66** Corpus median fallback for unassigned EPSS CVEs.
- **FR-67** Risk presentation gating in text/HTML reports.
- **FR-68** Expiring, auditable accepted-risk exceptions (max 730-day expiry).
- **FR-69** Host and software wildcard exception scoping.
- **FR-70** Exception annotation (never deleting from audit trail).
- **FR-71** Expiration reporting and return-to-active tracking.
- **FR-72** Canonical CVE ID validation for exception rules.

---

## 7. Functional Requirements — Phase 21 (Enterprise Accuracy & Reachability)

### 7.1 Runtime Module Reachability (N3)
- **FR-73** `Reachability` enum SHALL provide three states: `Loaded` (module mapped into live process), `NotObserved` (full sweep confirmed unmapped), and `Unknown` (partial sweep or unevaluable).
- **FR-74** An incomplete sweep (`readable < total`) SHALL force all non-matches to `Unknown`, never asserting `NotObserved`.
- **FR-75** Toolhelp32 process/module enumeration SHALL run without external dependencies via direct `kernel32`/`advapi32` FFI, including `TH32CS_SNAPMODULE32` for WOW64 processes.
- **FR-76** Risk scoring multiplier for reachability SHALL be strictly `>= 1.0` (it may elevate priority, but never demote risk on a transient sample).
- **FR-77** Software classification SHALL compare exact normalised paths for `pe://` keys and prefix directories for package-manager installs.
- **FR-78** Remote WinRM reachability collection SHALL execute fixed non-interpolated script blocks (`SEC-8`).
- **FR-79** Text, JSON, CSV, and HTML reports SHALL disclose coverage statistics (`readable / total processes`).
- **FR-80** `--no-reachability` SHALL skip process collection and set state to `Unknown`.
- **FR-81** CycloneDX VEX mapping SHALL map `Loaded` to `affected`, and `NotObserved` / `Unknown` to `under_investigation`.
- **FR-82** Reachability observations SHALL NOT be persisted to `scan_findings` (reachability is an ephemeral runtime state).

### 7.2 Cross-Asset Remediation Aggregation (N7)
- **FR-83** `evedoo fleet report` SHALL aggregate stored findings across all scanned hosts in `scan_history.db`.
- **FR-84** Risk scores in fleet rollups SHALL be computed at report time from the live CVE database and NEVER persisted (`FR-84`).
- **FR-85** Stored findings with status `Resolved` or `NoLongerApplicable` SHALL be excluded at the SQL level.
- **FR-86** Aggregations SHALL report affected host count, hostnames list, total CVEs, total risk reduction, max risk score, and KEV counts.
- **FR-87** CVEs unscoreable due to missing metrics SHALL be excluded from numeric sums AND counted in report headers.
- **FR-88** Fleet report SHALL accept `--tag` to filter by asset tag, `--limit` to cap displayed rows (default 20), and `--json` to emit the DC-7 machine-readable object instead of the text table.

### 7.3 Authoritative Vendor Advisories — MSRC (N5)
- **FR-89** MSRC CVRF ingestion SHALL be opt-in via `--enable-msrc`, printing the Microsoft APIs Terms of Use notice before any request.
- **FR-90** Sync SHALL ingest all documents from `GET /cvrf/v3.0/updates` and re-fetch only when `CurrentReleaseDate` changes.
- **FR-91** Where an MSRC verdict exists for a `(CVE, product)` pair, it SHALL override the NVD match. Absence of MSRC data SHALL leave the NVD finding standing.
- **FR-92** Suppression SHALL require a successful `Version::parse` comparison against `fixed_build`. Unparseable versions SHALL leave the finding standing.
- **FR-93** MSRC-enriched findings SHALL disclose the exact Microsoft KB article and `fixed_build` version in all reports.
- **FR-94** No release or distribution of Evedoo SHALL contain MSRC-derived data; the data exists only in local user-synced databases.
- **FR-95** Failed or malformed CVRF documents SHALL be logged, skipped without aborting sync, and retried on the next run.
- **FR-96** MSRC CPE vendor and product tokens SHALL be lowercased on ingest to ensure case-insensitive joins against NVD dictionaries.

### 7.4 Configuration & Compliance Auditing — DISA STIG / NIST SP 800-53 (N6)
- **FR-97** `evedoo audit` CLI subcommand SHALL evaluate Windows system configurations against authoritative compliance benchmarks.
- **FR-98** Compliance auditing SHALL output an overall Compliance Score (% Pass Rate) and CAT I (High), CAT II (Medium), and CAT III (Low) breakdowns.
- **FR-99** Bundled audit checks SHALL be the project's own wording (Apache-2.0), derived from DISA STIGs and NIST SP 800-53, and SHALL be presented as derived checks with a disclaimer, never as DISA's publication. *(Revised November 2026: the original wording claimed the bundled rules were public-domain government works, which they are not.)*
- **FR-100** Bundled benchmarks SHALL include: Windows 11 STIG (V1R4), Windows 10 STIG (V2R8), Windows Server 2022 STIG (V1R3), and Microsoft Edge STIG (V1R2).
- **FR-101** Every benchmark rule SHALL map to exact STIG ID (`V-XXXXX`), Rule ID (`SV-XXXXX`), severity, and NIST SP 800-53 controls (e.g. `AC-2`, `CM-6`, `IA-5`, `SC-7`, `SI-2`).
- **FR-102** Registry assertions SHALL support HKLM, HKCU, and HKU hives with DWORD, QWORD, String, ExpandString, MultiString, and Binary data types.
- **FR-103** Comparison operators SHALL support `Equals`, `NotEquals`, `GreaterThanOrEqual`, `LessThanOrEqual`, `BitwiseAnd` masks, `Exists`, `NotExists`, and `Contains`.
- **FR-104** Engine SHALL accept custom operator-supplied benchmark files via `--policy <file>`, deserialized as **JSON** into the `Benchmark` model. *Implementation status: JSON is implemented; XCCDF/XML ingestion is **not implemented** — an operator holding licensed XCCDF content must convert it to the JSON shape first.*
- **FR-105** Audit reports SHALL render in `text` (colored with `owo-colors`), `json`, `csv`, and interactive `html`.

---

## 8. Non-Functional & Security Standards

- **NFR-1 Licensing**: Apache-2.0 only; 100% permissive dependencies (MIT, Apache-2.0, BSD, ISC); zero copyleft; Rust exclusively for core implementation.
- **NFR-2 Platform**: Windows 10/11/Server for scanner; cross-platform for DB builder and taskstate; MSRV Rust 1.83+ (1.88+ for taskstate).
- **NFR-3 Performance**: O(1) in-memory CpeIndex lookups; full mirror sync ~1.5–3 min; scan execution under 2 seconds.
- **NFR-4 Quality Gate**: `cargo clippy --workspace --all-targets -- -D warnings` clean (0 warnings) and 441 passing automated tests (378 `evedoo` · 34 `cve-db-builder` · 26 `evedoo-taskstate` · 3 `evedoo-gui`).
- **NFR-5 Schema Evolution**: Transactional migrations via `PRAGMA user_version` on `scan_history.db`.
- **NFR-9 Reachability Cost**: reachability collection SHALL add no more than roughly one second to a typical scan (~one snapshot per live process) and SHALL never block the scan on an unreadable process.
- **NFR-10 MSRC Sync Cost**: a full first MSRC sync is roughly 850 MB of downloads. It SHALL report progress per document and SHALL be resumable — a re-run after interruption fetches only what is missing or changed.
- **SEC-1 Report Escaping**: Context-correct HTML entity and attribute escaping across all report templates.
- **SEC-2 Credential Protection**: Stdin password channel (`--password-stdin`) and memory zeroization on drop (`zeroize`). Every credential argument bound to an environment variable SHALL set clap's `hide_env_values`, so `--help` renders the variable name but never its live value (`--api-key`/`NVD_API_KEY`, `--password`/`EVEDOO_REMOTE_PASSWORD`).
- **SEC-3 Parameterized Queries**: All database operations use parameterized SQL queries exclusively.
- **SEC-4 Transport Security**: TLS enforced by default; HTTPS-only external synchronization.
- **SEC-8 Remote WinRM Isolation**: Fixed non-interpolated PowerShell script blocks for remote reachability and inventory.
- **SEC-9 Ingest Validation**: Document ID validation and 64 MB size bounding on MSRC and NVD downloads.
- **SEC-10 Safe Audit Execution**: Non-destructive read-only registry and service inspection with fail-safe error handling.

---

## 9. Data Contracts

- **DC-1 CVE Database Schema (`vulndb.sqlite`)**: `cves`, `cpe_matches`, `cve_references`, `product_mappings`, `cpe_dictionary`, `epss`, `kev`, `sync_metadata`, `schema_version`.
- **DC-2 Dedup Key Schemes**: `registry://`, `appx://`, `winget://`, `chocolatey://`, `scoop://`, `pe://`, `pip://`, `npm://`, `cargo://`, `os://windows/<build>.<ubr>`.
- **DC-3 JSON Scan Output**: `scan_time`, `hostname`, `scan_mode`, `delta_known`, `total_software`, `total_vulnerabilities`, `findings[]`, `software[]`.
- **DC-5 State Database (`scan_history.db`)**: `scan_findings`, `fleet_assets`, `scan_inventory`, `exceptions`.
- **DC-6 Reachability in JSON output**: each finding gains an optional `reachability` string (`loaded` | `not_observed` | `unknown`), absent from artifacts produced before FR-73. Per FR-82 it is never written to `scan_findings`.
- **DC-7 Fleet Rollup JSON (`fleet report --json`)**: object of `generated_at`, `assets_covered`, `findings_excluded`, and `remediations[]` — each `{ software_name, affected_assets, affected_hostnames, cve_count, total_risk_removed, max_risk_score, kev_count, versions_seen, fixed_version, upgrade_command }`, ordered by `total_risk_removed` descending.
- **DC-8 MSRC Tables (`vulndb.sqlite`)**: `msrc_products (product_id, name, cpe, vendor, product)`, `msrc_fixes (cve_id, product_id, kb_article, fixed_build, document_id)`, `msrc_sync (document_id, current_release, ingested_at)`.
- **DC-9 Compliance Audit Schema (`evedoo/src/audit/policy.rs`)**: `Benchmark`, `BenchmarkRule`, `CheckAssertion`, `RuleResult`, `AuditSummary`.

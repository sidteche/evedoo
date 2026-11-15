# AI Generation Log

> **APPEND-ONLY HISTORICAL LOG.** Sessions 1-10 end at 20 tests for this crate.
> The MSRC CVRF ingest path (`src/msrc/`) was added later under the spec-driven
> workflow - see `docs/superpowers/specs/2026-08-28-msrc-advisories-design.md`.
> Current total for this crate: **34 tests**.

This file documents AI-generated code sections in the Evedoo project.

## Generation Sessions

### Session 1: Initial Project Setup — cve-db-builder

- **Date**: 2026-02-09
- **AI System**: Anthropic Claude
- **Prompt Summary**: Create Phase 0 CVE Database Builder — standalone Rust program to download NVD CVE database into SQLite
- **Files Generated**:
  - `cve-db-builder/Cargo.toml` — project manifest with dependencies
  - `cve-db-builder/src/main.rs` — CLI entry point
  - `cve-db-builder/src/models.rs` — NVD API data structures
  - `cve-db-builder/src/nvd_client.rs` — NVD API client with rate limiting
  - `cve-db-builder/src/database.rs` — SQLite operations
  - `cve-db-builder/migrations/001_initial_schema.sql` — database schema (cves, cpe_matches, cve_references, product_mappings, sync_metadata)
  - `LICENSE` — Apache 2.0 license text
  - `NOTICE` — third-party attribution
- **Review Status**: Reviewed and shipped

### Session 2: EPSS + CISA KEV Enrichment — cve-db-builder

- **Date**: 2026-02-09
- **AI System**: Anthropic Claude
- **Prompt Summary**: Add EPSS and CISA KEV enrichment tables to the CVE database for real-world exploitation prioritisation
- **Files Generated**:
  - `cve-db-builder/migrations/002_epss_kev.sql` — EPSS and KEV table schemas
  - `cve-db-builder/src/database.rs` — EPSS CSV ingest + KEV JSON sync logic
- **Review Status**: Reviewed and shipped

### Session 3: Scanner Core — evedoo

- **Date**: 2026-02-09 to 2026-05-07
- **AI System**: Anthropic Claude (Claude Code)
- **Prompt Summary**: Build the scanner binary with multi-source software inventory, CPE matching, version comparison, and reporting
- **Files Generated / Modified**:
  - `evedoo/src/main.rs` — CLI entry point with clap, orchestrates all scanners
  - `evedoo/src/scanner/registry.rs` — Registry Uninstall key scanner (HKLM/HKCU, 32/64-bit)
  - `evedoo/src/scanner/appx.rs` — AppX/MSIX package scanner via PowerShell
  - `evedoo/src/scanner/winget.rs` — WinGet list column parser
  - `evedoo/src/scanner/chocolatey.rs` — filesystem-based Chocolatey nuspec scanner
  - `evedoo/src/scanner/scoop.rs` — filesystem-based Scoop manifest.json scanner
  - `evedoo/src/scanner/pe_fingerprint.rs` — PE header fingerprinter via direct FFI to version.dll
  - `evedoo/src/scanner/packages.rs` — pip/npm/cargo package scanners
  - `evedoo/src/scanner/version_resolver.rs` — registry + CLI fallback version resolution
  - `evedoo/src/scanner/mod.rs` — scanner module declarations
  - `evedoo/src/matcher/cpe.rs` — CpeIndex (in-memory HashMap), token matching, confidence scoring, accuracy gate tests
  - `evedoo/src/normalize/mod.rs` — tokenisation, structured Version type with Ord, name/publisher cleanup
  - `evedoo/src/report/` — text, json, csv, html report generators
  - `evedoo/src/history/` — SQLite-backed delta tracking (New/Persisting/Resolved)
  - `evedoo/Cargo.toml` — project manifest
- **Review Status**: Reviewed and shipped

### Session 4: CI + Documentation

- **Date**: 2026-02-09 to 2026-05-07
- **AI System**: Anthropic Claude (Claude Code)
- **Prompt Summary**: GitHub Actions CI, README, AI rules files, roadmap documentation
- **Files Generated / Modified**:
  - `.github/workflows/ci.yml` — CI pipeline (evedoo on Windows; cve-db-builder on Windows + Linux)
  - `README.md` — project documentation
  - `CLAUDE.md` — Claude Code project rules
  - `GEMINI.md` — Gemini AI rules
  - `skill.md` — universal AI assistant rules
  - `evedoo/IMPROVEMENT_ROADMAP.md` — phase roadmap
- **Review Status**: Reviewed and shipped

### Session 5: Knowledge Transfer + Root Documentation

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Comprehensive KT document, root LICENSE for GitHub detection, updated AI rules files
- **Files Generated / Modified**:
  - `KNOWLEDGE_TRANSFER.md` — 647-line system design and KT document
  - `LICENSE` — Apache 2.0 root-level for GitHub sidebar
  - `CLAUDE.md` — updated project guidelines
  - `GEMINI.md` — refreshed with current state
  - `skill.md` — universal AI rules file
- **Review Status**: Reviewed and shipped

### Session 6: Scanner Phases 7–10B

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: SBOM export (CycloneDX + SPDX), expanded CPE mappings, WinRM remote scanning, patch recommendation engine
- **Files Generated / Modified**:
  - See `evedoo/AI_GENERATION_LOG.md` sessions 2–5 for full file list
  - `README.md` — updated with new features, CLI flags, roadmap entries
- **Review Status**: Reviewed and shipped

### Session 7: Scanner Security Hardening (Phase 11)

- **Date**: 2026-05-18
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Security review + hardening of scanner modules (remote session, schedule, serve, HTML report)
- **Files Modified**:
  - See `evedoo/AI_GENERATION_LOG.md` sessions 8–9 for full file list
  - Scanner test count: 153 → 169 (16 new security tests)
- **Review Status**: Reviewed and shipped

### Session 8: GUI Companion App (Phase 12)

- **Date**: 2026-05-19
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Build egui/eframe GUI companion app as third workspace member. GUI wraps both `evedoo.exe` and `cve-db-builder.exe` via `std::process::Command`.
- **Impact on cve-db-builder**:
  - `cve-db-builder/Cargo.toml` — removed `[profile.release]` section (moved to workspace root `Cargo.toml`)
  - `cve-db-builder/Cargo.lock` — deleted (workspace uses single root lock file)
  - GUI's Update DB tab calls `cve-db-builder.exe` with `--api-key`, `--output`, `--update` flags
- **Review Status**: Reviewed and shipped

### Session 9: CPE Dictionary + Mirror-First Sync

- **Date**: 2026-07-09 to 2026-07-26
- **AI System**: Anthropic Claude (Claude Code)
- **Prompt Summary**: Broaden correlation coverage beyond the curated table,
  then fix the NVD API's unreliability as a bulk-transfer channel
- **Files Generated / Modified**:
  - `cve-db-builder/migrations/003_cpe_dictionary.sql` — CPE dictionary schema
  - `cve-db-builder/src/cpe_dict.rs` — **new**: NVD Products API 2.0 client
    (~1.8M products → ~148k deduplicated identities), version-stripped titles,
    retry on malformed pages, 30-day staleness gate so routine syncs skip it
  - `cve-db-builder/src/mirror.rs` — **new**: FKIE-CAD bulk feed fetcher
    (`.json.xz` per CVE year + `CVE-Modified` delta) via `xz2`. Same API 2.0
    object shape, so existing models parse it unchanged
  - `cve-db-builder/src/main.rs` — mirror-first sync flow with automatic NVD
    API fallback, `--no-mirror` / `--skip-cpe-dict` flags, exponential backoff
    on API page failures; API key now optional
  - `cve-db-builder/src/models.rs` — `ParsedCpe` struct exposing `target_sw`
  - `cve-db-builder/src/database.rs` — `replace_cpe_dictionary()`,
    `cpe_dictionary_age_days()`, `target_sw` column with additive guard
- **Impact**: Full corpus sync went from hours of flaky NVD API pagination
  (two attempts died to truncated responses) to **~1.5 minutes** of bulk
  downloads with no API key required.
- **Review Status**: Reviewed and shipped

### Session 10: Feed Integrity + Ingest Validation (Security Remediation)

- **Date**: 2026-08-10
- **AI System**: Anthropic Claude Opus 5 (Claude Code)
- **Prompt Summary**: Act on a branch security review, then close out the
  follow-ups it recorded
- **Files Generated / Modified**:
  - `cve-db-builder/src/mirror.rs` — **SEC-6**: `.meta` sidecar fetch and
    verification. Each feed ships `sha256` and `size` describing the
    *decompressed* JSON (verified empirically against the live mirror); a
    payload that disagrees is rejected before a single row is parsed. Missing
    sidecar warns and proceeds; a malformed one is a hard error, since that is
    the shape tampering takes.
  - `cve-db-builder/src/database.rs` — **SEC-4**: `is_valid_cve_id()` rejects
    identifiers outside canonical `CVE-YYYY-NNNN+` at `insert_cve`, so a
    tampered feed cannot put markup-bearing ids into the database regardless of
    how each of the six output formats escapes
  - `cve-db-builder/Cargo.toml` — added `sha2` (RustCrypto, MIT/Apache-2.0)
- **Coverage bug found while implementing**: `FIRST_FEED_YEAR` was 2002, with a
  comment claiming pre-2002 CVEs are folded into the 2002 feed "matching NVD's
  historical feed layout". False for this mirror, which publishes a feed per
  year from **1999**. A fresh mirror-only build silently dropped **4,378 CVEs**
  (1999: 1579, 2000: 1243, 2001: 1556) — false negatives in a vulnerability
  scanner. Existing databases only had them as leftovers from the retired API
  path. A fresh build now totals 374,405 CVEs.
- **Verification**: every feed logs `(sha256 verified)` against the live mirror;
  all 370,413 pre-existing CVE ids pass the new validator, so the rule
  introduces no false rejects.
- **Tests**: 12 → 20
- **Review Status**: Reviewed and shipped

## Licensing Compliance

All AI-generated code is licensed under **Apache 2.0**. All dependencies use permissive licenses (Apache 2.0, MIT, BSD). No GPL/AGPL dependencies. See `LICENSE` for full text.
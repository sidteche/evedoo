# AI Generation Log — evedoo (Scanner)

> **APPEND-ONLY HISTORICAL LOG.** Sessions 1–13 cover Phases 1–19 and end at
> 230 workspace tests. Phase 20 (operationalisation) and Phase 21 (reachability,
> MSRC, compliance audit, fleet rollups, Studio) were developed under the
> spec-driven workflow instead, and are recorded in
> `docs/superpowers/specs/`, `docs/superpowers/plans/`, and the append-only
> agent ledger `docs/agent-state/tasks.jsonl`. Current total: **441 tests**.

This file documents AI-generated code sections in the evedoo scanner binary.

## Generation Sessions

### Session 1: Scanner Core (Phases 1–6)

- **Date**: 2026-02-09 to 2026-05-07
- **AI System**: Anthropic Claude (Claude Code)
- **Prompt Summary**: Build the scanner binary with multi-source software inventory, CPE matching, structured version comparison, EPSS/KEV enrichment, and reporting

- **Files Generated / Modified**:
  - `src/main.rs` — CLI entry point with clap, orchestrates all scanners
  - `src/scanner/registry.rs` — Registry Uninstall key scanner (HKLM/HKCU, 32/64-bit)
  - `src/scanner/appx.rs` — AppX/MSIX package scanner via PowerShell
  - `src/scanner/winget.rs` — WinGet list column parser
  - `src/scanner/chocolatey.rs` — filesystem-based Chocolatey nuspec scanner
  - `src/scanner/scoop.rs` — filesystem-based Scoop manifest.json scanner
  - `src/scanner/pe_fingerprint.rs` — PE header fingerprinter via direct FFI to version.dll
  - `src/scanner/packages.rs` — pip/npm/cargo package scanners
  - `src/scanner/version_resolver.rs` — registry + CLI fallback version resolution
  - `src/scanner/mod.rs` — scanner module declarations
  - `src/matcher/cpe.rs` — CpeIndex (in-memory HashMap), token matching, confidence scoring, curated mappings, accuracy gate tests
  - `src/matcher/index.rs` — in-memory CpeIndex with flat row store
  - `src/matcher/mod.rs` — matcher module declarations
  - `src/normalize/mod.rs` — tokenisation, structured Version type with Ord
  - `src/normalize/names.rs` — name/publisher cleanup, AppX normalisation
  - `src/report/text.rs` — terminal-friendly report with severity grouping
  - `src/report/json.rs` — full ScanResult JSON serialization
  - `src/report/csv.rs` — enterprise CSV columns with EPSS/KEV
  - `src/report/html.rs` — self-contained HTML dashboard with KEV card
  - `src/report/mod.rs` — Reporter trait, OutputFormat enum, format dispatch
  - `src/history.rs` — SQLite-backed delta tracking (New/Persisting/Resolved)
  - `src/models.rs` — DetectedSoftware, Finding, Vulnerability, ScanResult
  - `src/error.rs` — ScanError enum with thiserror
  - `Cargo.toml` — project manifest
  - `IMPROVEMENT_ROADMAP.md` — phase roadmap

- **Review Status**: Reviewed and shipped

### Session 2: SBOM Export (Phase 7)

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Add CycloneDX 1.6 and SPDX 2.3 SBOM export formats for EO 14028 compliance

- **Files Generated**:
  - `src/report/cyclonedx.rs` — CycloneDX 1.6 JSON with VEX vulnerability data (6 tests)
  - `src/report/spdx.rs` — SPDX 2.3 JSON inventory with DESCRIBED_BY relationships (5 tests)

- **Files Modified**:
  - `src/report/mod.rs` — added CycloneDx/Spdx variants to OutputFormat, match arms
  - `src/main.rs` — updated --format help text
  - `Cargo.toml` — added uuid = { version = "1", features = ["v4"] }

- **Review Status**: Reviewed and shipped

### Session 3: Expanded CPE Mappings (Phase 8)

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Expand KNOWN_MAPPINGS from 160→242 and PUBLISHER_VENDORS from 81→130 entries across 20+ software categories

- **Files Modified**:
  - `src/matcher/cpe.rs` — added 82 KNOWN_MAPPINGS entries (security tools, cloud/DevOps, databases, monitoring, networking/VPN, media/creative, enterprise, pip/npm/cargo) + 49 PUBLISHER_VENDORS entries + 3 validation tests

- **New categories**: Security tools, Cloud/DevOps, Databases, Monitoring, Networking/VPN, Enterprise software, Media/Creative, additional pip/npm/cargo packages

- **Review Status**: Reviewed and shipped

### Session 4: Remote Scanning via WinRM (Phase 9)

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Add agentless remote vulnerability scanning via PowerShell Invoke-Command (WinRM) and SMB for Chocolatey/Scoop

- **Files Generated**:
  - `src/remote/mod.rs` — remote module declarations
  - `src/remote/session.rs` — RemoteTarget + RemoteSession with credential management, SSL, UNC paths (5 tests)
  - `src/remote/scanners.rs` — remote variants for registry, AppX, WinGet, Chocolatey (SMB), Scoop (SMB), pip/npm/cargo (8 tests)

- **Files Modified**:
  - `src/main.rs` — added `remote-scan` subcommand with --target, --username, --password, --port, --use-ssl
  - `src/models.rs` — added ScanMode enum (Local/Remote)
  - `src/error.rs` — added RemoteError variant

- **Security measures**: passwords via env var (EVEDOO_REMOTE_PASSWORD), never logged, redacted from error output, SSL support

- **Review Status**: Reviewed and shipped

### Session 5: Patch Recommendation Engine (Phase 10B)

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Add actionable patch recommendations with fixed versions from CPE ranges, Microsoft KB extraction, and auto-generated upgrade commands

- **Files Modified**:
  - `src/matcher/cpe.rs` — added extract_kb_from_url(), build_recommendation(), build_upgrade_command() functions; modified get_cve_details() to accept fixed_version and extract KB articles from references (15 tests)
  - `src/matcher/mod.rs` — re-exported build_upgrade_command
  - `src/models.rs` — added kb_articles and upgrade_command fields to Remediation struct
  - `src/main.rs` — populates upgrade_command on findings in both local and remote scan loops
  - `src/report/text.rs` — displays Fixed in, KB Patches, Upgrade command lines
  - `src/report/csv.rs` — added Fixed Version, KB Articles, Upgrade Command columns

- **Review Status**: Reviewed and shipped

### Session 6: Fleet Management (Phase 10C)

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Add asset tagging and multi-target management with SQLite-backed fleet registry

- **Files Generated**:
  - `src/fleet.rs` — FleetManager with SQLite fleet_assets table, Asset/FleetSummary structs, CRUD + tagging operations (8 tests)

- **Files Modified**:
  - `src/main.rs` — added Fleet subcommand group (Add, Remove, List, Tag, Summary) with run_fleet_command()

- **Review Status**: Reviewed and shipped

### Session 7: Scheduled Scanning (Phase 10D)

- **Date**: 2026-05-17
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Add Windows Task Scheduler integration for recurring vulnerability scans

- **Files Generated**:
  - `src/schedule.rs` — ScheduleFrequency enum, create_schedule/list_schedules/remove_schedule functions using schtasks.exe, CSV parser for task query output (7 tests)

- **Files Modified**:
  - `src/main.rs` — added Schedule subcommand group (Create, List, Remove) with run_schedule_command()
  - `src/error.rs` — added ScheduleError variant

- **Review Status**: Reviewed and shipped

### Session 8: Security Hardening — Injection Fixes (Phase 11a)

- **Date**: 2026-05-18
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Fix 4 injection vulnerabilities identified in security review: PowerShell injection via hostname/username, command injection in schedule args, XSS in HTML report modal

- **Files Modified**:
  - `src/remote/session.rs` — added `validate_hostname()`, `validate_username()`, `ps_escape()` functions; changed `RemoteTarget::new()` to return `Result<Self>` with input validation; applied escaping to hostname, username, and password in PowerShell strings (6 tests)
  - `src/schedule.rs` — added `validate_schedule_args()` to reject shell metacharacters in `--args` before `schtasks` command (1 test)
  - `src/report/html.rs` — wrapped all `dataset` values in `esc()` before `innerHTML` assignment in detail modal JS
  - `src/main.rs` — updated `RemoteTarget::new()` call site for `Result` return type

- **Review Status**: Reviewed and shipped

### Session 9: Security Hardening — Defense-in-Depth (Phase 11b)

- **Date**: 2026-05-18
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Fix 5 additional security findings: TLS validation default-on, privilege escalation opt-in, UNC path traversal, serve token auth, credential zeroization

- **Files Modified**:
  - `src/remote/session.rs` — added `skip_tls_verify` field and `with_tls_options()` constructor; TLS validation enforced by default; `unc_path()` returns `Option<String>` rejecting `..` and non-absolute paths; `impl Drop` with `zeroize` for password (5 tests)
  - `src/remote/scanners.rs` — updated `scan_chocolatey()` and `scan_scoop()` to handle `Option` from `unc_path()`
  - `src/schedule.rs` — `create_schedule()` accepts `elevated` bool; `/RL HIGHEST` only when opted in
  - `src/serve.rs` — random 64-bit hex token appended to URL; requests without token get 403 Forbidden
  - `src/main.rs` — added `--skip-tls-verify` and `--elevated` CLI flags with warning messages
  - `Cargo.toml` — added `zeroize = "1"` dependency

- **Review Status**: Reviewed and shipped

### Session 10: GUI Companion App (Phase 12)

- **Date**: 2026-05-19
- **AI System**: Anthropic Claude Opus 4.6 (Claude Code)
- **Prompt Summary**: Build an egui/eframe companion GUI that wraps the CLI binaries via `std::process::Command`, with tabs for local scan, remote scan, DB update, and settings

- **Files Generated**:
  - `evedoo-gui/Cargo.toml` — GUI package manifest (eframe, serde, chrono, directories, dotenvy, rfd)
  - `evedoo-gui/src/main.rs` — eframe entry point, 1000x700 window
  - `evedoo-gui/src/app.rs` — EvedooApp state, tab routing, command polling, follow-up CSV/HTML chain, JSON extraction from mixed stdout
  - `evedoo-gui/src/command.rs` — background CLI execution via std::thread + mpsc, CREATE_NO_WINDOW flag
  - `evedoo-gui/src/config.rs` — persistent config (%APPDATA%), .env loading via dotenvy, multi-location exe detection
  - `evedoo-gui/src/models.rs` — serde Deserialize structs mirroring evedoo's JSON output
  - `evedoo-gui/src/results_table.rs` — sortable findings table with color-coded severity and expandable detail rows
  - `evedoo-gui/src/tabs/mod.rs` — tab module re-exports
  - `evedoo-gui/src/tabs/local_scan.rs` — local scan form with build_args(), build_csv_args(), build_html_args()
  - `evedoo-gui/src/tabs/remote_scan.rs` — remote scan form with credential fields and SSL options
  - `evedoo-gui/src/tabs/update_db.rs` — DB update form with API key source selection (settings/env/.env file)
  - `evedoo-gui/src/tabs/settings.rs` — settings with .env indicator, Browse buttons for all paths

- **Files Modified**:
  - `Cargo.toml` (repo root, NEW) — workspace manifest unifying all three packages
  - `evedoo/Cargo.toml` — removed `[profile.release]` (moved to workspace root)
  - `cve-db-builder/Cargo.toml` — removed `[profile.release]` (moved to workspace root)

- **Review Status**: Reviewed and shipped

### Session 11: Correlation Engine Overhaul + Detection Expansion

- **Date**: 2026-05-22 to 2026-07-26
- **AI System**: Anthropic Claude (Claude Code)
- **Prompt Summary**: Improve correlation accuracy end to end — reduce false
  positives, expand detection coverage, and make coverage measurable
- **Files Generated / Modified**:
  - `evedoo/src/normalize/tokens.rs` — `TokenClass` + `classify_token()`
    with QUALIFIERS / NOISE lists (Phase A qualifier-aware scoring)
  - `evedoo/src/matcher/cpe.rs` — `CuratedMapping` alias struct (246 → 508
    DB-verified aliases), per-token penalty scoring, `NEGATIVE_MAPPINGS` with
    wildcard vendor vetoes, `target_sw` ecosystem gating, `resolves_identity()`
    coverage diagnostic, expanded accuracy gate (53 TP + 53 TN)
  - `evedoo/src/matcher/dict.rs` — **new**: CPE dictionary title index
    (Phase C), inverted token lookup with strict corroboration threshold
  - `evedoo/src/matcher/index.rs` — load-time filtering on the NVD
    `vulnerable` flag and platform (~25% of raw rows excluded as
    non-applicable), `target_sw` column with backward-compatible fallback
  - `evedoo/src/scanner/pe_fingerprint.rs` — bundled library DLL
    fingerprinting (OpenSSL, zlib, sqlite3, libcurl, FFmpeg, …) and
    updater/staging directory suppression
  - `evedoo/src/scanner/os_version.rs` — **new**: Windows OS identity from
    the registry, build-accurate matching against `windows_*` CPEs
  - `evedoo/src/main.rs` — `--show-unmatched` coverage diagnostic, OS
    scanner wiring
- **Impact**: On a real 621-application machine, findings went from 896
  (dominated by updater false positives) to 822 genuine findings while adding
  three new detection classes. Documented FP taxonomy drove each fix.
- **Review Status**: Reviewed and shipped

### Session 12: Security Remediation (SEC-1 … SEC-7)

- **Date**: 2026-08-10
- **AI System**: Anthropic Claude Opus 5 (Claude Code)
- **Prompt Summary**: Work a branch security review into a phased remediation
  document and implement it, then close out the follow-ups it recorded
- **Design doc**: `docs/superpowers/specs/2026-08-10-security-remediation-design.md`
- **Files Modified**:
  - `src/report/html.rs` — **SEC-1**: the client-side `esc()` used a
    `textContent → innerHTML` round-trip, which escapes `& < >` but *not*
    quotes, then fed attribute positions. Because `data-*` values are
    HTML-decoded by the parser before JS reads them, this silently undid the
    correct Rust-side escaping, letting a CVE reference URL append attributes
    to an anchor. Added `escAttr()` for attribute contexts and `safeUrl()`
    (http/https allowlist, closing a `javascript:` link vector).
    **SEC-2**: five raw interpolations (`cve_url`, `pub_date`, `cve_lc`,
    `date`, `id_lc`) that omitted the `html_escape()` their neighbours applied.
  - `evedoo-gui/src/{command,app}.rs`, `tabs/{remote_scan,update_db}.rs` —
    **SEC-3/SEC-5**: the WinRM password sat in the child's argv, spawned three
    times per remote scan, with the `--serve` run holding it for the report
    server's lifetime. argv is captured by Windows event 4688, Sysmon event 1,
    and EDR agents, then persisted to SIEM. Moved to the environment, then to
    **stdin** via a new `--password-stdin` flag — the channel `remote/session.rs`
    already used for its PowerShell credentials and the CLI's own help text
    recommended. `spawn_command` was removed entirely so no spawn path can
    route secrets through argv.
  - `src/main.rs` — `--password-stdin` (conflicts_with `password`),
    `resolve_remote_password()` channel selection
  - `evedoo-gui/src/config.rs` — **SEC-7**: `detect_exe_paths` searched the
    CWD and fell back to a bare name, which `CreateProcess` also resolves via
    the CWD — a binary-planting path into a process subsequently handed WinRM
    credentials. Now anchored to the GUI binary's own directory with sibling
    `target/{debug,release}` probes; no CWD, no bare-name fallback.
- **Honest limitation recorded**: the `.meta` sidecar shares an origin with the
  payload, so it proves integrity, not authorship; detached signatures would be
  needed against a fully compromised mirror, and none are published.
- **Tests**: 210 → 223 (XSS regressions driving hostile payloads through every
  field; argv-absence assertions; CVE-id validation)
- **Review Status**: Reviewed and shipped

### Session 13: Companion-Artifact Veto + Report Redesign

- **Date**: 2026-08-10 to 2026-08-20
- **AI System**: Anthropic Claude Opus 5 (Claude Code)
- **Prompt Summary**: Investigate a 4× finding-count jump after a DB update,
  then redesign the HTML report's visual language and interaction

- **Files Modified**:
  - `src/normalize/tokens.rs`, `src/matcher/cpe.rs` — a live scan returned
    3,287 findings, of which **2,385 (73%) were one false positive**: "Google
    Chrome Installer v127.0.6512.0" matching `google:chrome` and therefore
    every Chrome CVE fixed between v127 and the installed v151. Root cause was
    Session 11's own classification — `installer` sat in the NOISE list (zero
    penalty), so the name scored a perfect 1.00. Added `TokenClass::Artifact`
    (installer, setup, updater, update, uninstall, helper, bootstrapper,
    launcher): when such a word appears as an *extra* token it **vetoes** the
    match, because the binary is a companion artifact carrying the product's
    name with its own version stream. Products legitimately named that way are
    unaffected — the word is then part of the pattern, never "extra".
    Findings 3,287 → 901.
  - `src/report/html.rs` — replaced the stock Chakra/Tailwind gray ramp with a
    token-driven design system, iterated twice on feedback: first a sharp
    "console" treatment, then the macOS/Material language actually wanted —
    Apple's dark system palette, Material elevation (`--e1`…`--e4`), vibrancy
    (backdrop blur) on header/sticky head/modal, capsule chips, segmented tab
    control, and a print stylesheet that flattens elevation for PDF sharing.
    UX: KEV/Has-Fix filter chips that AND with severity, live row counter,
    sticky header, sort-direction arrows, zero-KEV rendered as an explicit
    CLEAR result, sqrt-scaled EPSS magnitude bars, clickable solution cards
    opening the full CVE list, and always-visible copy buttons with an
    `execCommand` fallback.
  - `src/matcher/cpe.rs`, `src/scanner/version_resolver.rs`, `src/main.rs` —
    three clippy lints (`question_mark` ×2, `unnecessary_sort_by`) that had
    broken CI since `bc77db0`

- **Two self-inflicted bugs caught and fixed here, worth recording:**
  1. Binding `data-epss` to the EPSS *cell markup* rather than the raw score —
     the quote in `class="epss"` terminated the attribute and dumped every
     row's remaining attributes into the page as text, destroying the entire
     findings table. Now guarded by a test that walks every row's `data-*`
     values and rejects markup.
  2. The filter JS toggled a `.hidden` class no stylesheet defined, so
     filtering depended on a rule that did not exist.
- **CI note**: the clippy failures were **toolchain drift, not the commit**.
  Local clippy was 0.1.93 (Jan 2026) against CI's stable 1.98.0 (Aug 2026);
  the tell was `version_resolver.rs`, untouched by the blamed commit. Local
  toolchain updated so the gate is reproducible.
- **Tests**: 223 → 230
- **Review Status**: Reviewed and shipped

## Test Coverage

| Session | Tests Added | Total After |
|---|---|---|
| Session 1 (Core) | 96 | 96 |
| Session 2 (SBOM) | 11 | 107 |
| Session 3 (Mappings) | 3 | 110 |
| Session 4 (Remote) | 13 | 123 |
| Session 5 (Patches) | 15 | 138 |
| Session 6 (Fleet) | 8 | 146 |
| Session 7 (Schedule) | 7 | 153 |
| Session 8 (Security 1) | 7 | 160 |
| Session 9 (Security 2) | 9 | 169 |
| Session 11 (Correlation + detection) | 29 | 198 |
| Session 12 (Security remediation) | 25 | 223 |
| Session 13 (Artifact veto + report) | 7 | 230 |

Totals are workspace-wide from Session 11 onward (evedoo + cve-db-builder +
evedoo-gui), matching `cargo test --workspace`.

## Licensing Compliance

All AI-generated code is licensed under **Apache 2.0**. All dependencies use permissive licenses (Apache 2.0, MIT, BSD). No GPL/AGPL dependencies. See `../LICENSE` for full text.
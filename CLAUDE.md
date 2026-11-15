# CLAUDE.md — Project Guidelines for Evedoo

## Project Overview

**Evedoo** is a cross-platform (Windows, Linux, macOS) offline vulnerability scanner and Windows configuration auditor written in Rust. It inventories installed software across multiple sources (Windows Registry, AppX, WinGet, Chocolatey, Scoop, PE headers; Linux dpkg, rpm, pacman, apk, elf; macOS bundles, Homebrew, MAS, Mach-O; pip/npm/cargo, container rootfs, and OS versions), correlates entries against a local NIST NVD SQLite database (plus opt-in Microsoft MSRC data and experimental Ubuntu notices) for offline CVE matching, and audits Windows configuration against baseline checks derived from DISA STIGs.

The project is public and pre-1.0. README.md is the user-facing description and must stay accurate: do not describe a feature there (or here) as working unless the code does it.

Four Cargo packages in a single workspace (`Cargo.toml` at repo root) plus a modern SecOps frontend:
- `evedoo/` — the cross-platform scanner and compliance CLI binary (Windows, Linux, macOS, and offline rootfs container scanning)
- `cve-db-builder/` — NVD/MSRC/Distro → SQLite sync tool (cross-platform). Mirror-first: FKIE-CAD bulk feeds are the primary CVE source (no API key, ~1.5 min full sync), NVD API is the fallback. Ingests CPE dictionary, EPSS, CISA KEV, optional MSRC CVRF (`--enable-msrc`) and experimental Ubuntu security notices (`--enable-ubuntu`). There is no Red Hat, Debian, SUSE or Alpine feed.
- `evedoo-gui/` — egui companion GUI (Windows-only, wraps CLI via `std::process::Command`, zero copyleft dependencies)
- `evedoo-taskstate/` — cross-runtime agent task coordination server & CLI (cross-platform, MCP server over stdio + CLI subcommands)
- `evedoo-studio/` — modern React 18 + TypeScript + Tailwind SecOps web workspace with Apple HIG / Google Material 3 aesthetics and live engine bridge

## Licensing (Non-Negotiable)

- **Apache 2.0 only** — commercially viable, enterprise-friendly
- Dependencies must be 100% permissively licensed: Apache 2.0, MIT, BSD-2/3-Clause, ISC
- **Zero Copyleft** — reject any GPL, AGPL, LGPL, or MPL copyleft dependency
- All code must have explicit patent grants (Apache 2.0/MIT sources)
- Language: **Rust exclusively** for core engine — no Python, Go, C#, or PowerShell for core implementation
- Bundled audit checks are Evedoo's own wording (Apache-2.0), *derived from* DISA STIGs and mapped to NIST SP 800-53. Never label them as DISA's text, as authoritative, or as public-domain government works. CIS Benchmarks must not be bundled (CC BY-NC-SA)
- The licence policy is enforced by `deny.toml` (`cargo deny check`) in CI

## Build & Test

```bash
# Full workspace build and test
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings  # CI gate (0 warnings)

# Individual packages
cargo build --release -p evedoo          # multi-platform scanner & audit CLI
cargo build --release -p cve-db-builder    # NVD/MSRC/Distro sync tool (cross-platform)
cargo build --release -p evedoo-gui      # GUI companion (Windows only)
cargo build --release -p evedoo-taskstate # agent task state MCP server (cross-platform)

# Studio is npm, not a Cargo workspace member
cd evedoo-studio && npm install && npm run build
```

Do not hard-code test counts in documentation; they go stale. CI is the record.

- MSRV: `evedoo-taskstate` declares Rust 1.88 (edition 2024). The other crates declare none and are only tested on stable
- CI (`.github/workflows/ci.yml`): clippy `-D warnings` and tests for the whole workspace on Windows, Linux and macOS (`evedoo-gui` excluded off Windows), the Studio npm build, `cargo deny`, and a secret scan. Code used only on one OS must not become dead code on the others
- Never commit databases (`*.db`, `*.sqlite`), scan output, captured `--help` output or `.env` files. A scan database and an API key were once committed this way; CI now rejects them
- `winreg` dependency is platform-gated under `[target.'cfg(windows)'.dependencies]`; Linux (`dpkg`, `rpm`, `pacman`, `apk`, `elf`) and macOS (`bundle`, `homebrew`, `mas`, `macho`) scanner modules are platform-partitioned with pure-Rust parsers.

### Build notes

Builds go to cargo's default `target/`; binaries are in `target/release/`. Keep
checkouts out of cloud-synced folders (a sync client rewriting `target/`
mid-build corrupts artifacts). Never commit `.cargo/`: an absolute local path
in it breaks other machines and CI. Machine-specific notes belong in an
untracked `CLAUDE.local.md`.

## Code Security Standards

- Always use parameterized queries — never string concatenation for database queries
- Implement proper input validation and sanitization for all user inputs
- Never hardcode secrets, API keys, or passwords in source code
- Implement proper error handling that doesn't expose sensitive information
- Follow OWASP Top 10 guidelines
- Fail-secure patterns (deny by default)
- Log security events without exposing sensitive data

## Dependency Management

- Only use well-maintained crates with recent updates and strong security records
- 100% pure permissive license tree (MIT, Apache-2.0, BSD, ISC)
- Prefer `rusqlite` with `bundled` feature for SQLite (no system dependency)
- Avoid adding heavy crate dependencies when direct FFI or hand-parsing suffices (e.g. PE fingerprinting uses `version.dll` FFI, Toolhelp32 uses direct kernel32 FFI)

## Architecture Notes

- **Scanner modules** (`evedoo/src/scanner/`): parsers read untrusted files and release builds use `panic = "abort"`, so they must be panic-free (checked slicing, truncation/mutation tests). RPM: only `rpmdb.sqlite` is read; Berkeley DB and NDB are warned about. modular per-source inventory (Windows: registry, appx, winget, chocolatey, scoop, pe_fingerprint; Linux: dpkg, rpm, pacman, apk, elf; macOS: bundle, homebrew, mas, macho; cross-platform packages: pip, npm, cargo; and OS identity). Supports offline container image / chroot / disk scanning via `--rootfs <PATH>`.
- **Matcher** (`evedoo/src/matcher/`): in-memory `CpeIndex` keyed on `(vendor, product)` for O(1) lookups. Token-based matching with weighted confidence, alias table, CPE dictionary layer, negative-mapping vetoes, and `target_sw` ecosystem gating.
- **MSRC Overrides** (`evedoo/src/msrc_override.rs`): Authoritative Microsoft Security Response Center verdict lookup. Compares exact Windows build numbers (`is_patched`), suppressing patched CVEs and enriching unpatched findings with exact KB articles and fixed versions (FR-89..FR-96).
- **Distro Overrides** (`evedoo/src/distro_override.rs`): applies distribution advisories (today only experimental Ubuntu notices) to suppress patched CVEs and enrich unpatched ones. Applied only when the scanned system's distribution and release are known and match the advisory (`HostDistro`, read from the inventory's os-release entry); anything unknown suppresses nothing.
- **Configuration Audit** (`evedoo/src/audit/`): Windows hardening checks derived from DISA STIGs (Windows 11 V1R4, 10 V2R8, Server 2022 V1R3, Edge V1R2: 35 bundled checks, a small sample of each STIG) mapped to NIST SP 800-53 controls. Registry and service-startup evaluation, pass rate, CAT I/II/III breakdowns. `resolve_benchmark` picks the benchmark: `--benchmark` names a bundled one only, `--policy <file>` reads a **JSON** benchmark (no XCCDF parser), and with neither the detected Windows version decides. Windows benchmarks are refused on non-Windows hosts. Every report carries `AUDIT_DISCLAIMER` and a scope statement.
- **Interactive Menu** (`evedoo/src/menu/`): `evedoo menu` — a single-keypress front end over every subcommand, for operators who would rather not memorise flags. Dispatches by re-invoking the executable with the subcommand the user would otherwise have typed (and printing it first), so menu and CLI share one code path. Header states CVE-database freshness and whether the process is elevated, because unelevated runs silently degrade reachability to `Unknown`. Structured so the testable parts are pure: `model.rs` is a key→action table, `render.rs` a string build, `actions.rs` an argument-vector function; only `term.rs` (keypress/VT/clear via direct kernel32, msvcrt and advapi32 FFI) and the executor touch the world. No TUI dependency.
- **Runtime Reachability** (`evedoo/src/reachability/`): In-memory loaded module inspection via Toolhelp32 FFI on Windows and `/proc/[pid]/maps` on Linux (`Loaded`, `NotObserved`, `Unknown`) with strict `multiplier >= 1.0` safety floor (FR-73..FR-82).
- **Fleet Remediation Aggregation** (`evedoo/src/aggregate.rs`): `evedoo fleet report` groups stored findings across all scanned hosts and ranks upgrades by total risk removed (FR-83..FR-88).
- **Normalisation** (`evedoo/src/normalize/`): structured `Version` type with Ord for semver/calver/pre-release/letter suffix comparison, plus Debian `DpkgVersion`, RPM EVR `RpmVersion`, Alpine `ApkVersion`, and Apple `AppleVersion`.
- **Reports** (`evedoo/src/report/`): text (owo-colors), json, csv, html, cyclonedx, spdx output formats.
- **History & Exceptions** (`evedoo/src/history.rs`, `evedoo/src/exceptions.rs`): SQLite-backed delta tracking (`New`, `NewlyApplicable`, `Persisting`, `Resolved`, `NoLongerApplicable` — see `models::FindingStatus`) and expiring accepted-risk rules.
- **Remote** (`evedoo/src/remote/`): Agentless WinRM session management. HTTP (5985) is the default and prints a warning; `--use-ssl` enables HTTPS with certificate validation. `ps_escape()` doubles all five PowerShell single-quote characters; credentials are zeroized and redacted from `Debug`.
- **Risk & Serve** (`evedoo/src/risk.rs`, `evedoo/src/serve.rs`): corpus-calibrated Impact × Likelihood scoring with P1–P4 tiers and KEV override; token-authenticated local HTTP server for `--serve` HTML reports (`std::net` only, no web framework; exact token match, no-store/no-referrer/CSP headers).
- **GUI** (`evedoo-gui/`): egui companion app wrapping CLI with auto-export of CSV and HTML report browser launch.
- **Studio** (`evedoo-studio/`): Modern React 18 + TS + Tailwind workspace with Dark/Light modes, live scanner engine bridge, SBOM viewer, and fleet grid.
- **Task State** (`evedoo-taskstate/`): Cross-runtime agent coordination via append-only ledger `docs/agent-state/tasks.jsonl` with advisory locking (`fs4`), pure fold state derivation, and 8 MCP tools (`task_state`, `task_declare`, `task_start`, `task_finish`, `task_review`, `task_ruling`, `task_history`, `task_handoff`).

## Conventions

- `clippy -D warnings` must pass (0 warnings) — CI gate
- Tests live in `#[cfg(test)] mod tests` blocks within each source file ; `evedoo-taskstate` additionally has `tests/concurrency.rs`, and `evedoo` has `tests/env_file.rs` and `tests/empty_database.rs`, which run the built binary to prove it never reads a `.env` and never reports a clean result from a missing or empty CVE database
- Use `tracing` crate macros (`info!`, `debug!`, `warn!`) for diagnostics — **not** the `log` crate
- `clap` for CLI argument parsing; values with a fixed set of choices are validated at parse time, never mapped to a silent default
- Registry keys for dedup use scheme prefixes: `registry://`, `appx://`, `winget://`, `chocolatey://`, `scoop://`, `pe://`, `pip://`, `npm://`, `cargo://`, `os://`

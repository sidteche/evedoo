# Evedoo

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/sidteche/evedoo/actions/workflows/ci.yml/badge.svg)](https://github.com/sidteche/evedoo/actions/workflows/ci.yml)

Evedoo is an offline vulnerability scanner and Windows configuration auditor written in Rust.

It inventories the software installed on a machine, matches it against a local copy of the NIST National Vulnerability Database, and reports the CVEs that apply, ranked by how likely they are to be exploited. Nothing about your machine leaves it: the scan reads a local SQLite database and makes no network calls.

**Status: 0.1, pre-release, single maintainer.** Windows is the most exercised platform. Linux and macOS support is newer and less tested. See [What works where](#what-works-where) before relying on it.

## What it does

- **Inventories installed software** from the Windows Registry, AppX, WinGet, Chocolatey, Scoop and PE version resources; Linux dpkg, rpm, pacman, apk and ELF libraries; macOS app bundles, Homebrew, Mac App Store receipts and Mach-O libraries; and pip, npm and cargo packages.
- **Matches it to CVEs offline** against a local database built from NVD data, with EPSS exploitation-probability scores and the CISA Known Exploited Vulnerabilities catalog.
- **Ranks findings by risk** into P1 to P4 tiers, and on Windows and Linux checks whether a vulnerable library is loaded by a running process.
- **Tracks change between scans**: new, persisting and resolved findings, with expiring accepted-risk exceptions that require a reason and an owner.
- **Reports** as text, JSON, CSV, a self-contained HTML page, CycloneDX 1.6 or SPDX 2.3.
- **Audits Windows hardening** against a small set of baseline checks derived from DISA STIGs (see [Configuration audit](#configuration-audit)).
- **Scans a container image or disk offline** from an extracted root filesystem with `--rootfs`.

## Quick start

You need a [Rust toolchain](https://rustup.rs) (stable). Run everything from the repository root.

**1. Build**

```bash
cargo build --release -p cve-db-builder -p evedoo
```

The binaries land in `target/release/` (`evedoo.exe` and `cve-db-builder.exe` on Windows).

**2. Build the CVE database**

```bash
./target/release/cve-db-builder
```

This downloads NVD data from the [FKIE-CAD mirror](https://github.com/fkie-cad/nvd-json-data-feeds), plus EPSS and CISA KEV, into `vulndb.sqlite` in the current directory. No API key is needed. Expect a download of a few minutes and a database of roughly 1 GB. Re-run with `--update` to refresh it.

**3. Scan**

```bash
./target/release/evedoo scan -f html -o report.html
```

The scanner looks for `vulndb.sqlite` in the current directory; use `--database <path>` or the `EVEDOO_DB_PATH` environment variable to point elsewhere. A missing or empty database is an error, never a clean result.

On Windows, run from an elevated prompt for full results: without elevation, the loaded-module check cannot read most processes.

Prefer not to remember flags? `evedoo menu` offers every command from a keypress menu and prints the command it runs.

### Useful commands

```bash
evedoo scan --risk --sort risk              # show risk tiers, highest first
evedoo scan --severity critical,high        # filter by severity
evedoo scan --rootfs /mnt/image             # scan an extracted Linux root filesystem
evedoo reassess                             # re-check the stored inventory against a refreshed database
evedoo exception add --help                 # accept a risk until a date
evedoo fleet report                         # which upgrade removes the most risk across scanned hosts
evedoo audit                                # Windows configuration audit
```

`evedoo <command> --help` documents every flag. The full reference is in [docs/cli-reference.md](docs/cli-reference.md).

## What works where

| Capability | Windows | Linux | macOS |
|---|---|---|---|
| Software inventory | Registry, AppX, WinGet, Chocolatey, Scoop, PE | dpkg, rpm (SQLite database only), pacman, apk, ELF | App bundles, Homebrew, Mac App Store, Mach-O |
| pip / npm / cargo packages | Yes | Yes | Yes |
| CVE matching, risk tiers, reports | Yes | Yes | Yes |
| Loaded-module (reachability) check | Yes | Yes | No (reported as unknown) |
| Vendor fix data | Microsoft MSRC, opt-in | Ubuntu notices, opt-in, experimental | None |
| Configuration audit | Yes | No | No |
| Remote scan | Windows targets over WinRM | No | No |
| Scheduled scans | Task Scheduler | No | No |
| Desktop GUI (`evedoo-gui`) | Yes | No | No |

Known limits worth knowing before you trust a result:

- **Linux findings are NVD matches.** Distributions backport fixes without changing the upstream version, so a package can be reported as vulnerable when the distribution has already patched it. Only the experimental Ubuntu feed adjusts for this, and only on Ubuntu.
- **RPM databases:** only the SQLite format is read (RHEL, Rocky and Alma 9 or later, Fedora 33 or later). The older Berkeley DB format (RHEL and CentOS 7 and 8, Amazon Linux 2) and SUSE's NDB format are detected and reported with a warning, but their packages are not inventoried.
- **`--rootfs`** reads operating-system packages only, not language packages or binaries inside the image.
- **Matching is name-based.** Installed software names are matched to NVD product identifiers with a confidence level; `--min-confidence` (default `high`) trades missed findings against false ones.

## Configuration audit

`evedoo audit` checks Windows registry and service settings against bundled baseline checks and reports which pass.

```bash
evedoo audit                                   # picks the checks for the detected Windows version
evedoo audit --benchmark ms-edge -f html -o edge.html
evedoo audit --policy my-benchmark.json        # your own checks, as JSON
```

| Bundled checks | Alias | Checks |
|---|---|---:|
| Derived from the Microsoft Windows 11 STIG (V1R4) | `windows-11` | 16 |
| Derived from the Microsoft Windows 10 STIG (V2R8) | `windows-10` | 8 |
| Derived from the Microsoft Windows Server 2022 STIG (V1R3) | `windows-server-2022` | 6 |
| Derived from the Microsoft Edge STIG (V1R2) | `ms-edge` | 5 |

These are Evedoo's own checks covering a small sample of each STIG, which contain hundreds of rules. A pass rate here is **not** a STIG compliance score. The STIG identifiers shown are cross-references and have not been verified against DISA's published files. Evedoo is not an official DISA product and is not endorsed by DISA or the U.S. Department of Defense.

Custom benchmarks are JSON only, in the shape of the `Benchmark` type in [evedoo/src/audit/policy.rs](evedoo/src/audit/policy.rs). There is no XCCDF importer.

## Optional vendor data

Two additional sources are off by default because their data carries the vendor's own terms and is meant for local use:

```bash
cve-db-builder --update --enable-msrc      # Microsoft: exact fixed builds and KB articles for Windows
cve-db-builder --update --enable-ubuntu    # Ubuntu security notices (experimental)
```

Sources, terms and required attributions are listed in [DATA_SOURCES.md](DATA_SOURCES.md).

## Repository layout

| Path | What it is |
|---|---|
| `evedoo/` | The scanner and audit command-line tool |
| `cve-db-builder/` | Builds and updates the CVE database |
| `evedoo-gui/` | Windows desktop front end that runs the CLI |
| `evedoo-studio/` | React web UI. A development prototype: its live mode needs the Vite dev server, and a production build shows sample data only |
| `evedoo-taskstate/` | A task ledger used while developing Evedoo with AI coding agents. Not part of the scanner |
| `docs/` | CLI reference, architecture, design notes and history |

## Responsible use

Scan only systems you own or are authorised to assess. A scan report is a list of a machine's weaknesses: treat it as sensitive, and do not paste one into a public issue.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md): how to build, test and propose changes.
- [SECURITY.md](SECURITY.md): how to report a vulnerability in Evedoo privately.
- [CHANGELOG.md](CHANGELOG.md): notable changes.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Dependencies are limited to permissive licences, enforced in CI by [deny.toml](deny.toml).

This product uses the NVD API but is not endorsed or certified by the NVD. All product names are trademarks of their respective owners; Evedoo is not affiliated with or endorsed by Microsoft, Canonical, NIST, CISA or DISA.

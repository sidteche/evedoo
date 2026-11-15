# Evedoo — Dependency License Audit & Commercial Impact Analysis

**Date:** 2026-08-29 (updated post P21-LICENSE-MPL; Studio npm tree added)  
**Scope:** Full transitive dependency tree across all 4 Cargo workspace crates (`evedoo`, `cve-db-builder`, `evedoo-gui`, `evedoo-taskstate`) **and** the `evedoo-studio` npm tree  
**Project license:** Apache-2.0  
**Policy:** permissive licences only; no GPL/LGPL/AGPL/MPL copyleft  
**Status:** a manual review as of the date above. The enforced, current policy is [`deny.toml`](../deny.toml), checked by `cargo deny` in CI. It allows a few permissive licences this document does not list (Zlib, BSL-1.0, Unicode-3.0, CC0-1.0) and one font-licence exception for the GUI's embedded fonts (OFL-1.1, Ubuntu Font Licence)

---

## Executive Summary

> [!NOTE]
> **100% of all dependencies across the entire Cargo workspace are fully permissive** (MIT, Apache-2.0, BSD-*, ISC, Zlib, BSL-1.0, Unicode-3.0). Zero copyleft dependencies remain.

| Verdict | Count | Details |
|---------|------:|---------|
| ✅ Fully Compliant (permissive) | **All** | MIT, Apache-2.0, BSD-*, ISC, Zlib, BSL-1.0, CC0, Unicode-3.0, Unlicense |
| ⚠️ Policy Violations (weak copyleft) | **0** | `colored` replaced with `owo-colors` (MIT); `option-ext` eliminated |
| 🚫 Strong Copyleft (GPL/LGPL/AGPL) | **0** | None found |

---

## Resolution of Prior Findings (P21-LICENSE-MPL)

### 1. `colored` → `owo-colors` (MIT) [Resolved]
* **Action:** Replaced `colored = "2.1"` (MPL-2.0) with `owo-colors = "4.2"` (MIT) in `evedoo`.
* **Outcome:** Clean drop-in using `use owo_colors::OwoColorize;`. Zero MPL-2.0 in the scanner CLI crate.

### 2. `directories` / `option-ext` [Resolved]
* **Action:** Removed `directories = "6"` (which transitively pulled `dirs-sys` → `option-ext` under MPL-2.0) from `evedoo-gui`. Replaced with standard library `std::env::var_os("APPDATA")` / `std::env::var_os("HOME")` path resolution in `evedoo-gui/src/config.rs`.
* **Outcome:** Completely eliminated `option-ext` and `dirs-sys` from `Cargo.lock`.

---

## `evedoo-studio` (npm tree)

Studio is not a Cargo workspace member, so it is audited separately. It is a
build-time-only React application — nothing from this tree is linked into or
redistributed with the Rust binaries.

| License | Packages | Category | Commercial Risk |
|:---|---:|:---|:---|
| `MIT` | 118 | Permissive | None |
| `ISC` | 9 | Permissive | None |
| `Apache-2.0` | 4 | Permissive | None |
| `BSD-3-Clause` | 1 | Permissive | None |
| `CC-BY-4.0` | 1 | Attribution-only (`caniuse-lite`, a build-time browser data table) | None |
| **`MPL-2.0` / `GPL` / `LGPL` / `AGPL`** | **0** | **Copyleft** | **ZERO (0)** |

Direct dependencies are `react`, `react-dom`, `clsx`, `tailwind-merge`, and
`lucide-react` (all MIT); the dev toolchain is `vite`, `typescript`,
`tailwindcss`, `postcss`, `autoprefixer`, and `@vitejs/plugin-react`.

> `CC-BY-4.0` on `caniuse-lite` is an attribution licence with no ShareAlike or
> NonCommercial term. It is not copyleft and imposes no obligation on the
> compiled output; it is called out here only for completeness.

---

## License Distribution

| License Expression | Category | Commercial Risk |
|:---|:---|:---|
| `MIT OR Apache-2.0` / `MIT/Apache-2.0` | Permissive | None |
| `MIT` | Permissive | None |
| `Apache-2.0` | Permissive | None |
| `Unicode-3.0` | Permissive | None |
| `Apache-2.0 WITH LLVM-exception` | Permissive | None |
| `BSD-2-Clause` / `BSD-3-Clause` | Permissive | None |
| `ISC` | Permissive | None |
| `Zlib` / `BSL-1.0` | Permissive | None |
| `CC0-1.0` | Public Domain | None |
| **`MPL-2.0` / `GPL` / `LGPL` / `AGPL`** | **Copyleft** | **ZERO (0)** |

---

## Patent Risk Assessment

| License | Patent Grant | Defensive Termination | Risk |
|:---|:---|:---|:---|
| Apache-2.0 | ✅ Explicit (§3) | ✅ Yes (§3) | None |
| MIT | ❌ Implied only | ❌ No | Very Low |
| BSD-* | ❌ None | ❌ No | Very Low |
| ISC | ❌ None | ❌ No | Very Low |
| Zlib | ❌ None | ❌ No | Very Low |

---

## Conclusion

**Evedoo's dependency tree is 100% commercially clean and fully permissive.**
- Zero copyleft dependencies (weak or strong) across the Cargo workspace *and*
  the Studio npm tree.
- 100% compliant with Apache-2.0 commercial distribution.
- Zero license taint for enterprise procurement pipelines.

### Bundled content licensing

Beyond code dependencies, Evedoo ships configuration-audit checks. They are
written by the Evedoo contributors and licensed Apache-2.0 with the code. They
are derived from DISA STIGs and mapped to NIST SP 800-53 controls, but are not
copies of those documents. *(Corrected November 2026: this section previously
described them as public-domain U.S. Government works.)*

CIS Benchmarks are **deliberately not bundled**: they are licensed
CC BY-NC-SA 4.0, whose NonCommercial and ShareAlike terms are both
incompatible with this project's Apache-2.0 zero-copyleft policy. Operators
holding a CIS SecureSuite licence can load their own rules through
`evedoo audit --policy <file>` instead. (Ruling recorded 2026-08-28; see
`docs/agent-state/CURRENT.md`.)

CVE, EPSS, KEV, and MSRC data are **never redistributed** — each user syncs
their own database with `cve-db-builder`. MSRC ingestion in particular is
opt-in behind `--enable-msrc` because the Microsoft APIs Terms of Use prohibit
redistributing data obtained through the API (FR-89, FR-94).

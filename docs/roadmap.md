# Evedoo Improvement Roadmap

Prioritised algorithmic/architectural improvements for the vulnerability scanner.

Phases 1–6 were the original correctness/performance plan; everything from #7 onward was added as the tool matured. **Phases 1–21 are shipped.**

---

## Phase 20: Operationalisation (N1, N2, N4) — shipped

- **N1 Reassess without rescanning (`evedoo reassess`)**: Re-correlates persisted inventory snapshots against updated CVE databases offline.
- **N2 Unified Risk Scoring & Priority Tiers (P1–P4)**: Multiplicative formula `100 · impact^0.4 · likelihood^0.6 · criticality` with KEV priority overrides and fleet criticality scaling.
- **N4 Expiring Accepted-Risk Exceptions (`evedoo exception`)**: Scoped `(hostname, cve_id, software_name)` exception rules with mandatory owner, reason, and maximum 730-day expiration.
- **Status:** ✅ Done (294 tests at the time of that phase)

---

## Phase 21: Enterprise Accuracy, Reachability & Compliance — shipped

- **N3 Runtime Module Reachability (`evedoo/src/reachability/`)**: In-memory loaded module inspection via Toolhelp32 Win32 FFI. Classifies findings into `Loaded`, `NotObserved`, and `Unknown`, prioritizing active services over dormant code on disk (`FR-73..FR-82`). **Known limitation:** because FR-74 forces every non-match to `Unknown` when process coverage is incomplete, `NotObserved` is unreachable in practice on an unelevated scan (measured: 159/332 processes readable → 6 `Loaded`, 0 `NotObserved`, 982 `Unknown`). The feature promotes loaded findings but cannot yet report a finding as dormant. This is a deliberate ruling, not a defect — see `docs/agent-state/CURRENT.md`.
- **N5 Authoritative Vendor Advisories (`evedoo/src/msrc_override.rs`, `cve-db-builder/src/msrc/`)**: Microsoft Security Response Center CVRF sync (`--enable-msrc`), lowercased CPE vendor/product normalization (`FR-96`), exact KB number extraction, and version build comparison suppressing patched findings (`FR-89..FR-96`).
- **N6 Configuration & Compliance Auditing (`evedoo/src/audit/`)**: Native automated hardening assessment against baseline checks derived from **DISA STIG (Defense Information Systems Agency Security Technical Implementation Guides)** and **NIST SP 800-53** baselines — 35 bundled rules across Windows 11 (V1R4, 16 rules), Windows 10 (V2R8, 8), Windows Server 2022 (V1R3, 6), and Microsoft Edge (V1R2, 5). Evaluates registry assertions and service startup types, calculating Compliance Scores (% pass rate) and CAT I/II/III breakdowns (`FR-97..FR-105`). Custom benchmarks load via `--policy <file>` as **JSON only** — XCCDF/XML ingestion is not implemented.
- **N7 Cross-Asset Remediation Aggregation (`evedoo/src/aggregate.rs`)**: `evedoo fleet report` groups stored findings across all scanned hosts and ranks patch actions by total fleet risk reduction (`FR-83..FR-88`).
- **Evedoo Studio (`evedoo-studio/`)**: Dual-target (Web + Desktop) React 18 + TypeScript + Tailwind workspace with Dark/Light modes, live scanner engine bridge, SBOM inspector, and triage table.
- **Dependency Cleanliness (P21-LICENSE-MPL)**: 100% pure permissive dependency tree (replaced `colored` with `owo-colors` and eliminated `directories`/`option-ext`).
- **Status:** ✅ Done — **441 tests** passing at commit `971a817` (378 scanner · 34 db-builder · 26 taskstate · 3 GUI), `clippy -D warnings` clean

---

# What's next — closing the remaining enterprise gap

Ranked by value × feasibility given the completed Phase 21 architecture:

1. **Native Universal Linux & macOS Scanners** — Implementation plans authored in `docs/superpowers/plans/` (Universal Linux for Ubuntu/RHEL/Debian/SUSE/Alpine/Arch, Native macOS for 11–15+ with Mach-O inspection and Apple HT201222 advisories).
2. **Ticketing Integration** — Automated Jira / ServiceNow issue creation driven off CISA KEV due dates.
3. **Historical Risk Burn-Down Trends** — Time-series fleet risk tracking across consecutive scan snapshots.
4. **Automated Remediation Actions** — Dry-run gated patch deployment for winget/choco/apt/dnf.
5. **XCCDF / SCAP ingestion** — Parse licensed XCCDF benchmark XML directly, so operators holding CIS SecureSuite content no longer have to hand-convert it into the `--policy` JSON shape.
6. **Reachability coverage thresholds** — Optional per-directory or percentage-based completeness so `NotObserved` becomes attainable without reintroducing the false negatives FR-74 exists to prevent.

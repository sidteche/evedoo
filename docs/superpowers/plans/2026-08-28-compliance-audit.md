# Compliance Auditing (DISA STIG / NIST SP 800-53) Implementation Plan

**Task:** `P21-N6` (Phase 21, Enterprise Accuracy & Reachability)  
**Spec:** `docs/superpowers/specs/2026-08-28-compliance-audit-design.md`  
**License Standard:** 100% Apache-2.0 / Public Domain (17 U.S.C. § 105)  
**Status:** SHIPPED (commit `89b96ab`). 35 bundled rules across four DISA STIG
benchmarks. Two as-built deviations from the design are recorded at the top of
`docs/superpowers/specs/2026-08-28-compliance-audit-design.md`: `--policy` is
JSON-only (no XCCDF parser), and only the Registry and Service evaluation layers
were implemented.  

---

## 1. Overview & Architecture

Implements native configuration and compliance hardening assessment against official **DISA STIG (Defense Information Systems Agency Security Technical Implementation Guides)** and **NIST SP 800-53** baselines.

```
evedoo/src/audit/
  mod.rs        — Audit coordinator and public API
  policy.rs     — Benchmark, Rule, CheckAssertion, and Severity data models
  evaluator.rs  — Registry & policy assertion evaluator against Windows subsystem
  builtin.rs    — Bundled Public Domain DISA STIG baselines (Windows 11, 10, Server)
  report.rs     — Text, JSON, CSV, and HTML compliance scoring & reporting
```

---

## 2. Implementation Tasks

### Task 1: Policy Data Structures & Comparison Operators (`evedoo/src/audit/policy.rs`)
* Define `Benchmark`, `BenchmarkRule`, `AuditSeverity`, `CheckAssertion`, `ComparisonOperator`, `RegistryHive`, and `RuleResult`.
* Implement operator evaluation: `Equals`, `NotEquals`, `GreaterThanOrEqual`, `LessThanOrEqual`, `BitwiseAnd`, `Exists`, `NotExists`.
* Author exhaustive unit tests for all comparison operators.

### Task 2: Windows System Evaluator (`evedoo/src/audit/evaluator.rs`)
* Evaluate registry checks against `winreg` (`HKLM`, `HKCU`, `HKU`).
* Handle DWORD, QWORD, String, ExpandString, MultiString, and binary data types.
* Evaluate service startup types via Windows Service Controller.
* Safely handle missing keys, missing values, and access-denied scenarios, mapping them to `RuleStatus::Fail` or `RuleStatus::NotApplicable` cleanly.

### Task 3: Bundled DISA STIG Benchmarks (`evedoo/src/audit/builtin.rs`)
* Bundle curated, high-impact DISA STIG baseline rules (Windows 11 / Windows 10 / Server):
  * Account Lockout Threshold (CAT II)
  * SMBv1 Protocol Disabled (CAT I)
  * LLMNR Broadcast Disabled (CAT II)
  * PowerShell Script Block Logging Enabled (CAT II)
  * UAC Admin Approval Mode Enabled (CAT II)
  * Windows Defender Antivirus Realtime Protection (CAT I)
  * Remote Desktop Network Level Authentication Required (CAT I)
  * AutoRun / AutoPlay Disabled (CAT II)
* 100% Public Domain (17 U.S.C. § 105) content with zero copyleft.

### Task 4: CLI Subcommand & Reporting (`evedoo/src/audit/report.rs`, `evedoo/src/main.rs`)
* Add `evedoo audit` subcommand with `--benchmark <id>`, `--policy <file>`, `--format <text|json|csv|html>`, and `--output <path>`.
* Calculate compliance score (`passed_rules / total_applicable * 100.0`).
* Render colored terminal output and structured JSON/CSV/HTML reports.

---

## 3. Verification Plan
* `cargo test -p evedoo audit::`
* `cargo clippy --workspace --all-targets -- -D warnings`
* Real execution: `evedoo audit --benchmark windows-11` on live machine.

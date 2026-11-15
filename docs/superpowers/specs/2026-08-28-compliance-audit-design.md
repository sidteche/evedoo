# Configuration and Compliance Auditing (DISA STIG / NIST SP 800-53) — Design

**Task:** `P21-N6` (Phase 21, Enterprise Accuracy & Reachability)  
**Status:** SHIPPED (commit `89b96ab`) — see the as-built note below  
**Spec IDs introduced:** `FR-97` … `FR-105`, `SEC-10`, `DC-9`  
**Licensing Standard:** 100% Apache-2.0 / Public Domain (17 U.S.C. § 105)  

---

> ### As-built deviations from this design
>
> This document is the **pre-implementation design**. Two things in it describe
> intent that was not built, and the shipped code is authoritative:
>
> 1. **No XCCDF/XML ingestion engine.** `--policy <file>` reads **JSON only** and
>    deserializes it directly into `audit::policy::Benchmark`
>    (`evedoo/src/audit/mod.rs::run_audit`). There is no XML parser anywhere in
>    `evedoo/src/audit/`. Operators holding licensed XCCDF content must convert
>    it to that JSON shape. Native XCCDF parsing is tracked as a future item in
>    `evedoo/IMPROVEMENT_ROADMAP.md`.
> 2. **Two of the four evaluation layers shipped.** `CheckAssertion` implements
>    `Registry` (HKLM/HKCU/HKU across DWORD, QWORD, SZ, EXPAND_SZ, MULTI_SZ, and
>    BINARY) and `Service` (startup type). The diagram's *Security Policy /
>    Rights* and *Audit Policy Settings* layers were not implemented.
>
> Shipped scope: **35 bundled rules** — Windows 11 V1R4 (16), Windows 10 V2R8 (8),
> Windows Server 2022 V1R3 (6), Microsoft Edge V1R2 (5).


## 1. Problem & Strategic Objectives

Vulnerability management is only half the attack surface. Systems patched against all known CVEs remain vulnerable if misconfigured (e.g. unencrypted SMBv1 enabled, LLMNR broadcast resolution active, weak password lockouts, or disabled PowerShell script block logging).

Federal standards (NIST SP 800-53, DoD Zero Trust) and enterprise security frameworks require automated compliance auditing against authoritative hardening benchmarks.

### Licensing Strategic Decision (Ruling P21-N6-T0)
* **CIS Benchmarks** are licensed under CC-BY-NC-SA 4.0 (Non-Commercial prohibition and viral ShareAlike copyleft). Bundling CIS Benchmark rules in Evedoo would breach Evedoo's non-negotiable Apache-2.0 / zero-copyleft policy.
* **DISA STIGs (Defense Information Systems Agency Security Technical Implementation Guides)** and **NIST SP 800-53** are works of the United States Government in the **Public Domain (17 U.S.C. § 105)**. They carry zero copyright restrictions, zero copyleft, and zero commercial limitations.
* **Architecture:** Evedoo ships native, bundled **DISA STIG** hardening rules (Windows 11, Windows 10, Windows Server 2022, Microsoft Edge), while providing a generic **open XCCDF/XML ingestion engine** allowing operators with commercial CIS SecureSuite licenses to load custom benchmarks without Evedoo distributing proprietary content.

---

## 2. Architecture & Check Assertion Model

The compliance engine is split into four layers:

```
┌────────────────────────────────────────────────────────┐
│               Compliance Benchmark Rules               │
│   • Bundled DISA STIGs (Windows 11/10/Server, Edge)   │
│   • Custom XCCDF / XML / JSON Benchmarks (Operator)    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│               Policy Evaluation Engine                 │
│                                                        │
│  • Registry Checks (HKLM / HKCU values & bitmasks)    │
│  • Security Policy / Rights (Account lockout, LSA)     │
│  • System Service States (Disabled, Manual, Auto)      │
│  • Audit Policy Settings (Subcategory audit status)    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                   Audit Results & Score                │
│                                                        │
│  • Rule Outcomes: Pass, Fail, NotApplicable, Error     │
│  • Severity Categorization: CAT I (High), CAT II (Med) │
│  • NIST SP 800-53 Mapping (AC-2, CM-6, IA-5, etc.)     │
│  • Compliance Percentage Score (% Pass rate)           │
│  • Output Formats: Text, JSON, CSV, HTML               │
└────────────────────────────────────────────────────────┘
```

---

## 3. Data Models & Specification Requirements

### 3.1. Policy Data Structures (`evedoo/src/audit/policy.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Benchmark {
    pub id: String,                  // e.g. "U_MS_Windows_11_STIG"
    pub title: String,               // "Microsoft Windows 11 STIG Benchmark"
    pub version: String,             // "V1R4"
    pub publisher: String,           // "DISA"
    pub target_os: String,           // "windows_11"
    pub rules: Vec<BenchmarkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRule {
    pub id: String,                  // e.g. "WN11-CC-000010"
    pub stig_id: Option<String>,     // e.g. "V-253378"
    pub rule_id: Option<String>,     // e.g. "SV-253378r828876_rule"
    pub title: String,
    pub description: String,
    pub severity: AuditSeverity,     // CatI (High), CatII (Medium), CatIII (Low)
    pub check: CheckAssertion,
    pub fix_text: String,
    pub nist_controls: Vec<String>,  // e.g. ["CM-6", "AC-3"]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditSeverity {
    CatI,   // High severity (immediate compromise)
    CatII,  // Medium severity (defense in depth weakness)
    CatIII, // Low severity (hygiene / administrative)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CheckAssertion {
    Registry {
        hive: RegistryHive,
        key_path: String,
        value_name: String,
        expected_type: RegistryValueType,
        operator: ComparisonOperator,
        expected_value: serde_json::Value,
    },
    Service {
        service_name: String,
        expected_status: ServiceStartupType,
    },
    SecurityPolicy {
        section: String,
        setting: String,
        operator: ComparisonOperator,
        expected_value: String,
    },
}
```

---

## 4. CLI Surface

* **`FR-97`**: `evedoo audit` CLI subcommand:
  ```bash
  evedoo audit                               # Runs default OS DISA STIG benchmark
  evedoo audit --benchmark windows-11        # Runs specific bundled benchmark
  evedoo audit --policy custom_stig.json     # Ingests custom operator policy
  evedoo audit --format html --output report.html
  ```
* **`FR-98`**: Display compliance summary with percentage pass rate and CAT I/II/III severity breakdown.
* **`FR-99`**: All bundled compliance benchmarks must be 100% public domain (DISA STIG / NIST).

---

## 5. Verification Plan
* 100% unit test coverage for registry assertion evaluation, comparison operators, and DISA STIG JSON parsing.
* Closes `P21-N6` cleanly.

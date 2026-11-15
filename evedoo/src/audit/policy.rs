//! Compliance Policy Data Models and Operators
//!
//! SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};

/// Shown in every audit report format.
pub const AUDIT_DISCLAIMER: &str =
    "Not an official DISA product; not endorsed by DISA or the U.S. Department of Defense.";

/// Compliance Benchmark containing a set of rules (e.g. DISA STIG, NIST SP 800-53 baseline).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Benchmark {
    /// Unique identifier for the benchmark, e.g. "U_MS_Windows_11_STIG"
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Benchmark version, e.g. "V1R4"
    pub version: String,
    /// Publisher/Author, e.g. "DISA", "NIST"
    pub publisher: String,
    /// Target operating system, e.g. "windows_11", "windows_10", "windows_server_2022"
    pub target_os: String,
    /// Set of audit rules in this benchmark
    pub rules: Vec<BenchmarkRule>,
}

/// A specific configuration rule / check within a benchmark.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkRule {
    /// Unique rule identifier, e.g. "WN11-CC-000010"
    pub id: String,
    /// DISA STIG Vuln ID if applicable, e.g. "V-253378"
    pub stig_id: Option<String>,
    /// DISA STIG Rule ID if applicable, e.g. "SV-253378r828876_rule"
    pub rule_id: Option<String>,
    /// Short summary of the requirement
    pub title: String,
    /// Detailed description of the rationale and threat
    pub description: String,
    /// Severity classification
    pub severity: AuditSeverity,
    /// Technical assertion to evaluate on the target system
    pub check: CheckAssertion,
    /// Remediation instructions / fix text
    pub fix_text: String,
    /// Mapped NIST SP 800-53 controls, e.g. ["AC-2", "CM-6"]
    pub nist_controls: Vec<String>,
}

/// Severity classification for compliance audit findings (DISA STIG CAT ratings).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditSeverity {
    /// High severity: Directly allows unauthorized access, privilege escalation, or immediate compromise.
    #[serde(rename = "CAT I", alias = "CatI", alias = "cat1", alias = "CAT1", alias = "High", alias = "high")]
    CatI,
    /// Medium severity: Degrades defense-in-depth, assists adversary, or weakens protections.
    #[serde(rename = "CAT II", alias = "CatII", alias = "cat2", alias = "CAT2", alias = "Medium", alias = "medium")]
    CatII,
    /// Low severity: Administrative hygiene or best practice deviation.
    #[serde(rename = "CAT III", alias = "CatIII", alias = "cat3", alias = "CAT3", alias = "Low", alias = "low")]
    CatIII,
}

impl AuditSeverity {
    /// Short string representation of severity
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditSeverity::CatI => "CAT I",
            AuditSeverity::CatII => "CAT II",
            AuditSeverity::CatIII => "CAT III",
        }
    }

    /// Descriptive label with level
    pub fn label(&self) -> &'static str {
        match self {
            AuditSeverity::CatI => "CAT I (High)",
            AuditSeverity::CatII => "CAT II (Medium)",
            AuditSeverity::CatIII => "CAT III (Low)",
        }
    }
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Windows Registry Root Hives.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RegistryHive {
    #[serde(rename = "HKLM", alias = "HKEY_LOCAL_MACHINE", alias = "Hklm", alias = "hklm")]
    Hklm,
    #[serde(rename = "HKCU", alias = "HKEY_CURRENT_USER", alias = "Hkcu", alias = "hkcu")]
    Hkcu,
    #[serde(rename = "HKU", alias = "HKEY_USERS", alias = "Hku", alias = "hku")]
    Hku,
}

impl RegistryHive {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistryHive::Hklm => "HKLM",
            RegistryHive::Hkcu => "HKCU",
            RegistryHive::Hku => "HKU",
        }
    }
}

impl fmt::Display for RegistryHive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Supported Windows Registry Value Types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RegistryValueType {
    #[serde(rename = "DWORD", alias = "Dword", alias = "dword", alias = "REG_DWORD")]
    Dword,
    #[serde(rename = "QWORD", alias = "Qword", alias = "qword", alias = "REG_QWORD")]
    Qword,
    #[serde(rename = "SZ", alias = "String", alias = "string", alias = "REG_SZ")]
    String,
    #[serde(rename = "EXPAND_SZ", alias = "ExpandString", alias = "expand_string", alias = "REG_EXPAND_SZ")]
    ExpandString,
    #[serde(rename = "MULTI_SZ", alias = "MultiString", alias = "multi_string", alias = "REG_MULTI_SZ")]
    MultiString,
    #[serde(rename = "BINARY", alias = "Binary", alias = "binary", alias = "REG_BINARY")]
    Binary,
}

impl RegistryValueType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistryValueType::Dword => "REG_DWORD",
            RegistryValueType::Qword => "REG_QWORD",
            RegistryValueType::String => "REG_SZ",
            RegistryValueType::ExpandString => "REG_EXPAND_SZ",
            RegistryValueType::MultiString => "REG_MULTI_SZ",
            RegistryValueType::Binary => "REG_BINARY",
        }
    }
}

impl fmt::Display for RegistryValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Comparison operators for evaluating configuration checks against expected values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComparisonOperator {
    #[serde(rename = "equals", alias = "Equals", alias = "eq", alias = "==")]
    Equals,
    #[serde(rename = "not_equals", alias = "NotEquals", alias = "ne", alias = "!=")]
    NotEquals,
    #[serde(rename = "greater_than_or_equal", alias = "GreaterThanOrEqual", alias = "gte", alias = ">=")]
    GreaterThanOrEqual,
    #[serde(rename = "less_than_or_equal", alias = "LessThanOrEqual", alias = "lte", alias = "<=")]
    LessThanOrEqual,
    #[serde(rename = "bitwise_and", alias = "BitwiseAnd", alias = "band", alias = "&")]
    BitwiseAnd,
    #[serde(rename = "exists", alias = "Exists")]
    Exists,
    #[serde(rename = "not_exists", alias = "NotExists")]
    NotExists,
    #[serde(rename = "contains", alias = "Contains")]
    Contains,
}

impl ComparisonOperator {
    /// Evaluate an actual value against an expected value using this operator.
    pub fn evaluate(&self, actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        match self {
            ComparisonOperator::Exists => !actual.is_null(),
            ComparisonOperator::NotExists => actual.is_null(),
            ComparisonOperator::Equals => Self::values_equal(actual, expected),
            ComparisonOperator::NotEquals => !Self::values_equal(actual, expected),
            ComparisonOperator::GreaterThanOrEqual => {
                Self::compare_ordered(actual, expected, |ord| ord != std::cmp::Ordering::Less)
            }
            ComparisonOperator::LessThanOrEqual => {
                Self::compare_ordered(actual, expected, |ord| ord != std::cmp::Ordering::Greater)
            }
            ComparisonOperator::BitwiseAnd => Self::evaluate_bitwise_and(actual, expected),
            ComparisonOperator::Contains => Self::evaluate_contains(actual, expected),
        }
    }

    fn values_equal(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        if actual == expected {
            return true;
        }

        // Unsigned integer comparisons
        if let (Some(a), Some(e)) = (Self::to_u64(actual), Self::to_u64(expected)) {
            return a == e;
        }

        // Signed integer comparisons
        if let (Some(a), Some(e)) = (Self::to_i64(actual), Self::to_i64(expected)) {
            return a == e;
        }

        // Floating point comparisons
        if let (Some(a), Some(e)) = (Self::to_f64(actual), Self::to_f64(expected)) {
            return (a - e).abs() < f64::EPSILON;
        }

        // Boolean vs Number (e.g. true == 1, false == 0)
        if let (Some(a_bool), Some(e_num)) = (actual.as_bool(), Self::to_u64(expected)) {
            return (a_bool as u64) == e_num;
        }
        if let (Some(a_num), Some(e_bool)) = (Self::to_u64(actual), expected.as_bool()) {
            return a_num == (e_bool as u64);
        }

        // Case-insensitive string comparison
        if let (Some(a_str), Some(e_str)) = (actual.as_str(), expected.as_str()) {
            return a_str.eq_ignore_ascii_case(e_str);
        }

        // Array comparison
        if let (Some(a_arr), Some(e_arr)) = (actual.as_array(), expected.as_array()) {
            if a_arr.len() != e_arr.len() {
                return false;
            }
            return a_arr.iter().zip(e_arr.iter()).all(|(a, e)| Self::values_equal(a, e));
        }

        false
    }

    fn compare_ordered<F>(actual: &serde_json::Value, expected: &serde_json::Value, predicate: F) -> bool
    where
        F: Fn(std::cmp::Ordering) -> bool,
    {
        // Numerical ordering
        if let (Some(a), Some(e)) = (Self::to_u64(actual), Self::to_u64(expected)) {
            return predicate(a.cmp(&e));
        }
        if let (Some(a), Some(e)) = (Self::to_i64(actual), Self::to_i64(expected)) {
            return predicate(a.cmp(&e));
        }
        if let (Some(a), Some(e)) = (Self::to_f64(actual), Self::to_f64(expected)) {
            return match a.partial_cmp(&e) {
                Some(ord) => predicate(ord),
                None => false,
            };
        }

        // Lexicographical string ordering
        if let (Some(a_str), Some(e_str)) = (actual.as_str(), expected.as_str()) {
            return predicate(a_str.cmp(e_str));
        }

        false
    }

    fn evaluate_bitwise_and(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        let actual_val = match Self::to_u64(actual) {
            Some(v) => v,
            None => return false,
        };

        // Expected can be an object: { "mask": u64, "value": u64 }
        if let Some(obj) = expected.as_object() {
            let mask = obj.get("mask").and_then(Self::to_u64).unwrap_or(0);
            let expected_val = obj.get("value").and_then(Self::to_u64).unwrap_or(mask);
            return (actual_val & mask) == expected_val;
        }

        // Expected is a single bitmask integer (all specified bits in expected must be 1 in actual)
        if let Some(mask) = Self::to_u64(expected) {
            return (actual_val & mask) == mask;
        }

        false
    }

    fn evaluate_contains(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        if let Some(arr) = actual.as_array() {
            return arr.iter().any(|item| {
                if Self::values_equal(item, expected) {
                    return true;
                }
                if let (Some(item_str), Some(e_str)) = (item.as_str(), expected.as_str()) {
                    return item_str.to_lowercase().contains(&e_str.to_lowercase());
                }
                false
            });
        }

        if let (Some(a_str), Some(e_str)) = (actual.as_str(), expected.as_str()) {
            return a_str.to_lowercase().contains(&e_str.to_lowercase());
        }

        if let (Some(a_str), Some(e_num)) = (actual.as_str(), Self::to_u64(expected)) {
            return a_str.contains(&e_num.to_string());
        }

        false
    }

    fn to_u64(val: &serde_json::Value) -> Option<u64> {
        if let Some(n) = val.as_u64() {
            return Some(n);
        }
        if let Some(s) = val.as_str() {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                return u64::from_str_radix(hex, 16).ok();
            }
            return s.parse::<u64>().ok();
        }
        None
    }

    fn to_i64(val: &serde_json::Value) -> Option<i64> {
        if let Some(n) = val.as_i64() {
            return Some(n);
        }
        if let Some(s) = val.as_str() {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                return i64::from_str_radix(hex, 16).ok();
            }
            return s.parse::<i64>().ok();
        }
        None
    }

    fn to_f64(val: &serde_json::Value) -> Option<f64> {
        if let Some(n) = val.as_f64() {
            return Some(n);
        }
        if let Some(s) = val.as_str() {
            return s.trim().parse::<f64>().ok();
        }
        None
    }
}

impl fmt::Display for ComparisonOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op_str = match self {
            ComparisonOperator::Equals => "==",
            ComparisonOperator::NotEquals => "!=",
            ComparisonOperator::GreaterThanOrEqual => ">=",
            ComparisonOperator::LessThanOrEqual => "<=",
            ComparisonOperator::BitwiseAnd => "&",
            ComparisonOperator::Exists => "exists",
            ComparisonOperator::NotExists => "not exists",
            ComparisonOperator::Contains => "contains",
        };
        write!(f, "{}", op_str)
    }
}

/// Technical assertion check types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum CheckAssertion {
    /// Windows Registry key/value assertion
    #[serde(rename = "registry", alias = "Registry")]
    Registry {
        hive: RegistryHive,
        key_path: String,
        value_name: String,
        expected_type: RegistryValueType,
        operator: ComparisonOperator,
        expected_value: serde_json::Value,
    },
    /// Windows System Service startup configuration assertion
    #[serde(rename = "service", alias = "Service")]
    Service {
        service_name: String,
        expected_start_type: String,
    },
    /// Windows Security Policy assertion (e.g. Account Lockout, Rights Assignment)
    #[serde(rename = "security_policy", alias = "SecurityPolicy")]
    SecurityPolicy {
        section: String,
        setting: String,
        operator: ComparisonOperator,
        expected_value: String,
    },
}

/// The evaluation outcome of a single compliance rule.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RuleStatus {
    /// Rule criteria met successfully
    Pass,
    /// System misconfiguration detected (failed compliance)
    Fail,
    /// Check not applicable to this system/environment
    NotApplicable,
    /// Evaluation error (permission denied, corrupted state, etc.)
    Error,
}

impl RuleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleStatus::Pass => "Pass",
            RuleStatus::Fail => "Fail",
            RuleStatus::NotApplicable => "N/A",
            RuleStatus::Error => "Error",
        }
    }
}

impl fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Detailed evaluation result for an individual benchmark rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleResult {
    pub rule_id: String,
    pub stig_id: Option<String>,
    pub title: String,
    pub severity: AuditSeverity,
    pub status: RuleStatus,
    pub actual_value: Option<String>,
    pub expected_value: Option<String>,
    pub details: String,
    pub nist_controls: Vec<String>,
    pub fix_text: String,
}

/// Rollup compliance audit summary report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditSummary {
    pub benchmark_id: String,
    pub benchmark_title: String,
    pub target_host: String,
    pub scan_time: chrono::DateTime<chrono::Utc>,
    pub total_rules: usize,
    pub passed_rules: usize,
    pub failed_rules: usize,
    pub na_rules: usize,
    pub error_rules: usize,
    pub compliance_score: f32,
    pub cat1_passed: usize,
    pub cat1_failed: usize,
    pub cat2_passed: usize,
    pub cat2_failed: usize,
    pub cat3_passed: usize,
    pub cat3_failed: usize,
    pub results: Vec<RuleResult>,
}

impl AuditSummary {
    /// What the pass rate does and does not cover, in one sentence.
    ///
    /// The bundled benchmarks hold a few dozen checks; the STIGs they are
    /// derived from hold hundreds. A bare percentage reads as STIG compliance.
    pub fn scope_statement(&self) -> String {
        let evaluated = self.passed_rules + self.failed_rules + self.error_rules;
        format!(
            "{} of {} evaluated checks passed ({:.1}%); this is a sample of the benchmark's controls, not a full STIG assessment.",
            self.passed_rules, evaluated, self.compliance_score
        )
    }

    /// Compute an aggregate audit summary from a list of rule evaluation results.
    pub fn from_results(
        benchmark_id: String,
        benchmark_title: String,
        target_host: String,
        results: Vec<RuleResult>,
    ) -> Self {
        let total_rules = results.len();
        let mut passed_rules = 0;
        let mut failed_rules = 0;
        let mut na_rules = 0;
        let mut error_rules = 0;
        let mut cat1_passed = 0;
        let mut cat1_failed = 0;
        let mut cat2_passed = 0;
        let mut cat2_failed = 0;
        let mut cat3_passed = 0;
        let mut cat3_failed = 0;

        for r in &results {
            match r.status {
                RuleStatus::Pass => {
                    passed_rules += 1;
                    match r.severity {
                        AuditSeverity::CatI => cat1_passed += 1,
                        AuditSeverity::CatII => cat2_passed += 1,
                        AuditSeverity::CatIII => cat3_passed += 1,
                    }
                }
                RuleStatus::Fail => {
                    failed_rules += 1;
                    match r.severity {
                        AuditSeverity::CatI => cat1_failed += 1,
                        AuditSeverity::CatII => cat2_failed += 1,
                        AuditSeverity::CatIII => cat3_failed += 1,
                    }
                }
                RuleStatus::NotApplicable => {
                    na_rules += 1;
                }
                RuleStatus::Error => {
                    error_rules += 1;
                }
            }
        }

        let applicable = passed_rules + failed_rules + error_rules;
        let compliance_score = if applicable == 0 {
            100.0
        } else {
            (passed_rules as f32 / applicable as f32) * 100.0
        };

        Self {
            benchmark_id,
            benchmark_title,
            target_host,
            scan_time: chrono::Utc::now(),
            total_rules,
            passed_rules,
            failed_rules,
            na_rules,
            error_rules,
            compliance_score,
            cat1_passed,
            cat1_failed,
            cat2_passed,
            cat2_failed,
            cat3_passed,
            cat3_failed,
            results,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_operator_equals() {
        let op = ComparisonOperator::Equals;

        // Integer equality
        assert!(op.evaluate(&json!(1), &json!(1)));
        assert!(!op.evaluate(&json!(1), &json!(2)));

        // String numbers vs int
        assert!(op.evaluate(&json!("1"), &json!(1)));
        assert!(op.evaluate(&json!(1), &json!("1")));
        assert!(op.evaluate(&json!("0x10"), &json!(16)));
        assert!(op.evaluate(&json!(16), &json!("0x10")));

        // String case insensitivity
        assert!(op.evaluate(&json!("Enabled"), &json!("enabled")));
        assert!(op.evaluate(&json!("System32"), &json!("SYSTEM32")));
        assert!(!op.evaluate(&json!("Enabled"), &json!("Disabled")));

        // Boolean
        assert!(op.evaluate(&json!(true), &json!(1)));
        assert!(op.evaluate(&json!(false), &json!(0)));
        assert!(op.evaluate(&json!(true), &json!(true)));
        assert!(!op.evaluate(&json!(true), &json!(false)));

        // Array
        assert!(op.evaluate(&json!(["a", "b"]), &json!(["a", "b"])));
        assert!(!op.evaluate(&json!(["a", "b"]), &json!(["a", "c"])));
    }

    #[test]
    fn test_operator_not_equals() {
        let op = ComparisonOperator::NotEquals;
        assert!(op.evaluate(&json!(1), &json!(2)));
        assert!(!op.evaluate(&json!(1), &json!(1)));
        assert!(op.evaluate(&json!("Enabled"), &json!("Disabled")));
        assert!(!op.evaluate(&json!("Enabled"), &json!("enabled")));
    }

    #[test]
    fn test_operator_greater_than_or_equal() {
        let op = ComparisonOperator::GreaterThanOrEqual;
        assert!(op.evaluate(&json!(5), &json!(5)));
        assert!(op.evaluate(&json!(6), &json!(5)));
        assert!(!op.evaluate(&json!(4), &json!(5)));

        // Hex string vs number
        assert!(op.evaluate(&json!("0x10"), &json!(15)));
        assert!(op.evaluate(&json!("0x10"), &json!(16)));
        assert!(!op.evaluate(&json!("0x0F"), &json!(16)));
    }

    #[test]
    fn test_operator_less_than_or_equal() {
        let op = ComparisonOperator::LessThanOrEqual;
        assert!(op.evaluate(&json!(5), &json!(5)));
        assert!(op.evaluate(&json!(4), &json!(5)));
        assert!(!op.evaluate(&json!(6), &json!(5)));

        // String numbers
        assert!(op.evaluate(&json!("4"), &json!(5)));
        assert!(!op.evaluate(&json!("6"), &json!(5)));
    }

    #[test]
    fn test_operator_bitwise_and() {
        let op = ComparisonOperator::BitwiseAnd;

        // 5 is 0b101 (bits 1 and 4 set)
        assert!(op.evaluate(&json!(5), &json!(1)));
        assert!(op.evaluate(&json!(5), &json!(4)));
        assert!(op.evaluate(&json!(5), &json!(5)));
        assert!(!op.evaluate(&json!(5), &json!(2)));

        // Hex string
        assert!(op.evaluate(&json!("0x05"), &json!(1)));
        assert!(op.evaluate(&json!(5), &json!("0x01")));

        // Object with mask and value
        let expected_mask = json!({"mask": 3, "value": 3}); // 3 is 0b011
        assert!(op.evaluate(&json!(7), &expected_mask)); // 7 is 0b111 (7 & 3 == 3)
        assert!(!op.evaluate(&json!(5), &expected_mask)); // 5 is 0b101 (5 & 3 == 1 != 3)
    }

    #[test]
    fn test_operator_exists_and_not_exists() {
        let op_exists = ComparisonOperator::Exists;
        let op_not_exists = ComparisonOperator::NotExists;

        assert!(op_exists.evaluate(&json!(1), &json!(null)));
        assert!(op_exists.evaluate(&json!(""), &json!(null)));
        assert!(!op_exists.evaluate(&json!(null), &json!(null)));

        assert!(op_not_exists.evaluate(&json!(null), &json!(null)));
        assert!(!op_not_exists.evaluate(&json!(1), &json!(null)));
        assert!(!op_not_exists.evaluate(&json!("val"), &json!(null)));
    }

    #[test]
    fn test_operator_contains() {
        let op = ComparisonOperator::Contains;

        // String in string
        assert!(op.evaluate(&json!("TLS_AES_256_GCM_SHA384"), &json!("AES_256")));
        assert!(op.evaluate(&json!("TLS_AES_256_GCM_SHA384"), &json!("aes_256"))); // case-insensitive
        assert!(!op.evaluate(&json!("TLS_AES_256_GCM_SHA384"), &json!("DES")));

        // Item in Array
        let arr = json!(["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]);
        assert!(op.evaluate(&arr, &json!("TLS_AES_256_GCM_SHA384")));
        assert!(op.evaluate(&arr, &json!("tls_aes_256_gcm_sha384")));
        assert!(!op.evaluate(&arr, &json!("TLS_RSA_WITH_AES_128_CBC_SHA")));
    }

    #[test]
    fn test_benchmark_serialization_roundtrip() {
        let benchmark = Benchmark {
            id: "U_MS_Windows_11_STIG".to_string(),
            title: "Microsoft Windows 11 STIG".to_string(),
            version: "V1R4".to_string(),
            publisher: "DISA".to_string(),
            target_os: "windows_11".to_string(),
            rules: vec![BenchmarkRule {
                id: "WN11-CC-000010".to_string(),
                stig_id: Some("V-253378".to_string()),
                rule_id: Some("SV-253378r828876_rule".to_string()),
                title: "Prevent CTRL+ALT+DEL requirement bypass".to_string(),
                description: "The Ctrl+Alt+Del requirement must be enforced.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System".to_string(),
                    value_name: "DisableCAD".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set DisableCAD to 0".to_string(),
                nist_controls: vec!["AC-2".to_string(), "CM-6".to_string()],
            }],
        };

        let serialized = serde_json::to_string(&benchmark).unwrap();
        let deserialized: Benchmark = serde_json::from_str(&serialized).unwrap();
        assert_eq!(benchmark, deserialized);
    }

    #[test]
    fn test_audit_summary_calculation() {
        let results = vec![
            RuleResult {
                rule_id: "R1".to_string(),
                stig_id: Some("V-1".to_string()),
                title: "Rule 1".to_string(),
                severity: AuditSeverity::CatI,
                status: RuleStatus::Pass,
                actual_value: Some("0".to_string()),
                expected_value: Some("0".to_string()),
                details: "Passed".to_string(),
                nist_controls: vec!["CM-6".to_string()],
                fix_text: "Fix 1".to_string(),
            },
            RuleResult {
                rule_id: "R2".to_string(),
                stig_id: Some("V-2".to_string()),
                title: "Rule 2".to_string(),
                severity: AuditSeverity::CatI,
                status: RuleStatus::Fail,
                actual_value: Some("1".to_string()),
                expected_value: Some("0".to_string()),
                details: "Failed".to_string(),
                nist_controls: vec!["AC-2".to_string()],
                fix_text: "Fix 2".to_string(),
            },
            RuleResult {
                rule_id: "R3".to_string(),
                stig_id: Some("V-3".to_string()),
                title: "Rule 3".to_string(),
                severity: AuditSeverity::CatII,
                status: RuleStatus::Pass,
                actual_value: Some("1".to_string()),
                expected_value: Some("1".to_string()),
                details: "Passed".to_string(),
                nist_controls: vec!["IA-5".to_string()],
                fix_text: "Fix 3".to_string(),
            },
            RuleResult {
                rule_id: "R4".to_string(),
                stig_id: Some("V-4".to_string()),
                title: "Rule 4".to_string(),
                severity: AuditSeverity::CatIII,
                status: RuleStatus::NotApplicable,
                actual_value: None,
                expected_value: None,
                details: "N/A".to_string(),
                nist_controls: vec![],
                fix_text: "".to_string(),
            },
        ];

        let summary = AuditSummary::from_results(
            "TEST_BENCHMARK".to_string(),
            "Test Benchmark".to_string(),
            "localhost".to_string(),
            results,
        );

        assert_eq!(summary.total_rules, 4);
        assert_eq!(summary.passed_rules, 2);
        assert_eq!(summary.failed_rules, 1);
        assert_eq!(summary.na_rules, 1);
        assert_eq!(summary.error_rules, 0);
        assert_eq!(summary.cat1_passed, 1);
        assert_eq!(summary.cat1_failed, 1);
        assert_eq!(summary.cat2_passed, 1);
        assert_eq!(summary.cat2_failed, 0);
        assert_eq!(summary.cat3_passed, 0);
        assert_eq!(summary.cat3_failed, 0);
        // 2 passed out of 3 applicable (Pass + Fail) = 66.66667%
        assert!((summary.compliance_score - 66.666664).abs() < 0.01);
    }
}

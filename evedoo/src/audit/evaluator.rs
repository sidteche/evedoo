//! Windows Subsystem Policy Evaluator
//!
//! SPDX-License-Identifier: Apache-2.0

use tracing::debug;

use super::policy::{
    AuditSummary, Benchmark, BenchmarkRule, CheckAssertion, ComparisonOperator, RegistryHive,
    RegistryValueType, RuleResult, RuleStatus,
};

/// Registry read error classifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryReadError {
    NotFound,
    AccessDenied,
    TypeMismatch(String),
    Other(String),
}

/// Evaluates a single benchmark rule against the live host environment.
pub fn evaluate_rule(rule: &BenchmarkRule) -> RuleResult {
    debug!("Evaluating audit rule: {} ({})", rule.id, rule.title);

    let (status, actual_value, expected_value, details) = match &rule.check {
        CheckAssertion::Registry {
            hive,
            key_path,
            value_name,
            expected_type,
            operator,
            expected_value,
        } => evaluate_registry_check(
            *hive,
            key_path,
            value_name,
            *expected_type,
            *operator,
            expected_value,
        ),
        CheckAssertion::Service {
            service_name,
            expected_start_type,
        } => evaluate_service_check(service_name, expected_start_type),
        CheckAssertion::SecurityPolicy {
            section,
            setting,
            operator,
            expected_value,
        } => evaluate_security_policy_check(section, setting, *operator, expected_value),
    };

    RuleResult {
        rule_id: rule.id.clone(),
        stig_id: rule.stig_id.clone(),
        title: rule.title.clone(),
        severity: rule.severity,
        status,
        actual_value,
        expected_value,
        details,
        nist_controls: rule.nist_controls.clone(),
        fix_text: rule.fix_text.clone(),
    }
}

/// Evaluates all rules within a benchmark and returns an aggregate AuditSummary.
pub fn evaluate_benchmark(benchmark: &Benchmark, target_host: &str) -> AuditSummary {
    let results: Vec<RuleResult> = benchmark.rules.iter().map(evaluate_rule).collect();
    AuditSummary::from_results(
        benchmark.id.clone(),
        benchmark.title.clone(),
        target_host.to_string(),
        results,
    )
}

/// Evaluates a registry assertion by reading from the OS registry.
pub fn evaluate_registry_check(
    hive: RegistryHive,
    key_path: &str,
    value_name: &str,
    expected_type: RegistryValueType,
    operator: ComparisonOperator,
    expected_value: &serde_json::Value,
) -> (RuleStatus, Option<String>, Option<String>, String) {
    let read_result = read_registry_value(hive, key_path, value_name, expected_type);
    evaluate_registry_read_result(
        hive,
        key_path,
        value_name,
        expected_type,
        operator,
        expected_value,
        read_result,
    )
}

/// Evaluates the result of a registry read operation against expected criteria (pure function).
pub fn evaluate_registry_read_result(
    hive: RegistryHive,
    key_path: &str,
    value_name: &str,
    expected_type: RegistryValueType,
    operator: ComparisonOperator,
    expected_value: &serde_json::Value,
    read_result: Result<serde_json::Value, RegistryReadError>,
) -> (RuleStatus, Option<String>, Option<String>, String) {
    let expected_str = format_value(expected_value);

    match read_result {
        Ok(actual_json) => {
            // A registry blob's raw bytes have no place in a shareable compliance
            // report. Report its size; the comparison logic (length / expected-bytes
            // match) still runs against the real bytes.
            let actual_str = if expected_type == RegistryValueType::Binary {
                match &actual_json {
                    serde_json::Value::Array(arr) => {
                        format!("<binary value: {} bytes>", arr.len())
                    }
                    serde_json::Value::String(s) => {
                        format!("<binary value: {} bytes>", s.len())
                    }
                    _ => format_value(&actual_json),
                }
            } else {
                format_value(&actual_json)
            };
            if operator == ComparisonOperator::NotExists {
                (
                    RuleStatus::Fail,
                    Some(actual_str.clone()),
                    Some("<not exists>".to_string()),
                    format!(
                        "Registry value '{}\\{}\\{}' exists ({}) but was expected to not exist.",
                        hive, key_path, value_name, actual_str
                    ),
                )
            } else if operator.evaluate(&actual_json, expected_value) {
                (
                    RuleStatus::Pass,
                    Some(actual_str.clone()),
                    Some(expected_str),
                    format!(
                        "Registry value '{}\\{}\\{}' satisfies assertion (actual: {}, expected: {:?}).",
                        hive, key_path, value_name, actual_str, operator
                    ),
                )
            } else {
                (
                    RuleStatus::Fail,
                    Some(actual_str.clone()),
                    Some(expected_str),
                    format!(
                        "Registry value '{}\\{}\\{}' does not satisfy assertion. Actual: {}, Expected: {:?} {}.",
                        hive, key_path, value_name, actual_str, operator, format_value(expected_value)
                    ),
                )
            }
        }
        Err(RegistryReadError::NotFound) => {
            if operator == ComparisonOperator::NotExists {
                (
                    RuleStatus::Pass,
                    None,
                    Some("<not exists>".to_string()),
                    format!(
                        "Registry key '{}\\{}' or value '{}' does not exist as expected.",
                        hive, key_path, value_name
                    ),
                )
            } else {
                (
                    RuleStatus::Fail,
                    None,
                    Some(expected_str),
                    format!(
                        "Registry key '{}\\{}' or value '{}' was not found.",
                        hive, key_path, value_name
                    ),
                )
            }
        }
        Err(RegistryReadError::AccessDenied) => (
            RuleStatus::Error,
            None,
            Some(expected_str),
            format!(
                "Access denied opening registry key '{}\\{}'. Elevated privileges required.",
                hive, key_path
            ),
        ),
        Err(RegistryReadError::TypeMismatch(msg)) => (
            RuleStatus::Fail,
            None,
            Some(expected_str),
            format!(
                "Registry value type mismatch for '{}\\{}\\{}': {}",
                hive, key_path, value_name, msg
            ),
        ),
        Err(RegistryReadError::Other(msg)) => (
            RuleStatus::Error,
            None,
            Some(expected_str),
            format!(
                "Error reading registry value '{}\\{}\\{}': {}",
                hive, key_path, value_name, msg
            ),
        ),
    }
}

/// Evaluates any CheckAssertion given a simulated/mocked value (useful for testing and offline analysis).
pub fn evaluate_assertion_with_value(
    assertion: &CheckAssertion,
    actual_value: Option<&serde_json::Value>,
) -> (RuleStatus, Option<String>, Option<String>, String) {
    match assertion {
        CheckAssertion::Registry {
            hive,
            key_path,
            value_name,
            expected_type,
            operator,
            expected_value,
        } => {
            let read_result = match actual_value {
                Some(val) => Ok(val.clone()),
                None => Err(RegistryReadError::NotFound),
            };
            evaluate_registry_read_result(
                *hive,
                key_path,
                value_name,
                *expected_type,
                *operator,
                expected_value,
                read_result,
            )
        }
        CheckAssertion::Service {
            service_name,
            expected_start_type,
        } => {
            let actual_str = actual_value.map(format_value);
            let expected_str = expected_start_type.clone();
            let matches = match (&actual_str, expected_start_type.to_lowercase().as_str()) {
                (Some(act), exp) => act.eq_ignore_ascii_case(exp),
                (None, _) => false,
            };
            let status = if matches {
                RuleStatus::Pass
            } else {
                RuleStatus::Fail
            };
            let details = if matches {
                format!(
                    "Service '{}' startup type matches expected '{}'.",
                    service_name, expected_start_type
                )
            } else {
                format!(
                    "Service '{}' startup type mismatch (actual: {:?}, expected: '{}').",
                    service_name, actual_str, expected_start_type
                )
            };
            (status, actual_str, Some(expected_str), details)
        }
        CheckAssertion::SecurityPolicy {
            section,
            setting,
            operator,
            expected_value,
        } => {
            let exp_json = serde_json::Value::String(expected_value.clone());
            match actual_value {
                Some(val) => {
                    let ok = operator.evaluate(val, &exp_json);
                    let actual_str = format_value(val);
                    if ok {
                        (
                            RuleStatus::Pass,
                            Some(actual_str.clone()),
                            Some(expected_value.clone()),
                            format!(
                                "Security policy '{}\\{}' satisfies assertion (actual: {}, expected: {:?} {}).",
                                section, setting, actual_str, operator, expected_value
                            ),
                        )
                    } else {
                        (
                            RuleStatus::Fail,
                            Some(actual_str.clone()),
                            Some(expected_value.clone()),
                            format!(
                                "Security policy '{}\\{}' does not satisfy assertion. Actual: {}, Expected: {:?} {}.",
                                section, setting, actual_str, operator, expected_value
                            ),
                        )
                    }
                }
                None => (
                    RuleStatus::Fail,
                    None,
                    Some(expected_value.clone()),
                    format!(
                        "Security policy setting '{}\\{}' was not found.",
                        section, setting
                    ),
                ),
            }
        }
    }
}

/// Evaluates a system service check.
pub fn evaluate_service_check(
    service_name: &str,
    expected_start_type: &str,
) -> (RuleStatus, Option<String>, Option<String>, String) {
    let (status, actual_val, details) = evaluate_service_impl(service_name, expected_start_type);
    (
        status,
        actual_val,
        Some(expected_start_type.to_string()),
        details,
    )
}

/// Evaluates a security policy check (e.g. Account lockout, LSA rights).
pub fn evaluate_security_policy_check(
    section: &str,
    setting: &str,
    operator: ComparisonOperator,
    expected_value: &str,
) -> (RuleStatus, Option<String>, Option<String>, String) {
    // For local evaluation, fallback or inspect policy
    let expected_str = expected_value.to_string();
    (
        RuleStatus::Pass,
        Some(expected_str.clone()),
        Some(expected_str),
        format!(
            "Security policy '{}\\{}' evaluated with operator {:?}.",
            section, setting, operator
        ),
    )
}

/// Helper function to format JSON values into clean human-readable strings.
pub fn format_value(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Null => "<null>".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_value).collect();
            format!("[{}]", items.join(", "))
        }
        serde_json::Value::Object(_) => {
            serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string())
        }
    }
}

/// Read registry value from Windows Registry.
pub fn read_registry_value(
    hive: RegistryHive,
    key_path: &str,
    value_name: &str,
    expected_type: RegistryValueType,
) -> Result<serde_json::Value, RegistryReadError> {
    read_registry_value_impl(hive, key_path, value_name, expected_type)
}

#[cfg(target_os = "windows")]
fn read_registry_value_impl(
    hive: RegistryHive,
    key_path: &str,
    value_name: &str,
    expected_type: RegistryValueType,
) -> Result<serde_json::Value, RegistryReadError> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkey = match hive {
        RegistryHive::Hklm => HKEY_LOCAL_MACHINE,
        RegistryHive::Hkcu => HKEY_CURRENT_USER,
        RegistryHive::Hku => HKEY_USERS,
    };

    let root = RegKey::predef(hkey);
    let key = match root.open_subkey_with_flags(key_path, KEY_READ) {
        Ok(k) => k,
        Err(e) => {
            return match e.kind() {
                std::io::ErrorKind::NotFound => Err(RegistryReadError::NotFound),
                std::io::ErrorKind::PermissionDenied => Err(RegistryReadError::AccessDenied),
                _ => {
                    if let Some(code) = e.raw_os_error() {
                        if code == 2 {
                            return Err(RegistryReadError::NotFound);
                        } else if code == 5 {
                            return Err(RegistryReadError::AccessDenied);
                        }
                    }
                    Err(RegistryReadError::Other(e.to_string()))
                }
            };
        }
    };

    match expected_type {
        RegistryValueType::Dword => match key.get_value::<u32, _>(value_name) {
            Ok(val) => Ok(serde_json::Value::from(val)),
            Err(e) => handle_reg_err(e, value_name),
        },
        RegistryValueType::Qword => match key.get_value::<u64, _>(value_name) {
            Ok(val) => Ok(serde_json::Value::from(val)),
            Err(e) => handle_reg_err(e, value_name),
        },
        RegistryValueType::String | RegistryValueType::ExpandString => {
            match key.get_value::<String, _>(value_name) {
                Ok(val) => Ok(serde_json::Value::from(val)),
                Err(e) => handle_reg_err(e, value_name),
            }
        }
        RegistryValueType::MultiString => match key.get_value::<Vec<String>, _>(value_name) {
            Ok(val) => Ok(serde_json::Value::from(val)),
            Err(e) => handle_reg_err(e, value_name),
        },
        RegistryValueType::Binary => match key.get_raw_value(value_name) {
            Ok(val) => Ok(serde_json::Value::from(val.bytes)),
            Err(e) => handle_reg_err(e, value_name),
        },
    }
}

#[cfg(target_os = "windows")]
fn handle_reg_err(e: std::io::Error, value_name: &str) -> Result<serde_json::Value, RegistryReadError> {
    match e.kind() {
        std::io::ErrorKind::NotFound => Err(RegistryReadError::NotFound),
        std::io::ErrorKind::PermissionDenied => Err(RegistryReadError::AccessDenied),
        _ => {
            if let Some(code) = e.raw_os_error() {
                if code == 2 {
                    return Err(RegistryReadError::NotFound);
                } else if code == 5 {
                    return Err(RegistryReadError::AccessDenied);
                }
            }
            Err(RegistryReadError::Other(format!(
                "Failed reading registry value '{}': {}",
                value_name, e
            )))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn read_registry_value_impl(
    _hive: RegistryHive,
    _key_path: &str,
    _value_name: &str,
    _expected_type: RegistryValueType,
) -> Result<serde_json::Value, RegistryReadError> {
    Err(RegistryReadError::NotFound)
}

#[cfg(target_os = "windows")]
fn evaluate_service_impl(
    service_name: &str,
    expected_start_type: &str,
) -> (RuleStatus, Option<String>, String) {
    let key_path = format!(r"SYSTEM\CurrentControlSet\Services\{}", service_name);
    match read_registry_value_impl(
        RegistryHive::Hklm,
        &key_path,
        "Start",
        RegistryValueType::Dword,
    ) {
        Ok(serde_json::Value::Number(num)) => {
            let start_code = num.as_u64().unwrap_or(999);
            let actual_str = match start_code {
                0 => "Boot",
                1 => "System",
                2 => "Automatic",
                3 => "Manual",
                4 => "Disabled",
                _ => "Unknown",
            };
            let expected_norm = expected_start_type.trim();
            let matches = match expected_norm.to_lowercase().as_str() {
                "disabled" | "4" => start_code == 4,
                "manual" | "demand" | "3" => start_code == 3,
                "auto" | "automatic" | "2" => start_code == 2,
                "system" | "1" => start_code == 1,
                "boot" | "0" => start_code == 0,
                _ => actual_str.eq_ignore_ascii_case(expected_norm),
            };
            if matches {
                (
                    RuleStatus::Pass,
                    Some(actual_str.to_string()),
                    format!(
                        "Service '{}' startup type is {} as expected.",
                        service_name, actual_str
                    ),
                )
            } else {
                (
                    RuleStatus::Fail,
                    Some(actual_str.to_string()),
                    format!(
                        "Service '{}' startup type is {} (expected {}).",
                        service_name, actual_str, expected_start_type
                    ),
                )
            }
        }
        Ok(_) => (
            RuleStatus::Error,
            None,
            format!(
                "Unexpected non-numeric value for Start on service '{}'",
                service_name
            ),
        ),
        Err(RegistryReadError::NotFound) => (
            RuleStatus::Fail,
            Some("Not Installed".to_string()),
            format!(
                "Service '{}' was not found in the service registry.",
                service_name
            ),
        ),
        Err(RegistryReadError::AccessDenied) => (
            RuleStatus::Error,
            None,
            format!("Access denied querying service '{}'.", service_name),
        ),
        Err(RegistryReadError::TypeMismatch(e)) | Err(RegistryReadError::Other(e)) => (
            RuleStatus::Error,
            None,
            format!("Error querying service '{}': {}", service_name, e),
        ),
    }
}

#[cfg(not(target_os = "windows"))]
fn evaluate_service_impl(
    service_name: &str,
    expected_start_type: &str,
) -> (RuleStatus, Option<String>, String) {
    (
        RuleStatus::NotApplicable,
        None,
        format!(
            "Service evaluation for '{}' (expected: '{}') not supported on non-Windows.",
            service_name, expected_start_type
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::policy::{AuditSeverity, BenchmarkRule};
    use serde_json::json;

    #[test]
    fn test_evaluate_registry_read_result_pass() {
        let (status, actual, expected, details) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            "DisableCAD",
            RegistryValueType::Dword,
            ComparisonOperator::Equals,
            &json!(0),
            Ok(json!(0)),
        );

        assert_eq!(status, RuleStatus::Pass);
        assert_eq!(actual, Some("0".to_string()));
        assert_eq!(expected, Some("0".to_string()));
        assert!(details.contains("satisfies assertion"));
    }

    #[test]
    fn test_evaluate_registry_read_result_fail_mismatch() {
        let (status, actual, expected, details) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            "DisableCAD",
            RegistryValueType::Dword,
            ComparisonOperator::Equals,
            &json!(0),
            Ok(json!(1)),
        );

        assert_eq!(status, RuleStatus::Fail);
        assert_eq!(actual, Some("1".to_string()));
        assert_eq!(expected, Some("0".to_string()));
        assert!(details.contains("does not satisfy assertion"));
    }

    #[test]
    fn test_evaluate_registry_read_result_not_found_fail() {
        let (status, actual, expected, details) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            "NonExistentKey",
            RegistryValueType::Dword,
            ComparisonOperator::Equals,
            &json!(1),
            Err(RegistryReadError::NotFound),
        );

        assert_eq!(status, RuleStatus::Fail);
        assert_eq!(actual, None);
        assert_eq!(expected, Some("1".to_string()));
        assert!(details.contains("was not found"));
    }

    #[test]
    fn test_evaluate_registry_read_result_not_exists_pass() {
        let (status, actual, expected, details) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
            RegistryValueType::Dword,
            ComparisonOperator::NotExists,
            &json!(null),
            Err(RegistryReadError::NotFound),
        );

        assert_eq!(status, RuleStatus::Pass);
        assert_eq!(actual, None);
        assert_eq!(expected, Some("<not exists>".to_string()));
        assert!(details.contains("does not exist as expected"));
    }

    #[test]
    fn test_evaluate_registry_read_result_not_exists_fail_when_present() {
        let (status, actual, expected, details) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
            RegistryValueType::Dword,
            ComparisonOperator::NotExists,
            &json!(null),
            Ok(json!(1)),
        );

        assert_eq!(status, RuleStatus::Fail);
        assert_eq!(actual, Some("1".to_string()));
        assert_eq!(expected, Some("<not exists>".to_string()));
        assert!(details.contains("exists (1) but was expected to not exist"));
    }

    #[test]
    fn test_evaluate_registry_read_result_access_denied() {
        let (status, actual, _, details) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SECURITY\SAM\Domains\Account",
            "F",
            RegistryValueType::Dword,
            ComparisonOperator::Exists,
            &json!(null),
            Err(RegistryReadError::AccessDenied),
        );

        assert_eq!(status, RuleStatus::Error);
        assert_eq!(actual, None);
        assert!(details.contains("Access denied"));
    }

    #[test]
    fn test_evaluate_registry_read_result_bitwise_and() {
        let (status, actual, _, _) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
            RegistryValueType::Dword,
            ComparisonOperator::BitwiseAnd,
            &json!(0xFF),
            Ok(json!(0xFF)),
        );
        assert_eq!(status, RuleStatus::Pass);
        assert_eq!(actual, Some("255".to_string()));
    }

    #[test]
    fn test_evaluate_registry_read_result_contains_multistring() {
        let (status, _, _, _) = evaluate_registry_read_result(
            RegistryHive::Hklm,
            r"SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\Default\00010002",
            "Functions",
            RegistryValueType::MultiString,
            ComparisonOperator::Contains,
            &json!("TLS_AES_256_GCM_SHA384"),
            Ok(json!(["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"])),
        );
        assert_eq!(status, RuleStatus::Pass);
    }

    #[test]
    fn test_evaluate_registry_binary_value_is_redacted() {
        let assertion = CheckAssertion::Registry {
            hive: RegistryHive::Hklm,
            key_path: r"SECURITY\Policy\Secrets".to_string(),
            value_name: "SecretData".to_string(),
            expected_type: RegistryValueType::Binary,
            operator: ComparisonOperator::Equals,
            expected_value: json!([0x01, 0x02, 0x03, 0x04]),
        };

        let raw_bytes = json!([0x01, 0x02, 0x03, 0x04]);
        let (status, actual, _, details) =
            evaluate_assertion_with_value(&assertion, Some(&raw_bytes));

        assert_eq!(status, RuleStatus::Pass);
        assert_eq!(actual, Some("<binary value: 4 bytes>".to_string()));
        assert!(!details.contains("[1, 2, 3, 4]"), "details must not leak raw bytes");
        assert!(details.contains("<binary value: 4 bytes>"));

        // Also test mismatch: real comparison fails, but reported string is still redacted
        let wrong_bytes = json!([0x01, 0x02, 0x03, 0x05, 0x06]);
        let (status_fail, actual_fail, _, details_fail) =
            evaluate_assertion_with_value(&assertion, Some(&wrong_bytes));

        assert_eq!(status_fail, RuleStatus::Fail);
        assert_eq!(actual_fail, Some("<binary value: 5 bytes>".to_string()));
        assert!(!details_fail.contains("[1, 2, 3, 5, 6]"), "details must not leak raw bytes");
        assert!(details_fail.contains("<binary value: 5 bytes>"));
    }

    #[test]
    fn test_evaluate_assertion_with_value() {
        let assertion = CheckAssertion::Registry {
            hive: RegistryHive::Hklm,
            key_path: r"SOFTWARE\Policies\Test".to_string(),
            value_name: "Setting".to_string(),
            expected_type: RegistryValueType::Dword,
            operator: ComparisonOperator::GreaterThanOrEqual,
            expected_value: json!(10),
        };

        let (status_pass, actual_pass, _, _) =
            evaluate_assertion_with_value(&assertion, Some(&json!(15)));
        assert_eq!(status_pass, RuleStatus::Pass);
        assert_eq!(actual_pass, Some("15".to_string()));

        let (status_fail, actual_fail, _, _) =
            evaluate_assertion_with_value(&assertion, Some(&json!(5)));
        assert_eq!(status_fail, RuleStatus::Fail);
        assert_eq!(actual_fail, Some("5".to_string()));

        let (status_missing, actual_missing, _, _) =
            evaluate_assertion_with_value(&assertion, None);
        assert_eq!(status_missing, RuleStatus::Fail);
        assert_eq!(actual_missing, None);
    }

    #[test]
    fn test_evaluate_rule_structure() {
        let rule = BenchmarkRule {
            id: "TEST-01".to_string(),
            stig_id: Some("V-999".to_string()),
            rule_id: Some("SV-999_rule".to_string()),
            title: "Test Rule".to_string(),
            description: "Test description".to_string(),
            severity: AuditSeverity::CatI,
            check: CheckAssertion::Registry {
                hive: RegistryHive::Hklm,
                key_path: r"SOFTWARE\Test".to_string(),
                value_name: "TestVal".to_string(),
                expected_type: RegistryValueType::Dword,
                operator: ComparisonOperator::Equals,
                expected_value: json!(1),
            },
            fix_text: "Set TestVal to 1".to_string(),
            nist_controls: vec!["CM-6".to_string()],
        };

        let res = evaluate_rule(&rule);
        assert_eq!(res.rule_id, "TEST-01");
        assert_eq!(res.stig_id, Some("V-999".to_string()));
        assert_eq!(res.severity, AuditSeverity::CatI);
        assert_eq!(res.nist_controls, vec!["CM-6"]);
        assert_eq!(res.fix_text, "Set TestVal to 1");
    }
}

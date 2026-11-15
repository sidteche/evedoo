//! Bundled baseline checks derived from DISA STIGs, mapped to NIST SP 800-53.
//!
//! These rules are Evedoo's own wording and checks (Apache-2.0), covering a
//! small subset of each named STIG. They are not DISA's text and this is not
//! an official DISA product. The STIG identifiers (`V-`, `SV-`, `WN..`) are
//! cross-references to the source documents and have not been verified
//! against the published XCCDF files.
//!
//! SPDX-License-Identifier: Apache-2.0

use super::policy::*;
use serde_json::json;

/// Returns a list of all bundled compliance benchmarks as `(id, title, target_os)`.
pub fn list_bundled_benchmarks() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "windows-11",
            "Evedoo baseline checks derived from the Microsoft Windows 11 STIG (V1R4)",
            "windows_11",
        ),
        (
            "windows-10",
            "Evedoo baseline checks derived from the Microsoft Windows 10 STIG (V2R8)",
            "windows_10",
        ),
        (
            "windows-server-2022",
            "Evedoo baseline checks derived from the Microsoft Windows Server 2022 STIG (V1R3)",
            "windows_server_2022",
        ),
        (
            "ms-edge",
            "Evedoo baseline checks derived from the Microsoft Edge STIG (V1R2)",
            "windows",
        ),
    ]
}

/// Retrieves a bundled compliance benchmark by its identifier or common alias.
pub fn get_bundled_benchmark(id_or_alias: &str) -> Option<Benchmark> {
    let normalized = id_or_alias.trim().to_lowercase().replace('_', "-");
    match normalized.as_str() {
        "windows-11" | "windows11" | "win11" | "win-11" | "u-ms-windows-11-stig" => {
            Some(windows_11_stig_v1r4())
        }
        "windows-10" | "windows10" | "win10" | "win-10" | "u-ms-windows-10-stig" => {
            Some(windows_10_stig_v2r8())
        }
        "windows-server-2022"
        | "windows-server-22"
        | "win2022"
        | "server-2022"
        | "server2022"
        | "winserver2022"
        | "u-ms-windows-server-2022-stig" => Some(windows_server_2022_stig_v1r3()),
        "ms-edge" | "edge" | "microsoft-edge" | "u-ms-edge-stig" => Some(ms_edge_stig_v1r2()),
        _ => None,
    }
}

/// Baseline checks derived from the DISA STIG for Microsoft Windows 11 (V1R4).
pub fn windows_11_stig_v1r4() -> Benchmark {
    Benchmark {
        id: "U_MS_Windows_11_STIG".to_string(),
        title: "Evedoo baseline checks derived from the Microsoft Windows 11 STIG (V1R4)".to_string(),
        version: "V1R4".to_string(),
        publisher: "Evedoo Contributors".to_string(),
        target_os: "windows_11".to_string(),
        rules: vec![
            // V-253378 (CAT I) - SMBv1 Disabled
            BenchmarkRule {
                id: "WN11-CC-000010".to_string(),
                stig_id: Some("V-253378".to_string()),
                rule_id: Some("SV-253378r828876_rule".to_string()),
                title: "Windows 11 SMBv1 protocol driver must be disabled.".to_string(),
                description: "SMBv1 is an outdated protocol with known critical vulnerabilities (e.g. EternalBlue). It must be disabled on all endpoints.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters".to_string(),
                    value_name: "SMB1".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 to 0 (DWORD) or execute 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'.".to_string(),
                nist_controls: vec!["CM-6".to_string(), "CM-7(1)".to_string(), "SC-7".to_string()],
            },
            // V-253380 (CAT II) - LLMNR Disabled
            BenchmarkRule {
                id: "WN11-CC-000020".to_string(),
                stig_id: Some("V-253380".to_string()),
                rule_id: Some("SV-253380r828878_rule".to_string()),
                title: "Windows 11 Link-Local Multicast Name Resolution (LLMNR) must be disabled.".to_string(),
                description: "LLMNR allows unauthenticated multicast name resolution on the local link, enabling man-in-the-middle and credential-relay attacks.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient".to_string(),
                    value_name: "EnableMulticast".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Enable the Group Policy 'Turn off multicast name resolution' (sets EnableMulticast=0 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient).".to_string(),
                nist_controls: vec!["CM-6".to_string(), "SC-8".to_string()],
            },
            // V-253385 (CAT II) - PowerShell Script Block Logging
            BenchmarkRule {
                id: "WN11-CC-000030".to_string(),
                stig_id: Some("V-253385".to_string()),
                rule_id: Some("SV-253385r828883_rule".to_string()),
                title: "PowerShell Script Block Logging must be enabled.".to_string(),
                description: "PowerShell Script Block Logging captures full blocks of code executed by PowerShell, essential for threat detection and forensic analysis.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging".to_string(),
                    value_name: "EnableScriptBlockLogging".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Enable 'Turn on PowerShell Script Block Logging' in Group Policy (sets EnableScriptBlockLogging=1 under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging).".to_string(),
                nist_controls: vec!["AU-2".to_string(), "AU-3".to_string(), "AU-12".to_string(), "CM-6".to_string()],
            },
            // V-253390 (CAT II) - Account Lockout Threshold
            BenchmarkRule {
                id: "WN11-AC-000010".to_string(),
                stig_id: Some("V-253390".to_string()),
                rule_id: Some("SV-253390r828888_rule".to_string()),
                title: "The account lockout threshold must be configured to 5 or fewer invalid attempts.".to_string(),
                description: "Configuring account lockout limits brute-force and password guessing attacks against system accounts.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System".to_string(),
                    value_name: "MaxDevicePasswordFailedAttempts".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::LessThanOrEqual,
                    expected_value: json!(5),
                },
                fix_text: "Configure Account lockout threshold to 3 or 5 invalid logon attempts via Security Settings >> Account Policies >> Account Lockout Policy.".to_string(),
                nist_controls: vec!["AC-7".to_string(), "IA-5".to_string()],
            },
            // V-253400 (CAT II) - UAC Admin Approval Mode for Built-in Admin
            BenchmarkRule {
                id: "WN11-CC-000040".to_string(),
                stig_id: Some("V-253400".to_string()),
                rule_id: Some("SV-253400r828898_rule".to_string()),
                title: "User Account Control (UAC) Admin Approval Mode for the Built-in Administrator account must be enabled.".to_string(),
                description: "Admin Approval Mode ensures that administrative actions require explicit approval even when run from the built-in Administrator account.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System".to_string(),
                    value_name: "FilterAdministratorToken".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken to 1 (DWORD).".to_string(),
                nist_controls: vec!["AC-2(2)".to_string(), "AC-3".to_string(), "AC-6".to_string(), "CM-6".to_string()],
            },
            // V-253401 (CAT II) - UAC Run All Administrators in Admin Approval Mode
            BenchmarkRule {
                id: "WN11-CC-000045".to_string(),
                stig_id: Some("V-253401".to_string()),
                rule_id: Some("SV-253401r828899_rule".to_string()),
                title: "User Account Control (UAC) Run all administrators in Admin Approval Mode must be enabled.".to_string(),
                description: "Ensures all administrative users operate in standard user context until elevated, preventing silent privilege escalation.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System".to_string(),
                    value_name: "EnableLUA".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 1 (DWORD).".to_string(),
                nist_controls: vec!["AC-2(2)".to_string(), "AC-3".to_string(), "AC-6".to_string(), "CM-6".to_string()],
            },
            // V-253405 (CAT I) - Windows Defender Antivirus Real-time Protection
            BenchmarkRule {
                id: "WN11-EP-000010".to_string(),
                stig_id: Some("V-253405".to_string()),
                rule_id: Some("SV-253405r828903_rule".to_string()),
                title: "Windows Defender real-time monitoring must be enabled.".to_string(),
                description: "Real-time antimalware protection scans files and memory immediately upon access, preventing malware execution.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection".to_string(),
                    value_name: "DisableRealtimeMonitoring".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Ensure DisableRealtimeMonitoring is 0 or not configured in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection.".to_string(),
                nist_controls: vec!["SI-2".to_string(), "SI-3".to_string(), "SI-4".to_string()],
            },
            // V-253410 (CAT I) - Remote Desktop NLA Required
            BenchmarkRule {
                id: "WN11-CC-000050".to_string(),
                stig_id: Some("V-253410".to_string()),
                rule_id: Some("SV-253410r828908_rule".to_string()),
                title: "Remote Desktop connections must require Network Level Authentication (NLA).".to_string(),
                description: "NLA authenticates the client before establishing the RDP session, protecting against unauthorized connection attempts and denial of service.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp".to_string(),
                    value_name: "UserAuthentication".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication to 1 (DWORD).".to_string(),
                nist_controls: vec!["AC-3".to_string(), "AC-17(2)".to_string(), "IA-2".to_string(), "IA-5".to_string()],
            },
            // V-253415 (CAT II) - AutoRun / AutoPlay Disabled
            BenchmarkRule {
                id: "WN11-CC-000060".to_string(),
                stig_id: Some("V-253415".to_string()),
                rule_id: Some("SV-253415r828913_rule".to_string()),
                title: "AutoRun / AutoPlay must be disabled for all drives.".to_string(),
                description: "Disabling AutoRun prevents automatic execution of untrusted code when removable media or network drives are mounted.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer".to_string(),
                    value_name: "NoDriveTypeAutoRun".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(255),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 255 (0xFF).".to_string(),
                nist_controls: vec!["CM-6".to_string(), "MP-7".to_string()],
            },
            // V-253420 (CAT II) - WinRM Client Basic Auth Disabled
            BenchmarkRule {
                id: "WN11-CC-000070".to_string(),
                stig_id: Some("V-253420".to_string()),
                rule_id: Some("SV-253420r828918_rule".to_string()),
                title: "WinRM client Basic authentication must be disabled.".to_string(),
                description: "Basic authentication sends credentials in plaintext or reversible encoding and must be disabled in favor of Negotiate or Kerberos.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client".to_string(),
                    value_name: "AllowBasic".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowBasic to 0 (DWORD).".to_string(),
                nist_controls: vec!["IA-2".to_string(), "IA-5".to_string(), "AC-3".to_string()],
            },
            // V-253425 (CAT II) - WinRM Service Unencrypted Traffic Disallowed
            BenchmarkRule {
                id: "WN11-CC-000080".to_string(),
                stig_id: Some("V-253425".to_string()),
                rule_id: Some("SV-253425r828923_rule".to_string()),
                title: "WinRM service unencrypted traffic must be disallowed.".to_string(),
                description: "Disallowing unencrypted WinRM traffic enforces confidentiality and integrity for remote management sessions.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service".to_string(),
                    value_name: "AllowUnencryptedTraffic".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowUnencryptedTraffic to 0 (DWORD).".to_string(),
                nist_controls: vec!["SC-8".to_string(), "SC-13".to_string(), "AC-17".to_string()],
            },
            // V-253440 (CAT I) - Restrict Anonymous SAM Enumeration
            BenchmarkRule {
                id: "WN11-CC-000090".to_string(),
                stig_id: Some("V-253440".to_string()),
                rule_id: Some("SV-253440r828938_rule".to_string()),
                title: "Anonymous enumeration of SAM accounts and shares must be restricted.".to_string(),
                description: "Restricting anonymous enumeration prevents unauthenticated network users from discovering valid account names and network shares.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Lsa".to_string(),
                    value_name: "RestrictAnonymous".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous to 1 (DWORD).".to_string(),
                nist_controls: vec!["AC-3".to_string(), "AC-6".to_string()],
            },
            // V-253445 (CAT II) - Require SMB Security Signatures
            BenchmarkRule {
                id: "WN11-CC-000100".to_string(),
                stig_id: Some("V-253445".to_string()),
                rule_id: Some("SV-253445r828943_rule".to_string()),
                title: "SMB server must require digital signatures for communications.".to_string(),
                description: "Digitally signing SMB packets prevents packet tampering and man-in-the-middle attacks on network file sharing.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters".to_string(),
                    value_name: "RequireSecuritySignature".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature to 1 (DWORD).".to_string(),
                nist_controls: vec!["SC-8".to_string(), "CM-6".to_string()],
            },
            // V-253455 (CAT II) - LSA Protection (RunAsPPL)
            BenchmarkRule {
                id: "WN11-CC-000120".to_string(),
                stig_id: Some("V-253455".to_string()),
                rule_id: Some("SV-253455r828953_rule".to_string()),
                title: "LSA Protection (RunAsPPL) must be enabled to protect LSASS memory.".to_string(),
                description: "Running LSASS as a Protected Process Light (PPL) prevents non-protected processes from reading LSASS memory and dumping credentials (e.g. Mimikatz).".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Lsa".to_string(),
                    value_name: "RunAsPPL".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1 (or 2 for UEFI variable lock).".to_string(),
                nist_controls: vec!["AC-3".to_string(), "AC-6".to_string(), "IA-5".to_string()],
            },
            // V-253460 (CAT III) - Disable RDP Password Saving
            BenchmarkRule {
                id: "WN11-CC-000130".to_string(),
                stig_id: Some("V-253460".to_string()),
                rule_id: Some("SV-253460r828958_rule".to_string()),
                title: "Remote Desktop client password saving must be disabled.".to_string(),
                description: "Disabling password saving in the Remote Desktop client prevents stored credentials from being extracted from credential managers.".to_string(),
                severity: AuditSeverity::CatIII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services".to_string(),
                    value_name: "DisablePasswordSaving".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\DisablePasswordSaving to 1 (DWORD).".to_string(),
                nist_controls: vec!["AC-3".to_string(), "IA-5".to_string()],
            },
            // V-253465 (CAT II) - Remote Desktop Encryption Level High
            BenchmarkRule {
                id: "WN11-CC-000140".to_string(),
                stig_id: Some("V-253465".to_string()),
                rule_id: Some("SV-253465r828963_rule".to_string()),
                title: "Remote Desktop connection encryption level must be set to High.".to_string(),
                description: "Setting RDP encryption level to High enforces 128-bit encryption for all client-to-server traffic.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp".to_string(),
                    value_name: "MinEncryptionLevel".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(3),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\MinEncryptionLevel to 3 (High).".to_string(),
                nist_controls: vec!["SC-8".to_string(), "SC-13".to_string()],
            },
        ],
    }
}

/// Baseline checks derived from the DISA STIG for Microsoft Windows 10 (V2R8).
pub fn windows_10_stig_v2r8() -> Benchmark {
    Benchmark {
        id: "U_MS_Windows_10_STIG".to_string(),
        title: "Evedoo baseline checks derived from the Microsoft Windows 10 STIG (V2R8)".to_string(),
        version: "V2R8".to_string(),
        publisher: "Evedoo Contributors".to_string(),
        target_os: "windows_10".to_string(),
        rules: vec![
            BenchmarkRule {
                id: "WN10-CC-000010".to_string(),
                stig_id: Some("V-220700".to_string()),
                rule_id: Some("SV-220700r569187_rule".to_string()),
                title: "Windows 10 SMBv1 protocol driver must be disabled.".to_string(),
                description: "SMBv1 is an outdated protocol with known vulnerabilities. It must be disabled.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters".to_string(),
                    value_name: "SMB1".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 to 0 (DWORD).".to_string(),
                nist_controls: vec!["CM-6".to_string(), "CM-7(1)".to_string(), "SC-7".to_string()],
            },
            BenchmarkRule {
                id: "WN10-CC-000020".to_string(),
                stig_id: Some("V-220705".to_string()),
                rule_id: Some("SV-220705r569188_rule".to_string()),
                title: "Windows Defender real-time protection must be enabled on Windows 10.".to_string(),
                description: "Real-time antimalware protection must be enabled on all endpoints.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection".to_string(),
                    value_name: "DisableRealtimeMonitoring".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring to 0.".to_string(),
                nist_controls: vec!["SI-2".to_string(), "SI-3".to_string(), "SI-4".to_string()],
            },
            BenchmarkRule {
                id: "WN10-CC-000030".to_string(),
                stig_id: Some("V-220710".to_string()),
                rule_id: Some("SV-220710r569189_rule".to_string()),
                title: "Remote Desktop must require Network Level Authentication (NLA) on Windows 10.".to_string(),
                description: "NLA authenticates client sessions before establishing the full RDP connection.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp".to_string(),
                    value_name: "UserAuthentication".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication to 1.".to_string(),
                nist_controls: vec!["AC-3".to_string(), "AC-17(2)".to_string(), "IA-2".to_string()],
            },
            BenchmarkRule {
                id: "WN10-CC-000040".to_string(),
                stig_id: Some("V-220715".to_string()),
                rule_id: Some("SV-220715r569190_rule".to_string()),
                title: "Anonymous enumeration of SAM accounts must be restricted.".to_string(),
                description: "Restricts unauthenticated enumeration of security accounts.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Lsa".to_string(),
                    value_name: "RestrictAnonymous".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous to 1.".to_string(),
                nist_controls: vec!["AC-3".to_string(), "AC-6".to_string()],
            },
            BenchmarkRule {
                id: "WN10-CC-000050".to_string(),
                stig_id: Some("V-220720".to_string()),
                rule_id: Some("SV-220720r569191_rule".to_string()),
                title: "Link-Local Multicast Name Resolution (LLMNR) must be disabled on Windows 10.".to_string(),
                description: "LLMNR allows unauthenticated multicast name resolution on the local subnet.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient".to_string(),
                    value_name: "EnableMulticast".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast to 0.".to_string(),
                nist_controls: vec!["CM-6".to_string(), "SC-8".to_string()],
            },
            BenchmarkRule {
                id: "WN10-CC-000060".to_string(),
                stig_id: Some("V-220725".to_string()),
                rule_id: Some("SV-220725r569192_rule".to_string()),
                title: "PowerShell Script Block Logging must be enabled on Windows 10.".to_string(),
                description: "Captures full blocks of executed PowerShell commands.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging".to_string(),
                    value_name: "EnableScriptBlockLogging".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging to 1.".to_string(),
                nist_controls: vec!["AU-2".to_string(), "AU-3".to_string(), "CM-6".to_string()],
            },
            BenchmarkRule {
                id: "WN10-CC-000070".to_string(),
                stig_id: Some("V-220730".to_string()),
                rule_id: Some("SV-220730r569193_rule".to_string()),
                title: "UAC Admin Approval Mode for the Built-in Administrator must be enabled on Windows 10.".to_string(),
                description: "Requires approval for administrative tasks even for built-in Administrator.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System".to_string(),
                    value_name: "FilterAdministratorToken".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken to 1.".to_string(),
                nist_controls: vec!["AC-2(2)".to_string(), "AC-3".to_string(), "AC-6".to_string()],
            },
            BenchmarkRule {
                id: "WN10-CC-000080".to_string(),
                stig_id: Some("V-220735".to_string()),
                rule_id: Some("SV-220735r569194_rule".to_string()),
                title: "AutoRun / AutoPlay must be disabled on Windows 10.".to_string(),
                description: "Disables automatic execution of media on mount.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer".to_string(),
                    value_name: "NoDriveTypeAutoRun".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(255),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 255.".to_string(),
                nist_controls: vec!["CM-6".to_string(), "MP-7".to_string()],
            },
        ],
    }
}

/// Baseline checks derived from the DISA STIG for Microsoft Windows Server 2022 (V1R3).
pub fn windows_server_2022_stig_v1r3() -> Benchmark {
    Benchmark {
        id: "U_MS_Windows_Server_2022_STIG".to_string(),
        title: "Evedoo baseline checks derived from the Microsoft Windows Server 2022 STIG (V1R3)".to_string(),
        version: "V1R3".to_string(),
        publisher: "Evedoo Contributors".to_string(),
        target_os: "windows_server_2022".to_string(),
        rules: vec![
            BenchmarkRule {
                id: "WS22-CC-000010".to_string(),
                stig_id: Some("V-254200".to_string()),
                rule_id: Some("SV-254200r848900_rule".to_string()),
                title: "Windows Server 2022 SMBv1 protocol driver must be disabled.".to_string(),
                description: "SMBv1 is an insecure protocol and must not be enabled on server infrastructure.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters".to_string(),
                    value_name: "SMB1".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 to 0 (DWORD).".to_string(),
                nist_controls: vec!["CM-6".to_string(), "CM-7(1)".to_string(), "SC-7".to_string()],
            },
            BenchmarkRule {
                id: "WS22-CC-000020".to_string(),
                stig_id: Some("V-254205".to_string()),
                rule_id: Some("SV-254205r848905_rule".to_string()),
                title: "Windows Defender real-time protection must be enabled on Windows Server 2022.".to_string(),
                description: "Real-time antimalware protection must remain active on server workloads.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection".to_string(),
                    value_name: "DisableRealtimeMonitoring".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring to 0.".to_string(),
                nist_controls: vec!["SI-2".to_string(), "SI-3".to_string(), "SI-4".to_string()],
            },
            BenchmarkRule {
                id: "WS22-CC-000030".to_string(),
                stig_id: Some("V-254210".to_string()),
                rule_id: Some("SV-254210r848910_rule".to_string()),
                title: "Remote Desktop connections to Windows Server 2022 must require NLA.".to_string(),
                description: "Network Level Authentication must be enforced for all server administrative sessions.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp".to_string(),
                    value_name: "UserAuthentication".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication to 1.".to_string(),
                nist_controls: vec!["AC-3".to_string(), "AC-17(2)".to_string(), "IA-2".to_string()],
            },
            BenchmarkRule {
                id: "WS22-CC-000040".to_string(),
                stig_id: Some("V-254215".to_string()),
                rule_id: Some("SV-254215r848915_rule".to_string()),
                title: "Anonymous enumeration of SAM accounts must be restricted on Windows Server 2022.".to_string(),
                description: "Restricts unauthenticated network enumeration of domain and local security principals.".to_string(),
                severity: AuditSeverity::CatI,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Control\\Lsa".to_string(),
                    value_name: "RestrictAnonymous".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous to 1.".to_string(),
                nist_controls: vec!["AC-3".to_string(), "AC-6".to_string()],
            },
            BenchmarkRule {
                id: "WS22-CC-000050".to_string(),
                stig_id: Some("V-254220".to_string()),
                rule_id: Some("SV-254220r848920_rule".to_string()),
                title: "PowerShell Script Block Logging must be enabled on Windows Server 2022.".to_string(),
                description: "Enables deep inspection and SIEM ingestion of server PowerShell execution.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging".to_string(),
                    value_name: "EnableScriptBlockLogging".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging to 1.".to_string(),
                nist_controls: vec!["AU-2".to_string(), "AU-3".to_string(), "CM-6".to_string()],
            },
            BenchmarkRule {
                id: "WS22-CC-000060".to_string(),
                stig_id: Some("V-254225".to_string()),
                rule_id: Some("SV-254225r848925_rule".to_string()),
                title: "SMB server signing must be required on Windows Server 2022.".to_string(),
                description: "Digitally signs server SMB packets to prevent tampering.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters".to_string(),
                    value_name: "RequireSecuritySignature".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature to 1.".to_string(),
                nist_controls: vec!["SC-8".to_string(), "CM-6".to_string()],
            },
        ],
    }
}

/// Baseline checks derived from the DISA STIG for Microsoft Edge (V1R2).
pub fn ms_edge_stig_v1r2() -> Benchmark {
    Benchmark {
        id: "U_MS_Edge_STIG".to_string(),
        title: "Evedoo baseline checks derived from the Microsoft Edge STIG (V1R2)".to_string(),
        version: "V1R2".to_string(),
        publisher: "Evedoo Contributors".to_string(),
        target_os: "windows".to_string(),
        rules: vec![
            BenchmarkRule {
                id: "EDG-00-000010".to_string(),
                stig_id: Some("V-240000".to_string()),
                rule_id: Some("SV-240000r790000_rule".to_string()),
                title: "Microsoft Edge SmartScreen must be enabled.".to_string(),
                description: "SmartScreen warns users against visiting known phishing and malware sites.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Edge".to_string(),
                    value_name: "SmartScreenEnabled".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\SmartScreenEnabled to 1 (DWORD).".to_string(),
                nist_controls: vec!["SI-3".to_string(), "SI-4".to_string()],
            },
            BenchmarkRule {
                id: "EDG-00-000020".to_string(),
                stig_id: Some("V-240005".to_string()),
                rule_id: Some("SV-240005r790005_rule".to_string()),
                title: "Microsoft Edge built-in password manager must be disabled.".to_string(),
                description: "Disabling browser password saving enforces use of enterprise credential management solutions.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Edge".to_string(),
                    value_name: "PasswordManagerEnabled".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(0),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\PasswordManagerEnabled to 0 (DWORD).".to_string(),
                nist_controls: vec!["IA-5".to_string(), "AC-3".to_string()],
            },
            BenchmarkRule {
                id: "EDG-00-000030".to_string(),
                stig_id: Some("V-240010".to_string()),
                rule_id: Some("SV-240010r790010_rule".to_string()),
                title: "Microsoft Edge SmartScreen Potentially Unwanted App (PUA) blocking must be enabled.".to_string(),
                description: "PUA protection blocks download of adware, coin miners, and low-reputation software.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Edge".to_string(),
                    value_name: "SmartScreenPuaEnabled".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::Equals,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\SmartScreenPuaEnabled to 1 (DWORD).".to_string(),
                nist_controls: vec!["SI-3".to_string(), "SI-4".to_string()],
            },
            BenchmarkRule {
                id: "EDG-00-000040".to_string(),
                stig_id: Some("V-240015".to_string()),
                rule_id: Some("SV-240015r790015_rule".to_string()),
                title: "Microsoft Edge Developer Tools must be restricted or disabled in high security environments.".to_string(),
                description: "Restricting developer tools prevents unauthorized DOM manipulation or token exfiltration.".to_string(),
                severity: AuditSeverity::CatII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Edge".to_string(),
                    value_name: "DeveloperToolsAvailability".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::GreaterThanOrEqual,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\DeveloperToolsAvailability to 1 (disallow on extensions/internal pages) or 2 (disabled).".to_string(),
                nist_controls: vec!["CM-6".to_string(), "AC-3".to_string()],
            },
            BenchmarkRule {
                id: "EDG-00-000050".to_string(),
                stig_id: Some("V-240020".to_string()),
                rule_id: Some("SV-240020r790020_rule".to_string()),
                title: "Microsoft Edge telemetry / diagnostics reporting must be configured to minimum required.".to_string(),
                description: "Ensures diagnostic reporting complies with privacy and telemetry standards.".to_string(),
                severity: AuditSeverity::CatIII,
                check: CheckAssertion::Registry {
                    hive: RegistryHive::Hklm,
                    key_path: "SOFTWARE\\Policies\\Microsoft\\Edge".to_string(),
                    value_name: "DiagnosticData".to_string(),
                    expected_type: RegistryValueType::Dword,
                    operator: ComparisonOperator::LessThanOrEqual,
                    expected_value: json!(1),
                },
                fix_text: "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\DiagnosticData to 0 (off) or 1 (required only).".to_string(),
                nist_controls: vec!["CM-6".to_string()],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundled rules are Evedoo's own wording of a subset of each STIG.
    /// They must not be presented as DISA's publication.
    #[test]
    fn bundled_benchmarks_do_not_claim_to_be_disa_publications() {
        for (id, listed_title, _) in list_bundled_benchmarks() {
            let benchmark = get_bundled_benchmark(id).unwrap();
            assert_eq!(benchmark.publisher, "Evedoo Contributors", "{id}");
            for title in [listed_title, benchmark.title.as_str()] {
                assert!(title.contains("derived from"), "{id}: {title}");
                assert!(!title.to_lowercase().contains("authoritative"), "{id}: {title}");
            }
        }
    }

    #[test]
    fn test_list_bundled_benchmarks() {
        let benchmarks = list_bundled_benchmarks();
        assert_eq!(benchmarks.len(), 4);
        assert!(benchmarks.iter().any(|(id, _, _)| *id == "windows-11"));
        assert!(benchmarks.iter().any(|(id, _, _)| *id == "windows-10"));
        assert!(benchmarks.iter().any(|(id, _, _)| *id == "windows-server-2022"));
        assert!(benchmarks.iter().any(|(id, _, _)| *id == "ms-edge"));
    }

    #[test]
    fn test_get_bundled_benchmark_aliases() {
        assert!(get_bundled_benchmark("windows-11").is_some());
        assert!(get_bundled_benchmark("win11").is_some());
        assert!(get_bundled_benchmark("windows_11").is_some());
        assert!(get_bundled_benchmark("U_MS_Windows_11_STIG").is_some());

        assert!(get_bundled_benchmark("windows-10").is_some());
        assert!(get_bundled_benchmark("win10").is_some());

        assert!(get_bundled_benchmark("windows-server-2022").is_some());
        assert!(get_bundled_benchmark("win2022").is_some());
        assert!(get_bundled_benchmark("server-2022").is_some());

        assert!(get_bundled_benchmark("ms-edge").is_some());
        assert!(get_bundled_benchmark("edge").is_some());

        assert!(get_bundled_benchmark("non-existent-benchmark").is_none());
    }

    #[test]
    fn test_windows_11_stig_rules_integrity() {
        let bm = windows_11_stig_v1r4();
        assert!(!bm.rules.is_empty());
        assert!(bm.rules.iter().any(|r| r.id == "WN11-CC-000010" && r.stig_id.as_deref() == Some("V-253378")));
        assert!(bm.rules.iter().any(|r| r.id == "WN11-CC-000020" && r.stig_id.as_deref() == Some("V-253380")));
        assert!(bm.rules.iter().any(|r| r.id == "WN11-CC-000030" && r.stig_id.as_deref() == Some("V-253385")));
        assert!(bm.rules.iter().any(|r| r.id == "WN11-EP-000010" && r.stig_id.as_deref() == Some("V-253405")));
        assert!(bm.rules.iter().any(|r| r.id == "WN11-CC-000050" && r.stig_id.as_deref() == Some("V-253410")));
        assert!(bm.rules.iter().any(|r| r.id == "WN11-CC-000060" && r.stig_id.as_deref() == Some("V-253415")));

        // Verify all rules have non-empty title, fix_text, and nist_controls
        for rule in &bm.rules {
            assert!(!rule.title.is_empty());
            assert!(!rule.fix_text.is_empty());
            assert!(!rule.nist_controls.is_empty());
        }
    }
}

//! WinRM session management via PowerShell `Invoke-Command`.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::process::{Command, Stdio};

use tracing::{debug, info};
use zeroize::Zeroize;

use crate::error::{Result, ScanError};

/// Connection details for a remote Windows machine.
#[derive(Clone)]
pub struct RemoteTarget {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    /// Password is stored in-memory only, never logged or serialized.
    password: String,
    pub use_ssl: bool,
    /// When true, skip TLS certificate validation (CA, CN, revocation).
    /// Default is false — TLS checks are enforced unless explicitly opted out.
    pub skip_tls_verify: bool,
}

/// Hand-written so the password can never reach a log line through `{:?}`.
impl std::fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteTarget")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("use_ssl", &self.use_ssl)
            .field("skip_tls_verify", &self.skip_tls_verify)
            .finish()
    }
}

/// Validate that a hostname contains only safe characters (alphanumeric,
/// dots, hyphens, and underscores). Rejects anything that could break out
/// of a PowerShell single-quoted string or shell context.
fn validate_hostname(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(ScanError::RemoteError("Hostname cannot be empty".into()));
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err(ScanError::RemoteError(format!(
            "Hostname '{}' contains invalid characters — only alphanumeric, dots, hyphens, and underscores are allowed",
            s
        )))
    }
}

/// Validate that a username contains only safe characters (alphanumeric,
/// dots, hyphens, underscores, backslash for DOMAIN\\user, and @).
fn validate_username(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(ScanError::RemoteError("Username cannot be empty".into()));
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '\\' | '@'))
    {
        Ok(())
    } else {
        Err(ScanError::RemoteError(format!(
            "Username '{}' contains invalid characters — only alphanumeric, dots, hyphens, underscores, backslash, and @ are allowed",
            s
        )))
    }
}

/// Escape a string for use inside a PowerShell single-quoted string.
///
/// PowerShell's tokenizer treats five characters as a single quote: the ASCII
/// apostrophe and the typographic quotes U+2018, U+2019, U+201A and U+201B.
/// Any of them ends a single-quoted literal, and a doubled one stands for
/// itself, so each is doubled.
pub(crate) fn ps_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        out.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
    }
    out
}

impl RemoteTarget {
    #[allow(dead_code)]
    pub fn new(
        hostname: String,
        port: u16,
        username: String,
        password: String,
        use_ssl: bool,
    ) -> Result<Self> {
        Self::with_tls_options(hostname, port, username, password, use_ssl, false)
    }

    /// Create a new `RemoteTarget` with explicit TLS verification control.
    /// When `skip_tls_verify` is true, certificate validation is bypassed —
    /// use only in lab/test environments.
    pub fn with_tls_options(
        hostname: String,
        port: u16,
        username: String,
        password: String,
        use_ssl: bool,
        skip_tls_verify: bool,
    ) -> Result<Self> {
        validate_hostname(&hostname)?;
        validate_username(&username)?;
        Ok(Self {
            hostname,
            port,
            username,
            password,
            use_ssl,
            skip_tls_verify,
        })
    }

    /// Build the PowerShell credential and session option preamble.
    /// Returns a script fragment that creates `$cred` and `$so` variables.
    /// The caller must pipe this to PowerShell via stdin (not command-line
    /// arguments) so that the password is not visible in the process list.
    ///
    /// All interpolated values are escaped for PowerShell single-quoted
    /// strings to prevent injection attacks.
    fn credential_preamble(&self) -> String {
        let session_opts = if self.skip_tls_verify {
            "$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck"
        } else {
            "$so = New-PSSessionOption"
        };
        format!(
            r#"$pw = ConvertTo-SecureString '{escaped_pw}' -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential('{user}', $pw); {so}"#,
            escaped_pw = ps_escape(&self.password),
            user = ps_escape(&self.username),
            so = session_opts,
        )
    }

    /// Build full `Invoke-Command` wrapper for a remote script block.
    fn wrap_invoke_command(&self, script_block: &str) -> String {
        let preamble = self.credential_preamble();
        let use_ssl_flag = if self.use_ssl { " -UseSSL" } else { "" };
        format!(
            r#"{preamble}; Invoke-Command -ComputerName '{host}' -Port {port}{ssl} -Credential $cred -SessionOption $so -ScriptBlock {{ {script} }}"#,
            preamble = preamble,
            host = ps_escape(&self.hostname),
            port = self.port,
            ssl = use_ssl_flag,
            script = script_block,
        )
    }
}

/// Zeroize the password on drop so it doesn't linger in heap memory.
impl Drop for RemoteTarget {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// An active session to a remote machine. Wraps `RemoteTarget` with
/// convenience methods for executing commands.
pub struct RemoteSession {
    target: RemoteTarget,
}

impl RemoteSession {
    /// Establish a session by testing connectivity with a simple probe.
    pub fn connect(target: RemoteTarget) -> Result<Self> {
        info!(
            "Testing WinRM connectivity to {}:{}",
            target.hostname, target.port
        );

        let session = Self { target };

        // Test connectivity with a lightweight probe
        let probe = session.execute("$env:COMPUTERNAME")?;
        let remote_name = probe.trim();
        if remote_name.is_empty() {
            return Err(ScanError::RemoteError(
                "WinRM probe returned empty response — check credentials and WinRM configuration"
                    .to_string(),
            ));
        }

        info!("Connected to remote host: {}", remote_name);
        Ok(session)
    }

    /// Execute a PowerShell script block on the remote machine and return
    /// its stdout as a String.
    ///
    /// The script (including credentials) is piped via stdin so that
    /// passwords never appear in the process argument list.
    pub fn execute(&self, script_block: &str) -> Result<String> {
        let full_script = self.target.wrap_invoke_command(script_block);

        debug!("Executing remote command (script block redacted for security)");

        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "-", // read script from stdin
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                ScanError::RemoteError(format!("Failed to launch powershell.exe: {}", e))
            })?;

        // Write the script (containing credentials) to stdin, not the
        // command line, so it is invisible to process enumeration tools.
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(full_script.as_bytes()).map_err(|e| {
                ScanError::RemoteError(format!("Failed to write to powershell stdin: {}", e))
            })?;
            // stdin is dropped here, sending EOF to PowerShell
        }

        let output = child.wait_with_output().map_err(|e| {
            ScanError::RemoteError(format!("Failed to wait for powershell.exe: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Redact password from any error output
            let safe_stderr = stderr.replace(&self.target.password, "***");
            return Err(ScanError::RemoteError(format!(
                "Remote command failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                safe_stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Build a UNC path for SMB-based scanning.
    ///
    /// Rejects paths containing `..` segments to prevent directory traversal
    /// attacks from a compromised remote host returning malicious paths.
    pub fn unc_path(&self, remote_path: &str) -> Option<String> {
        // Reject path traversal attempts
        if remote_path.contains("..") {
            tracing::warn!(
                "Rejected remote path with traversal component: {}",
                remote_path
            );
            return None;
        }

        // Only accept absolute Windows paths (drive letter + colon)
        if remote_path.len() < 3
            || !remote_path.as_bytes()[0].is_ascii_alphabetic()
            || remote_path.as_bytes()[1] != b':'
            || remote_path.as_bytes()[2] != b'\\'
        {
            tracing::warn!(
                "Rejected non-absolute remote path: {}",
                remote_path
            );
            return None;
        }

        let drive = remote_path.as_bytes()[0].to_ascii_uppercase() as char;
        let rest = &remote_path[3..]; // skip "X:\"

        Some(format!(r"\\{}\{}$\{}", self.target.hostname, drive, rest))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_target() -> RemoteTarget {
        RemoteTarget::new(
            "server01".into(),
            5985,
            "admin".into(),
            "s3cret".into(),
            false,
        )
        .unwrap()
    }

    /// PowerShell accepts five characters as a single-quote delimiter, not
    /// just the ASCII apostrophe. A password containing a typographic quote
    /// used to end the string literal, and the rest of it ran as script.
    #[test]
    fn ps_escape_doubles_every_powershell_single_quote_character() {
        for quote in ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
            let escaped = ps_escape(&format!("a{quote}b"));
            assert_eq!(escaped, format!("a{quote}{quote}b"), "U+{:04X}", quote as u32);
        }
        assert_eq!(ps_escape("plain"), "plain");
    }

    #[test]
    fn password_with_a_typographic_quote_cannot_close_the_string_literal() {
        let target = RemoteTarget::new(
            "server01".into(),
            5985,
            "admin".into(),
            "pw\u{2019}; Start-Process calc; \u{2018}".into(),
            false,
        )
        .unwrap();
        let preamble = target.credential_preamble();
        // Every quote character inside the literal is doubled, so the literal
        // ends only at the delimiter the template itself wrote.
        assert!(preamble.contains("'pw\u{2019}\u{2019}; Start-Process calc; \u{2018}\u{2018}'"), "{preamble}");
    }

    #[test]
    fn debug_output_never_contains_the_password() {
        let target = test_target();
        let shown = format!("{target:?}");
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("server01"));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn credential_preamble_escapes_single_quotes() {
        let target = RemoteTarget::new(
            "host".into(),
            5986,
            "admin".into(),
            "pass'word".into(),
            true,
        )
        .unwrap();
        let preamble = target.credential_preamble();
        assert!(
            preamble.contains("pass''word"),
            "Single quotes in password must be doubled"
        );
        assert!(!preamble.contains("pass'word"));
    }

    #[test]
    fn username_escaped_in_preamble() {
        let target = RemoteTarget::new(
            "host".into(),
            5985,
            "DOMAIN\\admin".into(),
            "pw".into(),
            false,
        )
        .unwrap();
        let preamble = target.credential_preamble();
        assert!(preamble.contains("DOMAIN\\admin"));
    }

    #[test]
    fn hostname_escaped_in_invoke_command() {
        let target = test_target();
        let cmd = target.wrap_invoke_command("whoami");
        assert!(cmd.contains("-ComputerName 'server01'"));
    }

    #[test]
    fn wrap_invoke_command_includes_ssl_flag() {
        let target = RemoteTarget::new(
            "host".into(),
            5986,
            "admin".into(),
            "pw".into(),
            true,
        )
        .unwrap();
        let cmd = target.wrap_invoke_command("Get-Process");
        assert!(cmd.contains("-UseSSL"));
        assert!(cmd.contains("-Port 5986"));
    }

    #[test]
    fn wrap_invoke_command_omits_ssl_when_disabled() {
        let target = test_target();
        let cmd = target.wrap_invoke_command("whoami");
        assert!(!cmd.contains("-UseSSL"));
        assert!(cmd.contains("-Port 5985"));
    }

    #[test]
    fn rejects_hostname_with_quotes() {
        let result = RemoteTarget::new(
            "host'; malicious".into(),
            5985,
            "admin".into(),
            "pw".into(),
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_username_with_quotes() {
        let result = RemoteTarget::new(
            "host".into(),
            5985,
            "admin'; malicious".into(),
            "pw".into(),
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn accepts_domain_username() {
        let result = RemoteTarget::new(
            "server.domain.local".into(),
            5986,
            "DOMAIN\\admin.user".into(),
            "pw".into(),
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_upn_username() {
        let result = RemoteTarget::new(
            "server01".into(),
            5985,
            "admin@domain.local".into(),
            "pw".into(),
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn unc_path_converts_c_drive() {
        let target = test_target();
        let session = RemoteSession { target };
        assert_eq!(
            session.unc_path(r"C:\ProgramData\chocolatey"),
            Some(r"\\server01\C$\ProgramData\chocolatey".to_string())
        );
    }

    #[test]
    fn unc_path_handles_lowercase_drive() {
        let target = test_target();
        let session = RemoteSession { target };
        assert_eq!(
            session.unc_path(r"c:\Users\admin\scoop"),
            Some(r"\\server01\C$\Users\admin\scoop".to_string())
        );
    }

    #[test]
    fn unc_path_rejects_traversal() {
        let target = test_target();
        let session = RemoteSession { target };
        assert_eq!(session.unc_path(r"C:\..\..\sensitive"), None);
        assert_eq!(session.unc_path(r"C:\ProgramData\..\Windows\System32"), None);
    }

    #[test]
    fn unc_path_rejects_non_absolute() {
        let target = test_target();
        let session = RemoteSession { target };
        assert_eq!(session.unc_path("relative_path"), None);
        assert_eq!(session.unc_path(""), None);
    }

    #[test]
    fn tls_skip_flags_only_when_opted_in() {
        let target = RemoteTarget::with_tls_options(
            "host".into(), 5986, "admin".into(), "pw".into(), true, false,
        ).unwrap();
        let preamble = target.credential_preamble();
        assert!(!preamble.contains("-SkipCACheck"));

        let target_skip = RemoteTarget::with_tls_options(
            "host".into(), 5986, "admin".into(), "pw".into(), true, true,
        ).unwrap();
        let preamble_skip = target_skip.credential_preamble();
        assert!(preamble_skip.contains("-SkipCACheck"));
        assert!(preamble_skip.contains("-SkipCNCheck"));
    }
}

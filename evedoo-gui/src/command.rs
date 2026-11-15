// Background CLI command execution via std::thread and mpsc channels.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::mpsc::Sender;

#[derive(Debug)]
pub enum CommandOutput {
    /// A line from stderr (progress/log info).
    StderrLine(String),
    /// The command finished. Contains the full stdout and exit code.
    Finished {
        exit_code: Option<i32>,
        stdout: String,
        #[allow(dead_code)]
        stderr: String,
    },
    /// Failed to even start the process.
    Error(String),
}

/// Spawn a CLI command in a background thread. Results are sent over `tx`;
/// the GUI polls `rx.try_recv()` each frame.
///
/// Secrets must never travel in `args` (SEC-3): a process command line is
/// captured by Windows Security event 4688 with command-line auditing, by
/// Sysmon event 1, and by EDR agents — all of which persist it to logs/SIEM
/// with long retention.
///
/// Two safer channels are offered. `stdin_secret` (SEC-5) is the strongest:
/// the value is written to the child's stdin and never appears in argv, the
/// environment block, or on disk — the same approach
/// `evedoo/src/remote/session.rs` uses for its PowerShell credentials.
/// `envs` keeps a secret out of command-line telemetry but is still readable
/// from the process's PEB by admin/SYSTEM/same-user code.
pub fn spawn_command_with_env(
    program: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    stdin_secret: Option<String>,
    tx: Sender<CommandOutput>,
) {
    std::thread::spawn(move || {
        #[cfg(windows)]
        use std::os::windows::process::CommandExt;

        let mut cmd = std::process::Command::new(&program);
        cmd.args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        for (key, value) in &envs {
            cmd.env(key, value);
        }

        if stdin_secret.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }

        // Suppress console window flash on Windows.
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW

        // A secret on stdin needs spawn()+wait_with_output() rather than
        // output(), so the pipe can be written before the child is reaped.
        if let Some(secret) = stdin_secret {
            let result = cmd.spawn().and_then(|mut child| {
                if let Some(mut pipe) = child.stdin.take() {
                    use std::io::Write;
                    // Errors here are non-fatal: the child reports the
                    // resulting auth failure far more usefully than we can.
                    let _ = writeln!(pipe, "{}", secret);
                }
                child.wait_with_output()
            });
            send_result(result, &program, &tx);
            return;
        }

        send_result(cmd.output(), &program, &tx);
    });
}

/// Translate a finished child process into channel messages.
fn send_result(
    result: std::io::Result<std::process::Output>,
    program: &str,
    tx: &Sender<CommandOutput>,
) {
    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            // Send stderr lines individually so the log panel can stream them.
            for line in stderr.lines() {
                let _ = tx.send(CommandOutput::StderrLine(line.to_string()));
            }

            let _ = tx.send(CommandOutput::Finished {
                exit_code: output.status.code(),
                stdout,
                stderr,
            });
        }
        Err(e) => {
            let _ = tx.send(CommandOutput::Error(format!(
                "Failed to start '{}': {}",
                program, e
            )));
        }
    }
}

//! Scheduled scanning — Windows Task Scheduler integration.
//!
//! Creates, lists, and removes scheduled tasks that run `evedoo scan`
//! at user-specified intervals using `schtasks.exe`.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use crate::error::Result;

/// Prefix for all evedoo scheduled task names.
pub const TASK_PREFIX: &str = "Evedoo_";

/// Represents a scheduled scan task.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScheduledTask {
    pub name: String,
    pub schedule: ScheduleFrequency,
    pub time: String,
    pub day: Option<String>,
    pub command: String,
    pub arguments: String,
}

/// Supported scheduling frequencies.
#[derive(Debug, Clone, PartialEq)]
pub enum ScheduleFrequency {
    Daily,
    Weekly,
    Hourly,
    OnLogon,
}

impl ScheduleFrequency {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "daily" => Some(Self::Daily),
            "weekly" => Some(Self::Weekly),
            "hourly" => Some(Self::Hourly),
            "onlogon" | "logon" => Some(Self::OnLogon),
            _ => None,
        }
    }

    pub fn as_schtasks_str(&self) -> &str {
        match self {
            Self::Daily => "DAILY",
            Self::Weekly => "WEEKLY",
            Self::Hourly => "HOURLY",
            Self::OnLogon => "ONLOGON",
        }
    }
}

impl std::fmt::Display for ScheduleFrequency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Daily => write!(f, "Daily"),
            Self::Weekly => write!(f, "Weekly"),
            Self::Hourly => write!(f, "Hourly"),
            Self::OnLogon => write!(f, "On Logon"),
        }
    }
}

/// Validate that schedule arguments contain only safe characters.
/// Rejects shell metacharacters (`&`, `|`, `;`, `>`, `<`, backticks, `$`,
/// `(`, `)`) that could be used for command injection when the scheduled
/// task fires.
fn validate_schedule_args(args: &str) -> Result<()> {
    if args.is_empty() {
        return Ok(());
    }
    let forbidden = ['&', '|', ';', '>', '<', '`', '$', '(', ')', '{', '}', '!', '^'];
    for ch in args.chars() {
        if forbidden.contains(&ch) {
            return Err(crate::error::ScanError::ScheduleError(format!(
                "Schedule arguments contain forbidden character '{}' — \
                 only flags, paths, and values are allowed (no shell metacharacters)",
                ch
            )));
        }
    }
    Ok(())
}

/// Create a scheduled scan task in Windows Task Scheduler.
///
/// Uses `schtasks /Create` to register a recurring task that runs
/// the evedoo scanner at the specified frequency.
pub fn create_schedule(
    task_name: &str,
    frequency: &ScheduleFrequency,
    time: Option<&str>,
    day: Option<&str>,
    evedoo_args: &str,
    elevated: bool,
) -> Result<String> {
    // Reject args with shell metacharacters to prevent command injection
    // when the scheduled task fires with elevated privileges.
    validate_schedule_args(evedoo_args)?;

    let full_name = format!("{}{}", TASK_PREFIX, task_name);

    // Get the path to the current executable
    let exe_path = std::env::current_exe()
        .map_err(|e| crate::error::ScanError::ScheduleError(format!("Cannot determine executable path: {}", e)))?;

    let exe_str = exe_path.to_string_lossy();

    // Build schtasks command
    let mut cmd = Command::new("schtasks");
    cmd.args(["/Create", "/TN", &full_name, "/TR"]);

    // The task command: evedoo.exe scan <args>
    let task_command = if evedoo_args.is_empty() {
        format!("\"{}\" scan", exe_str)
    } else {
        format!("\"{}\" scan {}", exe_str, evedoo_args)
    };
    cmd.arg(&task_command);

    // Schedule type
    cmd.args(["/SC", frequency.as_schtasks_str()]);

    // Start time (not applicable for ONLOGON)
    if *frequency != ScheduleFrequency::OnLogon {
        if let Some(t) = time {
            cmd.args(["/ST", t]);
        } else {
            // Default to 02:00 for daily/weekly, not needed for hourly
            if *frequency != ScheduleFrequency::Hourly {
                cmd.args(["/ST", "02:00"]);
            }
        }
    }

    // Day of week (only for weekly)
    if *frequency == ScheduleFrequency::Weekly {
        if let Some(d) = day {
            cmd.args(["/D", d]);
        } else {
            cmd.args(["/D", "MON"]);
        }
    }

    // Only request highest privileges when explicitly opted in.
    // HIGHEST is needed for registry scanning but creates a privilege
    // escalation risk if the executable path is user-writable.
    if elevated {
        cmd.arg("/RL");
        cmd.arg("HIGHEST");
    }

    // Don't prompt to replace if already exists — force create
    cmd.arg("/F");

    let output = cmd
        .output()
        .map_err(|e| crate::error::ScanError::ScheduleError(format!("Failed to run schtasks: {}", e)))?;

    if output.status.success() {
        Ok(full_name)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = if !stderr.is_empty() {
            stderr.to_string()
        } else {
            stdout.to_string()
        };
        Err(crate::error::ScanError::ScheduleError(
            format!("schtasks /Create failed: {}", msg.trim()),
        ))
    }
}

/// List all evedoo scheduled tasks.
///
/// Queries Task Scheduler for tasks with the `Evedoo_` prefix.
pub fn list_schedules() -> Result<Vec<ParsedTask>> {
    let output = Command::new("schtasks")
        .args(["/Query", "/FO", "CSV", "/NH", "/V"])
        .output()
        .map_err(|e| crate::error::ScanError::ScheduleError(format!("Failed to run schtasks: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::ScanError::ScheduleError(
            format!("schtasks /Query failed: {}", stderr.trim()),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut tasks = Vec::new();

    for line in stdout.lines() {
        // CSV format: "HostName","TaskName","Next Run Time","Status","Logon Mode",...
        if !line.contains(TASK_PREFIX) {
            continue;
        }

        let fields: Vec<&str> = parse_csv_line(line);
        if fields.len() >= 9 {
            // Field indices for verbose CSV: 1=TaskName, 2=NextRunTime, 3=Status,
            // 6=ScheduleType, 7=StartTime, 8=TaskToRun
            let task_name = fields[1].trim_matches('"').to_string();
            if !task_name.contains(TASK_PREFIX) {
                continue;
            }

            tasks.push(ParsedTask {
                full_name: task_name.clone(),
                display_name: task_name
                    .strip_prefix(&format!("\\{}", TASK_PREFIX))
                    .or_else(|| task_name.strip_prefix(TASK_PREFIX))
                    .unwrap_or(&task_name)
                    .to_string(),
                next_run: fields.get(2).unwrap_or(&"").trim_matches('"').to_string(),
                status: fields.get(3).unwrap_or(&"").trim_matches('"').to_string(),
                schedule_type: fields.get(6).unwrap_or(&"").trim_matches('"').to_string(),
                start_time: fields.get(7).unwrap_or(&"").trim_matches('"').to_string(),
                command: fields.get(8).unwrap_or(&"").trim_matches('"').to_string(),
            });
        }
    }

    Ok(tasks)
}

/// Remove a evedoo scheduled task.
pub fn remove_schedule(task_name: &str) -> Result<bool> {
    let full_name = if task_name.starts_with(TASK_PREFIX) {
        task_name.to_string()
    } else {
        format!("{}{}", TASK_PREFIX, task_name)
    };

    let output = Command::new("schtasks")
        .args(["/Delete", "/TN", &full_name, "/F"])
        .output()
        .map_err(|e| crate::error::ScanError::ScheduleError(format!("Failed to run schtasks: {}", e)))?;

    Ok(output.status.success())
}

/// A parsed scheduled task from schtasks output.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ParsedTask {
    pub full_name: String,
    pub display_name: String,
    pub next_run: String,
    pub status: String,
    pub schedule_type: String,
    pub start_time: String,
    pub command: String,
}

/// Simple CSV line parser that handles quoted fields.
fn parse_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(&line[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    // Last field
    if start <= line.len() {
        fields.push(&line[start..]);
    }

    fields
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_basic() {
        let line = r#""HOST","Evedoo_daily_scan","11/01/2026 2:00:00 AM","Ready""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "\"HOST\"");
        assert_eq!(fields[1], "\"Evedoo_daily_scan\"");
        assert_eq!(fields[2], "\"11/01/2026 2:00:00 AM\"");
        assert_eq!(fields[3], "\"Ready\"");
    }

    #[test]
    fn parse_csv_with_comma_in_quotes() {
        let line = r#""HOST","Task, Name","Value""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[1], "\"Task, Name\"");
    }

    #[test]
    fn schedule_frequency_from_str() {
        assert_eq!(ScheduleFrequency::from_str("daily"), Some(ScheduleFrequency::Daily));
        assert_eq!(ScheduleFrequency::from_str("WEEKLY"), Some(ScheduleFrequency::Weekly));
        assert_eq!(ScheduleFrequency::from_str("hourly"), Some(ScheduleFrequency::Hourly));
        assert_eq!(ScheduleFrequency::from_str("onlogon"), Some(ScheduleFrequency::OnLogon));
        assert_eq!(ScheduleFrequency::from_str("logon"), Some(ScheduleFrequency::OnLogon));
        assert_eq!(ScheduleFrequency::from_str("bogus"), None);
    }

    #[test]
    fn schedule_frequency_display() {
        assert_eq!(format!("{}", ScheduleFrequency::Daily), "Daily");
        assert_eq!(format!("{}", ScheduleFrequency::Weekly), "Weekly");
        assert_eq!(format!("{}", ScheduleFrequency::Hourly), "Hourly");
        assert_eq!(format!("{}", ScheduleFrequency::OnLogon), "On Logon");
    }

    #[test]
    fn schtasks_str_mapping() {
        assert_eq!(ScheduleFrequency::Daily.as_schtasks_str(), "DAILY");
        assert_eq!(ScheduleFrequency::Weekly.as_schtasks_str(), "WEEKLY");
        assert_eq!(ScheduleFrequency::Hourly.as_schtasks_str(), "HOURLY");
        assert_eq!(ScheduleFrequency::OnLogon.as_schtasks_str(), "ONLOGON");
    }

    #[test]
    fn task_prefix_constant() {
        assert_eq!(TASK_PREFIX, "Evedoo_");
    }

    #[test]
    fn validate_args_rejects_shell_metacharacters() {
        assert!(validate_schedule_args("--format json --output report.json").is_ok());
        assert!(validate_schedule_args("-d vulndb.sqlite -f html").is_ok());
        assert!(validate_schedule_args("").is_ok());

        // All of these should be rejected
        assert!(validate_schedule_args("& net user hacker /add").is_err());
        assert!(validate_schedule_args("--output foo | evil").is_err());
        assert!(validate_schedule_args("$(whoami)").is_err());
        assert!(validate_schedule_args("; rm -rf /").is_err());
        assert!(validate_schedule_args("--output foo > bar").is_err());
        assert!(validate_schedule_args("`evil`").is_err());
    }

    #[test]
    fn remove_schedule_prefixes_correctly() {
        // Test that names with and without prefix both work
        let with_prefix = "Evedoo_test";
        let without_prefix = "test";

        // We can't actually run schtasks in tests, but we can verify the name logic
        let full1 = if with_prefix.starts_with(TASK_PREFIX) {
            with_prefix.to_string()
        } else {
            format!("{}{}", TASK_PREFIX, with_prefix)
        };

        let full2 = if without_prefix.starts_with(TASK_PREFIX) {
            without_prefix.to_string()
        } else {
            format!("{}{}", TASK_PREFIX, without_prefix)
        };

        assert_eq!(full1, "Evedoo_test");
        assert_eq!(full2, "Evedoo_test");
    }
}

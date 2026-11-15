//! Pure helpers for the one-shot CLI mutation subcommands (`task-start`,
//! `task-finish`, `task-handoff`).
//!
//! These subcommands exist so a non-MCP caller — Evedoo Studio's dev-server
//! today — can append a task-state event through the same `Store::append()`
//! path an MCP tool call uses: the same `fs4` advisory lock, the same
//! `current_actor()` attribution from `EVEDOO_TASKSTATE_RUNTIME`, and the
//! same `CURRENT.md` regeneration. Before this module existed, Evedoo
//! Studio wrote `tasks.jsonl` directly with `fs.appendFileSync`, bypassing
//! the lock, hardcoding attribution to `"antigravity-studio"` regardless of
//! who actually acted, and never touching `CURRENT.md` — so the rendered
//! fallback silently went stale the moment anyone used the Studio UI.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::model::Outcome;

/// Parse a CLI `--outcome` value into the model's `Outcome` enum.
///
/// Matches exactly the strings `Outcome`'s `#[serde(rename_all =
/// "snake_case")]` produces, so a value copied from JSON output (e.g. from
/// `task_state`) or from this project's own MCP tool descriptions works
/// unchanged on the command line.
///
/// An unrecognised value is an ERROR, not a silent fallback. FR-72 in the
/// scanner CLI established the same principle for `--sort`: a typo in an
/// argument must fail loudly, not be quietly absorbed into a default that
/// looks like it worked.
pub fn parse_outcome(s: &str) -> Result<Outcome, String> {
    match s {
        "done" => Ok(Outcome::Done),
        "done_with_concerns" => Ok(Outcome::DoneWithConcerns),
        "blocked" => Ok(Outcome::Blocked),
        "abandoned" => Ok(Outcome::Abandoned),
        other => Err(format!(
            "invalid --outcome {other:?}: expected one of \
             done, done_with_concerns, blocked, abandoned"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_valid_outcome_value() {
        assert_eq!(parse_outcome("done"), Ok(Outcome::Done));
        assert_eq!(parse_outcome("done_with_concerns"), Ok(Outcome::DoneWithConcerns));
        assert_eq!(parse_outcome("blocked"), Ok(Outcome::Blocked));
        assert_eq!(parse_outcome("abandoned"), Ok(Outcome::Abandoned));
    }

    /// FR-72's principle, applied here: an unrecognised outcome must be a
    /// loud error naming the valid options, not a silent default.
    #[test]
    fn rejects_an_unrecognised_value_with_a_helpful_error() {
        let err = parse_outcome("Done").unwrap_err(); // wrong case
        assert!(err.contains("Done"), "error should echo back what was typed");
        assert!(err.contains("done"), "error should list a valid option");
        assert!(err.contains("done_with_concerns"));
        assert!(err.contains("blocked"));
        assert!(err.contains("abandoned"));

        assert!(parse_outcome("").is_err());
        assert!(parse_outcome("complete").is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Actor {
    pub runtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

impl Actor {
    pub fn new(runtime: impl Into<String>) -> Self {
        Self {
            runtime: runtime.into(),
            agent_id: None,
        }
    }

    pub fn with_agent_id(runtime: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            runtime: runtime.into(),
            agent_id: Some(agent_id.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Done,
    DoneWithConcerns,
    Blocked,
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    ChangesRequested,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    PhaseOpened {
        phase: String,
        title: String,
        goal: String,
    },
    TaskDeclared {
        task: String,
        phase: String,
        title: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        depends_on: Vec<String>,
        #[serde(default = "default_true")]
        review_required: bool,
    },
    TaskStarted {
        task: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    TaskFinished {
        task: String,
        outcome: Outcome,
        summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commit: Option<String>,
    },
    ReviewRecorded {
        task: String,
        verdict: Verdict,
        note: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        concerns: Vec<String>,
    },
    RulingRecorded {
        subject: String,
        decision: String,
        rationale: String,
        cost_if_wrong: String,
    },
    HandoffRequested {
        to: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task: Option<String>,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Record {
    pub timestamp: DateTime<Utc>,
    pub by: Actor,
    #[serde(flatten)]
    pub event: Event,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Declared,
    InProgress,
    InReview,
    Closed,
    Blocked,
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PhaseSummary {
    pub phase: String,
    pub title: String,
    pub goal: String,
    pub opened_at: DateTime<Utc>,
    pub opened_by: Actor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TaskSummary {
    pub task: String,
    pub phase: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default = "default_true")]
    pub review_required: bool,
    pub status: TaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concerns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HandoffSummary {
    pub from: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RulingSummary {
    pub subject: String,
    pub decision: String,
    pub rationale: String,
    pub cost_if_wrong: String,
    pub by: Actor,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_phase: Option<PhaseSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_progress: Vec<TaskSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_review: Vec<TaskSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<TaskSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_done: Option<TaskSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_handoff: Option<HandoffSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_rulings: Vec<RulingSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recently_closed: Vec<TaskSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_tasks: Vec<TaskSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_serde_round_trip() {
        let ts = "2026-08-28T04:40:11Z".parse::<DateTime<Utc>>().unwrap();
        let record = Record {
            timestamp: ts,
            by: Actor::with_agent_id("claude-code", "agent-007"),
            event: Event::HandoffRequested {
                to: "antigravity".to_string(),
                task: Some("P21-T1".to_string()),
                reason: "cross-runtime verification".to_string(),
                note: Some("check store".to_string()),
            },
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_additive_compatibility_defaults() {
        let json = r#"{
            "timestamp": "2026-08-28T02:00:00Z",
            "by": { "runtime": "antigravity" },
            "type": "task_declared",
            "task": "P20-T1",
            "phase": "P20",
            "title": "Initial Task"
        }"#;

        let record: Record = serde_json::from_str(json).unwrap();
        assert_eq!(record.by.runtime, "antigravity");
        assert_eq!(record.by.agent_id, None);
        if let Event::TaskDeclared {
            task,
            phase,
            title,
            description,
            depends_on,
            review_required,
        } = record.event
        {
            assert_eq!(task, "P20-T1");
            assert_eq!(phase, "P20");
            assert_eq!(title, "Initial Task");
            assert_eq!(description, None);
            assert!(depends_on.is_empty());
            assert!(review_required);
        } else {
            panic!("Expected TaskDeclared event");
        }
    }

    #[test]
    fn test_outcome_and_verdict_serde() {
        assert_eq!(
            serde_json::to_string(&Outcome::DoneWithConcerns).unwrap(),
            "\"done_with_concerns\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::ChangesRequested).unwrap(),
            "\"changes_requested\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::InReview).unwrap(),
            "\"in_review\""
        );
    }
}

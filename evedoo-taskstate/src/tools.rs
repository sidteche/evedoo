// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::path::PathBuf;

use chrono::Utc;
use rmcp::{
    Json, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::{Actor, Event, Outcome, Record, State, Verdict};
use crate::store::Store;

pub fn current_actor() -> Actor {
    let runtime = std::env::var("EVEDOO_TASKSTATE_RUNTIME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    Actor::new(runtime)
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TaskDeclareParams {
    #[schemars(description = "Task ID, e.g. 'P20-T1'")]
    pub task: String,
    #[schemars(description = "Phase ID, e.g. 'P20'")]
    pub phase: String,
    #[schemars(description = "Human-readable task title")]
    pub title: String,
    #[serde(default)]
    #[schemars(description = "Optional detailed task description")]
    pub description: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional list of prerequisite task IDs that must be closed before this task is next")]
    pub depends_on: Option<Vec<String>>,
    #[serde(default)]
    #[schemars(description = "Whether this task requires a review to close (defaults to true)")]
    pub review_required: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TaskStartParams {
    #[schemars(description = "Task ID to start, e.g. 'P20-T1'")]
    pub task: String,
    #[serde(default)]
    #[schemars(description = "Optional note on what is being started")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TaskFinishParams {
    #[schemars(description = "Task ID, e.g. 'P20-T1'")]
    pub task: String,
    #[schemars(description = "Outcome of the task: 'done', 'done_with_concerns', 'blocked', or 'abandoned'")]
    pub outcome: Outcome,
    #[schemars(description = "Summary of the completed work or reason")]
    pub summary: String,
    #[serde(default)]
    #[schemars(description = "Optional git commit hash associated with the finish")]
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TaskReviewParams {
    #[schemars(description = "Task ID under review, e.g. 'P20-T1'")]
    pub task: String,
    #[schemars(description = "Verdict: 'clean', 'changes_requested', or 'blocked'")]
    pub verdict: Verdict,
    #[schemars(description = "Review note explaining the verdict")]
    pub note: String,
    #[serde(default)]
    #[schemars(description = "Optional list of specific concerns")]
    pub concerns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TaskRulingParams {
    #[schemars(description = "Subject of the ruling")]
    pub subject: String,
    #[schemars(description = "Decision reached")]
    pub decision: String,
    #[schemars(description = "Rationale for the decision")]
    pub rationale: String,
    #[schemars(description = "Cost or rollback path if the ruling is wrong")]
    pub cost_if_wrong: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct TaskHistoryParams {
    #[serde(default)]
    #[schemars(description = "Maximum number of matching records to return (most recent first if limited)")]
    pub limit: Option<usize>,
    #[serde(default)]
    #[schemars(description = "Filter records by phase name, e.g. 'P20'")]
    pub phase: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TaskHandoffParams {
    #[schemars(description = "Target runtime receiving handoff: e.g. 'claude-code' or 'antigravity'")]
    pub to: String,
    #[serde(default)]
    #[schemars(description = "Optional task ID to hand off, e.g. 'P21-T1'")]
    pub task: Option<String>,
    #[schemars(description = "Reason for handoff")]
    pub reason: String,
    #[serde(default)]
    #[schemars(description = "Optional additional note for the receiving runtime")]
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TaskStateServer {
    state_dir: Option<PathBuf>,
    tool_router: ToolRouter<Self>,
}

impl TaskStateServer {
    pub fn new() -> Self {
        Self {
            state_dir: None,
            tool_router: Self::tool_router(),
        }
    }

    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        Self {
            state_dir: Some(state_dir),
            tool_router: Self::tool_router(),
        }
    }

    fn store(&self) -> io::Result<Store> {
        if let Some(dir) = &self.state_dir {
            Ok(Store::new(dir.clone()))
        } else {
            Store::discover()
        }
    }
}

impl Default for TaskStateServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router(router = tool_router)]
impl TaskStateServer {
    #[tool(
        name = "task_state",
        description = "Get the current folded task state derived from tasks.jsonl"
    )]
    pub async fn task_state(&self) -> Result<Json<State>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let state = store.fold_state().map_err(|e| e.to_string())?;
        Ok(Json(state))
    }

    #[tool(
        name = "task_declare",
        description = "Declare a new task in a phase"
    )]
    pub async fn task_declare(
        &self,
        Parameters(params): Parameters<TaskDeclareParams>,
    ) -> Result<Json<State>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let record = Record {
            timestamp: Utc::now(),
            by: current_actor(),
            event: Event::TaskDeclared {
                task: params.task,
                phase: params.phase,
                title: params.title,
                description: params.description,
                depends_on: params.depends_on.unwrap_or_default(),
                review_required: params.review_required.unwrap_or(true),
            },
        };
        let state = store.append(&record).map_err(|e| e.to_string())?;
        Ok(Json(state))
    }

    #[tool(
        name = "task_start",
        description = "Mark a task as in progress"
    )]
    pub async fn task_start(
        &self,
        Parameters(params): Parameters<TaskStartParams>,
    ) -> Result<Json<State>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let record = Record {
            timestamp: Utc::now(),
            by: current_actor(),
            event: Event::TaskStarted {
                task: params.task,
                note: params.note,
            },
        };
        let state = store.append(&record).map_err(|e| e.to_string())?;
        Ok(Json(state))
    }

    #[tool(
        name = "task_finish",
        description = "Mark a task as finished (moves to in_review if review_required, or closed if no review required)"
    )]
    pub async fn task_finish(
        &self,
        Parameters(params): Parameters<TaskFinishParams>,
    ) -> Result<Json<State>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let record = Record {
            timestamp: Utc::now(),
            by: current_actor(),
            event: Event::TaskFinished {
                task: params.task,
                outcome: params.outcome,
                summary: params.summary,
                commit: params.commit,
            },
        };
        let state = store.append(&record).map_err(|e| e.to_string())?;
        Ok(Json(state))
    }

    #[tool(
        name = "task_review",
        description = "Record a review verdict on a finished task (clean closes the task)"
    )]
    pub async fn task_review(
        &self,
        Parameters(params): Parameters<TaskReviewParams>,
    ) -> Result<Json<State>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let record = Record {
            timestamp: Utc::now(),
            by: current_actor(),
            event: Event::ReviewRecorded {
                task: params.task,
                verdict: params.verdict,
                note: params.note,
                concerns: params.concerns.unwrap_or_default(),
            },
        };
        let state = store.append(&record).map_err(|e| e.to_string())?;
        Ok(Json(state))
    }

    #[tool(
        name = "task_ruling",
        description = "Record an architectural or operational ruling"
    )]
    pub async fn task_ruling(
        &self,
        Parameters(params): Parameters<TaskRulingParams>,
    ) -> Result<Json<State>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let record = Record {
            timestamp: Utc::now(),
            by: current_actor(),
            event: Event::RulingRecorded {
                subject: params.subject,
                decision: params.decision,
                rationale: params.rationale,
                cost_if_wrong: params.cost_if_wrong,
            },
        };
        let state = store.append(&record).map_err(|e| e.to_string())?;
        Ok(Json(state))
    }

    #[tool(
        name = "task_history",
        description = "List recorded event history with optional phase filtering and limit"
    )]
    pub async fn task_history(
        &self,
        Parameters(params): Parameters<TaskHistoryParams>,
    ) -> Result<Json<Vec<Record>>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let records = store.read_records().map_err(|e| e.to_string())?;

        let mut filtered: Vec<Record> = if let Some(target_phase) = &params.phase {
            let mut task_phase_map: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for r in &records {
                if let Event::TaskDeclared { task, phase, .. } = &r.event {
                    task_phase_map.insert(task.clone(), phase.clone());
                }
            }

            records
                .into_iter()
                .filter(|r| match &r.event {
                    Event::PhaseOpened { phase, .. } => phase == target_phase,
                    Event::TaskDeclared { phase, .. } => phase == target_phase,
                    Event::TaskStarted { task, .. } => task_phase_map
                        .get(task)
                        .map_or_else(|| task.starts_with(target_phase), |p| p == target_phase),
                    Event::TaskFinished { task, .. } => task_phase_map
                        .get(task)
                        .map_or_else(|| task.starts_with(target_phase), |p| p == target_phase),
                    Event::ReviewRecorded { task, .. } => task_phase_map
                        .get(task)
                        .map_or_else(|| task.starts_with(target_phase), |p| p == target_phase),
                    Event::RulingRecorded { .. } => false,
                    Event::HandoffRequested { task, .. } => task
                        .as_ref()
                        .map(|t| {
                            task_phase_map
                                .get(t)
                                .map_or_else(|| t.starts_with(target_phase), |p| p == target_phase)
                        })
                        .unwrap_or(false),
                })
                .collect()
        } else {
            records
        };

        if let Some(limit) = params.limit
            && filtered.len() > limit
        {
            filtered = filtered.split_off(filtered.len() - limit);
        }

        Ok(Json(filtered))
    }

    #[tool(
        name = "task_handoff",
        description = "Request handoff of task or context to another runtime (e.g. claude-code or antigravity)"
    )]
    pub async fn task_handoff(
        &self,
        Parameters(params): Parameters<TaskHandoffParams>,
    ) -> Result<Json<State>, String> {
        let store = self.store().map_err(|e| e.to_string())?;
        let record = Record {
            timestamp: Utc::now(),
            by: current_actor(),
            event: Event::HandoffRequested {
                to: params.to,
                task: params.task,
                reason: params.reason,
                note: params.note,
            },
        };
        let state = store.append(&record).map_err(|e| e.to_string())?;
        Ok(Json(state))
    }
}

#[tool_handler(
    name = "evedoo-taskstate",
    version = "0.1.0",
    instructions = "Shared agent task state management for Evedoo across Claude Code and Antigravity",
    router = self.tool_router
)]
impl ServerHandler for TaskStateServer {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Mutex;

    use super::*;
    use crate::model::TaskStatus;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_store() -> (PathBuf, TaskStateServer) {
        let dir = std::env::temp_dir().join(format!(
            "test_taskstate_tools_{}",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let server = TaskStateServer::with_state_dir(dir.clone());
        (dir, server)
    }

    #[tokio::test]
    async fn test_tool_workflow_end_to_end() {
        let (dir, server) = temp_store();

        // 1. Initial state empty
        let Json(state) = server.task_state().await.unwrap();
        assert_eq!(state.all_tasks.len(), 0);

        // 2. Declare task
        let Json(state) = server
            .task_declare(Parameters(TaskDeclareParams {
                task: "P20-T1".to_string(),
                phase: "P20".to_string(),
                title: "Build taskstate MCP".to_string(),
                description: Some("Implement tools and main".to_string()),
                depends_on: None,
                review_required: Some(true),
            }))
            .await
            .unwrap();
        assert_eq!(state.next.as_ref().unwrap().task, "P20-T1");

        // 3. Start task
        let Json(state) = server
            .task_start(Parameters(TaskStartParams {
                task: "P20-T1".to_string(),
                note: Some("Writing tools.rs".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(state.in_progress.len(), 1);
        assert_eq!(state.in_progress[0].task, "P20-T1");

        // 4. Finish task
        let Json(state) = server
            .task_finish(Parameters(TaskFinishParams {
                task: "P20-T1".to_string(),
                outcome: Outcome::Done,
                summary: "Tools implemented".to_string(),
                commit: Some("1234567".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(state.in_progress.len(), 0);
        assert_eq!(state.in_review.len(), 1);

        // 5. Review task
        let Json(state) = server
            .task_review(Parameters(TaskReviewParams {
                task: "P20-T1".to_string(),
                verdict: Verdict::Clean,
                note: "Looks solid".to_string(),
                concerns: None,
            }))
            .await
            .unwrap();
        assert_eq!(state.in_review.len(), 0);
        assert_eq!(state.last_done.as_ref().unwrap().task, "P20-T1");
        assert_eq!(state.last_done.as_ref().unwrap().status, TaskStatus::Closed);

        // 6. Record ruling
        let Json(state) = server
            .task_ruling(Parameters(TaskRulingParams {
                subject: "Storage Backend".to_string(),
                decision: "JSONL".to_string(),
                rationale: "Reviewable and git mergeable".to_string(),
                cost_if_wrong: "Low".to_string(),
            }))
            .await
            .unwrap();
        assert_eq!(state.recent_rulings.len(), 1);
        assert_eq!(state.recent_rulings[0].subject, "Storage Backend");

        // 7. Request handoff
        let Json(state) = server
            .task_handoff(Parameters(TaskHandoffParams {
                to: "claude-code".to_string(),
                task: Some("P20-T2".to_string()),
                reason: "Cross-runtime verification".to_string(),
                note: Some("Check stdio".to_string()),
            }))
            .await
            .unwrap();
        assert!(state.pending_handoff.is_some());
        assert_eq!(state.pending_handoff.as_ref().unwrap().to, "claude-code");

        // 8. History
        let Json(history) = server
            .task_history(Parameters(TaskHistoryParams {
                limit: Some(3),
                phase: None,
            }))
            .await
            .unwrap();
        assert_eq!(history.len(), 3);

        let Json(phase_history) = server
            .task_history(Parameters(TaskHistoryParams {
                limit: None,
                phase: Some("P20".to_string()),
            }))
            .await
            .unwrap();
        assert!(phase_history.len() >= 4);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_router_exposes_all_eight_tools() {
        let tools = TaskStateServer::tool_router().list_all();
        let tool_names: Vec<String> = tools.into_iter().map(|t| t.name.to_string()).collect();

        assert_eq!(tool_names.len(), 8);
        assert!(tool_names.contains(&"task_state".to_string()));
        assert!(tool_names.contains(&"task_declare".to_string()));
        assert!(tool_names.contains(&"task_start".to_string()));
        assert!(tool_names.contains(&"task_finish".to_string()));
        assert!(tool_names.contains(&"task_review".to_string()));
        assert!(tool_names.contains(&"task_ruling".to_string()));
        assert!(tool_names.contains(&"task_history".to_string()));
        assert!(tool_names.contains(&"task_handoff".to_string()));
    }

    #[test]
    fn test_current_actor_runtime_env() {
        let _guard = ENV_LOCK.lock().unwrap();

        // Unset env var -> default to unknown
        unsafe {
            std::env::remove_var("EVEDOO_TASKSTATE_RUNTIME");
        }
        assert_eq!(current_actor().runtime, "unknown");

        // Empty env var -> default to unknown
        unsafe {
            std::env::set_var("EVEDOO_TASKSTATE_RUNTIME", "   ");
        }
        assert_eq!(current_actor().runtime, "unknown");

        // Set env var -> uses specified runtime
        unsafe {
            std::env::set_var("EVEDOO_TASKSTATE_RUNTIME", "claude-code");
        }
        assert_eq!(current_actor().runtime, "claude-code");

        unsafe {
            std::env::remove_var("EVEDOO_TASKSTATE_RUNTIME");
        }
    }
}

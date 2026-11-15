// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::model::{
    Event, HandoffSummary, Outcome, PhaseSummary, Record, RulingSummary, State, TaskStatus,
    TaskSummary, Verdict,
};

pub fn fold(records: &[Record]) -> State {
    let mut sorted_records: Vec<&Record> = records.iter().collect();
    sorted_records.sort_by_key(|r| r.timestamp);

    let mut active_phase: Option<PhaseSummary> = None;
    let mut task_keys: Vec<String> = Vec::new();
    let mut tasks: HashMap<String, TaskSummary> = HashMap::new();
    let mut handoffs: Vec<HandoffSummary> = Vec::new();
    let mut recent_rulings: Vec<RulingSummary> = Vec::new();

    for record in &sorted_records {
        match &record.event {
            Event::PhaseOpened { phase, title, goal } => {
                active_phase = Some(PhaseSummary {
                    phase: phase.clone(),
                    title: title.clone(),
                    goal: goal.clone(),
                    opened_at: record.timestamp,
                    opened_by: record.by.clone(),
                });
            }
            Event::TaskDeclared {
                task,
                phase,
                title,
                description,
                depends_on,
                review_required,
            } => {
                if !task_keys.contains(task) {
                    task_keys.push(task.clone());
                }
                let summary = TaskSummary {
                    task: task.clone(),
                    phase: phase.clone(),
                    title: title.clone(),
                    description: description.clone(),
                    depends_on: depends_on.clone(),
                    review_required: *review_required,
                    status: TaskStatus::Declared,
                    by: Some(record.by.clone()),
                    outcome: None,
                    verdict: None,
                    summary: None,
                    note: None,
                    commit: None,
                    concerns: Vec::new(),
                    updated_at: Some(record.timestamp),
                    closed_at: None,
                };
                tasks.insert(task.clone(), summary);
            }
            Event::TaskStarted { task, note } => {
                let default_phase = active_phase
                    .as_ref()
                    .map(|p| p.phase.clone())
                    .unwrap_or_default();
                let t = tasks.entry(task.clone()).or_insert_with(|| {
                    task_keys.push(task.clone());
                    TaskSummary {
                        task: task.clone(),
                        phase: default_phase,
                        title: task.clone(),
                        description: None,
                        depends_on: Vec::new(),
                        review_required: true,
                        status: TaskStatus::InProgress,
                        by: Some(record.by.clone()),
                        outcome: None,
                        verdict: None,
                        summary: None,
                        note: None,
                        commit: None,
                        concerns: Vec::new(),
                        updated_at: Some(record.timestamp),
                        closed_at: None,
                    }
                });
                t.status = TaskStatus::InProgress;
                t.by = Some(record.by.clone());
                t.note = note.clone();
                t.outcome = None;
                t.verdict = None;
                t.updated_at = Some(record.timestamp);
                t.closed_at = None;
            }
            Event::TaskFinished {
                task,
                outcome,
                summary,
                commit,
            } => {
                let default_phase = active_phase
                    .as_ref()
                    .map(|p| p.phase.clone())
                    .unwrap_or_default();
                let t = tasks.entry(task.clone()).or_insert_with(|| {
                    task_keys.push(task.clone());
                    TaskSummary {
                        task: task.clone(),
                        phase: default_phase,
                        title: task.clone(),
                        description: None,
                        depends_on: Vec::new(),
                        review_required: true,
                        status: TaskStatus::InReview,
                        by: Some(record.by.clone()),
                        outcome: None,
                        verdict: None,
                        summary: None,
                        note: None,
                        commit: None,
                        concerns: Vec::new(),
                        updated_at: Some(record.timestamp),
                        closed_at: None,
                    }
                });
                t.outcome = Some(*outcome);
                t.summary = Some(summary.clone());
                t.commit = commit.clone();
                t.by = Some(record.by.clone());
                t.updated_at = Some(record.timestamp);

                match outcome {
                    Outcome::Done | Outcome::DoneWithConcerns => {
                        if !t.review_required {
                            t.status = TaskStatus::Closed;
                            t.closed_at = Some(record.timestamp);
                        } else {
                            t.status = TaskStatus::InReview;
                            t.closed_at = None;
                        }
                    }
                    Outcome::Blocked => {
                        t.status = TaskStatus::Blocked;
                        t.closed_at = None;
                    }
                    Outcome::Abandoned => {
                        t.status = TaskStatus::Abandoned;
                        t.closed_at = None;
                    }
                }
            }
            Event::ReviewRecorded {
                task,
                verdict,
                note,
                concerns,
            } => {
                let default_phase = active_phase
                    .as_ref()
                    .map(|p| p.phase.clone())
                    .unwrap_or_default();
                let t = tasks.entry(task.clone()).or_insert_with(|| {
                    task_keys.push(task.clone());
                    TaskSummary {
                        task: task.clone(),
                        phase: default_phase,
                        title: task.clone(),
                        description: None,
                        depends_on: Vec::new(),
                        review_required: true,
                        status: TaskStatus::InReview,
                        by: Some(record.by.clone()),
                        outcome: None,
                        verdict: None,
                        summary: None,
                        note: None,
                        commit: None,
                        concerns: Vec::new(),
                        updated_at: Some(record.timestamp),
                        closed_at: None,
                    }
                });
                t.verdict = Some(*verdict);
                t.note = Some(note.clone());
                t.concerns = concerns.clone();
                t.by = Some(record.by.clone());
                t.updated_at = Some(record.timestamp);

                match verdict {
                    Verdict::Clean => {
                        if matches!(
                            t.outcome,
                            Some(Outcome::Done) | Some(Outcome::DoneWithConcerns)
                        ) {
                            t.status = TaskStatus::Closed;
                            t.closed_at = Some(record.timestamp);
                        }
                    }
                    Verdict::ChangesRequested => {
                        t.status = TaskStatus::InReview;
                        t.closed_at = None;
                    }
                    Verdict::Blocked => {
                        t.status = TaskStatus::Blocked;
                        t.closed_at = None;
                    }
                }
            }
            Event::RulingRecorded {
                subject,
                decision,
                rationale,
                cost_if_wrong,
            } => {
                recent_rulings.push(RulingSummary {
                    subject: subject.clone(),
                    decision: decision.clone(),
                    rationale: rationale.clone(),
                    cost_if_wrong: cost_if_wrong.clone(),
                    by: record.by.clone(),
                    at: record.timestamp,
                });
            }
            Event::HandoffRequested {
                to,
                task,
                reason,
                note,
            } => {
                handoffs.push(HandoffSummary {
                    from: record.by.runtime.clone(),
                    to: to.clone(),
                    task: task.clone(),
                    reason: reason.clone(),
                    note: note.clone(),
                    at: record.timestamp,
                });
            }
        }
    }

    let all_tasks: Vec<TaskSummary> = task_keys
        .iter()
        .filter_map(|k| tasks.get(k).cloned())
        .collect();

    let in_progress: Vec<TaskSummary> = all_tasks
        .iter()
        .filter(|t| t.status == TaskStatus::InProgress)
        .cloned()
        .collect();

    let in_review: Vec<TaskSummary> = all_tasks
        .iter()
        .filter(|t| t.status == TaskStatus::InReview)
        .cloned()
        .collect();

    let mut recently_closed: Vec<TaskSummary> = all_tasks
        .iter()
        .filter(|t| t.status == TaskStatus::Closed)
        .cloned()
        .collect();
    recently_closed.sort_by_key(|a| std::cmp::Reverse(a.closed_at));

    let last_done = recently_closed.first().cloned();

    let is_task_closed =
        |task_id: &str| -> bool { tasks.get(task_id).is_some_and(|t| t.status == TaskStatus::Closed) };

    let next = all_tasks
        .iter()
        .find(|t| {
            t.status == TaskStatus::Declared && t.depends_on.iter().all(|dep| is_task_closed(dep))
        })
        .cloned();

    let pending_handoff = if let Some(h) = handoffs.last() {
        let satisfied = sorted_records.iter().any(|r| {
            if r.timestamp > h.at && r.by.runtime == h.to {
                if let Event::TaskStarted { task, .. } = &r.event {
                    if let Some(target_task) = &h.task {
                        task == target_task
                    } else {
                        true
                    }
                } else {
                    false
                }
            } else {
                false
            }
        });

        if !satisfied {
            Some(h.clone())
        } else {
            None
        }
    } else {
        None
    };

    if recent_rulings.len() > 5 {
        let start = recent_rulings.len() - 5;
        recent_rulings = recent_rulings.split_off(start);
    }

    State {
        active_phase,
        in_progress,
        in_review,
        next,
        last_done,
        pending_handoff,
        recent_rulings,
        recently_closed,
        all_tasks,
        store_path: None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::model::*;

    fn dt(s: &str) -> DateTime<Utc> {
        s.parse::<DateTime<Utc>>().unwrap()
    }

    #[test]
    fn test_fold_empty() {
        let state = fold(&[]);
        assert_eq!(state.active_phase, None);
        assert!(state.in_progress.is_empty());
        assert!(state.in_review.is_empty());
        assert_eq!(state.next, None);
        assert_eq!(state.last_done, None);
        assert_eq!(state.pending_handoff, None);
        assert!(state.recent_rulings.is_empty());
        assert!(state.recently_closed.is_empty());
    }

    #[test]
    fn test_fold_single_task_lifecycle() {
        let records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("antigravity"),
                event: Event::PhaseOpened {
                    phase: "P20".to_string(),
                    title: "Operationalisation".to_string(),
                    goal: "Get everything green".to_string(),
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:05:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: "P20-T1".to_string(),
                    phase: "P20".to_string(),
                    title: "Implement Task".to_string(),
                    description: Some("Task description".to_string()),
                    depends_on: vec![],
                    review_required: true,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:10:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskStarted {
                    task: "P20-T1".to_string(),
                    note: Some("Starting now".to_string()),
                },
            },
        ];

        let state = fold(&records);
        assert_eq!(state.in_progress.len(), 1);
        assert_eq!(state.in_progress[0].task, "P20-T1");
        assert_eq!(state.in_progress[0].by.as_ref().unwrap().runtime, "antigravity");
        assert_eq!(state.next, None);

        let mut records2 = records.clone();
        records2.push(Record {
            timestamp: dt("2026-08-28T01:20:00Z"),
            by: Actor::new("claude-code"),
            event: Event::TaskFinished {
                task: "P20-T1".to_string(),
                outcome: Outcome::Done,
                summary: "Implementation complete".to_string(),
                commit: Some("abcdef1".to_string()),
            },
        });

        let state2 = fold(&records2);
        assert!(state2.in_progress.is_empty());
        assert_eq!(state2.in_review.len(), 1);
        assert_eq!(state2.in_review[0].task, "P20-T1");
        assert_eq!(state2.last_done, None);

        let mut records3 = records2.clone();
        records3.push(Record {
            timestamp: dt("2026-08-28T01:30:00Z"),
            by: Actor::new("claude-code"),
            event: Event::ReviewRecorded {
                task: "P20-T1".to_string(),
                verdict: Verdict::Clean,
                note: "Looks great".to_string(),
                concerns: vec![],
            },
        });

        let state3 = fold(&records3);
        assert!(state3.in_progress.is_empty());
        assert!(state3.in_review.is_empty());
        assert_eq!(state3.last_done.as_ref().unwrap().task, "P20-T1");
        assert_eq!(state3.last_done.as_ref().unwrap().by.as_ref().unwrap().runtime, "claude-code");
        assert_eq!(state3.recently_closed.len(), 1);
    }

    #[test]
    fn test_fold_no_review_required() {
        let records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: "AUTO-1".to_string(),
                    phase: "P20".to_string(),
                    title: "Quick Fix".to_string(),
                    description: None,
                    depends_on: vec![],
                    review_required: false,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:05:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskStarted {
                    task: "AUTO-1".to_string(),
                    note: None,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:10:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskFinished {
                    task: "AUTO-1".to_string(),
                    outcome: Outcome::Done,
                    summary: "Done without review".to_string(),
                    commit: None,
                },
            },
        ];

        let state = fold(&records);
        assert!(state.in_progress.is_empty());
        assert!(state.in_review.is_empty());
        assert_eq!(state.last_done.as_ref().unwrap().task, "AUTO-1");
        assert_eq!(state.last_done.as_ref().unwrap().status, TaskStatus::Closed);
    }

    #[test]
    fn test_fold_changes_requested_cycle() {
        let records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: "P20-T1".to_string(),
                    phase: "P20".to_string(),
                    title: "Task with revision".to_string(),
                    description: None,
                    depends_on: vec![],
                    review_required: true,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:05:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskStarted {
                    task: "P20-T1".to_string(),
                    note: None,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:10:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskFinished {
                    task: "P20-T1".to_string(),
                    outcome: Outcome::Done,
                    summary: "Round 1".to_string(),
                    commit: None,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:15:00Z"),
                by: Actor::new("claude-code"),
                event: Event::ReviewRecorded {
                    task: "P20-T1".to_string(),
                    verdict: Verdict::ChangesRequested,
                    note: "Needs unit test".to_string(),
                    concerns: vec!["Missing coverage".to_string()],
                },
            },
        ];

        let state = fold(&records);
        assert_eq!(state.in_review.len(), 1);
        assert_eq!(state.last_done, None);

        let mut records2 = records.clone();
        records2.push(Record {
            timestamp: dt("2026-08-28T01:20:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskStarted {
                task: "P20-T1".to_string(),
                note: Some("Addressing review".to_string()),
            },
        });
        let state2 = fold(&records2);
        assert_eq!(state2.in_progress.len(), 1);
        assert!(state2.in_review.is_empty());

        records2.push(Record {
            timestamp: dt("2026-08-28T01:25:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskFinished {
                task: "P20-T1".to_string(),
                outcome: Outcome::Done,
                summary: "Round 2 with test".to_string(),
                commit: None,
            },
        });
        records2.push(Record {
            timestamp: dt("2026-08-28T01:30:00Z"),
            by: Actor::new("claude-code"),
            event: Event::ReviewRecorded {
                task: "P20-T1".to_string(),
                verdict: Verdict::Clean,
                note: "LGTM".to_string(),
                concerns: vec![],
            },
        });
        let state3 = fold(&records2);
        assert!(state3.in_progress.is_empty());
        assert!(state3.in_review.is_empty());
        assert_eq!(state3.last_done.as_ref().unwrap().task, "P20-T1");
    }

    #[test]
    fn test_fold_dependencies_and_next() {
        let records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: "T1".to_string(),
                    phase: "P20".to_string(),
                    title: "First".to_string(),
                    description: None,
                    depends_on: vec![],
                    review_required: true,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:01:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: "T2".to_string(),
                    phase: "P20".to_string(),
                    title: "Second".to_string(),
                    description: None,
                    depends_on: vec!["T1".to_string()],
                    review_required: true,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:02:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: "T3".to_string(),
                    phase: "P20".to_string(),
                    title: "Third".to_string(),
                    description: None,
                    depends_on: vec!["T2".to_string()],
                    review_required: true,
                },
            },
        ];

        let state = fold(&records);
        assert_eq!(state.next.as_ref().unwrap().task, "T1");

        let mut records2 = records.clone();
        records2.push(Record {
            timestamp: dt("2026-08-28T01:05:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskStarted {
                task: "T1".to_string(),
                note: None,
            },
        });
        let state2 = fold(&records2);
        assert_eq!(state2.in_progress.len(), 1);
        assert_eq!(state2.next, None);

        records2.push(Record {
            timestamp: dt("2026-08-28T01:10:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskFinished {
                task: "T1".to_string(),
                outcome: Outcome::Done,
                summary: "Done T1".to_string(),
                commit: None,
            },
        });
        records2.push(Record {
            timestamp: dt("2026-08-28T01:15:00Z"),
            by: Actor::new("claude-code"),
            event: Event::ReviewRecorded {
                task: "T1".to_string(),
                verdict: Verdict::Clean,
                note: "Clean".to_string(),
                concerns: vec![],
            },
        });
        let state3 = fold(&records2);
        assert_eq!(state3.last_done.as_ref().unwrap().task, "T1");
        assert_eq!(state3.next.as_ref().unwrap().task, "T2");
    }

    #[test]
    fn test_fold_out_of_order_records() {
        let r1 = Record {
            timestamp: dt("2026-08-28T01:00:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskDeclared {
                task: "T1".to_string(),
                phase: "P20".to_string(),
                title: "First".to_string(),
                description: None,
                depends_on: vec![],
                review_required: false,
            },
        };
        let r2 = Record {
            timestamp: dt("2026-08-28T01:05:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskStarted {
                task: "T1".to_string(),
                note: None,
            },
        };
        let r3 = Record {
            timestamp: dt("2026-08-28T01:10:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskFinished {
                task: "T1".to_string(),
                outcome: Outcome::Done,
                summary: "Done".to_string(),
                commit: None,
            },
        };

        let in_order = fold(&[r1.clone(), r2.clone(), r3.clone()]);
        let out_of_order = fold(&[r3, r1, r2]);
        assert_eq!(in_order, out_of_order);
    }

    #[test]
    fn test_fold_handoff_lifecycle_and_invalidation() {
        let mut records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("claude-code"),
                event: Event::HandoffRequested {
                    to: "antigravity".to_string(),
                    task: Some("P21-T2".to_string()),
                    reason: "Need antigravity verification".to_string(),
                    note: Some("Check memory".to_string()),
                },
            },
        ];

        let state = fold(&records);
        let handoff = state.pending_handoff.as_ref().unwrap();
        assert_eq!(handoff.from, "claude-code");
        assert_eq!(handoff.to, "antigravity");
        assert_eq!(handoff.task.as_deref(), Some("P21-T2"));

        records.push(Record {
            timestamp: dt("2026-08-28T01:05:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskStarted {
                task: "P21-T1".to_string(),
                note: None,
            },
        });
        let state2 = fold(&records);
        assert!(state2.pending_handoff.is_some());

        records.push(Record {
            timestamp: dt("2026-08-28T01:10:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskStarted {
                task: "P21-T2".to_string(),
                note: None,
            },
        });
        let state3 = fold(&records);
        assert_eq!(state3.pending_handoff, None);
    }

    #[test]
    fn test_fold_untargeted_handoff() {
        let mut records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("claude-code"),
                event: Event::HandoffRequested {
                    to: "antigravity".to_string(),
                    task: None,
                    reason: "General handoff".to_string(),
                    note: None,
                },
            },
        ];

        let state = fold(&records);
        assert!(state.pending_handoff.is_some());

        records.push(Record {
            timestamp: dt("2026-08-28T01:05:00Z"),
            by: Actor::new("antigravity"),
            event: Event::TaskStarted {
                task: "ANY-TASK".to_string(),
                note: None,
            },
        });
        let state2 = fold(&records);
        assert_eq!(state2.pending_handoff, None);
    }

    #[test]
    fn test_fold_blocked_and_abandoned() {
        let records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: "T-BLOCK".to_string(),
                    phase: "P20".to_string(),
                    title: "Blocked task".to_string(),
                    description: None,
                    depends_on: vec![],
                    review_required: true,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:05:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskStarted {
                    task: "T-BLOCK".to_string(),
                    note: None,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:10:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskFinished {
                    task: "T-BLOCK".to_string(),
                    outcome: Outcome::Blocked,
                    summary: "External dependency down".to_string(),
                    commit: None,
                },
            },
        ];

        let state = fold(&records);
        assert!(state.in_progress.is_empty());
        assert!(state.in_review.is_empty());
        assert_eq!(state.last_done, None);
        assert_eq!(state.all_tasks[0].status, TaskStatus::Blocked);
    }

    #[test]
    fn test_fold_rulings_order_and_cap() {
        let mut records = Vec::new();
        for i in 1..=8 {
            records.push(Record {
                timestamp: dt(&format!("2026-08-28T01:{:02}:00Z", i)),
                by: Actor::new("claude-code"),
                event: Event::RulingRecorded {
                    subject: format!("Subj {}", i),
                    decision: format!("Dec {}", i),
                    rationale: format!("Rat {}", i),
                    cost_if_wrong: format!("Cost {}", i),
                },
            });
        }

        let state = fold(&records);
        assert_eq!(state.recent_rulings.len(), 5);
        assert_eq!(state.recent_rulings[0].subject, "Subj 4");
        assert_eq!(state.recent_rulings[4].subject, "Subj 8");
    }

    #[test]
    fn test_fold_review_recorded_unknown_task_auto_creates() {
        let records = vec![Record {
            timestamp: dt("2026-08-28T01:00:00Z"),
            by: Actor::new("antigravity"),
            event: Event::ReviewRecorded {
                task: "UNEXPECTED-1".to_string(),
                verdict: Verdict::ChangesRequested,
                note: "Needs rework".to_string(),
                concerns: vec!["Missing tests".to_string()],
            },
        }];

        let state = fold(&records);
        assert_eq!(state.in_review.len(), 1);
        assert_eq!(state.in_review[0].task, "UNEXPECTED-1");
        assert_eq!(state.in_review[0].verdict, Some(Verdict::ChangesRequested));
    }

    #[test]
    fn test_fold_superseded_handoff_not_surfaced_after_newer_satisfied() {
        let records = vec![
            Record {
                timestamp: dt("2026-08-28T01:00:00Z"),
                by: Actor::new("claude-code"),
                event: Event::HandoffRequested {
                    to: "antigravity".to_string(),
                    task: Some("OLD-TASK".to_string()),
                    reason: "Old handoff".to_string(),
                    note: None,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:10:00Z"),
                by: Actor::new("claude-code"),
                event: Event::HandoffRequested {
                    to: "antigravity".to_string(),
                    task: Some("NEW-TASK".to_string()),
                    reason: "Newer handoff".to_string(),
                    note: None,
                },
            },
            Record {
                timestamp: dt("2026-08-28T01:15:00Z"),
                by: Actor::new("antigravity"),
                event: Event::TaskStarted {
                    task: "NEW-TASK".to_string(),
                    note: None,
                },
            },
        ];

        let state = fold(&records);
        assert_eq!(state.pending_handoff, None);
    }
}

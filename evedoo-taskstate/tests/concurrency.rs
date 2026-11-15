// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use evedoo_taskstate::model::{Actor, Event, Outcome, Record, Verdict};
use evedoo_taskstate::store::Store;

fn append_with_retry(store: &Store, record: &Record) {
    let mut retries = 0;
    loop {
        match store.append(record) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                retries += 1;
                if retries > 100 {
                    panic!("Timed out acquiring lock after {} retries", retries);
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("Unexpected store append error: {:?}", e),
        }
    }
}

#[test]
fn test_concurrent_appends() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_taskstate_concurrency_{}",
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let store = Arc::new(Store::new(temp_dir.clone()));

    const NUM_THREADS: usize = 10;
    const RECORDS_PER_THREAD: usize = 10;
    const TOTAL_RECORDS: usize = NUM_THREADS * RECORDS_PER_THREAD;

    let base_time = Utc::now();
    let mut handles = Vec::new();

    for t in 0..NUM_THREADS {
        let store_clone = Arc::clone(&store);
        let handle = thread::spawn(move || {
            for r in 0..RECORDS_PER_THREAD {
                let offset_ms = (t * RECORDS_PER_THREAD + r) as i64 * 50;
                let record = Record {
                    timestamp: base_time + chrono::Duration::milliseconds(offset_ms),
                    by: Actor::with_agent_id(
                        if t % 2 == 0 {
                            "claude-code"
                        } else {
                            "antigravity"
                        },
                        format!("worker-{}", t),
                    ),
                    event: Event::TaskDeclared {
                        task: format!("CONC-T{}-{}", t, r),
                        phase: "CONCURRENCY".to_string(),
                        title: format!("Concurrent Task {} from thread {}", r, t),
                        description: Some(format!(
                            "Payload test data with special characters: !@#$%^&*() and thread={} rec={}",
                            t, r
                        )),
                        depends_on: vec![],
                        review_required: false,
                    },
                };

                append_with_retry(&store_clone, &record);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked during execution");
    }

    // 1. Verify tasks.jsonl raw contents: exactly 100 non-empty lines, each valid JSON
    let tasks_path = store.tasks_path();
    assert!(tasks_path.exists());

    let raw_content = fs::read_to_string(&tasks_path).unwrap();
    let raw_lines: Vec<&str> = raw_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        raw_lines.len(),
        TOTAL_RECORDS,
        "Expected exactly {} non-empty lines in tasks.jsonl, found {}",
        TOTAL_RECORDS,
        raw_lines.len()
    );

    for (idx, line) in raw_lines.iter().enumerate() {
        let parsed: Result<Record, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "Line {} is corrupted JSON: '{}'. Error: {:?}",
            idx + 1,
            line,
            parsed.err()
        );
    }

    // 2. Verify read_records returns all 100 records
    let records = store.read_records().unwrap();
    assert_eq!(records.len(), TOTAL_RECORDS);

    // 3. Verify store.fold_state() runs cleanly and contains all 100 tasks
    let state = store.fold_state().unwrap();
    assert_eq!(state.all_tasks.len(), TOTAL_RECORDS);
    assert_eq!(
        state
            .all_tasks
            .iter()
            .filter(|t| t.phase == "CONCURRENCY")
            .count(),
        TOTAL_RECORDS
    );

    // 4. Verify CURRENT.md exists and is valid markdown
    let current_md_path = store.current_md_path();
    assert!(current_md_path.exists());
    let current_md = fs::read_to_string(&current_md_path).unwrap();
    assert!(current_md.contains("# Current Task State"));

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_concurrent_mixed_events() {
    let temp_dir = std::env::temp_dir().join(format!(
        "test_taskstate_concurrency_mixed_{}",
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let store = Arc::new(Store::new(temp_dir.clone()));

    // Phase Opened
    let base_time = Utc::now();
    store
        .append(&Record {
            timestamp: base_time,
            by: Actor::new("antigravity"),
            event: Event::PhaseOpened {
                phase: "P-MIXED".to_string(),
                title: "Mixed Concurrency Phase".to_string(),
                goal: "Verify lifecycle events under contention".to_string(),
            },
        })
        .unwrap();

    const NUM_TASKS: usize = 10;
    let mut handles = Vec::new();

    for i in 0..NUM_TASKS {
        let store_clone = Arc::clone(&store);
        let handle = thread::spawn(move || {
            let task_id = format!("P-MIXED-T{}", i);
            let t_base = base_time + chrono::Duration::milliseconds((i as i64 + 1) * 100);

            // 1. Declare task
            let r_decl = Record {
                timestamp: t_base,
                by: Actor::new("antigravity"),
                event: Event::TaskDeclared {
                    task: task_id.clone(),
                    phase: "P-MIXED".to_string(),
                    title: format!("Mixed task {}", i),
                    description: None,
                    depends_on: vec![],
                    review_required: true,
                },
            };
            append_with_retry(&store_clone, &r_decl);

            // 2. Start task
            let r_start = Record {
                timestamp: t_base + chrono::Duration::milliseconds(10),
                by: Actor::new("claude-code"),
                event: Event::TaskStarted {
                    task: task_id.clone(),
                    note: Some(format!("Worker starting task {}", i)),
                },
            };
            append_with_retry(&store_clone, &r_start);

            // 3. Finish task
            let r_finish = Record {
                timestamp: t_base + chrono::Duration::milliseconds(20),
                by: Actor::new("claude-code"),
                event: Event::TaskFinished {
                    task: task_id.clone(),
                    outcome: Outcome::Done,
                    summary: format!("Worker finished task {}", i),
                    commit: Some(format!("abcdef{}", i)),
                },
            };
            append_with_retry(&store_clone, &r_finish);

            // 4. Review task
            let r_review = Record {
                timestamp: t_base + chrono::Duration::milliseconds(30),
                by: Actor::new("antigravity"),
                event: Event::ReviewRecorded {
                    task: task_id.clone(),
                    verdict: Verdict::Clean,
                    note: format!("Review clean for task {}", i),
                    concerns: vec![],
                },
            };
            append_with_retry(&store_clone, &r_review);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked during mixed execution");
    }

    // Total records = 1 (PhaseOpened) + 10 * 4 (Task lifecycle) = 41 records
    let records = store.read_records().unwrap();
    assert_eq!(records.len(), 1 + NUM_TASKS * 4);

    let state = store.fold_state().unwrap();
    assert_eq!(state.active_phase.unwrap().phase, "P-MIXED");
    assert_eq!(state.recently_closed.len(), NUM_TASKS);
    assert!(state.in_progress.is_empty());
    assert!(state.in_review.is_empty());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_seed_tasks_jsonl_parses_and_folds() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get repo root")
        .to_path_buf();
    let seed_tasks_path = repo_root.join("docs").join("agent-state").join("tasks.jsonl");

    assert!(
        seed_tasks_path.exists(),
        "Seed tasks.jsonl does not exist at {}",
        seed_tasks_path.display()
    );

    // 1. Check raw lines parse as valid JSON
    let raw_content = fs::read_to_string(&seed_tasks_path).unwrap();
    let lines: Vec<&str> = raw_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert!(
        !lines.is_empty(),
        "Seed tasks.jsonl should not be empty"
    );

    for (i, line) in lines.iter().enumerate() {
        let record: Result<Record, _> = serde_json::from_str(line);
        assert!(
            record.is_ok(),
            "Line {} in tasks.jsonl failed to parse as Record: '{}'. Err: {:?}",
            i + 1,
            line,
            record.err()
        );
    }

    // 2. Read with read_all
    let records = evedoo_taskstate::store::read_all(&seed_tasks_path).unwrap();
    assert_eq!(records.len(), lines.len());

    // 3. Fold state
    let state = evedoo_taskstate::fold::fold(&records);

    // Verify Active Phase is P21
    assert!(state.active_phase.is_some());
    let phase = state.active_phase.as_ref().unwrap();
    assert_eq!(phase.phase, "P21");
    assert_eq!(phase.title, "Enterprise Accuracy & Reachability");

    // Verify P20 tasks are all closed
    let p20_tasks: Vec<_> = state
        .all_tasks
        .iter()
        .filter(|t| t.phase == "P20")
        .collect();
    assert_eq!(p20_tasks.len(), 10);
    for t in &p20_tasks {
        assert_eq!(
            t.status,
            evedoo_taskstate::model::TaskStatus::Closed,
            "P20 task {} should be Closed",
            t.task
        );
    }

    // Deliberately NOT asserted here: `last_done`, `next`, `in_progress`, and
    // `in_review`. Those are the *mutable* head of a live, append-only ledger
    // that both runtimes write to during normal work. Pinning them made this
    // test fail the moment anyone used the tool as designed — starting
    // P21-HTML-RESIDUAL turned `in_progress.is_empty()` false and reddened the
    // whole workspace suite. A test over shared mutable state must assert
    // invariants, not a snapshot of one moment; the derivation of `next` and
    // `last_done` is already covered by the pure `fold` unit tests, which own
    // fixtures they control.

    // Rulings survive the fold.
    assert!(!state.recent_rulings.is_empty());

    // Rendering runs against a COPY. `render_current()` writes CURRENT.md, and
    // pointing it at the repo's own state directory made this test mutate
    // tracked project data as a side effect of running the suite.
    let tmp_dir = std::env::temp_dir().join(format!(
        "evedoo_taskstate_seed_render_{}_{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    fs::create_dir_all(&tmp_dir).unwrap();
    fs::copy(&seed_tasks_path, tmp_dir.join("tasks.jsonl")).unwrap();

    let store = evedoo_taskstate::store::Store::new(tmp_dir.clone());
    store.render_current().expect("Failed to render CURRENT.md");

    let current_md_path = store.current_md_path();
    assert!(current_md_path.exists());
    let rendered_md = fs::read_to_string(&current_md_path).unwrap();
    // Structural, not snapshot: the active phase is the one immutable heading
    // for the duration of P21.
    assert!(rendered_md.contains("## Active Phase\n\n- **Phase**: P21"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

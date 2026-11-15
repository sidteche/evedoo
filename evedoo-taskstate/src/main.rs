// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;

use chrono::Utc;
use clap::{Parser, Subcommand};
use rmcp::ServiceExt;
use evedoo_taskstate::{cli_actions::parse_outcome, current_actor, Event, Record, Store, TaskStateServer};

#[derive(Parser, Debug)]
#[command(
    name = "evedoo-taskstate",
    version,
    about = "Shared agent task state management for Evedoo across Claude Code and Antigravity"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the MCP server over stdio
    Serve,
    /// Discover state dir, fold state from tasks.jsonl, and update CURRENT.md
    Render,
    /// Read all records from tasks.jsonl, fold state, and print validation summary
    Validate,

    /// One-shot: mark a task as started. For non-MCP callers (e.g. Evedoo
    /// Studio's dev server) that cannot hold an MCP session open. Goes
    /// through the same Store::append() as the MCP tool: the fs4 lock,
    /// CURRENT.md regeneration, and EVEDOO_TASKSTATE_RUNTIME attribution
    /// all apply identically.
    TaskStart {
        /// Task ID, e.g. "P21-N3"
        task: String,
        #[arg(long)]
        note: Option<String>,
    },

    /// One-shot: mark a task as finished. See `task-start` for why this
    /// exists alongside the MCP tool of the same name.
    TaskFinish {
        task: String,
        /// One of: done, done_with_concerns, blocked, abandoned
        #[arg(long)]
        outcome: String,
        #[arg(long)]
        summary: String,
        #[arg(long)]
        commit: Option<String>,
    },

    /// One-shot: request a handoff to another runtime.
    TaskHandoff {
        #[arg(long)]
        to: String,
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        note: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve => {
            tracing::info!("Starting evedoo-taskstate MCP stdio server");
            let server = TaskStateServer::new();
            let handle = server.serve(rmcp::transport::stdio()).await?;
            handle.waiting().await?;
        }
        Commands::Render => {
            let store = Store::discover()?;
            store.render_current()?;
            eprintln!(
                "Successfully rendered CURRENT.md at {}",
                store.current_md_path().display()
            );
        }
        Commands::Validate => {
            let store = Store::discover()?;
            let tasks_path = store.tasks_path();
            if !tasks_path.exists() {
                eprintln!(
                    "Validation failed: tasks file does not exist at {}",
                    tasks_path.display()
                );
                std::process::exit(1);
            }

            let records = store.read_records()?;
            let state = store.fold_state()?;

            println!("Validation successful: valid task state");
            println!("Store path: {}", tasks_path.display());
            println!("Total records: {}", records.len());
            println!("Total tasks: {}", state.all_tasks.len());
            if let Some(phase) = &state.active_phase {
                println!("Active phase: {} ({})", phase.phase, phase.title);
            }
            if let Some(in_prog) = state.in_progress.first() {
                println!("In progress: {} ({})", in_prog.task, in_prog.title);
            }
            if let Some(in_rev) = state.in_review.first() {
                println!("In review: {} ({})", in_rev.task, in_rev.title);
            }
            if let Some(next) = &state.next {
                println!("Next task: {} ({})", next.task, next.title);
            }
            if let Some(last) = &state.last_done {
                println!("Last done: {} ({})", last.task, last.title);
            }
            if let Some(handoff) = &state.pending_handoff {
                println!(
                    "Pending handoff: to `{}` from `{}` (reason: {})",
                    handoff.to, handoff.from, handoff.reason
                );
            }
        }
        Commands::TaskStart { task, note } => {
            let store = Store::discover()?;
            let record = Record {
                timestamp: Utc::now(),
                by: current_actor(),
                event: Event::TaskStarted { task: task.clone(), note },
            };
            store.append(&record)?;
            println!("{{\"ok\":true,\"task\":\"{task}\",\"event\":\"task_started\"}}");
        }
        Commands::TaskFinish { task, outcome, summary, commit } => {
            let outcome = parse_outcome(&outcome)?;
            let store = Store::discover()?;
            let record = Record {
                timestamp: Utc::now(),
                by: current_actor(),
                event: Event::TaskFinished { task: task.clone(), outcome, summary, commit },
            };
            store.append(&record)?;
            println!("{{\"ok\":true,\"task\":\"{task}\",\"event\":\"task_finished\"}}");
        }
        Commands::TaskHandoff { to, task, reason, note } => {
            let store = Store::discover()?;
            let record = Record {
                timestamp: Utc::now(),
                by: current_actor(),
                event: Event::HandoffRequested { to: to.clone(), task, reason, note },
            };
            store.append(&record)?;
            println!("{{\"ok\":true,\"to\":\"{to}\",\"event\":\"handoff_requested\"}}");
        }
    }

    Ok(())
}

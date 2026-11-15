# Shared Agent Task State (`evedoo-taskstate`)

This directory contains agent workspace configuration for **Evedoo**, enabling shared task tracking and coordination across agent runtimes (**Claude Code** and **Antigravity**).

## Overview

The `evedoo-taskstate` MCP server provides a committed, append-only, JSONL-backed task state store (`docs/agent-state/tasks.jsonl`) that both agent runtimes query and mutate over Model Context Protocol (MCP).

- **Source of truth:** `docs/agent-state/tasks.jsonl` (committed, append-only).
- **Cold-start fallback:** `docs/agent-state/CURRENT.md` (automatically rendered/updated on mutations).
- **Runtime attribution:** Stamped server-side from the `EVEDOO_TASKSTATE_RUNTIME` environment variable. Unset, blank, or whitespace-only values record the actor as `unknown` — the value is never taken from tool arguments, so an agent cannot claim to be a different runtime.
- **State directory discovery:** `store::discover_state_dir()` walks up from the current working directory looking for `docs/agent-state`, stopping at the `.git` repository root. There is no environment override for the path.

---

## Installation & Build

Build and install `evedoo-taskstate` into Cargo's binary directory (`~/.cargo/bin` / `%USERPROFILE%\.cargo\bin`), which is expected to be on your `PATH`:

```bash
cargo install --path evedoo-taskstate --locked
```

> **Note on `cargo install` vs `cargo run`:**
> `cargo install` installs a standalone binary to `~/.cargo/bin`. Running via `cargo run` inside MCP configs is avoided to prevent target directory lock contention, compilation timeout issues during agent initialization, and executable locking during workspace builds.

---

## Runtime Configurations

Both runtimes connect to the installed `evedoo-taskstate` binary via stdio MCP.

### 1. Claude Code
Configured in the repository root [`.mcp.json`](../.mcp.json):

```json
{
  "mcpServers": {
    "evedoo-taskstate": {
      "command": "evedoo-taskstate",
      "args": ["serve"],
      "env": {
        "EVEDOO_TASKSTATE_RUNTIME": "claude-code"
      }
    }
  }
}
```

### 2. Antigravity
Configured in [`.agents/mcp_config.json`](mcp_config.json):

```json
{
  "mcpServers": {
    "evedoo-taskstate": {
      "command": "evedoo-taskstate",
      "args": ["serve"],
      "env": {
        "EVEDOO_TASKSTATE_RUNTIME": "antigravity"
      }
    }
  }
}
```

---

## CLI

The same binary serves three subcommands:

| Command | Purpose |
|---|---|
| `evedoo-taskstate serve` | Run the MCP server over stdio (what both runtime configs invoke) |
| `evedoo-taskstate render` | Re-fold `tasks.jsonl` and rewrite `CURRENT.md` |
| `evedoo-taskstate validate` | Read all records, fold, and print a validation summary; exits non-zero if `tasks.jsonl` is missing |

## Available Tools

When connected, both runtimes have access to the following MCP tools:
- `task_state`: Query current active tasks, in-review tasks, next unblocked task, and pending handoffs.
- `task_declare`: Declare a task or phase.
- `task_start`: Mark a task as started.
- `task_finish`: Mark a task as finished with an outcome.
- `task_review`: Record review verdict on a completed task.
- `task_ruling`: Record an architectural or design ruling with rationale.
- `task_history`: Query historical events for a task or phase.
- `task_handoff`: Pass work between runtimes with stated intent.

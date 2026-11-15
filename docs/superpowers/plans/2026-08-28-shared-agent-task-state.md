# Shared agent task state across Claude Code and Antigravity

**Status:** SHIPPED. `evedoo-taskstate` is a Cargo workspace member with 26
passing tests, wired into Claude Code via `.mcp.json` and Antigravity via
`.agents/mcp_config.json`. The live ledger is `docs/agent-state/tasks.jsonl`,
rendered to `docs/agent-state/CURRENT.md`. This document is retained as the
original design rationale; for current usage see `.agents/README.md` and
`PARAMETERS.md` §4.
**Date:** 2026-08-28
**Supersedes:** nothing. **Depends on:** nothing.

**Why this document exists.** Agents are run against this repo from two
runtimes — Claude Code and Antigravity — and neither can tell you what the
other last did or what comes next. This plan makes that state shared,
committed, and derived rather than asserted.

**Provenance.** Written in plan mode after verifying, on this machine: that
Antigravity and its CLI are installed and MCP-capable; that both runtimes
already load MCP servers and both support committed project-scoped config
(`.mcp.json` and `.agents/mcp_config.json`); and that the existing per-task
history is entirely git-ignored while the committed plan's 51 checkboxes read
0% complete for work that is 100% done. Four claims made during planning were
wrong and are corrected inline: Antigravity's stdio schema has no `timeout`
field, the checkbox count is 51 rather than 52, `.gitignore` blanket-ignores
`*.db` and `*.sqlite` as well as `*.json`, and `rmcp` requires a higher MSRV
than the workspace declares.

**Read the acceptance gate first** (*Verification* → the end-to-end
cross-runtime proof). If that test cannot be made to pass, the rest of this
plan is not worth building.

---

## Context

You run agents in two runtimes against this repo — Claude Code and Antigravity — and neither can tell you what the other last did or what comes next. That gap is not an MCP gap. Both runtimes already load MCP servers, and `agy-bridge` is registered in both. The gap is **where the state lives**:

- `.superpowers/sdd/2026-08-21-operationalisation/progress.md` holds the real per-task history — 10 `Task N: complete` lines and 34 rulings — and is **entirely git-ignored** by a nested `.gitignore` containing `*`. Invisible to any other checkout or runtime.
- `docs/superpowers/plans/2026-08-21-operationalisation.md` is committed but has **51 unticked `- [ ]` boxes and zero ticked**, for work that is 100% complete. Anything reading them as state sees 0% done — worse than absent, actively wrong.
- Claude Code memory lives outside the repo.

So the outcome we want is a **committed, per-task state store both runtimes read and write through a defined interface**, with the derivation of "next" computed rather than asserted — so it cannot rot the way those 51 boxes did.

---

## Design

**A fourth Rust workspace crate, `evedoo-taskstate`, serving an append-only JSONL store over MCP.**

Rust rather than Node because `CLAUDE.md` says *"Language: Rust exclusively"* and requires Apache-2.0/MIT/BSD dependencies. `rmcp` 3.1.4 is the official Anthropic Rust MCP SDK under Apache-2.0 — verified.

**JSONL, not SQLite** — even though the repo loves `rusqlite`. Every existing SQLite use here is deliberately git-ignored machine-local state. This store has the opposite requirement: committed and reviewable. A committed `.db` is an unmergeable binary blob, invisible in review, conflicting on every push — which recreates the "invisible to another checkout" problem with extra steps. Verified: `.gitignore` lines 27 and 32 blanket-ignore `*.sqlite` and `*.db`, so SQLite would also be silently swallowed.

```
docs/agent-state/
  tasks.jsonl    # source of truth, append-only, one JSON object per line
  CURRENT.md     # GENERATED on every mutation — the cold-start fallback
  .lock          # git-ignored advisory lock
```

**The committed file is the source of truth; the server is a strict accessor, never a gatekeeper.** If the server is unavailable, an agent reads `CURRENT.md`. If the crate is ever deleted, no state is lost.

**"Last done" and "next" are derived, never stored.** A task is closed when it has a `TaskFinished` with outcome `done`/`done_with_concerns` **and** a `ReviewRecorded` verdict of `clean` (or was declared `review_required: false`). `next` is the first declared-but-unclosed task whose dependencies are closed. A task finished but not yet reviewed reports as `in_review`, not as `last_done` — a more honest answer than the ledger gave.

**Seven event types:** `phase_opened`, `task_declared`, `task_started`, `task_finished`, `review_recorded`, `ruling_recorded`, `handoff_requested`. Every optional field `#[serde(default)]`, per the same additive-compatibility discipline as **DC-3**.

**Eight tools:** `task_state` (no params — the tool that answers the question), `task_declare`, `task_start`, `task_finish`, `task_review`, `task_ruling`, `task_history`, `task_handoff`. No `task_close` (derived), no edit/delete (append-only is the audit property). `task_ruling` requires all four of subject/decision/rationale/cost_if_wrong — that shape is what made the 34 SDD rulings useful.

### Handoff between runtimes

Switching runtimes stays a human action — you open the other tool. What the handoff tool adds is that the **intent survives the switch** instead of living only in your head.

```
task_handoff:
  to:     "claude-code" | "antigravity"   (required)
  task?:  string        // what the next runtime should pick up
  reason: string        (required)        // why you are handing over
  note?:  string
```

`from` is **not** a parameter — it is stamped from `EVEDOO_TASKSTATE_RUNTIME`, same as `by.runtime`, so a handoff cannot claim to come from a runtime it did not.

`task_state` gains a `pending_handoff` field, so the first thing the receiving agent sees is that work was passed to it and why:

```jsonc
"pending_handoff": {
  "from": "claude-code", "to": "antigravity",
  "task": "P21-T1", "reason": "needs a non-Claude reviewer — every review in P20 was Claude reviewing Claude",
  "at": "2026-08-28T04:40:11Z"
}
```

**Acceptance is derived, not asserted.** There is deliberately no `task_handoff_accept` tool: a handoff is satisfied when the target runtime records `task_start` on the named task (or, for an untargeted handoff, any `task_start`). Same principle as task closure — one event, derived consequences, nothing to forget to call. A handoff older than the newest `task_started` by its target is stale and is not surfaced.

This is passive by design and does not make the integration bidirectional. See *Integration topology* below for what that would take.

### Integration topology — what this does and does not do

Three axes, easy to conflate:

| Axis | State today |
|---|---|
| **Delegation** (agent invokes agent) | **One direction only.** Claude Code → Antigravity via agy-bridge. Antigravity → Claude Code does not exist. |
| **Shared state** (this plan) | **Bidirectional but passive.** Both read and write the same store; neither can invoke the other. |
| **Co-location** | Already in place — Claude Code runs as an extension inside Antigravity (`anthropic.claude-code-2.1.109`). Same editor, two agents, switch panes. |

A true reverse bridge is feasible — `claude.exe` is on PATH — and would be an MCP server exposing `claude -p` to Antigravity, symmetric to agy-bridge. **Explicitly out of scope here**, and worth noting the cost if it is ever taken up: Claude Code invoked headlessly loses the interactive review loop this project depends on.

**Concurrency.** Both runtimes spawn their own server process, so there are ≥2 writers:
- **No cached state between calls** — every call re-reads and re-folds. A cache would make one runtime answer from a snapshot taken before the other's write, which is precisely the bug being fixed.
- **Append-only** writes, `sync_all`, never a rewrite. A truncated final line is dropped with a `warn!` rather than failing.
- **Advisory file lock** (`fs4`) around read→validate→append→render, with a bounded retry that fails loudly rather than proceeding silently.
- **`merge=union`** in `.gitattributes` for worktree merges — sound only because no sequence number is stored.

**`by.runtime` is stamped server-side** from `EVEDOO_TASKSTATE_RUNTIME`, not passed as a tool parameter, so attribution can't be spoofed by a confused agent.

---

## Files

**Create**

| Path | Purpose |
|---|---|
| `evedoo-taskstate/Cargo.toml` | `edition = "2024"`, `rust-version = "1.88"` (rmcp's MSRV — per-crate, workspace stays 1.83) |
| `evedoo-taskstate/src/main.rs` | `serve` / `render` / `validate` subcommands; **tracing to stderr only** |
| `evedoo-taskstate/src/model.rs` | `Record`, `Actor`, `Event`, `Outcome`, `Verdict` |
| `evedoo-taskstate/src/fold.rs` | `fold(&[Record]) -> State` — pure, where nearly all tests live |
| `evedoo-taskstate/src/store.rs` | lock, append, atomic `CURRENT.md` replace, state-dir discovery |
| `evedoo-taskstate/src/tools.rs` | the seven MCP tools |
| `evedoo-taskstate/tests/concurrency.rs` | N threads appending; asserts exact line count and parseability |
| `.mcp.json` | Claude Code registration |
| `.agents/mcp_config.json` | Antigravity registration |
| `.agents/README.md` | bootstrap line where an Antigravity user looks |
| `.gitattributes` | `merge=union` for `tasks.jsonl` |
| `docs/agent-state/tasks.jsonl` | seeded (below) |

**Modify**

| Path | Change |
|---|---|
| `.gitignore` | **negations — do this first, see below** |
| `Cargo.toml` | add `evedoo-taskstate` to `members` |
| `.github/workflows/ci.yml` | third job — existing jobs use `working-directory:` and will not pick up a new member |
| `CLAUDE.md`, `GEMINI.md` | task-state instruction block; amend the MSRV line |
| `docs/superpowers/plans/2026-08-21-operationalisation.md` | tick 51 boxes + status blockquote |

### The `.gitignore` negation — highest risk of silent failure

Verified: `.mcp.json` and `.agents/mcp_config.json` are **both currently ignored** by `.gitignore:42` (`*.json`). `tasks.jsonl` is not matched today, but the negation goes in anyway so intent survives someone tightening the rule to `*.json*`.

Append **below** the blanket rules — last matching pattern wins:

```gitignore
# Shared agent task state. The blanket *.json / *.db / *.sqlite rules above
# would silently swallow these, and they are SHARED STATE — if they are not
# committed, a second runtime and a second checkout cannot see them.
!.mcp.json
!.agents/mcp_config.json
!docs/agent-state/tasks.jsonl
docs/agent-state/.lock
```

This lands **alone, first, verified with `git check-ignore` before any other file is created.** If it is wrong, everything downstream is invisible and the failure is silent — the same class of bug this project's reviews caught twice in the operationalisation phase.

### Bootstrap: `cargo install`, not `cargo run`

```bash
cargo install --path evedoo-taskstate --locked
```

`cargo run` is wrong here for three repo-specific reasons: the first launch compiles rmcp+tokio under `lto = true, codegen-units = 1` and blows past any MCP connect timeout; it takes the target-directory lock, so MCP startup blocks whenever a build is in flight; and worst, it leaves a long-lived binary **inside** the target dir, so `cargo build --workspace` fails with `Access is denied (os error 5)` while relinking — the exact hazard already documented for `evedoo.exe --serve`, made permanent.

`~/.cargo/bin` is already on PATH here, so both configs reference a bare binary name — no absolute paths, unlike the git-ignored `.cargo/config.toml`.

---

## Seed the store

A store born empty reports `last_done: null` for completed work — the same lie as the 51 unticked boxes, in a system built to stop exactly that.

**Hand-author the seed; do not write an importer.** The ledger is free-form prose that will never be written again in that form, and a regex parser for a one-off would become permanent code that must pass `clippy -D warnings` forever. The 34 `Ruling:` blocks are multi-line prose a regex would mangle, and they need judgment to compress into the four required fields.

From `.superpowers/sdd/2026-08-21-operationalisation/progress.md`: one `phase_opened` for P20, ten `task_declared` (T1–T8, T9a, T9b), and per task the `task_started`/`task_finished`/`review_recorded` triple drawn from the `dispatched` / `implementer DONE` / `review` lines — fix rounds become extra finish/review pairs. Timestamps from git commit author dates.

**Import ~10 rulings, not all 34** — only those that constrain future work (the V4-in-place migration precedent, the parked HTML/CycloneDX residual, the B5 `NoLongerApplicable` reserved-not-emitted decision). All 34 would make `recent_rulings` noise.

**Seed the forward side too**, or `next` is empty on day one and the goal is half-met: `phase_opened` P21 plus `task_declared` for N3 (runtime reachability — the roadmap's "strongest single accuracy play"), N5, N6, N7, and the parked HTML/CycloneDX residual, which currently exists *only* in the git-ignored ledger and will otherwise be lost.

---

## Side fixes

**1. agy-bridge timeout — the Antigravity half is not what was assumed.**

Claude Code (real, documented field). Do not hand-edit `~/.claude.json` — Claude Code rewrites it on shutdown and a live-session edit can be clobbered:
```bash
claude mcp remove -s user agy-bridge
claude mcp add-json -s user agy-bridge '{"command":"npx","args":["-y","agy-bridge"],"timeout":600000}'
```

Antigravity: **verified that its documented stdio schema has no `timeout` field** — `command`, `args`, `env`, `cwd`, `disabled`, `disabledTools` only. Writing one is an inert no-op, i.e. the silent-miss class again. The working equivalent is the agy-side budget:
```json
{ "mcpServers": { "agy-bridge": {
    "command": "npx", "args": ["-y", "agy-bridge"],
    "env": { "AGY_TIMEOUT": "600" } } } }
```

**2. The plan checkboxes — 51, not 52.** All are `- [ ] **Step` at column 0, so `s/^- \[ \] \*\*Step/- [x] **Step/` is safe. Add a status blockquote after line 3 recording that they were ticked retroactively and that the document is a historical plan, not live state.

**3. The Antigravity self-loop — investigate, change nothing yet.**

`~/.gemini/config/mcp_config.json` registers `agy-bridge`, which means Antigravity → bridge → `agy`: Antigravity delegating to itself. It may be deliberate (wanting the bridge's structured tool shapes rather than raw agy), so establish what actually happens before touching it. Read-only:

- Does Antigravity list the bridge's tools? `ls ~/.gemini/antigravity-cli/mcp/agy-bridge/` already shows six cached schemas, so it connected — but connecting is not using.
- What happens on an actual call: `agy -p "Use the agy-bridge deep_search tool to find where FindingStatus is defined. Report only the file and line."` Does it recurse, spawn a second agy process, error, or work usefully?
- Check `~/.gemini/antigravity-cli/cache/` and any log for a nested invocation, and watch for two `agy.exe` processes.

Report findings and let the user decide. The likely outcomes are *harmless but redundant* (Antigravity has native agy access already) or *actively wasteful* (a second 186 MB process and a second model call per delegation) — but do not assume which.

**4. Skip-permissions — present as a decision, do not decide it here.** `agy-bridge@0.4.1` `dist/index.js:33` defaults `AGY_SKIP_PERMISSIONS` to on, and `:242` appends `--dangerously-skip-permissions`. It is live in both runtimes now, and `delegate` grants full shell/file/web access in a workspace holding a `.env` with an NVD API key and push access on `dev`. The asymmetry that makes it worth raising: `~/.gemini/config/config.json` already sets `autoExecutionPolicy: ...AUTO_EXECUTION_OFF` and `nonWorkspaceFileAccessPolicy: ...ASK`, so you have already chosen a conservative posture for the IDE — and the bridge path bypasses it. Options: keep it; set `AGY_SKIP_PERMISSIONS=false` (caveat: agy runs non-interactive under the bridge, so a prompt may hang to timeout rather than prompt — test first); or `AGY_SANDBOX=true`, likely the best middle path.

---

## Sequencing

1. `.gitignore` negations + `.gitattributes` — **alone, verified first**
2. Crate skeleton; prove `serve` speaks JSON-RPC before writing any tool
3. `model.rs` + `fold.rs` + `render.rs`, TDD against a fixture
4. `store.rs` — lock, append, atomic replace, discovery; concurrency test
5. The seven tools
6. `.mcp.json`; verify in Claude Code
7. `.agents/mcp_config.json`; verify in Antigravity — resolves the `cwd` unknown
8. Author and commit the seed; `render`; commit `CURRENT.md`
9. CI job
10. Docs + MSRV amendment
11. The three side fixes — independent, can run first

---

## Verification

**Nothing is silently ignored** (run before anything else):
```bash
git check-ignore -v .mcp.json .agents/mcp_config.json docs/agent-state/tasks.jsonl
# EXPECT: no output, exit 1
git check-ignore -v docs/agent-state/.lock   # EXPECT: a match
```

**Repo gates:** `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` (now needs ≥1.88), `cargo test --workspace` (318 + new), `cargo run -p evedoo-taskstate -- validate`.

**Stdout hygiene** — pipe an `initialize` + `tools/list` sequence into `serve` and assert every stdout line parses as JSON; re-run without `2>/dev/null` and confirm tracing appears on stderr.

**Antigravity registration signal** (does not depend on `agy mcp list` existing): after one agy run, `~/.gemini/antigravity-cli/mcp/evedoo-taskstate/` should contain seven schema files — exactly how `agy-bridge` currently appears there with six.

**The end-to-end proof, which is the actual acceptance gate:**
1. From **Antigravity**: `task_declare` phase `VERIFY` with `VERIFY-1` and `VERIFY-2`, then `task_start VERIFY-1`
2. From **Claude Code**: `task_state` — assert `store_path` is byte-identical to Antigravity's, `in_progress` contains `VERIFY-1`, and its `by.runtime == "antigravity"` (proving server-side attribution)
3. From **Claude Code**: `task_finish` then `task_review verdict=clean`
4. From **Antigravity**: `task_state` — assert `last_done.task == "VERIFY-1"` and `by.runtime == "claude-code"`
5. **Handoff round trip.** From **Claude Code**: `task_handoff to=antigravity task=VERIFY-2 reason="..."`. From **Antigravity**: `task_state` — assert `pending_handoff.from == "claude-code"` (again server-stamped, not self-reported) and that it names `VERIFY-2`. Then `task_start VERIFY-2` from Antigravity and re-read `task_state` — assert `pending_handoff` is now **absent**, proving acceptance is derived from the start event rather than needing its own call.

---

## Open items — verify, do not guess

1. **rmcp 3.1.4 API surface.** Version/license/MSRV confirmed from crates.io; the feature-flag and macro names are from docs and blog posts, not the pinned crate. Read `docs.rs/rmcp/3.1.4` before writing the first tool — the macro API changed across 0.x → 3.x.
2. **Antigravity's cwd for spawned stdio servers.** If it is not the workspace, the `.git` walk-up fails and the server errors loudly by design; the fix is then `cwd` in the **global** `~/.gemini/config/mcp_config.json`, not the committed workspace file.
3. **`fs4` version and license.** Confirm before adding; `fs2` is the obvious alternative but its last release was 2019, which trips CLAUDE.md's 12-month staleness rule.
4. **Edition-2024 member under the virtual workspace.** Expected fine (lockfile is already v4), but a cargo warning would not fail CI, so it could go unnoticed. Do not bump the root to `resolver = "3"` to silence it.

## Worth saying plainly

The stated goal is solvable with **zero code** — a committed `CURRENT.md` in a strict format, which both runtimes already read natively. The server buys three things a hand-maintained file does not: `next` is *derived* so it cannot rot like the 51 boxes; `task_ruling` structurally cannot accept a half-specified decision; and `by.runtime` is stamped server-side rather than self-reported. The design keeps the committed file as the source of truth precisely so that if the server proves to be overhead, deleting the crate costs nothing and loses no state.

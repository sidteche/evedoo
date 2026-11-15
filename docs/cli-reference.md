# Evedoo — Toolchain CLI & API Parameters Reference

Reference for the command-line options, API endpoints, environment variables and MCP tools of the Evedoo tools. `--help` on any command is always the authority; if this page disagrees with it, the page is out of date.

*Flags below are transcribed from the `clap` derive definitions in `evedoo/src/main.rs`, `cve-db-builder/src/main.rs`, and `evedoo-taskstate/src/main.rs`.*

---

## Table of Contents

1. [cve-db-builder](#1-cve-db-builder)
2. [evedoo CLI](#2-evedoo-cli)
   - [scan](#subcommand-scan)
   - [audit](#subcommand-audit)
   - [reassess](#subcommand-reassess)
   - [remote-scan](#subcommand-remote-scan)
   - [fleet](#subcommand-fleet)
   - [exception](#subcommand-exception)
   - [schedule](#subcommand-schedule)
3. [evedoo-gui](#3-evedoo-gui)
4. [evedoo-taskstate](#4-evedoo-taskstate-mcp--cli)
   - [CLI Commands](#taskstate-cli-commands)
   - [Environment Variables](#taskstate-environment-variables)
   - [MCP Tool Schemas](#taskstate-mcp-tool-schemas)
5. [evedoo-studio](#5-evedoo-studio-secops-workspace)
   - [Launch Commands](#studio-launch-commands)
   - [Dev Server & Engine Bridge Endpoints](#studio-engine-bridge-api)

---

## 1. cve-db-builder

Downloads and updates the local SQLite CVE database (`vulndb.sqlite`) from bulk mirrors, official NVD feeds, EPSS, CISA KEV, and Microsoft MSRC CVRF advisories.

```powershell
cve-db-builder.exe [OPTIONS]
```

### CLI Parameters

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--api-key <KEY>` | | `String` | `NVD_API_KEY` env / `.env` (cwd, exe dir, or workspace root) | NVD API key (raises CPE rate limit: 5 → 50 req/30s). Carries `hide_env_values`, so `--help` shows the variable *name* but never its value. |
| `--output <PATH>` | `-o` | `String` | `vulndb.sqlite` | Output SQLite database destination path |
| `--update` | `-u` | `bool` | `false` | Incremental delta update (uses 8-day modified feed) |
| `--enable-msrc` | | `bool` | `false` | Ingest Microsoft Security Response Center (MSRC) CVRF advisories. Subject to Microsoft's terms; local use only |
| `--enable-ubuntu` | | `bool` | `false` | Ingest Ubuntu security notices. **Experimental.** Fails with an error if the feed cannot be read. Subject to Canonical's terms; local use only |
| `--start-date <YYYY-MM-DD>` | | `String` | | Start date filter for CVE sync (forces API fallback) |
| `--end-date <YYYY-MM-DD>` | | `String` | | End date filter for CVE sync (forces API fallback) |
| `--stats` | | `bool` | `false` | Display database record counts and statistics without syncing |
| `--skip-kev` | | `bool` | `false` | Skip fetching CISA Known Exploited Vulnerabilities catalog |
| `--skip-epss` | | `bool` | `false` | Skip fetching FIRST.org daily EPSS probability scores |
| `--skip-cpe-dict` | | `bool` | `false` | Skip fetching NVD CPE Dictionary (~1.8M product identities) |
| `--enrichment-only` | | `bool` | `false` | Refresh only EPSS, KEV, and CPE dictionary; skip CVE corpus sync |
| `--no-mirror` | | `bool` | `false` | Bypass FKIE-CAD mirror and sync directly from NVD API 2.0 |
| `-v, --verbose` | | `bool` | `false` | Enable verbose/debug diagnostics |
| `-h, --help` | | | | Print help information |
| `-V, --version` | | | | Print version |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API 2.0 key. Precedence: `--api-key`, then the real environment variable, then a `.env` file in the **working directory itself, beside the executable, or — only for a binary run in place from a cargo build tree (`<repo>/target/<profile>/`) — the workspace root** derived from the executable's location; the working directory's parents are never searched, and no other key in that file is read or exported. Never rendered into `--help` output. |

> **`evedoo` itself never reads a `.env` file.** `EVEDOO_DB_PATH` and
> `EVEDOO_REMOTE_PASSWORD` come from the real environment or their flags
> only. A `.env` (which `dotenvy::dotenv()` used to find in *any* parent of the
> working directory) would let anyone who can write one above the operator's
> working directory swap the CVE database on an often-elevated scanner — or
> point it at a UNC path so the process authenticates to an attacker's SMB
> server. Guarded by `evedoo/tests/env_file.rs`.

> **Credential arguments that read an environment variable set clap's
> `hide_env_values`.** Without it clap prints the *live value* of the variable
> into `--help`, which would leak the secret into terminal scrollback, CI logs,
> and screenshots — defeating the whole point of moving it off argv. This
> applies to `cve-db-builder --api-key` and `evedoo remote-scan --password`.

---

## 2. evedoo CLI

Windows-native vulnerability scanner and configuration compliance auditor.

```powershell
evedoo.exe <COMMAND> [OPTIONS]
```

---

### Subcommand: `audit`

Audits Windows hardening against bundled baseline checks. The checks are Evedoo's own, derived from a small sample of each named DISA STIG and mapped to NIST SP 800-53 controls; the pass rate is not a STIG compliance score. Windows benchmarks are refused on Linux and macOS.

```powershell
evedoo.exe audit [OPTIONS]
```

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--benchmark <ID>` | `-b` | `String` | *(detected Windows version)* | Bundled benchmark ID/alias (`windows-11`, `windows-10`, `windows-server-2022`, `ms-edge`). Never read as a file path. Cannot be combined with `--policy` |
| `--policy <PATH>` | `-p` | `PathBuf` | | Path to a custom operator-supplied **JSON** benchmark file (deserialized into `audit::policy::Benchmark`; XCCDF/XML is not supported). Cannot be combined with `--benchmark`. |
| `--format <FMT>` | `-f` | `String` | `text` | Output format: `text` (colored), `json`, `csv`, `html` |
| `--output <PATH>` | `-o` | `PathBuf` | *(stdout)* | Write report to file instead of console |

---

### Subcommand: `scan`

Inventories installed software and correlates findings against the CVE database.

```powershell
evedoo.exe scan [OPTIONS]
```

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--database <PATH>` | `-d` | `PathBuf` | `vulndb.sqlite` | Path to CVE database (also `EVEDOO_DB_PATH`) |
| `--format <FMT>` | `-f` | `String` | `text` | `text`, `json`, `csv`, `html`, `cyclonedx` (`cdx`), `spdx` |
| `--output <PATH>` | `-o` | `PathBuf` | *(stdout)* | Write report to file |
| `--severity <LIST>` | `-s` | `String` | *(all)* | Comma-separated: `critical,high,medium,low,unknown`. An unrecognised value is an error |
| `--min-confidence <LVL>` | `-c` | `String` | `high` | Minimum confidence floor: `exact`, `high`, `medium`, `low` |
| `--no-reachability` | | `bool` | `false` | Skip Toolhelp32 module enumeration and mark every finding `Unknown` (FR-80). Reachability collection is **on by default**; there is no `--reachability` flag to turn it on. |
| `--risk` | | `bool` | `false` | Display computed risk score and priority tier in text output |
| `--min-priority <TIER>` | | `String` | *(none)* | Filter by priority tier: `p1`, `p2`, `p3`, `p4` (implies `--risk`) |
| `--sort <MODE>` | | `String` | *(default)* | Order results by `risk` (KEV/EPSS/CVSS is default) |
| `--history <PATH>` | | `PathBuf` | `scan_history.db` | History database for delta tracking and snapshots |
| `--no-history` | | `bool` | `false` | Disable delta tracking and snapshot persistence |
| `--show-unmatched` | | `bool` | `false` | List detected software with no resolved CPE identity |
| `--show-excepted` | | `bool` | `false` | Reveal findings suppressed by accepted-risk rules |
| `--serve` | | `bool` | `false` | Launch local token-authenticated HTTP server for the HTML report (rejected for any other `--format`) |
| `--rootfs <PATH>` | | `PathBuf` | | Scan an extracted Linux root filesystem (container image, chroot, mounted disk) instead of this machine. Operating-system packages only |
| `--target-os <OS>` | | `String` | *(host; `linux` with `--rootfs`)* | `windows`, `linux`, `macos` (`darwin`). An unrecognised value is an error |
| `--verbose` | `-v` | `bool` | `false` | Enable debug-level `tracing` diagnostics |

`--min-confidence` and `--min-priority` also reject unrecognised values.

---

### Subcommand: `reassess`

Re-correlates persisted inventory snapshots offline without touching the host.

```powershell
evedoo.exe reassess [OPTIONS]
```

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--host <NAME>` | | `String` | *(this machine)* | Host whose stored inventory to reassess — long form only, no short flag |
| `--database <PATH>` | `-d` | `PathBuf` | `vulndb.sqlite` | Path to CVE SQLite database (also `EVEDOO_DB_PATH`) |
| `--history <PATH>` | | `PathBuf` | `scan_history.db` | History database containing persisted snapshots |
| `--format <FMT>` | `-f` | `String` | `text` | `text`, `json`, `csv`, `html`, `cyclonedx`, `spdx` |
| `--output <PATH>` | `-o` | `PathBuf` | *(stdout)* | Write report to file |
| `--min-priority <TIER>` | | `String` | *(none)* | Filter by priority tier (`p1`–`p4`) |
| `--show-excepted` | | `bool` | `false` | Reveal findings suppressed by accepted-risk rules (FR-70) |
| `--max-age <DAYS>` | | `i64` | `7` | Warn when the stored snapshot is older than this many days |

---

### Subcommand: `remote-scan`

Scan a remote Windows host via WinRM (PowerShell `Invoke-Command`).

```powershell
evedoo.exe remote-scan --target <HOST> --username <USER> --password-stdin [OPTIONS]
```

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--target <HOST>` | `-t` | `String` | *(required)* | Target remote hostname or IP address |
| `--username <USER>` | `-u` | `String` | *(required)* | Remote username (e.g. `DOMAIN\admin`) |
| `--password-stdin` | | `bool` | `false` | **Recommended:** Read password securely from stdin |
| `--password <PASS>` | | `String` | `EVEDOO_REMOTE_PASSWORD` | Password as an argument — appears in this process's command line, which event 4688 / Sysmon / EDR record. Prefer `--password-stdin`. Carries `hide_env_values`, so `--help` never prints the live value of `EVEDOO_REMOTE_PASSWORD`. |
| `--port <PORT>` | `-p` | `u16` | `5985` | WinRM port (5985=HTTP, 5986=HTTPS) |
| `--use-ssl` | | `bool` | `false` | Use SSL/HTTPS (pair with `--port 5986`). Without it the scan runs over HTTP and prints a warning: the remote host's identity is not verified |
| `--skip-tls-verify` | | `bool` | `false` | Skip TLS certificate validation — disables MITM protection, lab use only |

`remote-scan` also accepts the full correlation and reporting flag set, with the
same meanings and defaults as [`scan`](#subcommand-scan):

| Parameter | Short | Type | Default |
|-----------|-------|------|---------|
| `--database <PATH>` | `-d` | `PathBuf` | `vulndb.sqlite` (also `EVEDOO_DB_PATH`) |
| `--format <FMT>` | `-f` | `String` | `text` |
| `--output <PATH>` | `-o` | `PathBuf` | *(stdout)* |
| `--severity <LIST>` | `-s` | `String` | *(all)* |
| `--min-confidence <LVL>` | `-c` | `String` | `high` |
| `--history <PATH>` | | `PathBuf` | `scan_history.db` |
| `--no-history` | | `bool` | `false` |
| `--serve` | | `bool` | `false` |
| `--risk` | | `bool` | `false` |
| `--min-priority <TIER>` | | `String` | *(none)* |
| `--show-excepted` | | `bool` | `false` |
| `--sort <MODE>` | | `String` | *(default)* — only `risk` is accepted |
| `--no-reachability` | | `bool` | `false` |
| `--verbose` | `-v` | `bool` | `false` |

> `remote-scan` has no `--show-unmatched`; that diagnostic is local-scan only.

---

### Subcommand: `fleet`

Manage asset registry and aggregate fleet-wide remediation actions.

```powershell
evedoo.exe fleet <COMMAND> [OPTIONS]
```

#### `fleet report`
```powershell
evedoo.exe fleet report [-d <CVE_DB>] [--db <HISTORY_DB>] [--tag <TAG>] [--limit <N>] [--json]
```

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--database <PATH>` | `-d` | `PathBuf` | `vulndb.sqlite` | CVE database. Required, because risk is derived at report time rather than read from a stored score (FR-84). |
| `--db <PATH>` | | `PathBuf` | `scan_history.db` | History/fleet database holding the stored findings |
| `--tag <TAG>` | | `String` | *(all)* | Only include assets carrying this fleet tag |
| `--limit <N>` | | `usize` | `20` | Maximum rows to display |
| `--json` | | `bool` | `false` | Emit the DC-7 JSON object instead of the text table |

> There is **no** `--format` flag on `fleet report` — use `--json`.

#### `fleet add`
```powershell
evedoo.exe fleet add <HOSTNAME> [--name <NAME>] [--tags <TAGS>] [--remote] [--use-ssl]
```

#### `fleet list`
```powershell
evedoo.exe fleet list [--tag <TAG>] [--json]
```

#### `fleet tag`
```powershell
evedoo.exe fleet tag <HOSTNAME> [--add <TAGS>] [--remove <TAGS>]
```

#### `fleet summary`
```powershell
evedoo.exe fleet summary [--json]
```

---

### Subcommand: `exception`

Manage scoped, expiring accepted-risk exception rules.

```powershell
evedoo.exe exception <COMMAND> [OPTIONS]
```

#### `exception add`
```powershell
evedoo.exe exception add --cve <CVE|*> --reason <TEXT> --owner <NAME> --expires <YYYY-MM-DD> [--software <NAME|*>] [--host <NAME|*>] [--history <PATH>]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--cve <ID>` | `String` | *(required)* | Canonical CVE id, or `*` for any (validated per FR-72) |
| `--reason <TEXT>` | `String` | *(required)* | Why the risk is accepted |
| `--owner <NAME>` | `String` | *(required)* | Who accepted it |
| `--expires <DATE>` | `String` | *(required)* | Absolute expiry, `YYYY-MM-DD`. Must be within **730 days** of today (FR-68). There is **no** `--expires-in` duration form. |
| `--software <NAME>` | `String` | `*` | Software name, or `*` for any |
| `--host <NAME>` | `String` | *(this machine)* | Host, or `*` for every host. Must be given explicitly — an estate cannot be silenced by omission (FR-69). |
| `--history <PATH>` | `String` | `scan_history.db` | State database |

#### `exception list`
```powershell
evedoo.exe exception list [--host <NAME>] [--json] [--history <PATH>]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--host <NAME>` | `String` | *(all rules)* | List rules for this host, plus fleet-wide `*` rules. Omit to list every rule. |
| `--json` | `bool` | `false` | Emit JSON instead of the text table |
| `--history <PATH>` | `String` | `scan_history.db` | State database |

> There is no `--cve` filter and no `--active-only` flag on `exception list`.

#### `exception remove`
```powershell
evedoo.exe exception remove <ID> [--history <PATH>]
```

`<ID>` is the positional integer rule id shown by `exception list`. Removal
annotates the audit trail rather than erasing it (FR-70).

---

### Subcommand: `schedule`

Manage recurring scans via Windows Task Scheduler (`schtasks.exe`).

```powershell
evedoo.exe schedule <create|list|remove> [OPTIONS]
```

#### `schedule create`
```powershell
evedoo.exe schedule create <NAME> --frequency <daily|weekly|hourly|onlogon> [--time <HH:MM>] [--day <DAY>] [--args <ARGS>] [--elevated]
```

---

## 3. evedoo-gui

Desktop companion application built with `egui` and `eframe`.

```powershell
evedoo-gui.exe
```

- **Local Scan:** Run scan, configure database, filters, and output paths.
- **Remote Scan:** Configure WinRM parameters with masked password input.
- **Update DB:** Configure NVD API key and run sync operations.
- **Settings:** Persistent configuration stored in `%APPDATA%\evedoo-gui\config.json`.
- **Auto-Export:** Automatically exports CSV and launches HTML dashboard in browser on scan completion.

---

## 4. evedoo-taskstate (MCP & CLI)

Cross-runtime agent task coordination server exposing 8 Model Context Protocol (MCP) tools over stdio.

### Taskstate CLI Commands

```powershell
# Run the stdio MCP server for agent runtimes
evedoo-taskstate serve

# Re-fold state from tasks.jsonl and update CURRENT.md
evedoo-taskstate render

# Validate tasks.jsonl integrity and invariant correctness
evedoo-taskstate validate
```

### Taskstate Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `EVEDOO_TASKSTATE_RUNTIME` | `unknown` | Identifies the calling runtime (`claude-code` or `antigravity`) and is stamped server-side onto every appended record. Blank/whitespace values fall back to `unknown`. |

> There is **no** `EVEDOO_TASKSTATE_DIR` override. The state directory is
> found by `store::discover_state_dir()`, which walks up from the current
> working directory looking for a `docs/agent-state` directory (stopping at the
> repository root marked by `.git`).

### Taskstate MCP Tool Schemas

1. **`task_state`**
   - **Arguments:** None
   - **Returns:** Folded `State` JSON (active phase, in-progress tasks, review queue, next task, recent rulings).

2. **`task_declare`**
   - **Arguments:** `task: String`, `phase: String`, `title: String`, `description?: String`, `depends_on?: Vec<String>`, `review_required?: bool`
   - **Action:** Declares a new task and appends `TaskDeclared` event.

3. **`task_start`**
   - **Arguments:** `task: String`, `note?: String`
   - **Action:** Moves task to `InProgress` and appends `TaskStarted` event.

4. **`task_finish`**
   - **Arguments:** `task: String`, `outcome: "done" | "done_with_concerns" | "blocked" | "abandoned"`, `summary: String`, `commit?: String`
   - **Action:** Marks task finished and appends `TaskFinished` event.

5. **`task_review`**
   - **Arguments:** `task: String`, `verdict: "clean" | "changes_requested" | "blocked"`, `note: String`, `concerns?: Vec<String>`
   - **Action:** Records review verdict and appends `ReviewRecorded` event.

6. **`task_ruling`**
   - **Arguments:** `subject: String`, `decision: String`, `rationale: String`, `cost_if_wrong: String`
   - **Action:** Appends `RulingRecorded` event to immutable ledger.

7. **`task_history`**
   - **Arguments:** `limit?: usize`, `phase?: String`
   - **Action:** Returns chronological slice of records.

8. **`task_handoff`**
   - **Arguments:** `to: String`, `reason: String`, `task?: String`, `note?: String`
   - **Action:** Appends `HandoffRequested` event for passive runtime transition.

---

## 5. evedoo-studio (SecOps Workspace)

Modern React 18 + TypeScript + Tailwind SecOps Web & Desktop Workspace.

### Studio Launch Commands

```powershell
cd evedoo-studio

# Install dependencies
npm install

# Start development server with Live Engine Bridge
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

### Studio Engine Bridge API

When running via `npm run dev`, Vite dev server provides native backend endpoints connecting the UI directly to the local scanner:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/status` | `GET` | Verifies connection to `evedoo.exe` and `vulndb.sqlite` |
| `/api/scan/run` | `POST` | Triggers a live local system scan (`evedoo.exe scan -f json`) |
| `/api/scan/latest` | `GET` | Retrieves the most recent scan result payload |
| `/api/taskstate` | `GET` | Reads and returns folded state from `docs/agent-state/tasks.jsonl` |
| `/api/taskstate/action` | `POST` | Dispatches a `start` / `finish` / `handoff` task action into the ledger |
| `/api/fleet` | `GET` | The local host, from the last real scan; empty until one has run |

> Every `/api` request must come from loopback, name this server in `Host`,
> carry the `X-Evedoo-Studio: 1` header, and (if not a `GET`) be a JSON `POST`.
> Requests from other origins are refused.
>
> These routes exist **only** under `npm run dev`. They are Vite dev-server
> middleware, not part of the `npm run build` bundle, which ships static assets
> that fall back to `src/api/mockData.ts`.

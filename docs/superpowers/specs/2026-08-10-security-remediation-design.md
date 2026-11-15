# Security Remediation — 2026-08-10 Review

**Status:** Complete — six phases implemented and verified (SEC-1..SEC-7)
**Source:** Branch security review of `dev` (commits `ced2e8d`..`75ba61f` and earlier
divergence from `main`)
**Spec IDs introduced:** `SEC-1` … `SEC-7` (added to `spec.md` §6)

Two findings survived false-positive filtering; one was investigated, confirmed
as a real code defect, but filtered below the reporting bar and is folded in
here as defense-in-depth because it shares a root cause with SEC-1 and costs
one line each to fix.

---

## Threat model context

The scanner consumes two untrusted inputs that matter here:

1. **CVE database contents.** The default sync path is a third-party GitHub
   mirror (`fkie-cad/nvd-json-data-feeds`, `cve-db-builder/src/mirror.rs:40`)
   fetched with no signature, checksum, or pinning. CVE IDs, dates,
   descriptions, and reference URLs are stored verbatim
   (`cve-db-builder/src/database.rs`) and read back verbatim
   (`evedoo/src/matcher/cpe.rs`). NVD reference URLs are also CNA-submitted.
2. **Scanned host filesystem.** Software names, publishers, and install paths
   come from disk and the registry.

Both flow into the generated HTML report, which under `--serve` is rendered
from a real `http://127.0.0.1:<port>` origin (`evedoo/src/serve.rs:19-96`).

---

## Phase 1 — XSS in the HTML report

### SEC-1 (Medium) — JS `esc()` is not attribute-safe

`evedoo/src/report/html.rs:553`

```js
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
```

Text-node serialization escapes only `&`, `<`, `>`, U+00A0 — **not** `"` or
`'`. Its output is concatenated into double-quoted attribute positions and
assigned via `modalBody.innerHTML` (`html.rs:614`):

- `html.rs:608` — `'<li><a href="' + esc(ref) + '" ...>'` ← live vector
- `html.rs:561` — `'<a href="' + esc(d.cveUrl) + '" ...>'`

This **defeats correct Rust-side escaping**: `ref_list` is escaped at
`html.rs:170`, but the HTML parser decodes `&quot;` back to `"` when populating
`dataset.refs`, so `esc()` receives a raw quote and passes it through. `<`/`>`
remain escaped, so no new tag can be injected — but arbitrary attributes can be
appended to the existing `<a>`, and `innerHTML` assignment does register inline
event handlers. `esc()` also applies no scheme restriction, so a `javascript:`
reference renders as a clickable link.

**Fix:**
1. Add `escAttr(s)` — `esc(s)` plus `.replace(/"/g,'&quot;').replace(/'/g,'&#39;')` —
   and use it in every attribute position.
2. Add `safeUrl(u)` returning the URL only when it parses as `http:`/`https:`,
   else `#`. Apply to both `href` sinks.

### SEC-2 (defense-in-depth) — five raw Rust-side interpolations

Every adjacent binding in the same `format!` blocks applies `html_escape()`
(which does encode `"` and `'`, `html.rs:875-881`); these five omit it:

| Value | Bound at | Sink |
|---|---|---|
| `cve_url` | `html.rs:152` | `html.rs:130` `data-cve-url="…"`, `html.rs:135` `href="…"` |
| `pub_date` | `html.rs:164` | `html.rs:126` `data-published="…"`, `html.rs:141` `<td>` |
| `cve_lc` | `html.rs:189` | `html.rs:188` `href="…"` |
| `date` | `html.rs:192` | `html.rs:188` `<td>` |
| `id_lc` | `html.rs:803` | `html.rs:802` `href="…"` |

Reaching these requires a `"` inside a CVE ID or ISO-8601 date, which cannot
occur in legitimate NVD data — hence "defense-in-depth", not a standalone
finding. Fixed anyway: one `html_escape()` wrap each.

**Tests:** a report generated from a finding whose CVE ID, published date, and
reference URL each contain `"`, `'`, `<`, and a `javascript:` URL must contain
no attribute-breaking sequence and no `javascript:` href.

---

## Phase 2 — SEC-3 (Medium): GUI leaks the WinRM password via argv

`evedoo-gui/src/tabs/remote_scan.rs:61-62` puts the password in the child's
argument vector; `evedoo-gui/src/command.rs:30-31` passes it via
`Command::args()` with stdin untouched and no `.env()` call. It is spawned
**three times per remote scan** — JSON (`app.rs:229`), CSV (`app.rs:203`), HTML
(`app.rs:212`) — and the HTML run uses `--serve`, which blocks until Ctrl+C
(`app.rs:177-178`), keeping the command line resident for the server's lifetime.

This regresses a countermeasure the codebase already built:
`evedoo/src/remote/session.rs:105-108,195-211` pipes credentials through
PowerShell **stdin** with the comment that it keeps the password "invisible to
process enumeration tools", and the CLI documents the safe channel at
`evedoo/src/main.rs:106-107` (`env = "EVEDOO_REMOTE_PASSWORD"`).

**Exposure (corrected from the initial report):** a different unprivileged
local user *cannot* read another user's command line — `Win32_Process.CommandLine`
needs a process handle. The real channel is process-creation telemetry:
Security Event 4688 with command-line auditing (a CIS/STIG-recommended
setting), Sysmon Event ID 1, and every commercial EDR — all of which persist
the full command line into logs/SIEM/EDR cloud with long retention. Because
this tool is designed to sweep a fleet, that credential is typically a
privileged domain account.

**Fix:** pass the password through the child's environment
(`cmd.env("EVEDOO_REMOTE_PASSWORD", …)`, which clap already reads) and drop
`--password` from `base_args()`. Requires a secret-aware spawn path in
`command.rs`.

**Honest limitation:** an environment block is still readable from the PEB by
admin/SYSTEM/same-user code. This removes the secret from command-line
telemetry — the dominant exposure — but is not a complete fix. A stdin
password reader (matching `session.rs`) would be strictly better and is
recorded as follow-up work.

**API key:** the NVD key followed the same argv pattern and was moved to
`NVD_API_KEY` alongside the password, since it costs nothing once the helper
exists. It is *not* the justification for this work — a rate-limit token with
no data access, freely regenerable, and already stored in plaintext at
`config.rs:66-68`. The password is the finding.

**Outcome:** `spawn_command` was removed entirely in favour of
`spawn_command_with_env`, so there is no longer a spawn path that silently
routes secrets through argv.

---

## Phase 3 — SEC-4: reject malformed CVE IDs at ingest

`cve-db-builder/src/database.rs::insert_cve` accepts any string as a CVE ID.
Validating `^CVE-\d{4}-\d{4,}$` at the ingest boundary means a tampered feed
cannot introduce markup-bearing identifiers into the database at all — a
boundary control that holds regardless of how many output formats exist now or
later (text, csv, html, cyclonedx, spdx all consume this field).

Rejected rows are logged and skipped, consistent with the existing
per-item-failure policy in the sync loops.

---

## Verification

1. `cargo test --workspace` — all existing tests green plus the new
   XSS-regression and CVE-ID-validation tests.
2. `cargo clippy --workspace --all-targets -- -D warnings` — clean.
3. Manual: generate an HTML report from the live database, open it, confirm the
   detail modal and References list still render correctly (no over-escaping
   regression).
4. Manual: run a remote scan from the GUI and confirm it still authenticates
   with the password supplied in the form.

---

## Phase 4 — SEC-6: mirror feed integrity (+ a coverage bug)

The mirror is a third-party GitHub project whose payload lands directly in the
CVE database, and it was fetched with no verification whatsoever. Each feed
ships a `.meta` sidecar:

```
lastModifiedDate:2026-06-16T21:50:47+00:00
size:5649950
sha256:dc9db7a4696829872457821f28c98763c338f381212828f2ba88a09a52c63fb9
```

Verified empirically against the live mirror: the digest and size describe the
**decompressed** JSON, not the `.xz`. The sync now fetches `.meta` first and
rejects a payload whose digest or size disagrees, before any row is parsed. A
missing sidecar warns and proceeds (older releases may lack one); a sidecar
that is present but malformed is a hard error, since that is the shape
tampering would take.

**Coverage bug found while implementing.** `FIRST_FEED_YEAR` was 2002, with a
comment claiming pre-2002 CVEs are folded into the 2002 feed "matching NVD's
historical feed layout". That is false for this mirror, which publishes one
feed per year from **1999**. A fresh mirror-only build silently dropped 4,378
CVEs — false negatives in a vulnerability scanner. Existing databases only had
those rows as leftovers from the retired NVD API path. Fixed to 1999; a fresh
build now totals 374,405 CVEs with 1999/2000/2001 present.

## Phase 5 — SEC-5: stdin credential handoff

Completes the Phase 2 work. The environment block is still readable from a
process's PEB, so the password now goes over stdin — the same channel
`remote/session.rs` already uses for its PowerShell credentials.

- `evedoo remote-scan --password-stdin` reads the first line of stdin
  (`conflicts_with = "password"`). Only the trailing newline is stripped;
  passwords may legitimately contain leading/trailing spaces.
- `--password` became optional, and its help text now states the exposure.
- `spawn_command_with_env` gained an optional `stdin_secret` and switches to
  `spawn()` + `wait_with_output()` so the pipe is written before the child is
  reaped.
- The GUI passes `--password-stdin` and writes the secret to the pipe, so it
  appears in neither argv nor the environment.

## Phase 6 — SEC-7: GUI helper-binary resolution

`detect_exe_paths` searched the current working directory and
`./target/{debug,release}` before falling back to a bare name — and a bare name
is resolved by `CreateProcess` using a search order that also includes the CWD.
Anyone able to drop `evedoo.exe` into the directory the GUI is launched from
could have it executed with the user's privileges, and that binary is
subsequently handed WinRM credentials.

Resolution is now anchored to the GUI binary's own directory, with sibling
`target/{debug,release}` probes for workspace dev builds. The CWD is never
searched, and the bare-name fallback is gone — if nothing is found, the user
sets an explicit path in Settings.

---

## Remaining follow-up

- The mirror `.meta` sidecar is served from the same origin as the payload, so
  it verifies transport/storage integrity, not authorship. Detached signatures
  would be needed to defend against a fully compromised mirror; none are
  published today.
- `config.rs:66-68` still stores the NVD API key in plaintext in
  `%APPDATA%`. Low value (rate-limit token), but DPAPI would be the Windows-
  native fix.

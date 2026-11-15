# Application Security Review: Evedoo

> **HISTORICAL RECORD — point-in-time review.** Conducted at commit `266f226`
> (2026-08-21) against a three-crate workspace. It does **not** cover code added
> since: `evedoo-taskstate`, the compliance audit engine (`evedoo/src/audit/`),
> runtime reachability (`evedoo/src/reachability/`, which introduces `unsafe`
> Win32 FFI), the MSRC ingest path (`cve-db-builder/src/msrc/`), or
> `evedoo-studio`. Treat the findings as accurate for the scope stated below
> and unassessed elsewhere.

**Scope:** `evedoo`, `cve-db-builder`, `evedoo-gui` (full workspace)
**Reviewed at:** commit `266f226`, 2026-08-21
**Method:** AI-assisted source review. Every claim below was verified against
the code at the cited location; claims that could be tested empirically were.
**Not performed:** dynamic analysis, fuzzing, dependency CVE scanning (see
finding **F-4**), or GitHub Actions supply-chain review beyond action pinning.

Reviewed against OWASP Top 10 and the project's own guidelines in `CLAUDE.md`
(parameterized queries, no hardcoded secrets, fail-secure defaults,
Apache-2.0-compatible dependencies only).

## Summary

The codebase has a **strong security posture**. The controls that matter for
this threat model — SQL parameterization, subprocess argument handling,
PowerShell escaping, credential channels, and output escaping in the HTML
report — are implemented deliberately, and several carry regression tests.

**No high or critical severity issues were found.** Four low-severity findings
and one informational item are recorded below. All are hardening opportunities
rather than exploitable defects.

> **Note on an earlier draft.** A previous version of this document contained
> four claims that do not hold against the code (token entropy, the CSRF
> characterisation, Windows argument escaping, and the credential channel being
> exclusively stdin), and omitted the HTML report — the primary untrusted-data
> sink — from its scope entirely. Those are corrected here and summarised in
> [Appendix A](#appendix-a--corrections-to-the-previous-draft).

---

## Verified Controls

### 1. Database security & SQL injection — **no issues**

- **Parameterized queries throughout.** Every SQLite interaction via `rusqlite`
  binds values with `params![]`. A workspace-wide search for dynamic SQL
  construction (`format!` into `prepare`/`query`/`execute`, `push_str` onto a
  query string) returns **no matches** in either `evedoo/src` or
  `cve-db-builder/src`.
- **Dynamic query *shape* without dynamic query *values*.**
  `fleet.rs:101` `list_assets()` selects between two **static** SQL strings with
  a `match` on whether a tag filter is present, then binds the tag itself as
  `params![format!("%{}%", tag)]` (`fleet.rs:117`). The `format!` builds the
  LIKE *pattern*, not the statement — the value still travels through `?1`.
  This is the correct pattern, and easy to misread as a defect.
- **Ingest validation.** `cve-db-builder/src/database.rs` enforces a canonical
  `CVE-YYYY-NNNN+` shape at `insert_cve`, so a tampered feed cannot introduce
  markup-bearing identifiers regardless of what downstream escaping does.

### 2. Command execution & process injection — **no issues, but see F-2**

- **No shell interpolation.** Arguments are passed as arrays to
  `std::process::Command`, never assembled into a shell string. The workspace
  contains exactly **one** shell-mediated spawn: `serve.rs:118`, which runs
  `cmd /C start "" <url>` to open the browser.
- **PowerShell escaping.** `remote/session.rs:66` `ps_escape()` doubles single
  quotes (`'` → `''`), the correct escape for PowerShell single-quoted strings,
  and every interpolated value (hostname, username, password) passes through it.
- **Validation before escaping** — defence in depth. `RemoteTarget::new()`
  returns `Result` and rejects hostnames and usernames containing anything
  outside an allowlist at construction time, so metacharacters never reach
  PowerShell in the first place.
- **Task Scheduler.** `schedule.rs:72` `validate_schedule_args()` rejects
  ``& | ; > < ` $ ( ) { } ! ^`` in `--args`, which matters because those
  arguments are stored and later executed by a different process at task-fire
  time.
- **Remote path handling.** UNC path construction rejects traversal (`..`) and
  non-absolute paths supplied by the remote host, logging
  `"Rejected unsafe Chocolatey path from remote host"` (`remote/scanners.rs:295`,
  `:380`).

> **Correction to a common rationale.** It is often said that Windows "natively
> escapes" array-passed arguments. It does not — Win32 has no argv array;
> `CreateProcess` takes a single command-line **string**, and Rust's `Command`
> applies quoting rules on your behalf. Those rules match the C runtime's
> parser, **not** `cmd.exe`'s. That mismatch was **CVE-2024-24576
> ("BatBadBut", CVSS 10.0)**, which required a fix in Rust 1.77.2 and still
> leaves `.bat`/`.cmd` targets special-cased. The safety of `serve.rs:118`
> therefore rests on the argument being **internally constructed**
> (`http://127.0.0.1:{port}/?t={hex}` — no user input reaches it), not on the
> escaping being automatic. See **F-2**.

### 3. Credentials & secrets — **no issues, but see F-3**

- **No hardcoded secrets.** No API keys, passwords, or tokens in source.
- **API key handling.** `NVD_API_KEY` is read from the environment or a `.env`
  via `dotenvy`; `.env` is git-ignored.
- **Three credential channels for WinRM, ranked and documented**
  (`main.rs:715` `resolve_remote_password`):
  1. `--password-stdin` — **preferred**; never touches argv, the environment
     block, or disk.
  2. `EVEDOO_REMOTE_PASSWORD` environment variable.
  3. `--password` — still available, and the CLI help states plainly that it
     appears in the process command line, which Windows process-creation
     auditing (event 4688), Sysmon event 1, and EDR agents record and forward
     to a SIEM.

  `--password-stdin` is declared `conflicts_with = "password"`, so the two
  cannot be combined. The GUI passes secrets **only** via `stdin_secret`
  (`evedoo-gui/src/command.rs:40`) and the argv-exposing path is unreachable
  from it — enforced by the test `password_never_appears_in_any_argv`
  (`tabs/remote_scan.rs:310`), which asserts both that the secret string is
  absent from the argument vector and that `--password` is never emitted.
- **Input validation before escaping.** `validate_hostname` and
  `validate_username` (`remote/session.rs:30`, `:48`) reject empty and
  out-of-allowlist values, returning `Err` at construction rather than
  sanitising downstream.
- **Zeroization.** `RemoteTarget` implements `Drop` to `zeroize()` the password
  (`remote/session.rs:142`), so it does not linger in freed heap memory.
- **Log hygiene.** Script blocks containing credentials are not logged:
  `debug!("Executing remote command (script block redacted for security)")`
  (`remote/session.rs:186`).

### 4. Output encoding in the HTML report — **no issues**

*This is the primary untrusted-data sink and was absent from the previous
draft's scope.* The report embeds CVE descriptions and reference URLs from the
NVD feed, plus software names, publishers, and install paths from the local
registry — none of which the tool controls — and renders them in a browser.

Escaping is **context-aware**, which is the part most implementations get wrong:

| Sink | Helper | Location |
|---|---|---|
| Server-side render | `html_escape()` — `& < > " '` | `report/html.rs:1294` |
| JS text node | `esc()` — `textContent → innerHTML` | `report/html.rs:900` |
| JS attribute | `escAttr()` — `esc()` **plus** quotes | `report/html.rs:905` |
| `href` | `safeUrl()` — `^https?://` allowlist | `report/html.rs:908` |

The attribute case is genuinely subtle and worth stating explicitly: `esc()`
escapes `& < >` but **not quotes**, and the browser HTML-decodes `data-*` values
before JavaScript reads them back — so using `esc()` in an attribute position
*undoes* the correct Rust-side escaping. `escAttr()` exists for exactly that
reason. `safeUrl()` keeps `javascript:` and `data:` URIs out of `href` sinks.

These are enforced by tests (`report/html.rs:1696`+), including
`data_attributes_never_contain_markup`, which walks every rendered row's
`data-*` values.

### 5. Parsing of external data — **no issues**

- **JSON** (NVD feeds, `pip`/`npm`/`cargo` output) is deserialized with
  `serde_json` into typed structs — no arbitrary object instantiation, so the
  deserialization-RCE class common to Python `pickle` or Java does not apply.
- **XXE is structurally impossible.** Chocolatey `.nuspec` files are parsed by
  plain string search (`chocolatey.rs:132` `extract_tag`) with no XML parser at
  all, so there is no entity resolution, external DTD fetch, or billion-laughs
  expansion. A side benefit of the project's "avoid heavy dependencies" rule.
- **No ReDoS surface.** The `regex` crate is **absent from the entire
  workspace** — verified across all three `Cargo.toml` files. Version
  normalization (`normalize/version.rs`) is a hand-written parser.

### 6. Feed integrity — **no issues**

`cve-db-builder/src/mirror.rs` verifies each feed's `.meta` sidecar **sha256 and
byte size**, both describing the *decompressed* JSON, before a single row is
parsed. A mismatch aborts that feed; a missing sidecar warns and proceeds; a
malformed one is a hard error, that being the shape tampering would take.

**Stated limitation:** the sidecar shares an origin with the payload, so this
proves **integrity, not authorship**. A fully compromised mirror could serve a
consistent payload/sidecar pair. Defending against that needs detached
signatures, which the FKIE-CAD project does not publish. This is a documented
accepted risk, not an oversight.

### 7. Memory safety & `unsafe` — **no issues**

`unsafe` is confined to **one file**, `scanner/pe_fingerprint.rs`, in 7 blocks
(lines 382, 389, 425, 437–438, 468, 481) wrapping `GetFileVersionInfoSizeW`,
`GetFileVersionInfoW`, and `VerQueryValueW`. No other module in the workspace
contains `unsafe`.

Bounds discipline was checked rather than assumed:
- The buffer is allocated from the size the API itself reports
  (`GetFileVersionInfoSizeW`), with a zero-size early return.
- `query_translation` requires `len_out >= 4` before dereferencing two `u16`s
  (`:433`), so the `offset(1)` read at `:438` is in bounds.
- `slice::from_raw_parts` at `:481` uses the length the API returned.

### 8. Error handling

`thiserror` provides structured error types. Messages are operational and do not
embed credentials or internal memory state.

---

## Findings

All findings are **Low** severity or informational. None is remotely
exploitable; each is a hardening improvement.

### F-1 (Low) — `--serve` token has 60 bits of entropy, not 64

**Location:** `evedoo/src/serve.rs:106` `random_u64()`

The token is `format!("{:016x}", random_u64())`, where `random_u64()` takes the
**first 8 bytes of a UUID v4**. UUID v4 places its 4-bit version field in
**byte 6**, which falls inside that slice, so 4 of the 64 bits are constant.

Verified empirically over 2,000 samples: **the third hex digit of every token is
always `4`.**

```
5d4d629f6538b966
09481aae7774ee79    ← position 2 is invariably '4'
65442975a80948e0
6e4e7f328a0118af
```

**Impact:** minimal. 2⁶⁰ is far beyond brute-forcing against a loopback server
that handles one connection at a time, and the underlying source *is* a CSPRNG
(`uuid` v4 → `getrandom` → OS entropy), so the "cryptographically generated"
half of the original claim holds. Only the bit count is wrong.

**Fix:** slice bytes `[8..16]` instead of `[0..8]` — that range carries the
2-bit variant field rather than the 4-bit version field, giving 62 bits — or,
cleaner, read 8 bytes straight from `getrandom` and drop the UUID round-trip.

### F-2 (Low) — browser launch goes through `cmd.exe`

**Location:** `evedoo/src/serve.rs:118`

`Command::new("cmd").args(["/C", "start", "", url])`.

**Not currently exploitable** — the URL is built internally from a loopback
address, an OS-assigned port, and a hex token, so no external input reaches it.
It is flagged because `cmd /C` is the one argument-handling path on Windows
where Rust's escaping does not match the parser (see the CVE-2024-24576 note in
§2), so this line would become dangerous the moment it gained a caller-supplied
argument.

**Fix:** call `ShellExecuteW` via FFI (consistent with the project's existing
direct-FFI approach in `pe_fingerprint.rs`), or spawn `explorer.exe <url>`, and
drop `cmd` from the process tree. At minimum, add a comment tying the safety
argument to the fact that the URL is internally constructed.

### F-3 (Low) — argv credential path remains available

**Location:** `evedoo/src/main.rs:106`

`--password` still accepts a credential on the command line. This is a
deliberate, documented compatibility affordance: the help text explains the
exposure, `--password-stdin` is marked preferred, and the GUI never uses argv.

**Residual risk:** an operator who has not read the help — or a script written
before `--password-stdin` existed — still leaks credentials to event 4688,
Sysmon, and EDR.

**Options, increasing in strictness:** emit a runtime `warn!` when `--password`
is used (cheap, breaks nothing); gate it behind an explicit
`--allow-insecure-password-arg`; or remove it, leaving stdin and the env var.

### F-4 (Low, process) — no dependency vulnerability scanning in CI

**Location:** `.github/workflows/ci.yml`

CI runs `build`, `clippy -D warnings`, and `test` — verified end to end. There
is **no `cargo audit` or `cargo deny` step.**

Clippy is a **lint** tool. It does not consult RustSec, does not know about
vulnerable dependency versions, and does not audit licences. Treating a green
clippy run as a dependency security check is a category error — and one worth
correcting in a project whose own purpose is finding vulnerable dependencies in
other people's software.

`cargo-deny` would additionally enforce the licence policy in `CLAUDE.md`
(Apache-2.0/MIT/BSD only, no GPL/AGPL) mechanically rather than by review.

**Fix:**

```yaml
- name: Dependency audit
  run: |
    cargo install cargo-deny --locked
    cargo deny check advisories licenses bans
```

### F-5 (Informational) — loose token comparison in `--serve`

**Location:** `evedoo/src/serve.rs:99` `request_has_token()`

The check is `first_line.contains(&format!("t={}", token))` — a substring search
across the whole request line rather than a parse of the `t` query parameter,
and a short-circuiting comparison rather than a constant-time one.

**Impact:** negligible here. A timing oracle over loopback against a
single-threaded accept loop is not a realistic attack, and a token appearing
anywhere in the request line still had to be known in order to be sent. Recorded
for completeness, because this pattern would be a genuine defect in a
multi-user or internet-facing server.

---

## Deliberate Risk Switches (verified fail-secure by default)

Both are **opt-in**, default to the secure behaviour, and warn when engaged:

| Switch | Default | When enabled |
|---|---|---|
| `--skip-tls-verify` | TLS validation **on** | Disables CA/CN/revocation checks on WinRM — removes MITM protection. Help text restricts it to lab use. |
| `--elevated` | Task runs at **normal** privilege | Registers the scheduled task at HIGHEST privilege. |

This is the correct shape: the insecure option exists for real operational
needs, but the user must ask for it explicitly.

---

## Threat Model Note: the `--serve` report server

Worth stating plainly, because the previous draft characterised this
incorrectly.

The token does **not** mitigate CSRF. CSRF requires a state-changing operation
performed with ambient credentials; this server exposes a single read-only
endpoint, sets no cookies, and has no state to change.

What the token actually mitigates is **unauthorized read of the report** — by
another local process, or by a web page in the user's browser probing localhost
ports. That matters because the report is a complete inventory of installed
software and its unpatched vulnerabilities: a reconnaissance gift to anything
already running on the box.

Controls in place: loopback-only bind (`127.0.0.1:0`, `serve.rs:21`), a 60-bit
token required per request, `Cache-Control: no-cache`, and a short-lived
process.

Not set, and reasonable to add: `Referrer-Policy: no-referrer` (the token sits
in the query string and the report links out to NVD and Microsoft — modern
browsers default to `strict-origin-when-cross-origin` and would send only the
origin, so this is belt-and-braces), `X-Content-Type-Options: nosniff`, and a
restrictive `Content-Security-Policy`. The report is self-contained with inline
CSS and JS, so a CSP would need `'unsafe-inline'` for both, which limits its
value — but `default-src 'none'; img-src data:` would still meaningfully
constrain a hypothetical injection.

---

## Conclusion

The project implements fail-secure controls around its genuinely highest-risk
capabilities: executing commands on remote hosts, rendering untrusted
vulnerability data into a browser, and querying a local database built from a
third-party feed. Parameterization, context-aware escaping, credential channel
design, and `unsafe` containment are all handled correctly, and the important
ones are backed by regression tests.

The five findings are hardening items. The one worth prioritising is **F-4** —
not because the risk is high, but because a vulnerability scanner with no
dependency vulnerability scanning in its own CI is an inconsistency worth
closing.

---

## Appendix A — Corrections to the previous draft

| Original claim | Status | Correction |
|---|---|---|
| "strong, cryptographically generated random **64-bit** token" | **Inaccurate** | 60 bits — the UUID v4 version nibble sits inside the sliced bytes. CSPRNG-backed is correct. See **F-1**. |
| "mitigating **Cross-Site Request Forgery (CSRF)**" | **Wrong category** | No state change, no ambient credentials. It mitigates unauthorized *read*. See the threat model note. |
| "array structures, which **Windows properly escapes natively**, bypassing the shell" | **Wrong mechanism** | Win32 has no argv array; Rust applies C-runtime quoting rules that do not match `cmd.exe` — the basis of CVE-2024-24576. One `cmd` spawn exists. See **F-2**. |
| "funneling them through standard input **rather than** passing them as command-line arguments" | **Incomplete** | `--password` still accepts argv, and `EVEDOO_REMOTE_PASSWORD` went unmentioned. See **F-3**. |
| §6 "**Dependency Chain** — Security Check: clippy … exit code 0" | **Category error** | Clippy is a linter, not a dependency auditor, and the section analysed no dependencies. No `cargo audit`/`cargo deny` exists. See **F-4**. |
| §6 "no unsafe anti-patterns identified by **`rustc`**" | **Conflation** | Those lints come from clippy, not rustc. |
| HTML report / XSS | **Absent from scope** | The primary untrusted-data sink was not reviewed. Now §4 — implementation is correct and tested. |
| XXE | **Absent from scope** | Now §5 — structurally impossible; `.nuspec` parsing uses no XML parser. |
| `--skip-tls-verify`, `--elevated` | **Absent from scope** | Now covered; both verified opt-in and fail-secure by default. |
| §1, §2 SQL, `ps_escape`, `validate_schedule_args` | **Confirmed** | Re-verified against the code; accurate as written. |
| §6 `unsafe` isolated to `pe_fingerprint.rs` | **Confirmed** | Verified workspace-wide; bounds checks confirmed rather than assumed. |
| §4 no-ReDoS, §5 log redaction, §3 no hardcoded secrets | **Confirmed** | `regex` absent workspace-wide; redaction line present verbatim. |
| "**No critical vulnerabilities** … were identified" | **Sustained** | Re-verified independently, with the scope gaps above closed. |

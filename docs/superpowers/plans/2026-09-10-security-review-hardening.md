# Security-Review Hardening — Implementation Plan

> **For the executing agent:** three targeted defense-in-depth fixes from the
> 2026-09-10 `/security-review` pass. All three candidate findings scored
> **below** the reporting threshold (4/10, 2/10, 3/10) — none is an exploitable
> vulnerability. These are the "recommended anyway" hardening items. TDD where
> code logic changes; `cargo test --workspace` and
> `cargo clippy --workspace --all-targets -- -D warnings` must both pass.

**Origin:** `/security-review` on the `dev` branch. The review found no
HIGH/MEDIUM findings. Full context: `docs/superpowers/specs/2026-08-29-*` and
the review output in this session's history.

**Handoff:** Claude Code → Antigravity, 2026-09-10.

---

## Task 1 — Studio dev server: bind to loopback

**File:** `evedoo-studio/vite.config.ts`

**Why:** `server: { host: true }` (line ~400) binds the Vite dev server — and
its `/api/*` middleware, which spawns `evedoo.exe` and returns the host's full
vulnerability inventory — to `0.0.0.0`. While a developer runs `npm run dev` on
an untrusted network, any LAN peer can pull that inventory and forge records
into `docs/agent-state/tasks.jsonl`. The middleware runs **only** under
`npm run dev` (never `vite build` / `vite preview`), so nothing ships — this is
dev-tooling hygiene, not a shipped defect. Reviewer confidence 4/10.

**Change:**

1. In the `server` block, replace `host: true` with `host: '127.0.0.1'`.
   (Do not simply delete the key — being explicit documents intent and resists
   a future "just add `host: true` back" edit.)

2. Defense in depth: in `configureServer(server)`, at the very top of the
   `server.middlewares.use(async (req, res, next) => { ... })` handler, before
   any route dispatch, reject non-loopback callers of `/api/`:

   ```ts
   const url = req.url || '';
   if (url.startsWith('/api/')) {
     const ra = req.socket.remoteAddress || '';
     const isLoopback =
       ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1';
     if (!isLoopback) {
       res.statusCode = 403;
       res.end('forbidden: /api is loopback-only');
       return;
     }
   }
   ```

   This keeps the `/api` surface loopback-only even if someone runs
   `vite dev --host` on the CLI (which overrides the config).

**Verify:** `cd evedoo-studio && npm run dev`, confirm the app loads at
`http://localhost:5173` and a scan through the UI still works. Confirm
`curl http://<lan-ip>:5173/api/status` from another host now fails to connect
(or returns 403 if `--host` was forced).

**No automated test** — Vite config, verified manually.

---

## Task 2 — CSV formula-injection neutralization

**Files:** `evedoo/src/report/mod.rs` (new helper),
`evedoo/src/audit/report.rs`, `evedoo/src/report/csv.rs`

**Why:** Both CSV generators write free-text fields (rule titles, fix text,
software names/versions, install paths, upgrade commands, registry values) into
cells with no formula-injection guard. A cell beginning `=`, `+`, `-`, `@`,
TAB, or CR is interpreted as a formula by Excel/LibreOffice. The data sources
here are largely operator-trusted (bundled STIGs, `--policy` files) or
admin-write registry keys, and modern Excel blocks DDE/`=cmd` by default — so
this is not a confidently-actionable vuln (reviewer 3/10). But formula
neutralization is standard, cheap, and every report generator should have it.

**Step 1 — the helper.** In `evedoo/src/report/mod.rs`:

```rust
/// Neutralise spreadsheet formula injection (OWASP CSV injection / CWE-1236).
///
/// A CSV cell whose first character is `=`, `+`, `-`, `@`, TAB, CR, or LF is
/// executed as a formula by Excel and LibreOffice. Prefixing a single quote
/// forces the cell to be read as text. Values that don't start with a
/// dangerous character are returned unchanged.
pub(crate) fn sanitize_csv_cell(value: &str) -> std::borrow::Cow<'_, str> {
    match value.as_bytes().first() {
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r' | b'\n') => {
            std::borrow::Cow::Owned(format!("'{value}"))
        }
        _ => std::borrow::Cow::Borrowed(value),
    }
}
```

TDD — write these first, watch them fail:

```rust
#[test]
fn sanitize_csv_cell_prefixes_every_dangerous_leader() {
    for lead in ["=cmd|' /c calc'!A1", "+1+1", "-1", "@SUM(A1)", "\tx", "\rx", "\nx"] {
        let out = sanitize_csv_cell(lead);
        assert!(out.starts_with('\''), "{lead:?} was not neutralised: {out:?}");
        assert!(out.ends_with(lead));
    }
}

#[test]
fn sanitize_csv_cell_leaves_safe_values_untouched_and_borrowed() {
    for safe in ["Google Chrome", "1.2.3", "", "CVE-2024-1234", "cmd|'/c calc'"] {
        assert!(matches!(sanitize_csv_cell(safe), std::borrow::Cow::Borrowed(_)));
        assert_eq!(sanitize_csv_cell(safe), safe);
    }
}
```

**Step 2 — apply in `audit/report.rs::generate_csv_report`.** Wrap the
free-text / value cells in the data row (`benchmark_id`, `benchmark_title`,
`title`, `expected_value`, `actual_value`, `details`, `fix_text`). The
fixed-vocabulary cells (`severity.as_str()`, `status.as_str()`, `audit_date`,
`rule_id`, `stig_id`, `nist_controls` join) don't need it but wrapping them is
harmless if it keeps the call site uniform. Header row is static — leave it.

Add a test: a `RuleResult` with `fix_text = "=cmd|'/c calc'!A1"` produces a CSV
whose corresponding cell is `'=cmd|'/c calc'!A1` (parse the CSV back with the
`csv` crate and assert on the field).

**Step 3 — apply in `evedoo/src/report/csv.rs::generate_csv`.** Wrap the
free-text cells in **both** `write_record` blocks (the findings block ~line 136
and the resolved-findings block ~line 261): `software.name`, `software.version`,
`software.publisher` / vendor, `registry_key`, the `"{name} v{version}"` and
`"{name}"` `format!` cells, `upgrade_command`, `kb_articles` join,
`fixed_version`, and the description-derived title. `classify_software()` output
is a fixed vocabulary — skip. The NVD URL is `https://…` — safe, skip.

Add a test mirroring the existing csv tests: a finding whose
`software.name` is `=HYPERLINK("http://evil","x")` yields a neutralised cell.

**Note the behaviour change:** downstream CSV consumers now see a leading `'`
on any cell that started with a dangerous character. This is the
OWASP-recommended trade-off and matches what every enterprise reporting tool
does.

---

## Task 3 — Redact raw binary registry values from audit reports

**File:** `evedoo/src/audit/evaluator.rs`

**Why:** When a `CheckAssertion::Registry` rule reads a `RegistryValueType::Binary`
value, the raw bytes are formatted as `[12, 34, 56, …]` by `format_value`
(`evaluator.rs` ~line 334) and land verbatim in `RuleResult.actual_value`,
which is rendered into every report format. Dumping raw registry blob bytes
into a document that gets shared as a "compliance report" is poor hygiene even
though the review concluded this is not exploitable (reviewer 2/10: `--policy`
files are operator-trusted config, and the sensitive `HKLM\SAM` / `HKLM\SECURITY`
keys are SYSTEM-only and return `AccessDenied` under a normal elevated run).

**Change:** where the registry read builds the `actual` JSON value for a
`Binary` result (the `RegistryValueType::Binary` branch of the read/compare
logic — find it near `get_raw_value` / `.bytes`), do **not** put the raw byte
array into the value used for `actual_value`. Replace it with a summary string:

```rust
// A registry blob's raw bytes have no place in a shareable compliance
// report. Report its size; the comparison logic (length / expected-bytes
// match) still runs against the real bytes.
format!("<binary value: {} bytes>", bytes.len())
```

Keep the actual byte comparison (does it match the expected value / expected
length) working against the real bytes — only the *reported* `actual_value`
string changes.

**Do NOT** add a registry key allowlist or denylist. The review was explicit:
directing an audit to read a specified key is the designed function of a
benchmark file (same trust model as a Nessus `.audit` or an osquery pack), and
an allowlist would break legitimate custom benchmarks.

Add a test: a `Binary` registry check result has
`actual_value == Some("<binary value: N bytes>")`, not a `[..]` byte dump.

---

## Done criteria

- [x] `evedoo-studio/vite.config.ts` binds `/api` to loopback (config + middleware guard); `npm run dev` still works locally
- [x] `sanitize_csv_cell` helper exists with passing unit tests
- [x] `audit/report.rs` and `report/csv.rs` CSV cells neutralised, with a regression test in each
- [x] Binary registry values render as `<binary value: N bytes>` in `actual_value`, with a test; **no** key allow/denylist added
- [x] `cargo test --workspace` — all pass
- [x] `cargo clippy --workspace --all-targets -- -D warnings` — clean
- [x] Record completion in `docs/agent-state/tasks.jsonl` and commit

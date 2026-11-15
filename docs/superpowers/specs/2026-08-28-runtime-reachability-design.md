# Runtime Reachability for Loaded Modules — Design

**Task:** `P21-N3` (Phase 21, Enterprise Accuracy & Reachability)
**Status:** SHIPPED — implemented as `evedoo/src/reachability/` (`P21-N3`, closed 2026-08-28). Accepted limitation: `NotObserved` is unreachable in practice on an unelevated scan, because FR-74 forces every non-match to `Unknown` when coverage is incomplete.
**Spec IDs introduced:** `FR-73` … `FR-82`, `NFR-9`, `SEC-8`, `DC-6`
**Depends on:** `FR-63`..`FR-66` (risk scoring), `FR-57` (inventory snapshot)

---

## 1. Problem

The largest remaining noise class in a real scan is bundled libraries. One
measured host carried three separate cURL copies and several OpenSSL copies,
each found by `pe_fingerprint` inside a different application's install
directory, each correlating to the same CVEs. Better CPE matching cannot fix
this: all three cURL copies genuinely *are* cURL, and all three genuinely *are*
the vulnerable version. The distinction that matters to an operator is not
identity but **whether the code is actually running**.

Enumerating loaded modules per process answers that question, and it is the one
accuracy play unavailable to a purely database-driven scanner. It is also the
axis enterprise tooling is converging on: "is this reachable?" rather than "is
this present?".

## 2. The governing constraint

**Reachability may raise a finding's priority. It may never lower one.**

A scan is a sample lasting seconds, taken against a machine that runs for
months. A vulnerable DLL that is not mapped into any process right now becomes
exploitable the instant its application launches — which may be thirty seconds
after the scan ends. Treating "not loaded now" as evidence of safety would
convert a sampling artifact into a security claim, and would do so most
aggressively for scans that run out-of-hours, when the fewest processes are
alive.

Every other decision in this document follows from that constraint.

## 3. Data model

```rust
pub enum Reachability {
    /// A module at this path is mapped into at least one live process.
    Loaded,
    /// Coverage was complete for this scan and no such module was mapped.
    NotObserved,
    /// Reachability was not determined: incomplete process coverage, a
    /// reassess against a stored snapshot, or a failed remote collection.
    Unknown,
}
```

`Unknown` is an honesty state, not an error state. Because only `Loaded`
affects scoring, `Unknown` and `NotObserved` are behaviourally identical
today — but they make different claims to a human reader, and collapsing them
is precisely how an observation gap turns into a false assurance. The
distinction is therefore load-bearing even though nothing branches on it.

The collector returns:

```rust
pub struct ModuleMap {
    paths: HashSet<String>,      // normalised, lowercased, absolute
    coverage: Coverage,
}

pub struct Coverage {
    pub readable: usize,
    pub total: usize,
}
```

- **FR-73** — The scanner SHALL enumerate modules mapped into live processes and
  expose the result as a `Reachability` value per finding.
- **FR-74** — When `coverage.readable < coverage.total`, every finding that does
  not match a collected module SHALL be `Unknown`, never `NotObserved`. Partial
  coverage SHALL NOT be capable of producing a negative observation.

## 4. Local collection

`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` with `Process32FirstW` /
`Process32NextW` to enumerate PIDs, then per PID a second snapshot with
`TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32` walked by `Module32FirstW` /
`Module32NextW`, reading `szExePath`.

Accessed through direct `#[link(name = "kernel32")] extern "system"`
declarations, matching the `version.dll` precedent already established in
`scanner/pe_fingerprint.rs`. **No new crate dependency** — consistent with the
project rule to prefer direct FFI over heavy crates.

`TH32CS_SNAPMODULE32` is included so a 64-bit scanner still sees the modules of
WOW64 (32-bit) processes. Omitting it would silently under-report exactly the
older bundled libraries most likely to be vulnerable.

Before enumerating, the scanner attempts to enable `SeDebugPrivilege`
(`OpenProcessToken` / `LookupPrivilegeValueW` / `AdjustTokenPrivileges` via
`advapi32`). Failure is not an error: it is the normal unelevated case, and the
run proceeds best-effort. This is what makes an elevated run see the whole
machine and an unelevated run see the current user's processes — which is where
user-installed vulnerable software actually runs.

Every process that cannot be opened increments `total` without incrementing
`readable`, feeding FR-74.

- **FR-75** — Local collection SHALL be best-effort: processes that cannot be
  opened SHALL be counted as unreadable and SHALL NOT abort the scan.

## 5. Remote collection

Remote hosts are reached over the existing WinRM transport
(`RemoteSession::execute`). The script block is a **fixed constant with no
interpolated values whatsoever** — no hostname, no path, no user-controlled
substring enters it.

- **SEC-8** — The remote reachability command SHALL contain no interpolated
  input. Its injection surface is eliminated by construction rather than by
  escaping, which is a stronger guarantee than the `ps_escape()` path used by
  scanners that must pass arguments.

A remote collection failure SHALL yield `Unknown` for every finding on that
host — never `NotObserved`, since a failed collection observed nothing.

- **FR-76** — `remote-scan` SHALL collect reachability over the existing WinRM
  session and SHALL degrade to `Unknown` on any collection failure.

## 6. Matching a module to a finding

Two rules, chosen so precision is highest where the payoff is highest:

| Finding source | Rule |
|---|---|
| `pe://` | **Exact path equality**, case-insensitive, after normalisation. The dedup key *is* the DLL's absolute path, so this is an identity comparison with no inference. |
| `registry://`, `winget://`, `chocolatey://`, `scoop://`, `appx://` | **Directory containment**: `Loaded` if any collected module path sits under `install_location`. |
| `os://`, `pip://`, `npm://`, `cargo://` | `Unknown` — these have no meaningful single on-disk image to match. |

Filename matching is deliberately **excluded**. Marking every `libcurl` finding
loaded because some `libcurl.dll` is mapped somewhere would conflate the three
distinct cURL copies that motivated this feature — it would destroy the very
distinction being built.

**A finding whose `install_location` is `None` SHALL be `Unknown`.** Containment
cannot be evaluated without a directory, and treating an unevaluable finding as
`NotObserved` would assert an observation that was never made — the same
false-negative class FR-74 exists to prevent, arriving through a different door.
`install_location` is `Option<String>` on `DetectedSoftware` and is genuinely
absent for many registry and AppX entries, so this is the common path, not an
edge case.

- **FR-77** — Reachability matching SHALL use exact path identity for `pe://`
  findings and install-directory containment for package-manager findings.
  Bare-filename matching SHALL NOT be used. A finding that cannot be evaluated
  under either rule SHALL be `Unknown`.

## 7. Risk integration

`risk::assess` gains a fourth input:

```rust
pub fn assess(
    v: &Vulnerability,
    has_exploit_ref: bool,
    criticality: f32,
    reachability: Reachability,
) -> RiskAssessment
```

with

```
reach_factor = 1.25 if Loaded, else 1.00
score = 100 · impact^0.4 · likelihood^0.6 · criticality · reach_factor
```

`1.25` matches the top of the existing `criticality_for` scale, keeping the two
multipliers commensurate so neither silently dominates, and it leaves the
P1/P2/P3 thresholds untouched.

Because the factor is `1.00` for both `NotObserved` and `Unknown`, a finding's
score can only ever rise relative to today's output. **No finding can be demoted
by this feature**, satisfying §2 arithmetically rather than by convention.

- **FR-78** — Reachability SHALL enter the risk score as a multiplier that is
  strictly `1.0` for every value except `Loaded`. No code path SHALL apply a
  reachability factor below `1.0`.

### Calibration verification (not an assumption)

The measured tier split on the 868-finding reference corpus is P1 1.5%,
P2 47.2%, P3 3.3%, P4 47.9% — P1 is underpopulated while P2 floods. Promoting
running code is the intended correction. The implementation SHALL re-measure the
split on that corpus and record the before/after distribution.

A prior ruling established that thresholds are not to be retuned on a single
host's data. This verification is therefore **reporting, not a tuning input**,
unless the observed shift is extreme enough to warrant its own ruling.

## 8. Reassess

`reassess` re-correlates a *stored* inventory snapshot against a refreshed CVE
database. That snapshot was captured at a different moment, so any reachability
recorded alongside it describes the past.

- **FR-79** — `reassess` SHALL pass `Unknown` for every finding. Stored
  reachability SHALL NOT be replayed as current.

## 9. Reporting

| Format | Treatment |
|---|---|
| Text | A `Reachability:` line, shown only when the value is not `Unknown` — the same "skip entirely rather than caveat" rule `delta_known` established for status. |
| CSV | A `Reachability` column. |
| JSON | A `reachability` field on each finding (`#[serde(default)]`, per DC-3 additive compatibility). |
| HTML | A badge in the findings table and a modal field, with the column dropped entirely when no finding has a determined value. |
| CycloneDX / SPDX | Unchanged. Neither format has a field whose meaning matches "loaded right now", and inventing a property would assert more than the data supports. |

- **FR-80** — Reachability SHALL appear in text, CSV, JSON, and HTML output and
  SHALL be omitted rather than rendered as a placeholder when undetermined.
- **FR-81** — The scanner SHALL print collection coverage to the console, e.g.
  `reachability: 142/210 processes readable — run elevated for full coverage`.
  Coverage SHALL be disclosed even when complete.

## 10. Persistence and control

- **FR-82** — Reachability SHALL NOT be persisted to `scan_findings`. It is
  point-in-time by nature and a stored value is stale the moment it is written.
- **DC-6** — The JSON scan artifact gains an optional `reachability` string per
  finding (`loaded` | `not_observed` | `unknown`), absent in artifacts produced
  before this feature.
- Collection is **on by default**; `--no-reachability` opts out.
- **NFR-9** — Reachability collection SHALL add no more than roughly one second
  to a typical scan (about one snapshot per live process, ~200 processes on a
  normal desktop) and SHALL never block the scan on an unreadable process.

## 11. Module boundaries

```
evedoo/src/reachability/
  mod.rs      — Reachability, ModuleMap, Coverage, matching rules, tests
  local.rs    — kernel32/advapi32 FFI, process + module enumeration
  remote.rs   — fixed WinRM script block and its parser
```

`mod.rs` holds all the pure logic (matching, the coverage-to-`Unknown` floor,
path normalisation) and is fully testable without Windows APIs or a remote host.
That is where the behaviour that can be wrong lives.

`local.rs` and `remote.rs` are thin collectors behind one shared return type, so
a caller cannot tell which produced a given `ModuleMap`. This mirrors the
existing `scanner/` plus `remote/scanners.rs` split.

## 12. Testing

Pure logic is unit-tested against constructed `ModuleMap` values with no FFI.
Each case below names the mutation that proves the test is not vacuous:

| # | Behaviour | Mutation that must fail the test |
|---|---|---|
| 1 | Partial coverage forces `Unknown` | Change the floor to emit `NotObserved` |
| 2 | `pe://` requires exact path equality | Relax to substring or filename matching; three distinct cURL copies stop being distinguished |
| 3 | Containment matches only under `install_location` | Relax to match any path |
| 3b | A finding with no `install_location` is `Unknown` | Return `NotObserved` for the `None` case |
| 4 | `reach_factor` is `1.0` for `Unknown` and `NotObserved` | Set it to `0.8`; the "never demote" test must fail |
| 5 | `reassess` passes `Unknown` | Substitute a live collection |
| 6 | Reports omit rather than placeholder | Render the literal "Unknown" |

FFI collection itself is verified by an integration test asserting that the
current process's own modules are found — the scanner can always open itself, so
this is deterministic — plus `coverage.readable >= 1`.

## 13. Out of scope

- Persisting reachability history or trending it over time.
- Reachability for `pip://`, `npm://`, `cargo://`, and `os://` findings.
- Any demotion, filtering, or suppression based on `NotObserved`.
- CycloneDX / SPDX schema extension.

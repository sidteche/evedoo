# Runtime Reachability Implementation Plan

> **Status: SHIPPED (Historical Plan).** All 39 steps executed and ticked
> (`P21-N3`, closed 2026-08-28). Implemented in `evedoo/src/reachability/`.
> **Known limitation, accepted by ruling:** because FR-74 forces every non-match
> to `Unknown` when process coverage is incomplete, `NotObserved` is unreachable
> in practice on an unelevated scan. See `docs/agent-state/CURRENT.md`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rank findings whose code is loaded into a live process above findings that merely exist on disk, without ever lowering the priority of a finding that is not currently loaded.

**Architecture:** A new `evedoo/src/reachability/` module with all pure logic in `mod.rs` (the three-state `Reachability` enum, `ModuleMap`, matching rules) and two thin collectors behind one shared return type: `local.rs` (direct `kernel32`/`advapi32` FFI via Toolhelp32) and `remote.rs` (a fixed PowerShell script block over the existing WinRM session). The value flows into `risk::assess` as a multiplier that is strictly `>= 1.0`, so no finding can be demoted.

**Tech Stack:** Rust 2021, direct Win32 FFI (no new crate dependencies), `serde`, existing `RemoteSession` WinRM transport.

**Spec:** `docs/superpowers/specs/2026-08-28-runtime-reachability-design.md`

> **Status: Completed.** All six tasks implemented, verified, and pushed
> (`7d8cd18`..`416705f`). Measured unelevated on a real desktop: 159/332
> processes readable, 6 findings Loaded, 0 NotObserved, 982 Unknown; the
> x1.25 multiplier confirmed exact (23.0 -> 28.7 and four others). See the
> ruling "NotObserved is unreachable in practice on unelevated scans" in
> `docs/agent-state/tasks.jsonl` for the one open design consequence.

## Global Constraints

- **Never demote.** The reachability multiplier is `1.25` for `Loaded` and exactly `1.0` for `NotObserved` and `Unknown`. No code path may apply a factor below `1.0`. (FR-78, spec §2)
- **Partial coverage cannot produce a negative.** When `coverage.readable < coverage.total`, a non-matching finding is `Unknown`, never `NotObserved`. (FR-74)
- **No new crate dependencies.** Win32 access is direct FFI, matching `scanner/pe_fingerprint.rs`. (spec §4)
- **No interpolated input in the remote script block.** (SEC-8)
- **MSRV Rust 1.83** for the `evedoo` crate; edition 2021 (so `extern "system" { … }` blocks are written without the `unsafe extern` prefix that edition 2024 requires).
- `cargo clippy --workspace --all-targets -- -D warnings` must pass — CI gate.
- Tests live in `#[cfg(test)] mod tests` blocks inside each source file.
- Parameterised SQL only; nothing in this feature writes to SQLite (FR-82).

---

### Task 1: Reachability type, ModuleMap, and matching rules

This is the whole of the logic that can be wrong. It has no FFI and no I/O.

**Files:**
- Create: `evedoo/src/reachability/mod.rs`
- Modify: `evedoo/src/main.rs` (add `mod reachability;` to the module list at lines 14-30, alphabetically between `mod normalize;` and `mod reconcile;`)
- Modify: `evedoo/src/models.rs` (add the `reachability` field to `Finding`)

**Interfaces:**
- Consumes: `crate::models::DetectedSoftware` (fields `registry_key: String`, `install_location: Option<String>`)
- Produces:
  - `pub enum Reachability { Loaded, NotObserved, Unknown }` — `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`, `Default` (defaults to `Unknown`)
  - `pub struct Coverage { pub readable: usize, pub total: usize }`
  - `pub struct ModuleMap` with `pub fn new(paths: HashSet<String>, coverage: Coverage) -> Self`, `pub fn empty_unknown() -> Self`, `pub fn is_complete(&self) -> bool`, `pub fn coverage(&self) -> Coverage`
  - `pub fn classify(software: &DetectedSoftware, map: &ModuleMap) -> Reachability`
  - `pub fn normalize_path(p: &str) -> String`
  - `Finding.reachability: Reachability` with `#[serde(default)]`

- [x] **Step 1: Write the failing tests**

Create `evedoo/src/reachability/mod.rs` with only the test module plus the imports it needs, so the tests fail to compile against absent items:

```rust
//! Runtime reachability: whether a finding's code is mapped into a live
//! process right now, as opposed to merely present on disk.
//!
//! The governing rule (spec §2) is that reachability may RAISE a finding's
//! priority and may never lower one. A scan samples seconds of a machine that
//! runs for months, so "not loaded now" is not evidence of safety.
//!
//! SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Architecture, DetectedSoftware};
    use std::collections::HashSet;

    fn sw(registry_key: &str, install_location: Option<&str>) -> DetectedSoftware {
        DetectedSoftware {
            name: "Test".into(),
            version: Some("1.0".into()),
            publisher: None,
            install_location: install_location.map(|s| s.to_string()),
            install_date: None,
            registry_key: registry_key.into(),
            architecture: Architecture::X64,
        }
    }

    fn map_of(paths: &[&str], readable: usize, total: usize) -> ModuleMap {
        let set: HashSet<String> = paths.iter().map(|p| normalize_path(p)).collect();
        ModuleMap::new(set, Coverage { readable, total })
    }

    /// FR-74. The single most important behaviour here: an incomplete sweep
    /// must not be able to say "not loaded". Only a complete sweep may.
    #[test]
    fn partial_coverage_forces_unknown_not_not_observed() {
        let m = map_of(&[r"C:\Other\thing.dll"], 5, 9);
        let s = sw(r"pe://C:\App\libcurl.dll", None);
        assert_eq!(classify(&s, &m), Reachability::Unknown);
    }

    /// The contrast case: with full coverage, a non-match is a real negative.
    #[test]
    fn full_coverage_non_match_is_not_observed() {
        let m = map_of(&[r"C:\Other\thing.dll"], 9, 9);
        let s = sw(r"pe://C:\App\libcurl.dll", None);
        assert_eq!(classify(&s, &m), Reachability::NotObserved);
    }

    /// FR-77. `pe://` keys ARE absolute paths, so this is identity, not
    /// inference. Case and separator differences must still match.
    #[test]
    fn pe_finding_matches_on_exact_path_case_insensitively() {
        let m = map_of(&[r"C:\App\libcurl.dll"], 9, 9);
        let s = sw(r"pe://c:/APP/LibCurl.DLL", None);
        assert_eq!(classify(&s, &m), Reachability::Loaded);
    }

    /// The noise class this whole feature exists to split. Three copies of the
    /// same library, one loaded. Filename matching would mark all three.
    #[test]
    fn three_sibling_copies_are_distinguished() {
        let m = map_of(&[r"C:\AppA\libcurl.dll"], 9, 9);
        let a = sw(r"pe://C:\AppA\libcurl.dll", None);
        let b = sw(r"pe://C:\AppB\libcurl.dll", None);
        let c = sw(r"pe://C:\AppC\libcurl.dll", None);

        assert_eq!(classify(&a, &m), Reachability::Loaded);
        assert_eq!(classify(&b, &m), Reachability::NotObserved);
        assert_eq!(classify(&c, &m), Reachability::NotObserved);
    }

    /// FR-77. Package-manager findings have no single image path, so any
    /// loaded module under the install directory counts.
    #[test]
    fn registry_finding_matches_by_install_directory_containment() {
        let m = map_of(&[r"C:\Program Files\Vendor\App\bin\helper.dll"], 9, 9);
        let s = sw("registry://vendor-app", Some(r"C:\Program Files\Vendor\App"));
        assert_eq!(classify(&s, &m), Reachability::Loaded);
    }

    /// Containment must not leak to a sibling directory sharing a prefix.
    #[test]
    fn containment_does_not_match_sibling_prefix_directory() {
        let m = map_of(&[r"C:\Program Files\Vendor\AppTwo\x.dll"], 9, 9);
        let s = sw("registry://vendor-app", Some(r"C:\Program Files\Vendor\App"));
        assert_eq!(classify(&s, &m), Reachability::NotObserved);
    }

    /// Spec §6. An unevaluable finding is Unknown, never NotObserved —
    /// asserting an observation that was never made is the same defect as
    /// FR-74, arriving through a different door. install_location is
    /// Option<String> and is genuinely absent for many registry/AppX entries.
    #[test]
    fn finding_without_install_location_is_unknown() {
        let m = map_of(&[r"C:\Anything\x.dll"], 9, 9);
        let s = sw("registry://no-location", None);
        assert_eq!(classify(&s, &m), Reachability::Unknown);
    }

    /// Spec §6. Ecosystem and OS findings have no single on-disk image.
    #[test]
    fn ecosystem_and_os_findings_are_unknown() {
        let m = map_of(&[r"C:\Anything\x.dll"], 9, 9);
        for key in ["pip://requests", "npm://lodash", "cargo://serde", "os://windows"] {
            let s = sw(key, Some(r"C:\Anything"));
            assert_eq!(
                classify(&s, &m),
                Reachability::Unknown,
                "{key} has no meaningful single image to match"
            );
        }
    }

    /// A map from a failed or skipped collection determines nothing.
    #[test]
    fn empty_unknown_map_classifies_everything_unknown() {
        let m = ModuleMap::empty_unknown();
        let s = sw(r"pe://C:\App\libcurl.dll", None);
        assert_eq!(classify(&s, &m), Reachability::Unknown);
    }

    #[test]
    fn default_reachability_is_unknown() {
        assert_eq!(Reachability::default(), Reachability::Unknown);
    }

    #[test]
    fn serde_uses_snake_case_per_dc6() {
        // DC-6: `loaded` | `not_observed` | `unknown`
        assert_eq!(
            serde_json::to_string(&Reachability::NotObserved).unwrap(),
            "\"not_observed\""
        );
        assert_eq!(
            serde_json::from_str::<Reachability>("\"loaded\"").unwrap(),
            Reachability::Loaded
        );
    }
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p evedoo reachability`
Expected: FAIL to compile — `cannot find type ModuleMap in this scope`, `cannot find function classify`, etc. This is the correct failure; it proves the tests bind to items that do not exist yet.

- [x] **Step 3: Write the minimal implementation**

Insert above the `#[cfg(test)]` block in `evedoo/src/reachability/mod.rs`:

```rust
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::models::DetectedSoftware;

pub mod local;
pub mod remote;

/// Whether a finding's code is mapped into a live process.
///
/// `Unknown` is an honesty state, not an error state. Only `Loaded` affects
/// scoring, so `Unknown` and `NotObserved` behave identically today — but they
/// make different claims to a reader, and collapsing them is how an
/// observation gap becomes a false assurance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// A module at this path is mapped into at least one live process.
    Loaded,
    /// Coverage was complete for this scan and no such module was mapped.
    NotObserved,
    /// Not determined: incomplete coverage, a reassess against a stored
    /// snapshot, a failed remote collection, or an unevaluable finding.
    #[default]
    Unknown,
}

impl std::fmt::Display for Reachability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reachability::Loaded => write!(f, "Loaded"),
            Reachability::NotObserved => write!(f, "Not loaded"),
            Reachability::Unknown => write!(f, "Unknown"),
        }
    }
}

/// How much of the process list the collector could actually read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    pub readable: usize,
    pub total: usize,
}

/// The set of module paths mapped into live processes, plus how complete the
/// sweep was.
#[derive(Debug, Clone, Default)]
pub struct ModuleMap {
    paths: HashSet<String>,
    coverage: Coverage,
}

impl ModuleMap {
    pub fn new(paths: HashSet<String>, coverage: Coverage) -> Self {
        Self { paths, coverage }
    }

    /// A map that determines nothing: used when collection was skipped
    /// (`--no-reachability`), failed, or is inapplicable (`reassess`).
    /// `total = 1, readable = 0` makes it deliberately incomplete, so FR-74
    /// forces every classification to `Unknown` through the normal path
    /// rather than through a special case.
    pub fn empty_unknown() -> Self {
        Self {
            paths: HashSet::new(),
            coverage: Coverage { readable: 0, total: 1 },
        }
    }

    pub fn is_complete(&self) -> bool {
        self.coverage.readable >= self.coverage.total
    }

    pub fn coverage(&self) -> Coverage {
        self.coverage
    }
}

/// Lowercase and canonicalise separators so Windows path comparisons behave.
/// Trailing separators are stripped so containment prefixes are exact.
pub fn normalize_path(p: &str) -> String {
    let lowered = p.trim().to_ascii_lowercase().replace('/', "\\");
    lowered.trim_end_matches('\\').to_string()
}

/// The negative that a non-match resolves to. Never `NotObserved` unless the
/// sweep was complete (FR-74).
fn negative_for(map: &ModuleMap) -> Reachability {
    if map.is_complete() {
        Reachability::NotObserved
    } else {
        Reachability::Unknown
    }
}

/// Classify one finding's software against the collected module set (FR-77).
pub fn classify(software: &DetectedSoftware, map: &ModuleMap) -> Reachability {
    let key = &software.registry_key;

    // `pe://` keys are the absolute path of the image itself, so this is an
    // identity comparison. Filename matching is deliberately excluded: it
    // would re-conflate sibling copies of a bundled library, which is the
    // exact distinction this feature exists to draw.
    if let Some(path) = key.strip_prefix("pe://") {
        return if map.paths.contains(&normalize_path(path)) {
            Reachability::Loaded
        } else {
            negative_for(map)
        };
    }

    // These have no single on-disk image to match against.
    if key.starts_with("pip://")
        || key.starts_with("npm://")
        || key.starts_with("cargo://")
        || key.starts_with("os://")
    {
        return Reachability::Unknown;
    }

    // Package-manager entries: any loaded module under the install directory.
    // Without a directory the finding is unevaluable, and an unevaluable
    // finding is Unknown — reporting it as NotObserved would assert an
    // observation that was never made.
    let Some(dir) = software.install_location.as_deref() else {
        return Reachability::Unknown;
    };
    let dir = normalize_path(dir);
    if dir.is_empty() {
        return Reachability::Unknown;
    }

    // The trailing separator matters: without it `...\App` would also match
    // `...\AppTwo\x.dll`.
    let prefix = format!("{dir}\\");
    if map.paths.iter().any(|p| p.starts_with(&prefix)) {
        Reachability::Loaded
    } else {
        negative_for(map)
    }
}
```

Create empty stubs so `pub mod local;` and `pub mod remote;` resolve. `evedoo/src/reachability/local.rs`:

```rust
//! Local Win32 module enumeration. Implemented in Task 2.
//!
//! SPDX-License-Identifier: Apache-2.0
```

`evedoo/src/reachability/remote.rs`:

```rust
//! Remote module enumeration over WinRM. Implemented in Task 3.
//!
//! SPDX-License-Identifier: Apache-2.0
```

Add to `evedoo/src/main.rs`, keeping the list alphabetical (it currently runs `normalize`, `reconcile`, `remote`, …):

```rust
mod reachability;
```

Add the field to `Finding` in `evedoo/src/models.rs`, immediately after `pub excepted: Option<ExceptionRef>,`:

```rust
    /// Whether this finding's code was mapped into a live process at scan
    /// time (FR-73). `#[serde(default)]` keeps older JSON artifacts readable
    /// per DC-3; they deserialise as `Unknown`, which is exactly right —
    /// those scans never determined it.
    #[serde(default)]
    pub reachability: crate::reachability::Reachability,
```

- [x] **Step 4: Fix every `Finding` construction site**

Adding a field breaks all struct literals. Run `cargo build -p evedoo 2>&1 | grep "missing field"` to list them, then add `reachability: Default::default(),` to each. Expect sites in `matcher/mod.rs`, `report/*.rs` test fixtures, and `main.rs` test fixtures.

- [x] **Step 5: Run tests to verify they pass**

Run: `cargo test -p evedoo reachability`
Expected: PASS, 11 tests.

Run: `cargo test --workspace`
Expected: all previously passing tests still pass.

- [x] **Step 6: Mutation-verify the two rules that carry the whole design**

Temporarily change `negative_for` to always return `Reachability::NotObserved`.
Run: `cargo test -p evedoo reachability`
Expected: `partial_coverage_forces_unknown_not_not_observed` FAILS. Revert.

Temporarily change the `pe://` branch to compare on filename only (`path.rsplit('\\').next()`).
Run: `cargo test -p evedoo reachability`
Expected: `three_sibling_copies_are_distinguished` FAILS. Revert.

Re-run `cargo test -p evedoo reachability` and confirm PASS after both reverts.

- [x] **Step 7: Commit**

```bash
git add evedoo/src/reachability/ evedoo/src/models.rs evedoo/src/main.rs
git commit -m "P21-N3: reachability type, module map, and matching rules (FR-73, FR-74, FR-77)"
```

---

### Task 2: Local Win32 module collection

**Files:**
- Modify: `evedoo/src/reachability/local.rs`

**Interfaces:**
- Consumes: `ModuleMap`, `Coverage`, `normalize_path` from Task 1
- Produces: `pub fn collect() -> ModuleMap`

- [x] **Step 1: Write the failing test**

Append to `evedoo/src/reachability/local.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The scanner can always open its own process, so this is deterministic
    /// rather than dependent on what happens to be running.
    #[test]
    fn collect_sees_at_least_this_process() {
        let map = collect();
        assert!(
            map.coverage().readable >= 1,
            "the collector must at minimum read its own process"
        );
        assert!(
            map.coverage().total >= map.coverage().readable,
            "total must never be less than readable"
        );
    }

    /// Every running Windows process maps ntdll.dll. If the walk returns
    /// paths at all, it must contain that one — a cheap proof that we are
    /// reading real module paths and not empty strings.
    #[test]
    fn collect_finds_ntdll() {
        let map = collect();
        assert!(
            map.contains_normalized(&crate::reachability::normalize_path(
                r"C:\Windows\System32\ntdll.dll"
            )),
            "ntdll.dll is mapped into every Windows process"
        );
    }
}
```

This needs one accessor on `ModuleMap`. Add to `mod.rs` in the `impl ModuleMap` block:

```rust
    /// Test and diagnostic accessor. Takes an already-normalised path.
    pub fn contains_normalized(&self, path: &str) -> bool {
        self.paths.contains(path)
    }
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p evedoo reachability::local`
Expected: FAIL to compile — `cannot find function collect in this scope`.

- [x] **Step 3: Write the implementation**

Replace the contents of `evedoo/src/reachability/local.rs`:

```rust
//! Local module enumeration via the Win32 Toolhelp32 API.
//!
//! Direct FFI against `kernel32` and `advapi32`, matching the `version.dll`
//! precedent in `scanner/pe_fingerprint.rs` — no new crate dependency.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::ffi::c_void;

use tracing::debug;

use super::{Coverage, ModuleMap, normalize_path};

const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY: u32 = 0x0008;
const SE_PRIVILEGE_ENABLED: u32 = 0x0002;

fn invalid_handle() -> *mut c_void {
    -1isize as *mut c_void
}

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[repr(C)]
struct ModuleEntry32W {
    dw_size: u32,
    th32_module_id: u32,
    th32_process_id: u32,
    glblcnt_usage: u32,
    proccnt_usage: u32,
    mod_base_addr: *mut u8,
    mod_base_size: u32,
    h_module: *mut c_void,
    sz_module: [u16; 256],
    sz_exe_path: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: u32,
}

#[repr(C)]
struct TokenPrivileges {
    privilege_count: u32,
    privileges: [LuidAndAttributes; 1],
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut c_void;
    fn Process32FirstW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn Module32FirstW(h_snapshot: *mut c_void, lpme: *mut ModuleEntry32W) -> i32;
    fn Module32NextW(h_snapshot: *mut c_void, lpme: *mut ModuleEntry32W) -> i32;
    fn CloseHandle(h_object: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(
        process_handle: *mut c_void,
        desired_access: u32,
        token_handle: *mut *mut c_void,
    ) -> i32;
    fn LookupPrivilegeValueW(
        lp_system_name: *const u16,
        lp_name: *const u16,
        lp_luid: *mut Luid,
    ) -> i32;
    fn AdjustTokenPrivileges(
        token_handle: *mut c_void,
        disable_all: i32,
        new_state: *const TokenPrivileges,
        buffer_length: u32,
        previous_state: *mut TokenPrivileges,
        return_length: *mut u32,
    ) -> i32;
}

/// Decode a fixed-size wide buffer up to its first NUL.
fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Best-effort SeDebugPrivilege. Failure is the normal unelevated case and is
/// NOT an error: it simply means the sweep sees only this user's processes,
/// which FR-74 then reports honestly as incomplete coverage.
fn try_enable_se_debug() -> bool {
    let name: Vec<u16> = "SeDebugPrivilege".encode_utf16().chain(std::iter::once(0)).collect();
    let mut token: *mut c_void = std::ptr::null_mut();

    unsafe {
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let mut luid = Luid::default();
        let ok = if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            false
        } else {
            let tp = TokenPrivileges {
                privilege_count: 1,
                privileges: [LuidAndAttributes { luid, attributes: SE_PRIVILEGE_ENABLED }],
            };
            AdjustTokenPrivileges(
                token,
                0,
                &tp,
                std::mem::size_of::<TokenPrivileges>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) != 0
        };

        CloseHandle(token);
        ok
    }
}

/// Collect every module path mapped into every process we are permitted to
/// open, together with how much of the process list that represents.
pub fn collect() -> ModuleMap {
    if try_enable_se_debug() {
        debug!("SeDebugPrivilege enabled — full process coverage available");
    } else {
        debug!("SeDebugPrivilege unavailable — reachability limited to this user's processes");
    }

    let mut paths: HashSet<String> = HashSet::new();
    let mut total = 0usize;
    let mut readable = 0usize;

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == invalid_handle() {
        // Nothing could be enumerated at all. total > readable, so FR-74
        // forces every classification to Unknown.
        return ModuleMap::empty_unknown();
    }

    let mut pe: ProcessEntry32W = unsafe { std::mem::zeroed() };
    pe.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;

    let mut ok = unsafe { Process32FirstW(snap, &mut pe) };
    while ok != 0 {
        total += 1;
        if collect_modules_for_pid(pe.th32_process_id, &mut paths) {
            readable += 1;
        }
        ok = unsafe { Process32NextW(snap, &mut pe) };
    }

    unsafe { CloseHandle(snap) };

    ModuleMap::new(paths, Coverage { readable, total })
}

/// Returns true when this process's module list could be read.
///
/// `TH32CS_SNAPMODULE32` is included so a 64-bit scanner still sees WOW64
/// (32-bit) processes; omitting it would silently under-report exactly the
/// older bundled libraries most likely to be vulnerable.
fn collect_modules_for_pid(pid: u32, out: &mut HashSet<String>) -> bool {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snap == invalid_handle() {
        return false;
    }

    let mut me: ModuleEntry32W = unsafe { std::mem::zeroed() };
    me.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;

    let mut ok = unsafe { Module32FirstW(snap, &mut me) };
    let read_any = ok != 0;
    while ok != 0 {
        let path = wide_to_string(&me.sz_exe_path);
        if !path.is_empty() {
            out.insert(normalize_path(&path));
        }
        ok = unsafe { Module32NextW(snap, &mut me) };
    }

    unsafe { CloseHandle(snap) };
    read_any
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p evedoo reachability::local`
Expected: PASS, 2 tests.

Run: `cargo clippy -p evedoo --all-targets -- -D warnings`
Expected: clean.

- [x] **Step 5: Verify the performance budget (NFR-9)**

Run this one-off timing check and confirm it prints under ~1s:

```bash
cargo test -p evedoo reachability::local -- --nocapture --test-threads=1
```

If it exceeds 2 seconds on a normal desktop, stop and report rather than proceeding — NFR-9 is a stated budget, not an aspiration.

- [x] **Step 6: Commit**

```bash
git add evedoo/src/reachability/local.rs evedoo/src/reachability/mod.rs
git commit -m "P21-N3: local Toolhelp32 module collection via direct FFI (FR-75, NFR-9)"
```

---

### Task 3: Remote module collection over WinRM

**Files:**
- Modify: `evedoo/src/reachability/remote.rs`

**Interfaces:**
- Consumes: `ModuleMap`, `Coverage`, `normalize_path` from Task 1; `crate::remote::session::RemoteSession` (method `execute(&self, script_block: &str) -> Result<String>`)
- Produces: `pub fn collect(session: &RemoteSession) -> ModuleMap`, `pub fn parse_output(raw: &str) -> ModuleMap`, `pub const MODULE_SCRIPT: &str`

**Note on PowerShell:** the project rule is Rust-only for *core implementation*. PowerShell here is the WinRM transport, exactly as `remote/scanners.rs` already uses it. The parsing and all logic stay in Rust.

- [x] **Step 1: Write the failing test**

Append to `evedoo/src/reachability/remote.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::reachability::{normalize_path, Reachability};

    #[test]
    fn parses_coverage_and_module_lines() {
        let raw = "COVERAGE\t7\t9\n\
                   MODULE\tC:\\Windows\\System32\\ntdll.dll\n\
                   MODULE\tC:\\App\\libcurl.dll\n";
        let map = parse_output(raw);

        assert_eq!(map.coverage().readable, 7);
        assert_eq!(map.coverage().total, 9);
        assert!(map.contains_normalized(&normalize_path(r"C:\App\libcurl.dll")));
        assert!(!map.is_complete(), "7 of 9 is not complete coverage");
    }

    #[test]
    fn complete_coverage_is_reported_complete() {
        let map = parse_output("COVERAGE\t9\t9\nMODULE\tC:\\x\\y.dll\n");
        assert!(map.is_complete());
    }

    /// Garbage, a truncated stream, or an error message must determine
    /// nothing rather than assert an empty machine.
    #[test]
    fn output_without_coverage_line_determines_nothing() {
        for raw in ["", "Access is denied.", "MODULE\tC:\\x\\y.dll\n"] {
            let map = parse_output(raw);
            assert!(
                !map.is_complete(),
                "missing COVERAGE must never yield a complete sweep: {raw:?}"
            );
        }
    }

    #[test]
    fn malformed_coverage_line_determines_nothing() {
        let map = parse_output("COVERAGE\tnotanumber\t9\nMODULE\tC:\\x\\y.dll\n");
        assert!(!map.is_complete());
    }

    /// SEC-8. The command must be a constant with nothing interpolated.
    #[test]
    fn script_block_has_no_interpolation_placeholders() {
        assert!(!MODULE_SCRIPT.contains("{}"));
        assert!(!MODULE_SCRIPT.contains("{0}"));
        assert!(!MODULE_SCRIPT.contains('\''), "no quoted interpolation slots");
    }

    /// An empty machine with full coverage still classifies as NotObserved,
    /// not Unknown — proving parse_output feeds the FR-74 machinery.
    #[test]
    fn full_coverage_with_no_modules_still_permits_a_negative() {
        use crate::models::{Architecture, DetectedSoftware};
        let map = parse_output("COVERAGE\t4\t4\n");
        let s = DetectedSoftware {
            name: "T".into(),
            version: None,
            publisher: None,
            install_location: None,
            install_date: None,
            registry_key: r"pe://C:\App\x.dll".into(),
            architecture: Architecture::X64,
        };
        assert_eq!(crate::reachability::classify(&s, &map), Reachability::NotObserved);
    }
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p evedoo reachability::remote`
Expected: FAIL to compile — `cannot find function parse_output`, `cannot find value MODULE_SCRIPT`.

- [x] **Step 3: Write the implementation**

Replace the contents of `evedoo/src/reachability/remote.rs`:

```rust
//! Remote module enumeration over the existing WinRM session.
//!
//! The script block is a fixed constant with NO interpolated values (SEC-8),
//! so its injection surface is eliminated by construction rather than by
//! escaping. PowerShell here is the transport, as in `remote/scanners.rs`;
//! all parsing and logic stay in Rust.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use tracing::warn;

use super::{Coverage, ModuleMap, normalize_path};
use crate::remote::session::RemoteSession;

/// Emits one `COVERAGE<TAB>readable<TAB>total` line followed by one
/// `MODULE<TAB>path` line per distinct loaded module.
///
/// Accessing `$p.Modules` throws for processes the caller cannot open, so the
/// try/catch is what distinguishes readable from unreadable processes — the
/// remote equivalent of a failed `CreateToolhelp32Snapshot`.
pub const MODULE_SCRIPT: &str = r#"
$total = 0
$readable = 0
$paths = New-Object System.Collections.Generic.HashSet[string]
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
  $total = $total + 1
  try {
    foreach ($m in $p.Modules) { [void]$paths.Add($m.FileName) }
    $readable = $readable + 1
  } catch { }
}
Write-Output ("COVERAGE" + [char]9 + $readable + [char]9 + $total)
foreach ($x in $paths) { Write-Output ("MODULE" + [char]9 + $x) }
"#;

/// Parse the collector's output.
///
/// A missing or malformed COVERAGE line yields an incomplete map, so FR-74
/// forces every classification to `Unknown`. Truncated or error output must
/// never be read as "this machine has nothing loaded".
pub fn parse_output(raw: &str) -> ModuleMap {
    let mut paths: HashSet<String> = HashSet::new();
    let mut coverage: Option<Coverage> = None;

    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("COVERAGE\t") {
            let mut parts = rest.split('\t');
            if let (Some(r), Some(t)) = (parts.next(), parts.next()) {
                if let (Ok(r), Ok(t)) = (r.trim().parse::<usize>(), t.trim().parse::<usize>()) {
                    coverage = Some(Coverage { readable: r, total: t });
                }
            }
        } else if let Some(path) = line.strip_prefix("MODULE\t") {
            let p = path.trim();
            if !p.is_empty() {
                paths.insert(normalize_path(p));
            }
        }
    }

    match coverage {
        Some(c) => ModuleMap::new(paths, c),
        None => {
            // Deliberately discard any MODULE lines gathered: without a
            // coverage line we cannot say how much of the machine they
            // represent, and a partial set presented as complete would be
            // worse than no data.
            ModuleMap::empty_unknown()
        }
    }
}

/// Collect reachability from a remote host. Any failure yields a map that
/// determines nothing (FR-76) — a failed collection observed nothing, which
/// is not the same as observing nothing loaded.
pub fn collect(session: &RemoteSession) -> ModuleMap {
    match session.execute(MODULE_SCRIPT) {
        Ok(out) => parse_output(&out),
        Err(e) => {
            warn!("Remote reachability collection failed: {e}");
            ModuleMap::empty_unknown()
        }
    }
}
```

If `crate::remote::session` is not public, use the existing re-export path used by `remote/scanners.rs` instead — check its `use` line and match it.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p evedoo reachability::remote`
Expected: PASS, 6 tests.

- [x] **Step 5: Mutation-verify the fail-safe**

Temporarily change the `None => ModuleMap::empty_unknown()` arm to
`None => ModuleMap::new(paths, Coverage { readable: 1, total: 1 })`.
Run: `cargo test -p evedoo reachability::remote`
Expected: `output_without_coverage_line_determines_nothing` FAILS. Revert and re-run to confirm PASS.

- [x] **Step 6: Commit**

```bash
git add evedoo/src/reachability/remote.rs
git commit -m "P21-N3: remote module collection over WinRM with no interpolated input (FR-76, SEC-8)"
```

---

### Task 4: Risk integration

**Files:**
- Modify: `evedoo/src/risk.rs`
- Modify: `evedoo/src/main.rs` (three `risk::assess` call sites: in `run_scan`, `run_remote_scan`, `run_reassess_pipeline`)

**Interfaces:**
- Consumes: `Reachability` from Task 1
- Produces: `pub fn assess(v: &Vulnerability, has_exploit_ref: bool, criticality: f32, reachability: Reachability) -> RiskAssessment`, `pub const REACH_LOADED_FACTOR: f32 = 1.25`

- [x] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `evedoo/src/risk.rs`:

```rust
    /// FR-78, and the constraint the whole feature rests on: a finding that
    /// is not loaded must score EXACTLY what it scores today. Not "roughly",
    /// not "close to" — a scan is a seconds-long sample of a machine that
    /// runs for months, so a non-observation must cost nothing.
    #[test]
    fn unloaded_and_unknown_never_change_the_score() {
        let v = vuln(7.5, Some(0.2), false);
        let baseline = assess(&v, false, 1.0, Reachability::Unknown);
        let not_observed = assess(&v, false, 1.0, Reachability::NotObserved);

        assert_eq!(baseline.score, not_observed.score);
        assert_eq!(baseline.tier, not_observed.tier);
    }

    #[test]
    fn loaded_raises_the_score_by_exactly_the_factor() {
        let v = vuln(7.5, Some(0.2), false);
        let base = assess(&v, false, 1.0, Reachability::NotObserved);
        let loaded = assess(&v, false, 1.0, Reachability::Loaded);

        let expected = (base.score * REACH_LOADED_FACTOR).min(100.0);
        assert!(
            (loaded.score - expected).abs() < 0.001,
            "loaded {} should be base {} * {}",
            loaded.score,
            base.score,
            REACH_LOADED_FACTOR
        );
    }

    /// No reachability value may ever reduce a score below the unloaded
    /// baseline. This is the guard that would catch a well-meaning future
    /// "demote dormant findings" change.
    #[test]
    fn no_reachability_value_lowers_the_score() {
        for cvss in [1.0_f32, 5.0, 9.8] {
            for epss in [None, Some(0.01_f32), Some(0.9)] {
                let v = vuln(cvss, epss, false);
                let base = assess(&v, false, 1.0, Reachability::NotObserved).score;
                for r in [Reachability::Loaded, Reachability::NotObserved, Reachability::Unknown] {
                    assert!(
                        assess(&v, false, 1.0, r).score >= base,
                        "reachability {r:?} lowered the score for cvss={cvss} epss={epss:?}"
                    );
                }
            }
        }
    }

    /// The score is clamped, so the boost cannot push past the scale.
    #[test]
    fn loaded_score_stays_within_the_scale() {
        let v = vuln(10.0, Some(0.99), true);
        let loaded = assess(&v, true, 1.25, Reachability::Loaded);
        assert!(loaded.score <= 100.0);
    }
```

Add `use crate::reachability::Reachability;` to the test module's imports if not already brought in by `use super::*;`.

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p evedoo risk::`
Expected: FAIL to compile — `this function takes 3 arguments but 4 arguments were supplied`, and `cannot find value REACH_LOADED_FACTOR`.

- [x] **Step 3: Write the implementation**

In `evedoo/src/risk.rs`, add near the other constants:

```rust
/// Multiplier applied when a finding's code is mapped into a live process
/// (FR-78). Chosen to match the top of the `criticality_for` scale so the two
/// multipliers stay commensurate and neither silently dominates.
///
/// There is deliberately no factor below 1.0. A scan is a seconds-long sample
/// of a machine that runs for months, so "not loaded right now" is not
/// evidence of safety and must never reduce a score.
pub const REACH_LOADED_FACTOR: f32 = 1.25;

fn reach_factor(r: Reachability) -> f32 {
    match r {
        Reachability::Loaded => REACH_LOADED_FACTOR,
        Reachability::NotObserved | Reachability::Unknown => 1.0,
    }
}
```

Add the import at the top of `risk.rs`:

```rust
use crate::reachability::Reachability;
```

Change the signature and the score line:

```rust
pub fn assess(
    v: &Vulnerability,
    has_exploit_ref: bool,
    criticality: f32,
    reachability: Reachability,
) -> RiskAssessment {
```

```rust
    let score = (100.0
        * impact.powf(0.4)
        * likelihood.powf(0.6)
        * criticality
        * reach_factor(reachability))
    .clamp(0.0, 100.0);
```

Update the three call sites in `main.rs`. In `run_scan` and `run_remote_scan`, the module map is threaded in by Task 6; for now pass the classified value from a `module_map` variable that Task 6 introduces. To keep this task independently compilable, add the parameter to both scan functions now:

In `run_scan` (around line 875) and `run_remote_scan` (around line 1236), replace the loop body:

```rust
    for f in &mut result.findings {
        let exploit = matcher
            .has_exploit_reference(&f.vulnerability.cve_id)
            .unwrap_or(false);
        f.reachability = reachability::classify(&f.software, &module_map);
        f.risk = Some(risk::assess(
            &f.vulnerability,
            exploit,
            criticality,
            f.reachability,
        ));
    }
```

and add, immediately above each loop, a temporary binding that Task 6 replaces with real collection:

```rust
    // Replaced with real collection in Task 6.
    let module_map = reachability::ModuleMap::empty_unknown();
```

In `run_reassess_pipeline` (around line 1509), the value is permanently `Unknown` per FR-79 — a stored snapshot describes the past:

```rust
    for f in &mut findings {
        let exploit = matcher
            .has_exploit_reference(&f.vulnerability.cve_id)
            .unwrap_or(false);
        // FR-79: the inventory snapshot was captured at a different moment.
        // Replaying stale reachability as current would be exactly the lie
        // this feature must not tell.
        f.reachability = reachability::Reachability::Unknown;
        f.risk = Some(risk::assess(
            &f.vulnerability,
            exploit,
            criticality,
            reachability::Reachability::Unknown,
        ));
    }
```

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p evedoo risk::`
Expected: PASS. Existing risk tests will need their `assess(...)` calls updated with a fourth argument of `Reachability::Unknown` — that is the correct value, since those fixtures determine nothing, and it keeps every existing expected score unchanged.

Run: `cargo test --workspace`
Expected: all pass.

- [x] **Step 5: Mutation-verify the never-demote guarantee**

Temporarily change `reach_factor` so `Reachability::Unknown => 0.8`.
Run: `cargo test -p evedoo risk::`
Expected: `unloaded_and_unknown_never_change_the_score` and `no_reachability_value_lowers_the_score` both FAIL. Revert and confirm PASS.

- [x] **Step 6: Commit**

```bash
git add evedoo/src/risk.rs evedoo/src/main.rs
git commit -m "P21-N3: reachability multiplier in risk scoring, strictly >= 1.0 (FR-78, FR-79)"
```

---

### Task 5: Reporting

**Files:**
- Modify: `evedoo/src/report/text.rs`
- Modify: `evedoo/src/report/csv.rs`
- Modify: `evedoo/src/report/html.rs`
- (JSON needs no change — it serialises `Finding` directly, so DC-6 is satisfied by the Task 1 field.)

**Interfaces:**
- Consumes: `Finding.reachability` from Task 1

- [x] **Step 1: Write the failing tests**

In `evedoo/src/report/text.rs` tests:

```rust
    /// FR-80. Same rule delta_known established for status: when the value is
    /// undetermined the line is omitted entirely, not shown with a caveat.
    #[test]
    fn text_report_omits_reachability_when_unknown() {
        let mut result = mk_result();
        for f in &mut result.findings {
            f.reachability = crate::reachability::Reachability::Unknown;
        }
        let out = TextReporter.generate(&result).unwrap();
        assert!(!out.contains("Reachability:"));
    }

    #[test]
    fn text_report_shows_reachability_when_loaded() {
        let mut result = mk_result();
        for f in &mut result.findings {
            f.reachability = crate::reachability::Reachability::Loaded;
        }
        let out = TextReporter.generate(&result).unwrap();
        assert!(out.contains("Reachability:"));
        assert!(out.contains("Loaded"));
    }
```

In `evedoo/src/report/csv.rs` tests:

```rust
    #[test]
    fn csv_has_reachability_column_with_the_value() {
        let mut result = mk_result();
        result.findings[0].reachability = crate::reachability::Reachability::Loaded;
        let out = CsvReporter.generate(&result).unwrap();
        let mut rdr = csv::Reader::from_reader(out.as_bytes());
        let headers = rdr.headers().unwrap().clone();
        let idx = headers
            .iter()
            .position(|h| h == "Reachability")
            .expect("Reachability column must exist");
        let row = rdr.records().next().unwrap().unwrap();
        assert_eq!(&row[idx], "Loaded");
    }
```

In `evedoo/src/report/html.rs` tests:

```rust
    #[test]
    fn html_omits_reachability_column_when_nothing_is_determined() {
        let result = mk_result(); // all findings default to Unknown
        let html = HtmlReporter.generate(&result).unwrap();
        assert!(!html.contains(">Reachability</th>"));
    }

    #[test]
    fn html_shows_reachability_column_when_any_finding_is_determined() {
        let mut result = mk_result();
        result.findings[0].reachability = crate::reachability::Reachability::Loaded;
        let html = HtmlReporter.generate(&result).unwrap();
        assert!(html.contains(">Reachability</th>"));
        assert!(html.contains("Loaded"));

        // The header and body must still agree — the same invariant the
        // status column gate needed.
        assert_eq!(
            column_counts(&html).0,
            column_counts(&html).1,
            "header and body must agree on column count"
        );
    }
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p evedoo report::`
Expected: the four new assertions FAIL (no `Reachability:` line, no column).

- [x] **Step 3: Implement text**

In `text.rs`, immediately after the `if result.delta_known { … }` status block:

```rust
            // Reachability (FR-80). Omitted entirely when undetermined,
            // matching the status rule: a placeholder would assert an
            // observation that was never made.
            if finding.reachability != crate::reachability::Reachability::Unknown {
                output.push_str(&format!(
                    "  {} {}\n",
                    "Reachability:".bright_white(),
                    finding.reachability
                ));
            }
```

- [x] **Step 4: Implement CSV**

Add `"Reachability",` to the header `write_record` at `csv.rs:27` (append after `"Finding Status"`), and the value to each data row's `write_record`:

```rust
            finding.reachability.to_string(),
```

Place it at the same ordinal position in both the header and the row, or the column will silently shift. CSV always carries the value, including `Unknown` — a fixed-width machine format has no "omit" option, and the literal string `Unknown` is honest there.

- [x] **Step 5: Implement HTML**

Compute once, before the row loop:

```rust
        let show_reach = result
            .findings
            .iter()
            .any(|f| f.reachability != crate::reachability::Reachability::Unknown);
```

Header cell, alongside `status_header`:

```rust
        let reach_header = if show_reach {
            r#"          <th data-col="12">Reachability</th>"#
        } else {
            ""
        };
```

Add `{reach_header}` to the template directly after `{status_header}`, and add `reach_header = reach_header,` to the outer `format!` argument list next to `status_header = status_header,`.

Per-row cell, alongside `status_cell`:

```rust
            let reach_cell = if show_reach {
                let badge = match finding.reachability {
                    crate::reachability::Reachability::Loaded => {
                        r#"<span class="badge new">Loaded</span>"#
                    }
                    crate::reachability::Reachability::NotObserved => {
                        r#"<span class="badge persisting">Not loaded</span>"#
                    }
                    crate::reachability::Reachability::Unknown => "\u{2014}",
                };
                format!("<td>{badge}</td>")
            } else {
                String::new()
            };
```

Add `{reach_cell}` to the row template directly after `{status_cell}`, and `reach_cell = reach_cell,` to that `format!`'s arguments.

**Ordering note:** `status_header`/`status_cell` are gated on `delta_known` and `reach_header`/`reach_cell` on `show_reach`, so the two can be independently present or absent. Both are appended after the fixed columns 0-10, so `data-col` indices 0-10 stay valid in every combination. When status is hidden but reachability shown, reachability occupies the position `data-col="12"` names — harmless, because the sort handler reads `th.dataset.col` and `a.cells[col]` positionally and the existing `column_counts` test asserts header/body parity for whichever combination is rendered.

- [x] **Step 6: Run tests to verify they pass**

Run: `cargo test -p evedoo report::`
Expected: PASS.

Run: `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
Expected: all pass, clippy clean.

- [x] **Step 7: Commit**

```bash
git add evedoo/src/report/
git commit -m "P21-N3: surface reachability in text, CSV, JSON, and HTML reports (FR-80, DC-6)"
```

---

### Task 6: Pipeline wiring, CLI flag, and coverage disclosure

**Files:**
- Modify: `evedoo/src/main.rs` (CLI struct, `run_scan`, `run_remote_scan`)

**Interfaces:**
- Consumes: `reachability::local::collect`, `reachability::remote::collect`, `ModuleMap::empty_unknown` from Tasks 1-3

- [x] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `main.rs`:

```rust
    /// FR-81. Coverage is disclosed even when complete, so a reader never has
    /// to guess whether the sweep was partial.
    #[test]
    fn coverage_line_is_produced_for_complete_and_partial_sweeps() {
        use crate::reachability::Coverage;

        let complete = reachability_coverage_line(Coverage { readable: 9, total: 9 });
        assert!(complete.contains("9/9"));
        assert!(
            !complete.contains("run elevated"),
            "a complete sweep must not nag about elevation"
        );

        let partial = reachability_coverage_line(Coverage { readable: 4, total: 9 });
        assert!(partial.contains("4/9"));
        assert!(
            partial.contains("run elevated"),
            "a partial sweep must say how to get the rest"
        );
    }
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p evedoo coverage_line`
Expected: FAIL to compile — `cannot find function reachability_coverage_line`.

- [x] **Step 3: Write the implementation**

Add to `main.rs`:

```rust
/// FR-81. Disclose collection coverage on every run, complete or not.
fn reachability_coverage_line(c: crate::reachability::Coverage) -> String {
    if c.readable >= c.total {
        format!(
            "  reachability: {}/{} processes readable",
            c.readable, c.total
        )
    } else {
        format!(
            "  reachability: {}/{} processes readable — run elevated for full coverage",
            c.readable, c.total
        )
    }
}
```

Add the flag to the `scan` and `remote-scan` argument structs:

```rust
    /// Skip runtime reachability collection (module enumeration).
    #[arg(long, default_value_t = false)]
    no_reachability: bool,
```

In `run_scan`, replace the Task 4 placeholder binding:

```rust
    let module_map = if no_reachability {
        reachability::ModuleMap::empty_unknown()
    } else {
        let m = reachability::local::collect();
        println!("{}", reachability_coverage_line(m.coverage()));
        m
    };
```

In `run_remote_scan`, the same shape against the session:

```rust
    let module_map = if no_reachability {
        reachability::ModuleMap::empty_unknown()
    } else {
        let m = reachability::remote::collect(&session);
        println!("{}", reachability_coverage_line(m.coverage()));
        m
    };
```

Thread `no_reachability` from the parsed CLI args into both functions as a `bool` parameter.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test --workspace`
Expected: all pass.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [x] **Step 5: Verify on the real machine**

```bash
cargo build --release -p evedoo
target/release/evedoo.exe scan -d vulndb.sqlite --risk -f text | head -40
```

Confirm: a `reachability: N/M processes readable` line appears, and at least one finding shows `Reachability: Loaded`. If zero findings are `Loaded` on a machine with browsers running, stop and investigate the matching rules rather than shipping — that would mean Task 1's classification is not connecting to real data.

- [x] **Step 6: Measure the tier shift (spec §7)**

Run the same scan with and without `--no-reachability`, count findings per tier in each, and record the before/after split in the commit message. The reference corpus split is P1 1.5%, P2 47.2%, P3 3.3%, P4 47.9%. This is **reporting, not a tuning input** — a prior ruling established that thresholds are not retuned on one host's data. If the shift is extreme (for example P1 above ~15%), record a ruling rather than silently adjusting `REACH_LOADED_FACTOR`.

- [x] **Step 7: Commit**

```bash
git add evedoo/src/main.rs
git commit -m "P21-N3: wire reachability into scan and remote-scan with coverage disclosure (FR-81, FR-82)"
```

---

## Self-Review

**Spec coverage:**

| Requirement | Task |
|---|---|
| FR-73 enumerate and expose per finding | 1, 2 |
| FR-74 partial coverage forces Unknown | 1 (mutation-verified) |
| FR-75 local best-effort | 2 |
| FR-76 remote collection, degrade to Unknown | 3 (mutation-verified) |
| FR-77 exact path / containment / no filename | 1 (mutation-verified) |
| FR-78 multiplier strictly >= 1.0 | 4 (mutation-verified) |
| FR-79 reassess passes Unknown | 4 |
| FR-80 reports omit rather than placeholder | 5 |
| FR-81 coverage disclosed | 6 |
| FR-82 not persisted | Satisfied by omission — no task writes to `scan_findings` |
| NFR-9 performance budget | 2 step 5 |
| SEC-8 no interpolated input | 3 (asserted) |
| DC-6 JSON field | 1 (field + serde test), 5 |
| Spec §6 no `install_location` is Unknown | 1 |
| Spec §7 calibration measurement | 6 step 6 |

**Type consistency:** `Reachability`, `ModuleMap`, `Coverage`, `classify`, `normalize_path`, `contains_normalized`, `empty_unknown`, `coverage()`, `is_complete()`, `REACH_LOADED_FACTOR`, `reach_factor`, `reachability_coverage_line`, `MODULE_SCRIPT`, `parse_output` are each defined once and referenced with the same name and arity throughout.

**Known follow-ups deliberately not in this plan:** reachability for `pip://`/`npm://`/`cargo://`/`os://`, trending over time, and CycloneDX/SPDX extension — all listed as out of scope in spec §13.

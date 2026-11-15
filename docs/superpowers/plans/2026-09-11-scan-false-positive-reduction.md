# Scan False-Positive Reduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the two remaining false-positive classes found while validating a live 928-finding scan — AppX packages whose Store package version is not the product version, and the same install reported twice because two scanners found it.

**Architecture:** Both fixes live in the inventory layer, before matching. The AppX scanner learns to look at what a package actually contains: a package with no executable payload carries no code and is dropped; a package with a payload takes its version from the primary executable's PE resource rather than the Store package number. A new dedup pass in `correlate.rs` collapses two `DetectedSoftware` entries that describe one install found by two scanners. Nothing in the matcher changes.

**Tech Stack:** Rust 1.83+, `serde_json`, existing `scanner::pe_fingerprint::version_info` FFI wrapper over `version.dll`, `tracing`.

**Spec:** This document. Origin: false-positive validation pass over a live scan of a Windows 11 development workstation, 2026-09-11 — see **Evidence** below. The related branch-selection bug found in the same pass is already fixed in `matcher/cpe.rs::fixed_version_for`.

## Global Constraints

- License: **Apache 2.0 only**. No new dependencies of any kind — both tasks use crates already in `evedoo/Cargo.toml`.
- Language: **Rust exclusively**. No PowerShell beyond the existing `Get-AppxPackage` invocation, which is extended by one property.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass with **0 warnings** — CI gate.
- `cargo test --workspace` must pass. Baseline at plan time: **539 tests**.
- Tests live in `#[cfg(test)] mod tests` blocks inside each source file.
- Diagnostics use `tracing` macros (`info!`, `debug!`, `warn!`), never the `log` crate.
- Windows-only code stays behind `#[cfg(target_os = "windows")]` with a non-Windows counterpart, matching the existing pattern in `pe_fingerprint.rs:323-341`.
- **Never suppress a finding on a name allowlist/denylist.** Both fixes must key on an observable property of the artifact (payload presence, path containment), never on a hardcoded product name. This is the same principle that governed Task 3 of the 2026-09-10 hardening plan.

---

## Evidence

Measured on the live scan (`vulndb.sqlite`, 383,401 CVEs; a Windows 11 development workstation; 928 findings at `--min-confidence high`).

### AppX payload survey

`Get-AppxPackage` version vs. what the package actually contains:

| Package | AppX `Version` | files | executables | Real product version | Findings |
|---|---|---|---|---|---|
| `Microsoft.VisualStudioCode` | `1.0.137.0` | 3 | **0** | none — no code at all | **60** |
| `PythonSoftwareFoundation.Python.3.13` | `3.13.3824.0` | 5849 | 28 | `python313.dll` → **3.13.14** | 1 |
| `Microsoft.PowerAutomateDesktop` | `1.0.2122.0` | 80 | 1 | `PAD.Console.Host.exe` → 1.0.0.0 | 2 |
| `MicrosoftCorporationII.WindowsSubsystemForLinux` | `2.6.3.0` | 37 | 1 | `wsl.exe` → **2.6.3.0** | 2 |

Two distinct defects, and one control:

1. **VS Code is a manifest-only stub.** Its package directory holds exactly `AppxBlockMap.xml`, `AppxManifest.xml`, `AppxSignature.p7x` — zero executables. `1.0.137` is the Store stub's own number and has no relation to VS Code product versions (1.9x–1.13x). Because `1.0.137` sorts below every VS Code CPE bound, **all 60 VS Code CVEs matched**, including ones fixed in `1.55.2` and `1.58.1` in 2021. All 60 are false positives.
2. **Python's Store version is not its product version.** `3.13.3824` vs. the real `3.13.14`. Note the direction: `3.13.3824` sorts *above* real CPE bounds like `< 3.13.6`, so this currently causes **false negatives**. Fixing it will likely *increase* Python findings — that is the correct outcome.
3. **WSL is the control.** Its AppX version `2.6.3.0` matches `wsl.exe`'s `2.6.3.0` exactly. Task 1 must not change WSL's result — this is the regression guard proving the fix reads the right thing rather than just discarding AppX data.

### Cross-source duplication

47 findings are one install counted twice. PostgreSQL 16.1 is found by both the registry scanner and the PE scanner:

| Source | `name` | `version` | `install_location` | `registry_key` |
|---|---|---|---|---|
| registry | `PostgreSQL 16 ` (trailing space) | `16.1` | `C:\Program Files\PostgreSQL\16` | `HKLM\...\Uninstall\PostgreSQL 16.1` |
| PE | `PostgreSQL` | `16.1` | `C:\Program Files\PostgreSQL\16` | `pe://C:\Program Files\PostgreSQL\16\uninstall-postgresql.exe` |

45 CVEs × 2 rows = 90 findings where 45 belong.

**The rule must not be "same directory".** `C:\Program Files\PostgreSQL\16\bin\libcurl.dll` (cURL 8.4.0, 34 real findings) sits inside that same install root and is a genuinely different product that must survive. Collapse requires matching normalized product name **and** version **and** path containment — all three.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `evedoo/src/scanner/appx.rs` | Windows Store package inventory | Modify — request `InstallLocation`, add payload inspection, resolve version from payload |
| `evedoo/src/correlate.rs` | Turns inventory into findings | Modify — add a dedup pass over inventory before correlation |
| `evedoo/src/scanner/pe_fingerprint.rs` | PE version resource reader | Read-only — reuse `version_info::query` |

---

### Task 1: AppX packages report their payload's version, not the Store package number

**Files:**
- Modify: `evedoo/src/scanner/appx.rs` (PowerShell query at `:24-30`, `parse_json` at `:50-108`, tests at `:160+`)
- Reuse (do not edit): `evedoo/src/scanner/pe_fingerprint.rs` — `version_info::query(&Path) -> Option<FileVersionInfo>`, where `FileVersionInfo { product_name, product_version, company_name }`

**Interfaces:**
- Consumes: `crate::scanner::pe_fingerprint::version_info::query` — currently a private `mod`; Step 3 makes it `pub(crate)`.
- Produces: `appx::resolve_payload_version(install_location: Option<&str>, appx_version: Option<String>) -> PayloadVerdict`, and `pub(crate) enum PayloadVerdict { Stub, Version(Option<String>) }`. Task 2 does not depend on either.

**Design:** `PayloadVerdict::Stub` means "this package contains no executable code" → the package is dropped from inventory entirely. `PayloadVerdict::Version(v)` means "keep the package with version `v`", where `v` is the primary executable's `product_version` when readable and the trimmed AppX version otherwise. Choosing the primary executable = the largest `.exe` or `.dll` under the install location, which is `python313.dll` for Python and `wsl.exe` for WSL.

- [x] **Step 1: Write the failing tests**

Add to the existing `mod tests` block at the bottom of `evedoo/src/scanner/appx.rs`:

```rust
    #[test]
    fn a_package_with_no_executable_payload_is_a_stub() {
        // Microsoft.VisualStudioCode ships exactly three files —
        // AppxBlockMap.xml, AppxManifest.xml, AppxSignature.p7x — and no code.
        // Its "1.0.137" is the Store stub's own number, unrelated to VS Code
        // product versions (1.9x-1.13x). Because it sorts below every VS Code
        // CPE bound it matched all 60 VS Code CVEs, including ones fixed in
        // 1.55.2 back in 2021. A package with no code carries no vulnerability.
        let dir = tempdir_with(&[
            ("AppxManifest.xml", b"<Package/>"),
            ("AppxBlockMap.xml", b"<BlockMap/>"),
            ("AppxSignature.p7x", b"\x30\x82"),
        ]);
        assert_eq!(
            resolve_payload_version(Some(dir.path_str()), Some("1.0.137".into())),
            PayloadVerdict::Stub
        );
    }

    #[test]
    fn a_package_with_executables_is_not_a_stub() {
        // wsl.exe is real code, so the package must survive even though this
        // test's stand-in carries no readable version resource.
        let dir = tempdir_with(&[("wsl.exe", b"MZ not-a-real-pe")]);
        assert!(matches!(
            resolve_payload_version(Some(dir.path_str()), Some("2.6.3".into())),
            PayloadVerdict::Version(_)
        ));
    }

    #[test]
    fn an_unreadable_version_resource_falls_back_to_the_appx_version() {
        // WSL is the control case: its AppX version 2.6.3.0 genuinely equals
        // wsl.exe's 2.6.3.0, so falling back must not change WSL's result.
        let dir = tempdir_with(&[("wsl.exe", b"MZ not-a-real-pe")]);
        assert_eq!(
            resolve_payload_version(Some(dir.path_str()), Some("2.6.3".into())),
            PayloadVerdict::Version(Some("2.6.3".into()))
        );
    }

    #[test]
    fn a_package_with_no_install_location_keeps_its_appx_version() {
        // Get-AppxPackage can return a null InstallLocation for a partially
        // staged package. Absence of evidence is not evidence of a stub —
        // dropping it there would be a false negative.
        assert_eq!(
            resolve_payload_version(None, Some("1.2.3".into())),
            PayloadVerdict::Version(Some("1.2.3".into()))
        );
    }

    #[test]
    fn an_unreadable_install_location_is_not_treated_as_a_stub() {
        // C:\Program Files\WindowsApps is heavily ACL'd. A directory that
        // cannot be read yields zero executables for the same reason a genuine
        // stub does, and the two must not be confused: treating a permission
        // failure as "no code here" would silently drop every Store package on
        // a machine whose ACLs differ from the one this was measured on.
        assert_eq!(
            resolve_payload_version(Some(r"C:\definitely\not\a\real\path"), Some("9.9".into())),
            PayloadVerdict::Version(Some("9.9".into()))
        );
    }
```

Add this test helper immediately above those tests, inside `mod tests`:

```rust
    struct TempPkg(std::path::PathBuf);

    impl TempPkg {
        fn path_str(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TempPkg {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir_with(files: &[(&str, &[u8])]) -> TempPkg {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "evedoo-appx-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
        TempPkg(dir)
    }
```

- [x] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p evedoo --bins -- appx`
Expected: FAIL to compile — `cannot find function 'resolve_payload_version' in this scope` and `cannot find type 'PayloadVerdict' in this scope`.

- [x] **Step 3: Make the PE version reader reachable**

In `evedoo/src/scanner/pe_fingerprint.rs`, both `mod version_info` declarations (line 323 for the non-Windows stub and line 341 for the Windows implementation) are currently private. Change **both** to `pub(crate)`:

```rust
pub(crate) mod version_info {
```

Leave everything inside them unchanged.

- [x] **Step 4: Write the minimal implementation**

Add to `evedoo/src/scanner/appx.rs`, immediately above the `#[cfg(test)] mod tests` block:

```rust
/// What a Store package's contents say about it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PayloadVerdict {
    /// The package contains no executable code, so it cannot carry a
    /// vulnerability. `Microsoft.VisualStudioCode` is one: three XML/signature
    /// files and nothing else, whose Store version `1.0.137` sorts below every
    /// VS Code CPE bound and therefore matched every VS Code CVE ever filed.
    Stub,
    /// The package contains code. The version is the primary executable's
    /// product version when one is readable, otherwise the Store version —
    /// absence of a version resource is not grounds to drop a real package.
    Version(Option<String>),
}

/// Decide a Store package's version from what it actually installs.
///
/// A Store package's `Version` is the *packaging* number and need not track
/// the product: `PythonSoftwareFoundation.Python.3.13` reports `3.13.3824`
/// while its `python313.dll` reports the true `3.13.14`. Reading the payload
/// fixes matching in both directions — `3.13.3824` sorts *above* real CPE
/// bounds like `< 3.13.6`, so the Store number was causing false negatives
/// there, just as it caused false positives for VS Code.
pub(crate) fn resolve_payload_version(
    install_location: Option<&str>,
    appx_version: Option<String>,
) -> PayloadVerdict {
    let Some(root) = install_location else {
        return PayloadVerdict::Version(appx_version);
    };

    // A directory that cannot be read yields zero executables for the same
    // reason a genuine stub does. Only a *successful* read that finds no code
    // is evidence of a stub; a permission failure is evidence of nothing.
    let Some(executables) = collect_executables(std::path::Path::new(root)) else {
        debug!("AppX: {root} unreadable, keeping Store version");
        return PayloadVerdict::Version(appx_version);
    };

    if executables.is_empty() {
        return PayloadVerdict::Stub;
    }

    // The largest executable is the product itself rather than a helper stub:
    // python313.dll for Python, wsl.exe for WSL.
    let primary = executables
        .iter()
        .max_by_key(|(_, size)| *size)
        .map(|(path, _)| path);

    let from_payload = primary
        .and_then(|p| crate::scanner::pe_fingerprint::version_info::query(p))
        .map(|info| info.product_version)
        .filter(|v| !v.trim().is_empty());

    PayloadVerdict::Version(from_payload.or(appx_version))
}

/// Every `.exe`/`.dll` under `root`, with its size, walked without recursing
/// through symlinks. Depth is capped because a Store package is shallow and an
/// unbounded walk of a reparse-point loop would hang the scan.
///
/// Returns `None` when `root` itself cannot be read, so the caller can tell a
/// package that contains no code from one whose ACLs hid its contents.
/// Unreadable *sub*directories are skipped rather than failing the whole walk —
/// finding code anywhere in the package is enough to prove it is not a stub.
fn collect_executables(root: &std::path::Path) -> Option<Vec<(std::path::PathBuf, u64)>> {
    fn walk(dir: &std::path::Path, depth: u32, out: &mut Vec<(std::path::PathBuf, u64)>) {
        if depth > 6 || out.len() > 4096 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_symlink() {
                continue;
            }
            let path = entry.path();
            if meta.is_dir() {
                walk(&path, depth + 1, out);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref(),
                Some("exe") | Some("dll")
            ) {
                out.push((path, meta.len()));
            }
        }
    }

    // Probe the root separately: this is the read whose failure is ambiguous.
    std::fs::read_dir(root).ok()?;

    let mut out = Vec::new();
    walk(root, 0, &mut out);
    Some(out)
}
```

- [x] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p evedoo --bins -- appx`
Expected: PASS — all five new tests plus the pre-existing `trim_version_*` tests.

- [x] **Step 6: Wire it into the scan path**

Two edits in `evedoo/src/scanner/appx.rs`.

First, extend the PowerShell query at line ~28 to fetch the install location:

```rust
                "Get-AppxPackage | Select-Object Name,Version,Publisher,InstallLocation | ConvertTo-Json -Compress",
```

Second, in `parse_json`, replace the single line `let version = trim_version(&version_raw);` with the payload check, and drop stubs. The surrounding `let publisher = ...` and `results.push(...)` lines stay as they are:

```rust
            let install_location = item["InstallLocation"].as_str().map(str::to_string);

            let version = match resolve_payload_version(
                install_location.as_deref(),
                trim_version(&version_raw),
            ) {
                PayloadVerdict::Stub => {
                    debug!(
                        "AppX: {} has no executable payload — Store stub, skipping",
                        name
                    );
                    continue;
                }
                PayloadVerdict::Version(v) => v,
            };
```

Then set the field on the pushed `DetectedSoftware` — change `install_location: None,` to:

```rust
                install_location,
```

- [x] **Step 7: Verify the full gate**

Run: `cargo test --workspace`
Expected: PASS, 544 tests (539 baseline + 5 new).

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [x] **Step 8: Verify against the live scan**

Run:
```bash
cargo build --release -p evedoo
"target/release/evedoo.exe" scan --database vulndb.sqlite \
  --format json --output scan-task1.json --min-confidence high --no-history
```

Confirm all three, and record the numbers in the commit message:
1. **Zero** findings remain whose `registry_key` is `appx://Microsoft.VisualStudioCode` (was 60).
2. `appx://MicrosoftCorporationII.WindowsSubsystemForLinux` still reports version `2.6.3` — the control case is unchanged.
3. `appx://PythonSoftwareFoundation.Python.3.13` now reports `3.13.14`, not `3.13.3824`. Its finding count may **rise**; that is the expected correction of a false negative, not a regression.

- [x] **Step 9: Commit**

```bash
git add evedoo/src/scanner/appx.rs evedoo/src/scanner/pe_fingerprint.rs
git commit -m "fix(scanner): resolve AppX version from package payload, drop code-less stubs

A Store package's Version is a packaging number, not the product version.
Microsoft.VisualStudioCode ships three XML files and no code; its 1.0.137
sorts below every VS Code CPE bound and matched all 60 VS Code CVEs,
including ones fixed in 1.55.2 in 2021. Packages with no executable payload
are now dropped, and packages with a payload take the primary executable's
PE product version — which also corrects Python 3.13, whose Store number
3.13.3824 sorted above real bounds and was causing false negatives.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Collapse one install found by two scanners

**Files:**
- Modify: `evedoo/src/correlate.rs` (`correlate` at `:24`, tests at `:64+`)

**Interfaces:**
- Consumes: `crate::models::DetectedSoftware { name, version, publisher, install_location, install_date, registry_key, architecture }`. Nothing from Task 1.
- Produces: `dedupe_inventory(Vec<DetectedSoftware>) -> Vec<DetectedSoftware>`, called at the top of `correlate`. Not used elsewhere.

**Design:** Two entries describe one install when **all three** hold: normalized name matches, version matches exactly, and one entry's PE path lies inside the other's `install_location`. The registry entry wins — it is the authoritative install record, and its `registry_key` is what history and exceptions key on. All three conditions are required: `libcurl.dll` inside `C:\Program Files\PostgreSQL\16\bin` shares the install root with PostgreSQL but is a different product and must survive.

- [x] **Step 1: Write the failing tests**

Add to the existing `mod tests` block in `evedoo/src/correlate.rs`:

```rust
    fn sw_full(
        name: &str,
        version: &str,
        install_location: Option<&str>,
        registry_key: &str,
    ) -> DetectedSoftware {
        DetectedSoftware {
            name: name.to_string(),
            version: Some(version.to_string()),
            publisher: None,
            install_location: install_location.map(str::to_string),
            install_date: None,
            registry_key: registry_key.to_string(),
            architecture: Architecture::Unknown,
        }
    }

    #[test]
    fn one_install_found_by_two_scanners_collapses_to_the_registry_entry() {
        // PostgreSQL 16.1 is found by the registry scanner as "PostgreSQL 16 "
        // and by the PE scanner as "PostgreSQL" from uninstall-postgresql.exe
        // inside the very same install root. That is one install, and counting
        // it twice doubled 45 CVEs into 90 findings.
        let inventory = vec![
            sw_full(
                "PostgreSQL 16 ",
                "16.1",
                Some(r"C:\Program Files\PostgreSQL\16"),
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PostgreSQL 16.1",
            ),
            sw_full(
                "PostgreSQL",
                "16.1",
                Some(r"C:\Program Files\PostgreSQL\16"),
                r"pe://C:\Program Files\PostgreSQL\16\uninstall-postgresql.exe",
            ),
        ];

        let out = dedupe_inventory(inventory);

        assert_eq!(out.len(), 1);
        assert!(
            out[0].registry_key.starts_with("HKLM"),
            "the registry entry is the authoritative install record, got {:?}",
            out[0].registry_key
        );
    }

    #[test]
    fn a_different_product_inside_the_same_install_root_survives() {
        // C:\Program Files\PostgreSQL\16\bin\libcurl.dll is a genuinely
        // separate vulnerable artifact with 34 real findings. Deduplicating on
        // shared directory alone would erase it.
        let inventory = vec![
            sw_full(
                "PostgreSQL 16 ",
                "16.1",
                Some(r"C:\Program Files\PostgreSQL\16"),
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PostgreSQL 16.1",
            ),
            sw_full(
                "cURL",
                "8.4.0",
                Some(r"C:\Program Files\PostgreSQL\16\bin"),
                r"pe://C:\Program Files\PostgreSQL\16\bin\libcurl.dll",
            ),
        ];

        assert_eq!(dedupe_inventory(inventory).len(), 2);
    }

    #[test]
    fn the_same_product_at_a_different_version_survives() {
        // Two copies of cURL at different versions are two real problems with
        // different fixes, even when one sits inside the other's tree.
        let inventory = vec![
            sw_full("cURL", "8.4.0", Some(r"C:\App"), r"pe://C:\App\libcurl.dll"),
            sw_full("cURL", "7.79.1", Some(r"C:\App\sub"), r"pe://C:\App\sub\libcurl.dll"),
        ];

        assert_eq!(dedupe_inventory(inventory).len(), 2);
    }

    #[test]
    fn the_same_product_in_unrelated_trees_survives() {
        // Audacity's libcurl and Samsung's libcurl are separate installs that
        // must each be reported and each be patched by their own vendor.
        let inventory = vec![
            sw_full("cURL", "7.82.0", Some(r"C:\A"), r"pe://C:\A\libcurl.dll"),
            sw_full("cURL", "7.82.0", Some(r"C:\B"), r"pe://C:\B\libcurl.dll"),
        ];

        assert_eq!(dedupe_inventory(inventory).len(), 2);
    }
```

The test module already has `use crate::models::Architecture;` at `correlate.rs:63` — no import change is needed here.

- [x] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p evedoo --bins -- correlate`
Expected: FAIL to compile — `cannot find function 'dedupe_inventory' in this scope`.

- [x] **Step 3: Write the minimal implementation**

Add to `evedoo/src/correlate.rs`, above `pub fn correlate`:

```rust
/// Collapse inventory entries that are one install found by two scanners.
///
/// PostgreSQL 16.1 appears as `PostgreSQL 16 ` from the registry and as
/// `PostgreSQL` from the PE fingerprint of `uninstall-postgresql.exe` in the
/// same directory — 45 CVEs reported as 90 findings.
///
/// All three of normalized name, exact version, and path containment must
/// agree. Containment alone is not enough: `libcurl.dll` under
/// `...\PostgreSQL\16\bin` shares the install root and is a different product
/// with 34 findings of its own. Version equality alone is not enough either:
/// two copies of the same library in unrelated trees are two real problems.
///
/// The registry entry wins. It is the authoritative install record, and
/// history and exceptions key on its `registry_key`.
fn dedupe_inventory(inventory: Vec<DetectedSoftware>) -> Vec<DetectedSoftware> {
    fn canonical(name: &str) -> String {
        name.trim()
            .to_ascii_lowercase()
            .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ' ')
            .trim()
            .to_string()
    }

    fn tree(sw: &DetectedSoftware) -> Option<String> {
        let raw = sw.install_location.as_deref().or_else(|| {
            sw.registry_key
                .strip_prefix("pe://")
                .and_then(|p| p.rsplit_once(['\\', '/']))
                .map(|(dir, _)| dir)
        })?;
        Some(raw.trim_end_matches(['\\', '/']).to_ascii_lowercase())
    }

    fn is_registry(sw: &DetectedSoftware) -> bool {
        !sw.registry_key.contains("://")
    }

    let mut keep: Vec<DetectedSoftware> = Vec::with_capacity(inventory.len());

    'outer: for candidate in inventory {
        for existing in keep.iter_mut() {
            let same_product = canonical(&existing.name) == canonical(&candidate.name);
            let same_version = existing.version == candidate.version;
            if !same_product || !same_version {
                continue;
            }

            let (Some(a), Some(b)) = (tree(existing), tree(&candidate)) else {
                continue;
            };
            if !(a.starts_with(&b) || b.starts_with(&a)) {
                continue;
            }

            // One install, two scanners. Keep the registry record.
            if is_registry(&candidate) && !is_registry(existing) {
                debug!(
                    "dedup: {} supersedes {}",
                    candidate.registry_key, existing.registry_key
                );
                *existing = candidate;
            } else {
                debug!(
                    "dedup: {} already covered by {}",
                    candidate.registry_key, existing.registry_key
                );
            }
            continue 'outer;
        }
        keep.push(candidate);
    }

    keep
}
```

Then make `correlate` use it. Change its first line so the body operates on the deduplicated list:

```rust
pub fn correlate(inventory: Vec<DetectedSoftware>, matcher: &CveMatcher) -> CorrelationOutcome {
    let inventory = dedupe_inventory(inventory);
```

`correlate.rs:10` currently reads `use tracing::info;` — the file does not import `debug`, which the new function needs. Change that line to:

```rust
use tracing::{debug, info};
```

- [x] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p evedoo --bins -- correlate`
Expected: PASS — the four new tests plus the pre-existing `outcome_partitions_matched_and_unmatched` and `every_finding_starts_unclassified`.

- [x] **Step 5: Verify the full gate**

Run: `cargo test --workspace`
Expected: PASS, 548 tests (544 after Task 1 + 4 new).

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [x] **Step 6: Verify against the live scan**

Run:
```bash
cargo build --release -p evedoo
"target/release/evedoo.exe" scan --database vulndb.sqlite \
  --format json --output scan-task2.json --min-confidence high --no-history
```

Confirm both, and record the numbers in the commit message:
1. `PostgreSQL` appears **once** per CVE, not twice — 45 findings where there were 90.
2. cURL 8.4.0 at `pe://C:\Program Files\PostgreSQL\16\bin\libcurl.dll` **still reports its 34 findings**. If this number dropped, the containment rule is too aggressive — stop and re-read Step 3.

- [x] **Step 7: Commit**

```bash
git add evedoo/src/correlate.rs
git commit -m "fix(correlate): collapse one install found by two scanners

PostgreSQL 16.1 was inventoried twice — as 'PostgreSQL 16 ' from the
registry and as 'PostgreSQL' from the PE fingerprint of
uninstall-postgresql.exe in the same directory — turning 45 CVEs into 90
findings. Entries now collapse only when normalized name, exact version,
and path containment all agree, so libcurl.dll inside the same install root
stays its own finding. The registry record wins, since history and
exceptions key on its registry_key.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Done Criteria

- [x] Store packages with no executable payload are dropped; `appx://Microsoft.VisualStudioCode` contributes 0 findings (was 60)
- [x] Store packages with a payload report the primary executable's product version; Python 3.13 reports `3.13.14`, not `3.13.3824`
- [x] WSL still reports `2.6.3` — the control case is unchanged
- [x] PostgreSQL 16.1 contributes 45 findings, not 90
- [x] cURL 8.4.0 under `...\PostgreSQL\16\bin` still contributes its 34 findings
- [x] No name allowlist or denylist was added in either task
- [x] `cargo test --workspace` passes — 548 tests
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [x] Completion recorded in `docs/agent-state/tasks.jsonl`

## Out of Scope

- **The `fixed_version` branch-selection bug.** Already fixed in `matcher/cpe.rs::fixed_version_for`; contradictory remediation fell from 294 findings (31.7%) to 29 (3.1%), and those 29 are artifacts of a crude numeric comparison in the validation script, not real defects.
- **FFmpeg vendor backports** (`4.4.1-Jellyfin`, 35 findings). Jellyfin backports fixes without bumping the upstream version, so upstream ranges over-report. This is the same problem `distro_override.rs` solves for Linux packages and needs an authoritative advisory source for vendored Windows builds — a design question, not a bug fix.
- **`Python 3.14-64`**, whose registry version string carries an architecture suffix that parses as a version component. 11 findings. Separate normalization issue in the registry scanner.
- **Reachability returning `Unknown` for every finding.** Correct fail-secure behavior when only 159 of 330 processes are readable. The fix is operational — run the scan elevated.
- **Count presentation.** 928 findings resolve to 51 remediation units because a vendored `libcurl.dll` carries ~55 CVEs. Both are true; a per-artifact rollup in the report layer is a reporting feature, not a false-positive fix.


---

## Execution Notes (2026-09-11)

Executed inline. **Result: 928 → 822 findings (-106, -11.4%).** Task 1 removed
61, Task 2 removed 45. 551 tests pass (539 baseline + 12 new), clippy clean.

Three deviations from the plan as written, each forced by evidence found while
executing. All are recorded here rather than silently folded in.

### 1. "Largest executable" was wrong — replaced by name matching

The plan chose a package's version from its **largest** executable, reasoning
from Python (`python313.dll`) and WSL (`wsl.exe`). `Microsoft.Paint` disproved
it: it ships a 15 MB vendored `ps-onnxruntime.dll` (version `1.23.20260526`)
beside its own 4 MB `mspaint.exe` (`11.2605.81.0`). The heuristic read the ML
runtime's version as Paint's, and `1.23.x` falls below the `< 6.2305.16087.0`
bound of the Paint 3D CVEs — **inventing two findings against a current Paint**,
against an entry whose Store version had been correct all along.

That collision is possible at all because the NVD CPE dictionary holds exactly
one Paint row: product `paint_3d`, titled "Microsoft Paint". The dictionary
defect is upstream and pre-existing; the wrong version is what tripped it.

`primary_executable_name` now picks the executable whose name resembles the
package name, and returns `None` when none does — vendored libraries are
already inventoried in their own right by the PE fingerprint scanner, so
declining to pick one loses nothing. Verified: Paint's two findings gone,
Python still `3.13.14`, WSL control still `2.6.3`.

### 2. Payload versions are trimmed like Store versions

`wsl.exe`'s PE resource reads `2.6.3.0` where the Store reports `2.6.3`. Left
untrimmed, a version changed shape depending on which source won. The payload
version now goes through the same `trim_version` the Store version does.

### 3. Task 2 became a one-line key fix, not a new dedup pass

The plan added `dedupe_inventory` to `correlate.rs`. **A cross-source dedup
already existed** at `main.rs:1020` (and a second at `:1460` for remote scans),
keyed on `lowercase(name)|version` — the plan was written without finding it and
would have added a second, competing dedup in a different layer.

PostgreSQL escaped the existing key only through the display name's release
suffix: `'postgresql 16 |16.1'` vs `'postgresql|16.1'`. The fix is therefore
`normalize::names::dedup_key`, which peels a trailing release token, replacing
the inline `format!` at both existing sites. DRY, one layer, no new pass.

The plan's path-containment rule proved unnecessary: the existing key already
separates products by name, which is what protects `libcurl.dll` inside
`...\PostgreSQLin`. Before implementing, a dry run over all 684 inventory
entries confirmed exactly 7 groups would newly collapse — Antigravity, CS Demo
Manager, HandBrake, KeePass, Notion, Pinokio, PostgreSQL — every one a registry
entry paired with the PE fingerprint of that same product's own executable, and
zero vendored libraries merged.

### Corrected false negatives

Task 1 fixed under-reporting as well as over-reporting, as the plan predicted:
Python 3.13's Store version `3.13.3824` sorted *above* real CPE bounds and hid
real findings. It now reports the true `3.13.14`, and its findings rose 1 → 3
while one finding that existed only because of the bogus high version went away.

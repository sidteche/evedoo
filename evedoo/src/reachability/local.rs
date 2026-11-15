//! Local module enumeration via the Win32 Toolhelp32 API.
//!
//! Direct FFI against `kernel32` and `advapi32`, matching the `version.dll`
//! precedent in `scanner/pe_fingerprint.rs` — no new crate dependency.
//!
//! SPDX-License-Identifier: Apache-2.0

#[allow(unused_imports)]
use std::collections::HashSet;
#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
use tracing::debug;

#[allow(unused_imports)]
use super::{normalize_path, Coverage, ModuleMap};

#[cfg(target_os = "windows")]
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
#[cfg(target_os = "windows")]
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
#[cfg(target_os = "windows")]
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;

#[cfg(target_os = "windows")]
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
#[cfg(target_os = "windows")]
const TOKEN_QUERY: u32 = 0x0008;
#[cfg(target_os = "windows")]
const SE_PRIVILEGE_ENABLED: u32 = 0x0002;

/// `CreateToolhelp32Snapshot` returns this when the target process is
/// modifying its module list mid-call. MSDN's documented remedy is to call
/// again rather than treat it as failure.
#[cfg(target_os = "windows")]
const ERROR_BAD_LENGTH: u32 = 24;

/// How many times to re-attempt a snapshot that lost the race. Bounded so a
/// process genuinely churning its modules cannot stall the sweep.
#[cfg(target_os = "windows")]
const SNAPSHOT_ATTEMPTS: u32 = 4;

#[cfg(target_os = "windows")]
fn invalid_handle() -> *mut c_void {
    -1isize as *mut c_void
}

/// Retry `f` while it fails with `ERROR_BAD_LENGTH`, up to `max_attempts`.
///
/// Only that one error is retried. `ERROR_ACCESS_DENIED` means we are not
/// permitted to read the process at all, and retrying cannot change that —
/// it would just multiply the syscall cost across every protected process on
/// the machine, which measured as roughly half of them.
///
/// Split out from the FFI so the policy is testable without mocking Win32.
#[cfg(target_os = "windows")]
fn retry_bad_length<T>(
    max_attempts: u32,
    mut f: impl FnMut() -> Result<T, u32>,
) -> Result<T, u32> {
    let mut last = ERROR_BAD_LENGTH;
    for _ in 0..max_attempts {
        match f() {
            Ok(v) => return Ok(v),
            Err(ERROR_BAD_LENGTH) => last = ERROR_BAD_LENGTH,
            Err(other) => return Err(other),
        }
    }
    Err(last)
}

// The unread fields below are NOT dead weight: `#[repr(C)]` lays the struct
// out to match the Win32 header exactly, and `dwSize` is validated by the API
// against `size_of`. Removing a field we happen not to read would shift every
// subsequent offset and silently corrupt the walk.
#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(dead_code)]
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

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(dead_code)]
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

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(dead_code)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(dead_code)]
struct TokenPrivileges {
    privilege_count: u32,
    privileges: [LuidAndAttributes; 1],
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut c_void;
    fn Process32FirstW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn Module32FirstW(h_snapshot: *mut c_void, lpme: *mut ModuleEntry32W) -> i32;
    fn Module32NextW(h_snapshot: *mut c_void, lpme: *mut ModuleEntry32W) -> i32;
    fn CloseHandle(h_object: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetLastError() -> u32;
}

#[cfg(target_os = "windows")]
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
#[cfg(target_os = "windows")]
fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Best-effort `SeDebugPrivilege`. Failure is the normal unelevated case and
/// is NOT an error: it simply means the sweep sees only this user's
/// processes, which FR-74 then reports honestly as incomplete coverage.
#[cfg(target_os = "windows")]
fn try_enable_se_debug() -> bool {
    let name: Vec<u16> = "SeDebugPrivilege"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
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
                privileges: [LuidAndAttributes {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                }],
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

/// Linux process & memory mapper via `/proc/[pid]/maps` and `/proc/[pid]/exe`.
#[cfg(target_os = "linux")]
pub fn collect() -> ModuleMap {
    use std::fs;

    let mut paths: HashSet<String> = HashSet::new();
    let mut total = 0usize;
    let mut readable = 0usize;

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            // Process directories in /proc are strictly numeric
            if name_str.chars().all(|c| c.is_ascii_digit()) && !name_str.is_empty() {
                total += 1;
                let pid_path = entry.path();
                let mut read_success = false;

                // 1. Target executable
                let exe_link = pid_path.join("exe");
                if let Ok(target) = fs::read_link(&exe_link) {
                    read_success = true;
                    paths.insert(normalize_path(&target.to_string_lossy()));
                }

                // 2. Mapped memory objects & libraries
                let maps_path = pid_path.join("maps");
                if let Ok(content) = fs::read_to_string(&maps_path) {
                    read_success = true;
                    for line in content.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 6 {
                            let map_path = parts[5];
                            if map_path.starts_with('/') {
                                paths.insert(normalize_path(map_path));
                            }
                        }
                    }
                }

                if read_success {
                    readable += 1;
                }
            }
        }
    }

    ModuleMap::new(paths, Coverage { readable, total })
}

/// Fallback for macOS and non-Linux/non-Windows platforms.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn collect() -> ModuleMap {
    ModuleMap::empty_unknown()
}

/// Collect every module path mapped into every process we are permitted to
/// open, together with how much of the process list that represents.
#[cfg(target_os = "windows")]
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
        // Nothing could be enumerated at all. `empty_unknown` is deliberately
        // incomplete, so FR-74 forces every classification to Unknown through
        // the normal path rather than through a special case.
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
#[cfg(target_os = "windows")]
fn collect_modules_for_pid(pid: u32, out: &mut HashSet<String>) -> bool {
    // MSDN: this call can lose a race with the target process loading or
    // unloading a DLL and fail with ERROR_BAD_LENGTH. Treating that as
    // "unreadable" would silently degrade coverage, and under FR-74 lower
    // coverage pushes findings to Unknown — a transient race would cost us
    // the signal. Retry only that error; access-denied is permanent.
    let snap = match retry_bad_length(SNAPSHOT_ATTEMPTS, || unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if h == invalid_handle() {
            Err(GetLastError())
        } else {
            Ok(h)
        }
    }) {
        Ok(h) => h,
        Err(_) => return false,
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The scanner can always open its own process, so this is deterministic
    /// rather than dependent on what happens to be running.
    #[test]
    #[cfg(any(target_os = "windows", target_os = "linux"))]
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

    #[test]
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn collect_fallback_empty_unknown() {
        let map = collect();
        assert_eq!(map.coverage().readable, 0);
        assert_eq!(map.coverage().total, 1);
    }

    /// Every running Windows process maps ntdll.dll. If the walk returns
    /// paths at all, it must contain that one — a cheap proof that we are
    /// reading real module paths and not empty strings.
    #[test]
    #[cfg(target_os = "windows")]
    fn collect_finds_ntdll() {
        let map = collect();
        assert!(
            map.contains_normalized(&crate::reachability::normalize_path(
                r"C:\Windows\System32\ntdll.dll"
            )),
            "ntdll.dll is mapped into every Windows process"
        );
    }

    /// MSDN documents that `CreateToolhelp32Snapshot` with TH32CS_SNAPMODULE
    /// can fail with ERROR_BAD_LENGTH while the target process is modifying
    /// its own module list, and that the remedy is to call it again.
    ///
    /// Without the retry, a process that happens to be loading a DLL during
    /// the sweep is silently counted as UNREADABLE. Under FR-74 that lowers
    /// coverage, which pushes findings to `Unknown` — so a transient race
    /// quietly costs us the very signal this feature exists to produce.
    #[test]
    #[cfg(target_os = "windows")]
    fn retries_only_on_bad_length_and_succeeds_once_the_race_clears() {
        let mut attempts = 0;
        let r = retry_bad_length(5, || {
            attempts += 1;
            if attempts < 3 {
                Err(ERROR_BAD_LENGTH)
            } else {
                Ok("snapshot")
            }
        });

        assert_eq!(r, Ok("snapshot"));
        assert_eq!(attempts, 3, "must retry through the transient failures");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn succeeds_first_time_without_retrying() {
        let mut attempts = 0;
        let r = retry_bad_length(5, || {
            attempts += 1;
            Ok(())
        });
        assert!(r.is_ok());
        assert_eq!(attempts, 1, "a clean call must not be repeated");
    }

    /// The bound matters: a process that is genuinely churning must not spin
    /// the sweep forever.
    #[test]
    #[cfg(target_os = "windows")]
    fn gives_up_after_the_attempt_bound() {
        let mut attempts = 0;
        let r: Result<(), u32> = retry_bad_length(4, || {
            attempts += 1;
            Err(ERROR_BAD_LENGTH)
        });
        assert_eq!(r, Err(ERROR_BAD_LENGTH));
        assert_eq!(attempts, 4, "bounded, not unbounded");
    }

    /// The load-bearing distinction. ERROR_ACCESS_DENIED means we are not
    /// permitted to read this process at all — retrying cannot change that,
    /// and doing so would multiply the syscall cost of every protected
    /// process on the machine (roughly half of them, measured).
    #[test]
    #[cfg(target_os = "windows")]
    fn does_not_retry_a_non_transient_error() {
        const ERROR_ACCESS_DENIED: u32 = 5;
        let mut attempts = 0;
        let r: Result<(), u32> = retry_bad_length(5, || {
            attempts += 1;
            Err(ERROR_ACCESS_DENIED)
        });
        assert_eq!(r, Err(ERROR_ACCESS_DENIED));
        assert_eq!(attempts, 1, "a permanent error must fail fast");
    }
}

//! PE header fingerprinter.
//!
//! Catches portable tools and toolchains that the registry / AppX / WinGet /
//! Chocolatey / Scoop / language-ecosystem scanners miss. Walks a bounded set
//! of install roots, reads `VS_VERSION_INFO` from every `.exe` via the Win32
//! version-info API (`version.dll`), and emits one [`DetectedSoftware`] per
//! unique `(ProductName, ProductVersion)`.
//!
//! No new crate dependencies — `version.dll` ships with every modern Windows
//! install and is accessed via direct FFI declarations.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

// ── Tunables ─────────────────────────────────────────────────────────────────

/// Maximum directory depth the walker descends below each root. Most installs
/// live at depth 2–3 (`C:\Program Files\Vendor\App\bin\foo.exe`).
const MAX_DEPTH: usize = 5;

/// Per-root safety valve — stops runaway walks on pathological trees.
const MAX_FILES_PER_ROOT: usize = 20_000;

/// Minimum file size for a PE to be worth fingerprinting. Stubs, shims, and
/// broken installs are typically tiny.
const MIN_FILE_SIZE: u64 = 1_024;

/// Maximum file size — skips enormous installer blobs.
const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024;

/// Well-known vulnerable library DLLs, matched by lowercase filename prefix.
/// Applications bundle these inside their install directories where no other
/// scanner sees them (no registry entry, no package manager). The display
/// name is forced so each maps onto its curated CPE identity instead of the
/// vendor-specific ProductName embedded in the DLL.
const KNOWN_LIBRARY_DLLS: &[(&str, &str)] = &[
    ("libcrypto", "OpenSSL"),
    ("libssl", "OpenSSL"),
    ("openssl", "OpenSSL"),
    ("sqlite3", "SQLite"),
    ("libcurl", "cURL"),
    ("zlib", "zlib"),
    ("libxml2", "libxml2"),
    ("libpng", "libpng"),
    ("freetype", "FreeType"),
    ("turbojpeg", "libjpeg-turbo"),
    ("libjpeg", "libjpeg-turbo"),
    ("avcodec", "FFmpeg"),
    ("avformat", "FFmpeg"),
    ("avutil", "FFmpeg"),
    ("swscale", "FFmpeg"),
];

/// If `path` is a known library DLL, return its canonical display name.
fn known_library_display(path: &Path) -> Option<&'static str> {
    let s = path.to_str()?;
    let file_part = s.rsplit(['/', '\\']).next().unwrap_or(s);
    let stem = Path::new(file_part).file_stem()?.to_str()?.to_ascii_lowercase();
    KNOWN_LIBRARY_DLLS
        .iter()
        .find(|(prefix, _)| stem.starts_with(prefix))
        .map(|(_, display)| *display)
}

// ── Scanner ──────────────────────────────────────────────────────────────────

pub struct PeFingerprintScanner;

impl PeFingerprintScanner {
    pub fn new() -> Self {
        PeFingerprintScanner
    }

    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let roots = Self::install_roots();
        let mut results: Vec<DetectedSoftware> = Vec::new();
        // Dedupe on (lowercase product name, version) within the scanner so
        // vendors shipping multiple exes under one install don't produce
        // N copies of the same entry.
        let mut seen: HashSet<(String, String)> = HashSet::new();

        for root in &roots {
            if !root.is_dir() {
                continue;
            }
            debug!("PE fingerprint: walking {}", root.display());
            let exes = walk_exes(root, MAX_DEPTH, MAX_FILES_PER_ROOT);
            for exe in &exes {
                let info = match version_info::query(exe) {
                    Some(i) => i,
                    None => continue,
                };
                // Known library DLLs get a canonical name so they map onto
                // their curated CPE identity; their embedded ProductName
                // varies per bundling vendor.
                let name = if let Some(display) = known_library_display(exe) {
                    if info.product_version.trim().is_empty() {
                        continue;
                    }
                    display.to_string()
                } else {
                    if is_skippable(&info) {
                        continue;
                    }
                    info.product_name.clone()
                };
                let key = (name.to_lowercase(), info.product_version.clone());
                if !seen.insert(key) {
                    continue;
                }

                let install_location =
                    exe.parent().map(|p| p.to_string_lossy().into_owned());

                results.push(DetectedSoftware {
                    name,
                    version: Some(info.product_version),
                    publisher: if info.company_name.is_empty() {
                        None
                    } else {
                        Some(info.company_name)
                    },
                    install_location,
                    install_date: None,
                    registry_key: format!("pe://{}", exe.display()),
                    architecture: Architecture::Unknown,
                });
            }
        }

        results
    }

    /// Default PE fingerprinting roots. Each is tried in order and skipped
    /// if it doesn't exist. Duplicates are removed so we never walk the
    /// same tree twice.
    fn install_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();

        // Environment-driven roots (cover non-standard installs)
        for var in &["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Ok(p) = std::env::var(var) {
                let path = PathBuf::from(p);
                if !roots.contains(&path) {
                    roots.push(path);
                }
            }
        }

        // Hard-coded defaults in case the env vars are missing
        for default in &[r"C:\Program Files", r"C:\Program Files (x86)"] {
            let path = PathBuf::from(default);
            if !roots.contains(&path) {
                roots.push(path);
            }
        }

        // Per-user install location used by many modern installers
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let path = PathBuf::from(local).join("Programs");
            if !roots.contains(&path) {
                roots.push(path);
            }
        }

        roots
    }
}

impl Default for PeFingerprintScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Updater, staging, and side-by-side version-cache directories. Binaries
/// inside carry the parent product's ProductName but the updater's own
/// version stream (EdgeUpdate helpers report "Microsoft Edge" v1.3.x) or a
/// stale cached version (EdgeCore keeps the previous browser build) — both
/// produce wall-to-wall false CVE matches against the real product. The
/// active install lives outside these directories and is still scanned.
fn is_updater_staging_dir(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "edgeupdate"
            | "edgecore"
            | "googleupdate"
            | "googleupdater"
            | "update"
            | "updates"
            | "updated"
            | "updater"
            | "installer"
            | "installers"
            | "staging"
            | "temp"
            // Its Uninstall.exe reports ProductName "Firefox" with the
            // stale version that installed the service.
            | "mozilla maintenance service"
    )
    // GUID-braced directories are download/staging areas
    // (EdgeUpdate\Download\{F3C4FE00-...}\).
    || (lower_name.starts_with('{') && lower_name.ends_with('}'))
}

// ── Directory walking ────────────────────────────────────────────────────────

/// Depth-limited DFS walker that collects `.exe` files matching the size
/// filter. Intentionally avoids pulling `walkdir` for one function.
fn walk_exes(root: &Path, max_depth: usize, max_files: usize) -> Vec<PathBuf> {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let mut results: Vec<PathBuf> = Vec::new();

    'outer: while let Some((dir, depth)) = stack.pop() {
        // Skip well-known OS directories — they contain thousands of system
        // binaries that are never interesting as "installed software".
        if let Some(name) = dir.file_name().and_then(OsStr::to_str) {
            let lower = name.to_ascii_lowercase();
            if lower == "windows"
                || lower == "system32"
                || lower == "syswow64"
                || lower == "winsxs"
                || lower == "servicing"
                || is_updater_staging_dir(&lower)
            {
                continue;
            }
        }

        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            if results.len() >= max_files {
                debug!("PE fingerprint: hit file cap in {}", root.display());
                break 'outer;
            }

            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };

            if file_type.is_symlink() {
                continue; // avoid cycles
            }

            if file_type.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
                continue;
            }

            if !file_type.is_file() {
                continue;
            }

            let ext = match path.extension().and_then(OsStr::to_str) {
                Some(e) => e.to_ascii_lowercase(),
                None => continue,
            };
            // Executables are fingerprinted unconditionally; DLLs only when
            // they are known vulnerable libraries (bundled OpenSSL, zlib,
            // sqlite3, ...) so vendor-private DLLs don't flood the inventory.
            if ext != "exe" && !(ext == "dll" && known_library_display(&path).is_some()) {
                continue;
            }

            // Size filter
            if let Ok(meta) = entry.metadata() {
                let size = meta.len();
                if !(MIN_FILE_SIZE..=MAX_FILE_SIZE).contains(&size) {
                    continue;
                }
            }

            results.push(path);
        }
    }

    results
}

// ── Filtering ────────────────────────────────────────────────────────────────

/// Returns `true` for entries we don't want in the output — empty metadata
/// and Microsoft Windows OS components (but NOT Microsoft applications like
/// Edge, Office, Teams which do have CVEs).
fn is_skippable(info: &version_info::FileVersionInfo) -> bool {
    if info.product_name.trim().is_empty() {
        return true;
    }
    if info.product_version.trim().is_empty() {
        return true;
    }
    // Drop Microsoft Windows OS components
    let is_ms = info.company_name.contains("Microsoft");
    let is_os = info.product_name.contains("Microsoft\u{00ae} Windows\u{00ae}")
        || info.product_name.contains("Windows\u{00ae} Operating System")
        || info.product_name == "Microsoft Windows";
    is_ms && is_os
}

// ── Win32 version info (FFI) ─────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
pub(crate) mod version_info {
    use std::path::Path;

    #[derive(Debug, Clone)]
    pub struct FileVersionInfo {
        pub product_name: String,
        pub product_version: String,
        pub company_name: String,
    }

    pub fn query(_path: &Path) -> Option<FileVersionInfo> {
        None
    }
}

// Win32 FFI types intentionally match the Windows SDK naming convention.
#[cfg(target_os = "windows")]
#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
pub(crate) mod version_info {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    type BOOL = i32;
    type DWORD = u32;
    type LPCWSTR = *const u16;
    type LPVOID = *mut std::ffi::c_void;

    #[link(name = "version")]
    extern "system" {
        fn GetFileVersionInfoSizeW(
            lptstrFilename: LPCWSTR,
            lpdwHandle: *mut DWORD,
        ) -> DWORD;

        fn GetFileVersionInfoW(
            lptstrFilename: LPCWSTR,
            dwHandle: DWORD,
            dwLen: DWORD,
            lpData: LPVOID,
        ) -> BOOL;

        fn VerQueryValueW(
            pBlock: LPVOID,
            lpSubBlock: LPCWSTR,
            lplpBuffer: *mut LPVOID,
            puLen: *mut u32,
        ) -> BOOL;
    }

    #[derive(Debug, Clone)]
    pub struct FileVersionInfo {
        pub product_name: String,
        pub product_version: String,
        pub company_name: String,
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn wstr(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Load version info for a PE file, returning `None` if the binary has
    /// no version resource (common for stripped installers and plain Rust
    /// binaries).
    pub fn query(path: &Path) -> Option<FileVersionInfo> {
        let wide = to_wide(path);
        let mut handle: DWORD = 0;

        let size = unsafe { GetFileVersionInfoSizeW(wide.as_ptr(), &mut handle) };
        if size == 0 {
            return None;
        }

        let mut buf: Vec<u8> = vec![0; size as usize];
        let ok =
            unsafe { GetFileVersionInfoW(wide.as_ptr(), 0, size, buf.as_mut_ptr() as LPVOID) };
        if ok == 0 {
            return None;
        }

        // Query the translation table — an array of (lang, codepage) u16
        // pairs. We use the first entry to build the StringFileInfo sub-block
        // path.
        let (lang, codepage) = query_translation(&mut buf)?;

        let product_name =
            query_string(&mut buf, lang, codepage, "ProductName").unwrap_or_default();

        // ProductVersion is sometimes empty but FileVersion is populated;
        // fall back so we still emit a usable version.
        let product_version =
            query_string(&mut buf, lang, codepage, "ProductVersion")
                .filter(|s| !s.is_empty())
                .or_else(|| query_string(&mut buf, lang, codepage, "FileVersion"))
                .unwrap_or_default();

        let company_name =
            query_string(&mut buf, lang, codepage, "CompanyName").unwrap_or_default();

        Some(FileVersionInfo {
            product_name,
            product_version,
            company_name,
        })
    }

    fn query_translation(buf: &mut [u8]) -> Option<(u16, u16)> {
        let sub = wstr("\\VarFileInfo\\Translation");
        let mut ptr_out: LPVOID = ptr::null_mut();
        let mut len_out: u32 = 0;

        let ok = unsafe {
            VerQueryValueW(
                buf.as_mut_ptr() as LPVOID,
                sub.as_ptr(),
                &mut ptr_out,
                &mut len_out,
            )
        };
        if ok == 0 || ptr_out.is_null() || len_out < 4 {
            return None;
        }

        let lang = unsafe { *(ptr_out as *const u16) };
        let codepage = unsafe { *((ptr_out as *const u16).offset(1)) };
        Some((lang, codepage))
    }

    fn query_string(
        buf: &mut [u8],
        lang: u16,
        codepage: u16,
        key: &str,
    ) -> Option<String> {
        // Try uppercase hex first (MSDN convention), then lowercase (some
        // tools emit it that way). VerQueryValueW is case-sensitive on the
        // sub-block path.
        query_raw(
            buf,
            &format!("\\StringFileInfo\\{:04X}{:04X}\\{}", lang, codepage, key),
        )
        .or_else(|| {
            query_raw(
                buf,
                &format!("\\StringFileInfo\\{:04x}{:04x}\\{}", lang, codepage, key),
            )
        })
    }

    fn query_raw(buf: &mut [u8], sub_path: &str) -> Option<String> {
        let sub = wstr(sub_path);
        let mut ptr_out: LPVOID = ptr::null_mut();
        let mut len_out: u32 = 0;

        let ok = unsafe {
            VerQueryValueW(
                buf.as_mut_ptr() as LPVOID,
                sub.as_ptr(),
                &mut ptr_out,
                &mut len_out,
            )
        };
        if ok == 0 || ptr_out.is_null() || len_out == 0 {
            return None;
        }

        // len_out is wchar count including the trailing NUL
        let slice = unsafe { std::slice::from_raw_parts(ptr_out as *const u16, len_out as usize) };
        let trimmed: Vec<u16> = slice.iter().copied().take_while(|&c| c != 0).collect();
        let result = String::from_utf16_lossy(&trimmed).trim().to_string();

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_fingerprint_scanner_does_not_panic() {
        let _ = PeFingerprintScanner::new().scan();
    }

    #[test]
    fn skips_empty_product_name() {
        let info = version_info::FileVersionInfo {
            product_name: String::new(),
            product_version: "1.0".to_string(),
            company_name: "Example".to_string(),
        };
        assert!(is_skippable(&info));
    }

    #[test]
    fn skips_empty_version() {
        let info = version_info::FileVersionInfo {
            product_name: "Example App".to_string(),
            product_version: "  ".to_string(),
            company_name: "Example".to_string(),
        };
        assert!(is_skippable(&info));
    }

    #[test]
    fn skips_microsoft_os_components() {
        let info = version_info::FileVersionInfo {
            product_name: "Microsoft\u{00ae} Windows\u{00ae} Operating System".to_string(),
            product_version: "10.0.19041.1".to_string(),
            company_name: "Microsoft Corporation".to_string(),
        };
        assert!(is_skippable(&info));
    }

    #[test]
    fn keeps_microsoft_applications() {
        // Microsoft Edge, Office, Teams etc. have real CVEs — never skip them.
        let info = version_info::FileVersionInfo {
            product_name: "Microsoft Edge".to_string(),
            product_version: "124.0.2478.51".to_string(),
            company_name: "Microsoft Corporation".to_string(),
        };
        assert!(!is_skippable(&info));
    }

    #[test]
    fn keeps_third_party_software() {
        let info = version_info::FileVersionInfo {
            product_name: "7-Zip".to_string(),
            product_version: "24.09".to_string(),
            company_name: "Igor Pavlov".to_string(),
        };
        assert!(!is_skippable(&info));
    }

    #[test]
    fn walker_respects_max_files_cap() {
        let tmp = std::env::temp_dir().join("evedoo_pe_walker_cap_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let cap = 5;
        for i in 0..(cap + 3) {
            let p = tmp.join(format!("fake{}.exe", i));
            fs::write(&p, vec![0u8; MIN_FILE_SIZE as usize]).unwrap();
        }

        let found = walk_exes(&tmp, 2, cap);
        assert!(
            found.len() <= cap,
            "walker must respect max_files cap: got {}",
            found.len()
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn walker_filters_by_extension_and_size() {
        let tmp = std::env::temp_dir().join("evedoo_pe_walker_filter_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // Too small — should be excluded
        fs::write(tmp.join("tiny.exe"), b"MZ").unwrap();
        // Not an exe — should be excluded
        fs::write(
            tmp.join("readme.txt"),
            vec![0u8; MIN_FILE_SIZE as usize],
        )
        .unwrap();
        // Right size + extension — should be included
        fs::write(
            tmp.join("ok.exe"),
            vec![0u8; (MIN_FILE_SIZE + 1) as usize],
        )
        .unwrap();

        let found = walk_exes(&tmp, 1, 100);
        let names: Vec<_> = found
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();

        assert!(names.contains(&"ok.exe"), "should include properly sized exe");
        assert!(!names.contains(&"tiny.exe"), "should exclude tiny exe");
        assert!(!names.contains(&"readme.txt"), "should exclude non-exe");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn walker_skips_updater_staging_directories() {
        let tmp = std::env::temp_dir().join("evedoo_pe_walker_updater_test");
        let _ = fs::remove_dir_all(&tmp);
        let payload = vec![0u8; MIN_FILE_SIZE as usize];

        // Updater/staging layouts that must be suppressed
        for sub in [
            "EdgeUpdate",
            "EdgeCore",
            "app/Installer",
            "Download/{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}",
        ] {
            let d = tmp.join(sub);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("staged.exe"), &payload).unwrap();
        }
        // A real application binary alongside them
        fs::create_dir_all(tmp.join("RealApp")).unwrap();
        fs::write(tmp.join("RealApp").join("app.exe"), &payload).unwrap();

        let found = walk_exes(&tmp, 4, 100);
        let names: Vec<_> = found
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();

        assert!(names.contains(&"app.exe"), "real app must be scanned");
        assert!(
            !names.contains(&"staged.exe"),
            "updater/staging binaries must be suppressed, got {:?}",
            found
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn updater_staging_dir_names() {
        for d in ["edgeupdate", "edgecore", "googleupdate", "googleupdater",
                  "installer", "temp", "updated", "mozilla maintenance service",
                  "{f3c4fe00-efd5-403b-9569-398a20f1ba4a}"] {
            assert!(is_updater_staging_dir(d), "{d} must be suppressed");
        }
        for d in ["application", "google", "microsoft", "bin", "150.0.4078.65"] {
            assert!(!is_updater_staging_dir(d), "{d} must be walked");
        }
    }

    #[test]
    fn known_library_display_maps_prefixes() {
        assert_eq!(
            known_library_display(Path::new(r"C:\app\libcrypto-3-x64.dll")),
            Some("OpenSSL")
        );
        assert_eq!(
            known_library_display(Path::new(r"C:\app\libssl-1_1.dll")),
            Some("OpenSSL")
        );
        assert_eq!(
            known_library_display(Path::new(r"C:\app\sqlite3.dll")),
            Some("SQLite")
        );
        assert_eq!(
            known_library_display(Path::new(r"C:\app\zlib1.dll")),
            Some("zlib")
        );
        assert_eq!(
            known_library_display(Path::new(r"C:\app\avcodec-60.dll")),
            Some("FFmpeg")
        );
        // Vendor-private DLLs are not fingerprinted.
        assert_eq!(known_library_display(Path::new(r"C:\app\vendor_app.dll")), None);
    }

    #[test]
    fn walker_includes_known_library_dlls_only() {
        let tmp = std::env::temp_dir().join("evedoo_pe_walker_dll_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let payload = vec![0u8; MIN_FILE_SIZE as usize];
        fs::write(tmp.join("libcrypto-3-x64.dll"), &payload).unwrap();
        fs::write(tmp.join("random_helper.dll"), &payload).unwrap();
        fs::write(tmp.join("app.exe"), &payload).unwrap();

        let found = walk_exes(&tmp, 1, 100);
        let names: Vec<_> = found
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();

        assert!(names.contains(&"libcrypto-3-x64.dll"), "known library DLL included");
        assert!(names.contains(&"app.exe"), "exe still included");
        assert!(
            !names.contains(&"random_helper.dll"),
            "vendor-private DLL excluded"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn walker_skips_system_directories() {
        let tmp = std::env::temp_dir().join("evedoo_pe_walker_skip_test");
        let _ = fs::remove_dir_all(&tmp);
        let sysdir = tmp.join("Windows");
        fs::create_dir_all(&sysdir).unwrap();

        // Place an exe inside a "Windows" subfolder
        fs::write(
            sysdir.join("system.exe"),
            vec![0u8; MIN_FILE_SIZE as usize],
        )
        .unwrap();
        // And one at the root level
        fs::write(
            tmp.join("app.exe"),
            vec![0u8; MIN_FILE_SIZE as usize],
        )
        .unwrap();

        let found = walk_exes(&tmp, 3, 100);
        let names: Vec<_> = found
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();

        assert!(names.contains(&"app.exe"), "should include root-level exe");
        assert!(
            !names.contains(&"system.exe"),
            "should skip exe inside Windows dir"
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
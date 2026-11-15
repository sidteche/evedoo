// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Mach-O 32/64-bit and Universal Fat binary parser and fingerprinter for macOS.
//!
//! Parses Mach-O binaries in pure Rust:
//! - Magic numbers: MH_MAGIC (0xFEEDFACE), MH_MAGIC_64 (0xFEEDFACF), FAT_MAGIC (0xCAFEBABE), FAT_MAGIC_64 (0xCAFEBABF)
//! - Load commands: LC_LOAD_DYLIB (0x0C), LC_ID_DYLIB (0x0D), LC_RPATH (0x8000001C)
//! - Identifies bundled third-party libraries (OpenSSL, cURL, SQLite, zlib, libxml2, etc.)
//! - Emits `macho://{path}` DetectedSoftware entries.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

// ── Magic Constants ─────────────────────────────────────────────────────────

pub const MH_MAGIC: u32 = 0xFEEDFACE;
pub const MH_CIGAM: u32 = 0xCEFAEDFE;
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;
pub const MH_CIGAM_64: u32 = 0xCFFAEDFE;

pub const FAT_MAGIC: u32 = 0xCAFEBABE;
pub const FAT_CIGAM: u32 = 0xBEBAFECA;
pub const FAT_MAGIC_64: u32 = 0xCAFEBABF;
pub const FAT_CIGAM_64: u32 = 0xBFBAFECA;

// ── Load Command Constants ──────────────────────────────────────────────────

pub const LC_LOAD_DYLIB: u32 = 0x0C;
pub const LC_ID_DYLIB: u32 = 0x0D;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x80000018;
pub const LC_RPATH: u32 = 0x8000001C;
pub const LC_REEXPORT_DYLIB: u32 = 0x8000001F;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000001D;

// ── Well-known vulnerable / tracked library dylibs ──────────────────────────

const KNOWN_LIBRARIES: &[(&str, &str)] = &[
    ("libcrypto", "OpenSSL"),
    ("libssl", "OpenSSL"),
    ("openssl", "OpenSSL"),
    ("sqlite3", "SQLite"),
    ("libsqlite3", "SQLite"),
    ("libcurl", "cURL"),
    ("curl", "cURL"),
    ("libz", "zlib"),
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

/// Known library lookup for display name mapping.
pub fn known_library_display(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let stem = Path::new(&lower)
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or(&lower);

    for &(prefix, display) in KNOWN_LIBRARIES {
        if stem.starts_with(prefix) || stem.contains(prefix) {
            return Some(display);
        }
    }
    None
}

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DylibReference {
    pub name: String,
    pub current_version: (u16, u8, u8), // major, minor, patch
    pub compatibility_version: (u16, u8, u8),
}

impl DylibReference {
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}",
            self.current_version.0, self.current_version.1, self.current_version.2
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachoInfo {
    pub is_64_bit: bool,
    pub cpu_type: i32,
    pub file_type: u32,
    pub id_dylib: Option<DylibReference>,
    pub loaded_dylibs: Vec<DylibReference>,
    pub rpaths: Vec<String>,
}

// ── Mach-O Parser ───────────────────────────────────────────────────────────

/// Parse a byte buffer containing a Mach-O 32-bit, 64-bit, or Universal Fat binary.
pub fn parse_macho(bytes: &[u8]) -> Option<Vec<MachoInfo>> {
    if bytes.len() < 4 {
        return None;
    }

    let magic = u32::from_be_bytes(bytes[0..4].try_into().ok()?);

    match magic {
        FAT_MAGIC | FAT_CIGAM => parse_fat_binary(bytes, false),
        FAT_MAGIC_64 | FAT_CIGAM_64 => parse_fat_binary(bytes, true),
        _ => parse_thin_macho(bytes),
    }
}

/// Parse a single-architecture Mach-O image. Fat headers are deliberately not
/// recognised here: a fat slice is always a thin image, and letting a slice be
/// another fat file would let a crafted file recurse until the stack overflows.
fn parse_thin_macho(bytes: &[u8]) -> Option<Vec<MachoInfo>> {
    if bytes.len() < 4 {
        return None;
    }

    let magic = u32::from_be_bytes(bytes[0..4].try_into().ok()?);

    match magic {
        MH_MAGIC => parse_single_macho(bytes, false, false).map(|info| vec![info]),
        MH_CIGAM => parse_single_macho(bytes, false, true).map(|info| vec![info]),
        MH_MAGIC_64 => parse_single_macho(bytes, true, false).map(|info| vec![info]),
        MH_CIGAM_64 => parse_single_macho(bytes, true, true).map(|info| vec![info]),
        _ => {
            // Also check host little-endian representation
            let magic_le = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
            match magic_le {
                MH_MAGIC => parse_single_macho(bytes, false, true).map(|info| vec![info]),
                MH_MAGIC_64 => parse_single_macho(bytes, true, true).map(|info| vec![info]),
                _ => None,
            }
        }
    }
}

fn parse_fat_binary(bytes: &[u8], is_64_bit_fat: bool) -> Option<Vec<MachoInfo>> {
    if bytes.len() < 8 {
        return None;
    }

    // Fat header is always Big Endian
    let nfat_arch = u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize;
    let mut results = Vec::new();

    let entry_size = if is_64_bit_fat { 32 } else { 20 };
    let header_size = 8;

    for i in 0..nfat_arch {
        let Some(entry) = i
            .checked_mul(entry_size)
            .and_then(|o| o.checked_add(header_size))
            .and_then(|o| sub_slice(bytes, o, entry_size))
        else {
            break;
        };

        // Offsets and sizes are file-controlled; convert without truncating
        // and never add them unchecked.
        let (offset, size) = if is_64_bit_fat {
            let off = u64::from_be_bytes(entry[8..16].try_into().ok()?);
            let sz = u64::from_be_bytes(entry[16..24].try_into().ok()?);
            (usize::try_from(off).ok(), usize::try_from(sz).ok())
        } else {
            let off = u32::from_be_bytes(entry[8..12].try_into().ok()?);
            let sz = u32::from_be_bytes(entry[12..16].try_into().ok()?);
            (usize::try_from(off).ok(), usize::try_from(sz).ok())
        };

        let slice = match (offset, size) {
            (Some(offset), Some(size)) => sub_slice(bytes, offset, size),
            _ => None,
        };
        if let Some(mut infos) = slice.and_then(parse_thin_macho) {
            results.append(&mut infos);
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// `bytes[offset..offset + len]`, or `None` when that range does not lie
/// entirely inside `bytes`.
fn sub_slice(bytes: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(len)?)
}

fn read_u32(bytes: &[u8], offset: usize, is_le: bool) -> Option<u32> {
    let slice: [u8; 4] = sub_slice(bytes, offset, 4)?.try_into().ok()?;
    Some(if is_le {
        u32::from_le_bytes(slice)
    } else {
        u32::from_be_bytes(slice)
    })
}

fn parse_single_macho(bytes: &[u8], is_64_bit: bool, is_le: bool) -> Option<MachoInfo> {
    let header_size = if is_64_bit { 32 } else { 28 };
    if bytes.len() < header_size {
        return None;
    }

    let cpu_type = read_u32(bytes, 4, is_le)? as i32;
    let file_type = read_u32(bytes, 12, is_le)?;
    let ncmds = read_u32(bytes, 16, is_le)? as usize;

    let mut id_dylib = None;
    let mut loaded_dylibs = Vec::new();
    let mut rpaths = Vec::new();

    let mut cursor = header_size;

    for _ in 0..ncmds {
        let (Some(cmd), Some(cmdsize)) = (
            read_u32(bytes, cursor, is_le),
            cursor.checked_add(4).and_then(|o| read_u32(bytes, o, is_le)),
        ) else {
            break;
        };
        let cmdsize = cmdsize as usize;

        if cmdsize < 8 {
            break;
        }
        let Some(cmd_bytes) = sub_slice(bytes, cursor, cmdsize) else {
            break;
        };

        match cmd {
            LC_ID_DYLIB => {
                if let Some(dylib) = parse_dylib_command(cmd_bytes, is_le) {
                    id_dylib = Some(dylib);
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                if let Some(dylib) = parse_dylib_command(cmd_bytes, is_le) {
                    loaded_dylibs.push(dylib);
                }
            }
            LC_RPATH => {
                if let Some(rpath) = parse_rpath_command(cmd_bytes, is_le) {
                    rpaths.push(rpath);
                }
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    Some(MachoInfo {
        is_64_bit,
        cpu_type,
        file_type,
        id_dylib,
        loaded_dylibs,
        rpaths,
    })
}

fn parse_dylib_command(cmd_bytes: &[u8], is_le: bool) -> Option<DylibReference> {
    if cmd_bytes.len() < 24 {
        return None;
    }

    let name_offset = read_u32(cmd_bytes, 8, is_le)? as usize;
    let current_version_raw = read_u32(cmd_bytes, 16, is_le)?;
    let compat_version_raw = read_u32(cmd_bytes, 20, is_le)?;

    let name = read_c_string(cmd_bytes, name_offset)?;

    let current_version = (
        (current_version_raw >> 16) as u16,
        ((current_version_raw >> 8) & 0xFF) as u8,
        (current_version_raw & 0xFF) as u8,
    );

    let compatibility_version = (
        (compat_version_raw >> 16) as u16,
        ((compat_version_raw >> 8) & 0xFF) as u8,
        (compat_version_raw & 0xFF) as u8,
    );

    Some(DylibReference {
        name,
        current_version,
        compatibility_version,
    })
}

fn parse_rpath_command(cmd_bytes: &[u8], is_le: bool) -> Option<String> {
    if cmd_bytes.len() < 12 {
        return None;
    }
    let path_offset = read_u32(cmd_bytes, 8, is_le)? as usize;
    read_c_string(cmd_bytes, path_offset)
}

fn read_c_string(bytes: &[u8], offset: usize) -> Option<String> {
    if offset >= bytes.len() {
        return None;
    }
    let slice = &bytes[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8(slice[..end].to_vec()).ok()
}

// ── Scanner Implementation ──────────────────────────────────────────────────

/// Fingerprint scanner for Mach-O binaries and bundled libraries.
pub struct MachoFingerprintScanner {
    custom_roots: Vec<PathBuf>,
}

impl MachoFingerprintScanner {
    pub fn new() -> Self {
        Self {
            custom_roots: Vec::new(),
        }
    }

    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { custom_roots: roots }
    }

    /// Default scan roots for Mach-O binaries on macOS.
    pub fn default_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for dir in &["/Applications", "/usr/local/lib", "/opt/homebrew/lib", "/Library/Frameworks"] {
            let p = PathBuf::from(dir);
            if p.is_dir() {
                roots.push(p);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let user_apps = PathBuf::from(home).join("Applications");
            if user_apps.is_dir() {
                roots.push(user_apps);
            }
        }
        roots
    }

    /// Scan directory roots for Mach-O binaries.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let roots = if !self.custom_roots.is_empty() {
            self.custom_roots.clone()
        } else {
            Self::default_roots()
        };

        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for root in roots {
            if !root.is_dir() {
                continue;
            }
            debug!("Mach-O scanner: walking {}", root.display());
            let files = walk_macho_files(&root, 5, 10_000);
            for file_path in files {
                if let Ok(bytes) = fs::read(&file_path) {
                    if let Some(infos) = parse_macho(&bytes) {
                        for info in infos {
                            // 1. Check ID dylib (is this file itself a known library?)
                            if let Some(ref id_lib) = info.id_dylib {
                                if let Some(canonical_name) = known_library_display(&id_lib.name) {
                                    let ver = id_lib.version_string();
                                    let registry_key = format!("macho://{}", file_path.display());
                                    if seen.insert((canonical_name.to_string(), ver.clone())) {
                                        results.push(DetectedSoftware {
                                            name: canonical_name.to_string(),
                                            version: Some(ver),
                                            publisher: None,
                                            install_location: Some(file_path.to_string_lossy().to_string()),
                                            install_date: None,
                                            registry_key,
                                            architecture: if info.is_64_bit {
                                                Architecture::X64
                                            } else {
                                                Architecture::X86
                                            },
                                        });
                                    }
                                }
                            }

                            // 2. Check loaded dylibs (bundled libraries inside application framework/bundle)
                            for loaded in &info.loaded_dylibs {
                                if let Some(canonical_name) = known_library_display(&loaded.name) {
                                    let ver = loaded.version_string();
                                    if ver != "0.0.0" {
                                        let registry_key = format!("macho://{}:{}", file_path.display(), loaded.name);
                                        if seen.insert((canonical_name.to_string(), ver.clone())) {
                                            results.push(DetectedSoftware {
                                                name: canonical_name.to_string(),
                                                version: Some(ver),
                                                publisher: None,
                                                install_location: Some(file_path.to_string_lossy().to_string()),
                                                install_date: None,
                                                registry_key,
                                                architecture: if info.is_64_bit {
                                                    Architecture::X64
                                                } else {
                                                    Architecture::X86
                                                },
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        debug!("Mach-O scanner: found {} fingerprinted libraries", results.len());
        results
    }
}

impl Default for MachoFingerprintScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded walker finding `.dylib`, `.so`, and executable binaries.
pub fn walk_macho_files(root: &Path, max_depth: usize, max_files: usize) -> Vec<PathBuf> {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let mut results: Vec<PathBuf> = Vec::new();

    while let Some((dir, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            if results.len() >= max_files {
                break;
            }

            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
                continue;
            }

            if file_type.is_file() {
                let ext = path.extension().and_then(OsStr::to_str).unwrap_or("");
                let is_macho_candidate = ext.eq_ignore_ascii_case("dylib")
                    || ext.eq_ignore_ascii_case("so")
                    || ext.eq_ignore_ascii_case("bundle")
                    || ext.is_empty()
                    || path.to_string_lossy().contains("/MacOS/")
                    || path.to_string_lossy().contains("/Frameworks/");

                if is_macho_candidate {
                    results.push(path);
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_64bit_macho_dylib() {
        // Construct a synthetic Mach-O 64-bit binary with LC_ID_DYLIB and LC_LOAD_DYLIB
        let mut data = Vec::new();
        // Mach-O 64-bit header (32 bytes)
        data.extend_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic
        data.extend_from_slice(&0x01000007i32.to_le_bytes()); // CPU_TYPE_X86_64
        data.extend_from_slice(&3i32.to_le_bytes()); // CPU_SUBTYPE
        data.extend_from_slice(&6u32.to_le_bytes()); // MH_DYLIB
        data.extend_from_slice(&2u32.to_le_bytes()); // ncmds = 2
        data.extend_from_slice(&128u32.to_le_bytes()); // sizeofcmds
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // Command 1: LC_ID_DYLIB
        let id_name = b"/usr/lib/libcrypto.dylib\0";
        let id_cmd_size = 24 + id_name.len() + (4 - (id_name.len() % 4)) % 4;
        data.extend_from_slice(&LC_ID_DYLIB.to_le_bytes());
        data.extend_from_slice(&(id_cmd_size as u32).to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes()); // name offset
        data.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        data.extend_from_slice(&0x00030002u32.to_le_bytes()); // current_version = 3.0.2
        data.extend_from_slice(&0x00030000u32.to_le_bytes()); // compat_version = 3.0.0
        data.extend_from_slice(id_name);
        while data.len() % 4 != 0 {
            data.push(0);
        }

        // Command 2: LC_LOAD_DYLIB for libssl.dylib
        let ssl_name = b"/usr/lib/libssl.dylib\0";
        let ssl_cmd_size = 24 + ssl_name.len() + (4 - (ssl_name.len() % 4)) % 4;
        data.extend_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
        data.extend_from_slice(&(ssl_cmd_size as u32).to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes()); // name offset
        data.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        data.extend_from_slice(&0x00030002u32.to_le_bytes()); // current_version = 3.0.2
        data.extend_from_slice(&0x00030000u32.to_le_bytes()); // compat_version = 3.0.0
        data.extend_from_slice(ssl_name);
        while data.len() % 4 != 0 {
            data.push(0);
        }

        let parsed = parse_macho(&data).unwrap();
        assert_eq!(parsed.len(), 1);
        let info = &parsed[0];
        assert!(info.is_64_bit);

        let id_lib = info.id_dylib.as_ref().unwrap();
        assert_eq!(id_lib.name, "/usr/lib/libcrypto.dylib");
        assert_eq!(id_lib.version_string(), "3.0.2");

        assert_eq!(info.loaded_dylibs.len(), 1);
        assert_eq!(info.loaded_dylibs[0].name, "/usr/lib/libssl.dylib");
        assert_eq!(info.loaded_dylibs[0].version_string(), "3.0.2");
    }

    /// fat_arch_64 offsets and sizes are attacker-controlled u64 values whose
    /// sum must not wrap around and pass the bounds check.
    #[test]
    fn fat64_slice_with_wrapping_offset_does_not_panic() {
        let mut fat = Vec::new();
        fat.extend_from_slice(&FAT_MAGIC_64.to_be_bytes());
        fat.extend_from_slice(&1u32.to_be_bytes());
        fat.extend_from_slice(&0x01000007i32.to_be_bytes()); // cputype
        fat.extend_from_slice(&3i32.to_be_bytes()); // cpusubtype
        fat.extend_from_slice(&u64::MAX.to_be_bytes()); // offset
        fat.extend_from_slice(&2u64.to_be_bytes()); // size: offset + size wraps to 1
        fat.extend_from_slice(&0u32.to_be_bytes()); // align
        fat.extend_from_slice(&0u32.to_be_bytes()); // reserved
        assert_eq!(parse_macho(&fat), None);
    }

    /// A fat slice that is itself the whole fat file must not recurse forever.
    #[test]
    fn fat_binary_containing_itself_does_not_recurse_forever() {
        let mut fat = Vec::new();
        fat.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        fat.extend_from_slice(&1u32.to_be_bytes());
        fat.extend_from_slice(&0x01000007i32.to_be_bytes());
        fat.extend_from_slice(&3i32.to_be_bytes());
        fat.extend_from_slice(&0u32.to_be_bytes()); // offset = 0: the slice is this file
        fat.extend_from_slice(&28u32.to_be_bytes()); // size = whole file
        fat.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(fat.len(), 28);
        assert_eq!(parse_macho(&fat), None);
    }

    /// Deterministic robustness sweep over a thin Mach-O with load commands and
    /// a fat wrapper: the parser may reject the input; it may not panic.
    #[test]
    fn truncated_and_mutated_input_never_panics() {
        let name = b"/usr/lib/libssl.3.dylib\0";
        let cmdsize = (24 + name.len() + 7) & !7;
        let mut thin = Vec::new();
        thin.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        thin.extend_from_slice(&0x01000007i32.to_le_bytes());
        thin.extend_from_slice(&3i32.to_le_bytes());
        thin.extend_from_slice(&6u32.to_le_bytes());
        thin.extend_from_slice(&2u32.to_le_bytes()); // ncmds
        thin.extend_from_slice(&((cmdsize * 2) as u32).to_le_bytes());
        thin.extend_from_slice(&0u32.to_le_bytes());
        thin.extend_from_slice(&0u32.to_le_bytes());
        for cmd in [LC_ID_DYLIB, LC_LOAD_DYLIB] {
            let start = thin.len();
            thin.extend_from_slice(&cmd.to_le_bytes());
            thin.extend_from_slice(&(cmdsize as u32).to_le_bytes());
            thin.extend_from_slice(&24u32.to_le_bytes()); // name offset
            thin.extend_from_slice(&0u32.to_le_bytes()); // timestamp
            thin.extend_from_slice(&0x0003_0000u32.to_le_bytes());
            thin.extend_from_slice(&0x0003_0000u32.to_le_bytes());
            thin.extend_from_slice(name);
            thin.resize(start + cmdsize, 0);
        }
        assert_eq!(parse_macho(&thin).unwrap()[0].loaded_dylibs.len(), 1);

        let mut fat = Vec::new();
        fat.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        fat.extend_from_slice(&1u32.to_be_bytes());
        fat.extend_from_slice(&0x01000007i32.to_be_bytes());
        fat.extend_from_slice(&3i32.to_be_bytes());
        fat.extend_from_slice(&28u32.to_be_bytes());
        fat.extend_from_slice(&(thin.len() as u32).to_be_bytes());
        fat.extend_from_slice(&12u32.to_be_bytes());
        fat.extend_from_slice(&thin);

        for base in [&thin, &fat] {
            for len in 0..=base.len() {
                let _ = parse_macho(&base[..len]);
            }
            for i in 0..base.len() {
                for b in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                    let mut m = base.to_vec();
                    m[i] = b;
                    let _ = parse_macho(&m);
                }
            }
            // every aligned 4-byte field forced to the extremes
            for i in (0..base.len().saturating_sub(3)).step_by(4) {
                for v in [u32::MAX, u32::MAX - 7, 0x8000_0000] {
                    let mut m = base.to_vec();
                    m[i..i + 4].copy_from_slice(&v.to_le_bytes());
                    let _ = parse_macho(&m);
                    m[i..i + 4].copy_from_slice(&v.to_be_bytes());
                    let _ = parse_macho(&m);
                }
            }
        }
    }

    #[test]
    fn parses_universal_fat_binary() {
        // Construct a Universal Fat binary wrapping 64-bit Mach-O slice
        let mut slice_data = Vec::new();
        slice_data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        slice_data.extend_from_slice(&0x01000007i32.to_le_bytes());
        slice_data.extend_from_slice(&3i32.to_le_bytes());
        slice_data.extend_from_slice(&6u32.to_le_bytes());
        slice_data.extend_from_slice(&0u32.to_le_bytes()); // ncmds = 0
        slice_data.extend_from_slice(&0u32.to_le_bytes());
        slice_data.extend_from_slice(&0u32.to_le_bytes());
        slice_data.extend_from_slice(&0u32.to_le_bytes());

        let mut fat_data = Vec::new();
        fat_data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        fat_data.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch = 1

        // fat_arch 1 (20 bytes)
        fat_data.extend_from_slice(&0x01000007i32.to_be_bytes()); // cputype
        fat_data.extend_from_slice(&3i32.to_be_bytes()); // cpusubtype
        fat_data.extend_from_slice(&28u32.to_be_bytes()); // offset = 28
        fat_data.extend_from_slice(&(slice_data.len() as u32).to_be_bytes()); // size
        fat_data.extend_from_slice(&12u32.to_be_bytes()); // align

        fat_data.extend_from_slice(&slice_data);

        let parsed = parse_macho(&fat_data).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_64_bit);
    }

    #[test]
    fn maps_known_libraries() {
        assert_eq!(known_library_display("libcrypto.3.dylib"), Some("OpenSSL"));
        assert_eq!(known_library_display("/usr/local/lib/libssl.dylib"), Some("OpenSSL"));
        assert_eq!(known_library_display("libsqlite3.0.dylib"), Some("SQLite"));
        assert_eq!(known_library_display("libcurl.4.dylib"), Some("cURL"));
        assert_eq!(known_library_display("libz.1.dylib"), Some("zlib"));
        assert_eq!(known_library_display("libavcodec.60.dylib"), Some("FFmpeg"));
        assert_eq!(known_library_display("libcustom_app.dylib"), None);
    }

    #[test]
    fn test_macho_fingerprint_scanner_with_roots() {
        let tmp = std::env::temp_dir().join("evedoo_macho_scan_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // Write a synthetic dylib
        let mut data = Vec::new();
        data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        data.extend_from_slice(&0x01000007i32.to_le_bytes());
        data.extend_from_slice(&3i32.to_le_bytes());
        data.extend_from_slice(&6u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // ncmds = 1
        data.extend_from_slice(&56u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let id_name = b"libcrypto.dylib\0";
        let id_cmd_size = 24 + id_name.len() + (4 - (id_name.len() % 4)) % 4;
        data.extend_from_slice(&LC_ID_DYLIB.to_le_bytes());
        data.extend_from_slice(&(id_cmd_size as u32).to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x00030000u32.to_le_bytes()); // 3.0.0
        data.extend_from_slice(&0x00030000u32.to_le_bytes());
        data.extend_from_slice(id_name);
        while data.len() % 4 != 0 {
            data.push(0);
        }

        fs::write(tmp.join("libcrypto.dylib"), &data).unwrap();

        let scanner = MachoFingerprintScanner::with_roots(vec![tmp.clone()]);
        let results = scanner.scan();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "OpenSSL");
        assert_eq!(results[0].version.as_deref(), Some("3.0.0"));
        assert_eq!(results[0].architecture, Architecture::X64);

        let _ = fs::remove_dir_all(&tmp);
    }
}

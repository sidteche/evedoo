// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Pure Rust 32-bit and 64-bit ELF Header & Dynamic Section Fingerprinter.
//!
//! Inspects ELF binaries (`\x7fELF`) for dynamic tags (`DT_SONAME`, `DT_NEEDED`),
//! identifies bundled vulnerable shared libraries (`libssl.so`, `libcrypto.so`,
//! `libcurl.so`, `libsqlite3.so`, `libxml2.so`), and extracts versions from
//! SONAME metadata and `.rodata` banners.
//!
//! Emits `DetectedSoftware` entries with `elf://{path}` registry keys.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

const MAX_DEPTH: usize = 3;
const MAX_FILES_PER_ROOT: usize = 2000;
const MIN_FILE_SIZE: u64 = 512;
const MAX_FILE_SIZE: u64 = 300 * 1024 * 1024;

/// Well-known libraries to identify from ELF headers and filenames.
const KNOWN_ELF_LIBRARIES: &[(&str, &str)] = &[
    ("libcrypto.so", "OpenSSL"),
    ("libssl.so", "OpenSSL"),
    ("libcurl.so", "cURL"),
    ("libsqlite3.so", "SQLite"),
    ("libxml2.so", "libxml2"),
    ("libz.so", "zlib"),
    ("libpng", "libpng"),
    ("libjpeg.so", "libjpeg-turbo"),
    ("libturbojpeg.so", "libjpeg-turbo"),
    ("libfreetype.so", "FreeType"),
    ("libavcodec.so", "FFmpeg"),
    ("libavformat.so", "FFmpeg"),
    ("libavutil.so", "FFmpeg"),
];

#[allow(dead_code)]
pub struct ElfFingerprintScanner {
    roots: Vec<PathBuf>,
}

#[allow(dead_code)]
impl ElfFingerprintScanner {
    pub fn new() -> Self {
        Self {
            roots: vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/local/lib"),
                PathBuf::from("/opt"),
            ],
        }
    }

    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

    /// Scan ELF files under configured root directories.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let mut results = Vec::new();
        let mut seen_keys: HashSet<String> = HashSet::new();

        for root in &self.roots {
            if !root.exists() || !root.is_dir() {
                continue;
            }
            debug!("ELF fingerprint: walking {:?}", root);
            let elfs = walk_elf_files(root, MAX_DEPTH, MAX_FILES_PER_ROOT);
            for elf_path in elfs {
                if let Some(softwares) = scan_elf_file(&elf_path) {
                    for sw in softwares {
                        if seen_keys.insert(sw.registry_key.clone()) {
                            results.push(sw);
                        }
                    }
                }
            }
        }

        results
    }
}

impl Default for ElfFingerprintScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn walk_elf_files(root: &Path, max_depth: usize, max_files: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut queue: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, depth)) = queue.pop() {
        if files.len() >= max_files || depth > max_depth {
            continue;
        }

        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            if files.len() >= max_files {
                break;
            }

            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                if depth < max_depth {
                    queue.push((path, depth + 1));
                }
            } else if file_type.is_file() {
                if let Ok(meta) = entry.metadata() {
                    let len = meta.len();
                    if (MIN_FILE_SIZE..=MAX_FILE_SIZE).contains(&len) {
                        // Check for ELF magic \x7fELF
                        if is_elf_file(&path) {
                            files.push(path);
                        }
                    }
                }
            }
        }
    }

    files
}

fn is_elf_file(path: &Path) -> bool {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == [0x7F, b'E', b'L', b'F']
}

/// Scan a single ELF binary on disk.
pub fn scan_elf_file(path: &Path) -> Option<Vec<DetectedSoftware>> {
    let bytes = fs::read(path).ok()?;
    parse_elf_bytes(&bytes, path)
}

/// Information parsed from an ELF binary.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ElfInfo {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub architecture: Architecture,
    pub soname: Option<String>,
    pub needed: Vec<String>,
}

/// Pure Rust parser for 32-bit and 64-bit ELF binaries.
pub fn parse_elf_bytes(bytes: &[u8], file_path: &Path) -> Option<Vec<DetectedSoftware>> {
    if bytes.len() < 52 {
        return None;
    }

    // 1. Verify Magic \x7fELF
    if bytes[0..4] != [0x7F, b'E', b'L', b'F'] {
        return None;
    }

    let is_64bit = bytes[4] == 2;
    let is_little_endian = bytes[5] == 1;

    let read_u16 = |offset: usize| -> Option<u16> {
        let arr: [u8; 2] = sub_slice(bytes, offset, 2)?.try_into().ok()?;
        Some(if is_little_endian {
            u16::from_le_bytes(arr)
        } else {
            u16::from_be_bytes(arr)
        })
    };

    let read_u32 = |offset: usize| -> Option<u32> {
        let arr: [u8; 4] = sub_slice(bytes, offset, 4)?.try_into().ok()?;
        Some(if is_little_endian {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    };

    let read_u64 = |offset: usize| -> Option<u64> {
        let arr: [u8; 8] = sub_slice(bytes, offset, 8)?.try_into().ok()?;
        Some(if is_little_endian {
            u64::from_le_bytes(arr)
        } else {
            u64::from_be_bytes(arr)
        })
    };

    let e_machine = read_u16(0x12)?;
    let architecture = match e_machine {
        62 => Architecture::X64, // EM_X86_64
        3 => Architecture::X86,  // EM_386
        _ => Architecture::Unknown,
    };

    let mut elf_info = ElfInfo {
        is_64bit,
        is_little_endian,
        architecture,
        soname: None,
        needed: Vec::new(),
    };

    // 2. Parse Section Headers to locate .dynstr and .dynamic
    let (shoff, shentsize, shnum, shstrndx) = if is_64bit {
        if bytes.len() < 64 {
            return None;
        }
        let shoff = read_u64(0x28)? as usize;
        let shentsize = read_u16(0x3A)? as usize;
        let shnum = read_u16(0x3C)? as usize;
        let shstrndx = read_u16(0x3E)? as usize;
        (shoff, shentsize, shnum, shstrndx)
    } else {
        let shoff = read_u32(0x20)? as usize;
        let shentsize = read_u16(0x2E)? as usize;
        let shnum = read_u16(0x30)? as usize;
        let shstrndx = read_u16(0x32)? as usize;
        (shoff, shentsize, shnum, shstrndx)
    };

    // Parse section table if valid
    if shentsize > 0 && shnum > 0 && sub_slice(bytes, shoff, shentsize.saturating_mul(shnum)).is_some() {
        let mut dynstr_offset = 0usize;
        let mut dynstr_size = 0usize;
        let mut dynamic_offset = 0usize;
        let mut dynamic_size = 0usize;
        let mut dynamic_link = 0usize;

        // Get section header string table
        let mut shstrtab_offset = 0usize;
        if shstrndx < shnum {
            let shstr_entry = shoff.saturating_add(shstrndx.saturating_mul(shentsize));
            shstrtab_offset = if is_64bit {
                read_u64(shstr_entry.saturating_add(0x18)).unwrap_or(0) as usize
            } else {
                read_u32(shstr_entry.saturating_add(0x10)).unwrap_or(0) as usize
            };
        }

        for i in 0..shnum {
            let entry = shoff.saturating_add(i.saturating_mul(shentsize));
            let sh_type = read_u32(entry.saturating_add(0x04)).unwrap_or(0);
            let sh_offset = if is_64bit {
                read_u64(entry.saturating_add(0x18)).unwrap_or(0) as usize
            } else {
                read_u32(entry.saturating_add(0x10)).unwrap_or(0) as usize
            };
            let sh_size = if is_64bit {
                read_u64(entry.saturating_add(0x20)).unwrap_or(0) as usize
            } else {
                read_u32(entry.saturating_add(0x14)).unwrap_or(0) as usize
            };
            let sh_link = read_u32(entry.saturating_add(if is_64bit { 0x28 } else { 0x18 })).unwrap_or(0) as usize;

            let sh_name_idx = read_u32(entry).unwrap_or(0) as usize;
            let sh_name = match shstrtab_offset.checked_add(sh_name_idx).and_then(|o| bytes.get(o..)) {
                Some(name) if shstrtab_offset > 0 && !name.is_empty() => read_c_string(name),
                _ => String::new(),
            };

            if sh_type == 6 || sh_name == ".dynamic" {
                dynamic_offset = sh_offset;
                dynamic_size = sh_size;
                dynamic_link = sh_link;
            } else if sh_type == 3 && (sh_name == ".dynstr" || i == dynamic_link) {
                dynstr_offset = sh_offset;
                dynstr_size = sh_size;
            }
        }

        // If dynamic_link points to dynstr, resolve dynstr_offset
        if dynstr_offset == 0 && dynamic_link < shnum {
            let link_entry = shoff.saturating_add(dynamic_link.saturating_mul(shentsize));
            dynstr_offset = if is_64bit {
                read_u64(link_entry.saturating_add(0x18)).unwrap_or(0) as usize
            } else {
                read_u32(link_entry.saturating_add(0x10)).unwrap_or(0) as usize
            };
            dynstr_size = if is_64bit {
                read_u64(link_entry.saturating_add(0x20)).unwrap_or(0) as usize
            } else {
                read_u32(link_entry.saturating_add(0x14)).unwrap_or(0) as usize
            };
        }

        // Parse dynamic section
        // Offsets and sizes come straight from the file. A section that does
        // not lie inside it is ignored; a string table that starts inside the
        // file but claims to run past its end is clamped to the file.
        if dynamic_offset > 0 && dynstr_offset > 0 {
            let dyn_data = sub_slice(bytes, dynamic_offset, dynamic_size);
            let str_data = sub_slice(bytes, dynstr_offset, dynstr_size).or_else(|| bytes.get(dynstr_offset..));
            if let (Some(dyn_data), Some(str_data)) = (dyn_data, str_data) {
                parse_dynamic_tags(dyn_data, str_data, is_64bit, is_little_endian, &mut elf_info);
            }
        }
    }

    // 3. Fallback: Parse Program Headers for PT_DYNAMIC if section headers were missing
    if elf_info.soname.is_none() && elf_info.needed.is_empty() {
        let (phoff, phentsize, phnum) = if is_64bit {
            let phoff = read_u64(0x20)? as usize;
            let phentsize = read_u16(0x36)? as usize;
            let phnum = read_u16(0x38)? as usize;
            (phoff, phentsize, phnum)
        } else {
            let phoff = read_u32(0x1C)? as usize;
            let phentsize = read_u16(0x2A)? as usize;
            let phnum = read_u16(0x2C)? as usize;
            (phoff, phentsize, phnum)
        };

        if phentsize > 0 && phnum > 0 && sub_slice(bytes, phoff, phentsize.saturating_mul(phnum)).is_some() {
            for i in 0..phnum {
                let entry = phoff.saturating_add(i.saturating_mul(phentsize));
                let p_type = read_u32(entry).unwrap_or(0);
                if p_type == 2 {
                    // PT_DYNAMIC = 2
                    let p_offset = if is_64bit {
                        read_u64(entry.saturating_add(0x08)).unwrap_or(0) as usize
                    } else {
                        read_u32(entry.saturating_add(0x04)).unwrap_or(0) as usize
                    };
                    let p_filesz = if is_64bit {
                        read_u64(entry.saturating_add(0x20)).unwrap_or(0) as usize
                    } else {
                        read_u32(entry.saturating_add(0x10)).unwrap_or(0) as usize
                    };
                    if let Some(dyn_data) = sub_slice(bytes, p_offset, p_filesz).filter(|_| p_offset > 0) {
                        // Scan for strings in raw file if dynstr not isolated
                        parse_dynamic_tags(dyn_data, bytes, is_64bit, is_little_endian, &mut elf_info);
                    }
                }
            }
        }
    }

    // 4. Generate DetectedSoftware findings
    let mut softwares = Vec::new();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();

    // Check if the binary itself is a known library
    if let Some(canonical_name) = match_known_library(&filename, elf_info.soname.as_deref()) {
        let version = extract_library_version(&filename, elf_info.soname.as_deref(), bytes);
        softwares.push(DetectedSoftware {
            name: canonical_name.to_string(),
            version,
            publisher: Some("ELF".to_string()),
            install_location: Some(file_path.to_string_lossy().to_string()),
            install_date: None,
            registry_key: format!("elf://{}", file_path.to_string_lossy()),
            architecture: elf_info.architecture,
        });
    }

    // Check bundled DT_NEEDED libraries
    for needed_lib in &elf_info.needed {
        if let Some(canonical_name) = match_known_library(needed_lib, None) {
            let version = extract_version_from_soname(needed_lib);
            softwares.push(DetectedSoftware {
                name: canonical_name.to_string(),
                version,
                publisher: Some("ELF-needed".to_string()),
                install_location: Some(file_path.to_string_lossy().to_string()),
                install_date: None,
                registry_key: format!("elf://{}:needed:{}", file_path.to_string_lossy(), needed_lib),
                architecture: elf_info.architecture,
            });
        }
    }

    if softwares.is_empty() {
        // Fallback: emit generic ELF binary entry
        let version = extract_banner_version(bytes);
        softwares.push(DetectedSoftware {
            name: filename.clone(),
            version,
            publisher: Some("ELF".to_string()),
            install_location: Some(file_path.to_string_lossy().to_string()),
            install_date: None,
            registry_key: format!("elf://{}", file_path.to_string_lossy()),
            architecture: elf_info.architecture,
        });
    }

    Some(softwares)
}

fn parse_dynamic_tags(
    dyn_bytes: &[u8],
    str_table: &[u8],
    is_64bit: bool,
    is_little_endian: bool,
    elf_info: &mut ElfInfo,
) {
    let entry_size = if is_64bit { 16 } else { 8 };
    let num_entries = dyn_bytes.len() / entry_size;

    for i in 0..num_entries {
        let off = i * entry_size;
        let (d_tag, d_val) = if is_64bit {
            let (Some(tag), Some(val)) = (sub_slice(dyn_bytes, off, 8), sub_slice(dyn_bytes, off + 8, 8)) else {
                break;
            };
            let arr_tag: [u8; 8] = tag.try_into().unwrap_or_default();
            let arr_val: [u8; 8] = val.try_into().unwrap_or_default();
            let tag = if is_little_endian { u64::from_le_bytes(arr_tag) } else { u64::from_be_bytes(arr_tag) };
            let val = if is_little_endian { u64::from_le_bytes(arr_val) } else { u64::from_be_bytes(arr_val) };
            (tag, val as usize)
        } else {
            let (Some(tag), Some(val)) = (sub_slice(dyn_bytes, off, 4), sub_slice(dyn_bytes, off + 4, 4)) else {
                break;
            };
            let arr_tag: [u8; 4] = tag.try_into().unwrap_or_default();
            let arr_val: [u8; 4] = val.try_into().unwrap_or_default();
            let tag = if is_little_endian { u32::from_le_bytes(arr_tag) } else { u32::from_be_bytes(arr_tag) };
            let val = if is_little_endian { u32::from_le_bytes(arr_val) } else { u32::from_be_bytes(arr_val) };
            (tag as u64, val as usize)
        };

        if d_tag == 0 {
            // DT_NULL = 0
            break;
        } else if d_tag == 14 {
            // DT_SONAME = 14
            if let Some(tail) = str_table.get(d_val..).filter(|t| !t.is_empty()) {
                let name = read_c_string(tail);
                if !name.is_empty() {
                    elf_info.soname = Some(name);
                }
            }
        } else if d_tag == 1 {
            // DT_NEEDED = 1
            if let Some(tail) = str_table.get(d_val..).filter(|t| !t.is_empty()) {
                let needed = read_c_string(tail);
                if !needed.is_empty() {
                    elf_info.needed.push(needed);
                }
            }
        }
    }
}

/// `bytes[offset..offset + len]`, or `None` when that range does not lie
/// entirely inside `bytes`. Every offset and size in an ELF file is
/// attacker-controlled, so the sum must be checked before it is used.
fn sub_slice(bytes: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(len)?)
}

fn read_c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn match_known_library(filename: &str, soname: Option<&str>) -> Option<&'static str> {
    let f_lower = filename.to_ascii_lowercase();
    for (prefix, display_name) in KNOWN_ELF_LIBRARIES {
        if f_lower.contains(prefix) {
            return Some(*display_name);
        }
    }
    if let Some(s) = soname {
        let s_lower = s.to_ascii_lowercase();
        for (prefix, display_name) in KNOWN_ELF_LIBRARIES {
            if s_lower.contains(prefix) {
                return Some(*display_name);
            }
        }
    }
    None
}

fn extract_library_version(filename: &str, soname: Option<&str>, binary_bytes: &[u8]) -> Option<String> {
    // 1. Try embedded version banners in .rodata / string pool
    if let Some(ver) = extract_banner_version(binary_bytes) {
        return Some(ver);
    }

    // 2. Try SONAME version (e.g. libssl.so.3, libcurl.so.4.8.0)
    if let Some(s) = soname {
        if let Some(ver) = extract_version_from_soname(s) {
            return Some(ver);
        }
    }

    // 3. Try filename version (e.g. libcrypto.so.1.1.1w)
    extract_version_from_soname(filename)
}

fn extract_version_from_soname(name: &str) -> Option<String> {
    if let Some(idx) = name.find(".so.") {
        let ver = &name[idx + 4..];
        if !ver.is_empty() && ver.chars().next().unwrap().is_ascii_digit() {
            return Some(ver.to_string());
        }
    }
    None
}

fn extract_banner_version(bytes: &[u8]) -> Option<String> {
    // Look for OpenSSL banner: "OpenSSL 3.0.7 " or "OpenSSL 1.1.1w "
    if let Some(pos) = find_subsequence(bytes, b"OpenSSL ") {
        let rest = &bytes[pos + 8..];
        let ver_str: String = rest
            .iter()
            .take(20)
            .take_while(|&&b| b != b' ' && b != b'\0' && b != b'\n' && b.is_ascii_graphic())
            .map(|&b| b as char)
            .collect();
        if !ver_str.is_empty() && ver_str.chars().next().unwrap().is_ascii_digit() {
            return Some(ver_str);
        }
    }

    // Look for cURL banner: "curl 7.88.1" or "libcurl/7.88.1"
    if let Some(pos) = find_subsequence(bytes, b"libcurl/") {
        let rest = &bytes[pos + 8..];
        let ver_str: String = rest
            .iter()
            .take(15)
            .take_while(|&&b| b != b' ' && b != b'\0' && b != b'\n' && (b.is_ascii_digit() || b == b'.'))
            .map(|&b| b as char)
            .collect();
        if !ver_str.is_empty() && ver_str.chars().next().unwrap().is_ascii_digit() {
            return Some(ver_str);
        }
    }

    // Look for SQLite banner: "SQLite 3."
    if let Some(pos) = find_subsequence(bytes, b"SQLite 3.") {
        let rest = &bytes[pos + 7..];
        let ver_str: String = rest
            .iter()
            .take(15)
            .take_while(|&&b| (b.is_ascii_digit() || b == b'.') && b != b'\0')
            .map(|&b| b as char)
            .collect();
        if !ver_str.is_empty() {
            return Some(format!("3.{}", ver_str));
        }
    }

    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a valid minimal 64-bit Little-Endian ELF binary with SONAME in .dynamic
    fn make_test_elf64(soname: &str, needed: &[&str], banner: Option<&str>) -> Vec<u8> {
        let mut elf = vec![0u8; 512];
        // 1. ELF Header
        elf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        elf[4] = 2; // 64-bit
        elf[5] = 1; // Little endian
        elf[6] = 1; // ELF version
        elf[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64

        // Section header info: shoff = 64, shentsize = 64, shnum = 4, shstrndx = 1
        elf[0x28..0x30].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        elf[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        elf[0x3C..0x3E].copy_from_slice(&4u16.to_le_bytes());  // e_shnum
        elf[0x3E..0x40].copy_from_slice(&1u16.to_le_bytes());  // e_shstrndx

        // Strings section at offset 320
        let strtab_offset = 320usize;
        let mut str_table = vec![0u8]; // Leading null byte

        // Section names
        let shstr_dynstr = str_table.len();
        str_table.extend_from_slice(b".dynstr\0");
        let shstr_dynamic = str_table.len();
        str_table.extend_from_slice(b".dynamic\0");

        // SONAME
        let soname_idx = str_table.len();
        str_table.extend_from_slice(soname.as_bytes());
        str_table.push(0);

        // DT_NEEDED entries
        let mut needed_indices = Vec::new();
        for n in needed {
            let idx = str_table.len();
            str_table.extend_from_slice(n.as_bytes());
            str_table.push(0);
            needed_indices.push(idx);
        }

        // Write strtab to elf
        elf[strtab_offset..strtab_offset + str_table.len()].copy_from_slice(&str_table);

        // Dynamic section at offset 384
        let dynamic_offset = 384usize;
        let mut dyn_entries = Vec::new();
        // DT_SONAME = 14
        dyn_entries.extend_from_slice(&14u64.to_le_bytes());
        dyn_entries.extend_from_slice(&(soname_idx as u64).to_le_bytes());

        // DT_NEEDED = 1
        for n_idx in needed_indices {
            dyn_entries.extend_from_slice(&1u64.to_le_bytes());
            dyn_entries.extend_from_slice(&(n_idx as u64).to_le_bytes());
        }

        // DT_NULL = 0
        dyn_entries.extend_from_slice(&0u64.to_le_bytes());
        dyn_entries.extend_from_slice(&0u64.to_le_bytes());

        elf[dynamic_offset..dynamic_offset + dyn_entries.len()].copy_from_slice(&dyn_entries);

        // Section Headers at offset 64:
        // Section 0: NULL
        // Section 1: .shstrtab / .dynstr (type 3 SHT_STRTAB)
        let s1 = 64 + 64;
        elf[s1..s1 + 0x04].copy_from_slice(&(shstr_dynstr as u32).to_le_bytes()); // sh_name
        elf[s1 + 0x04..s1 + 0x08].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        elf[s1 + 0x18..s1 + 0x20].copy_from_slice(&(strtab_offset as u64).to_le_bytes()); // sh_offset
        elf[s1 + 0x20..s1 + 0x28].copy_from_slice(&(str_table.len() as u64).to_le_bytes()); // sh_size

        // Section 2: .dynamic (type 6 SHT_DYNAMIC)
        let s2 = 64 + 128;
        elf[s2..s2 + 0x04].copy_from_slice(&(shstr_dynamic as u32).to_le_bytes()); // sh_name
        elf[s2 + 0x04..s2 + 0x08].copy_from_slice(&6u32.to_le_bytes()); // SHT_DYNAMIC
        elf[s2 + 0x18..s2 + 0x20].copy_from_slice(&(dynamic_offset as u64).to_le_bytes()); // sh_offset
        elf[s2 + 0x20..s2 + 0x28].copy_from_slice(&(dyn_entries.len() as u64).to_le_bytes()); // sh_size
        elf[s2 + 0x28..s2 + 0x2C].copy_from_slice(&1u32.to_le_bytes()); // sh_link -> Section 1

        // If banner requested, append to binary
        if let Some(b) = banner {
            elf.extend_from_slice(b.as_bytes());
            elf.push(0);
        }

        elf
    }

    /// A file whose `.dynstr` section header points past the end of the file
    /// must be skipped, not abort the scan (release builds use panic = "abort").
    #[test]
    fn dynstr_offset_past_end_of_file_does_not_panic() {
        let mut elf = make_test_elf64("libssl.so.3", &["libc.so.6"], None);
        let s1 = 64 + 64; // section 1 = .dynstr
        let past_end = (elf.len() as u64) + 4096;
        elf[s1 + 0x18..s1 + 0x20].copy_from_slice(&past_end.to_le_bytes());
        let _ = parse_elf_bytes(&elf, Path::new("/usr/lib/libssl.so.3"));
    }

    /// Offsets and sizes are attacker-controlled u64 values: sums must not wrap.
    #[test]
    fn huge_section_offsets_do_not_overflow() {
        let s1 = 64 + 64;
        let s2 = 64 + 128;
        for field in [0x28usize, 0x20, s1 + 0x18, s1 + 0x20, s2 + 0x18, s2 + 0x20] {
            for value in [u64::MAX, u64::MAX - 1, u64::MAX / 2 + 1, u32::MAX as u64] {
                let mut elf = make_test_elf64("libssl.so.3", &["libc.so.6"], None);
                elf[field..field + 8].copy_from_slice(&value.to_le_bytes());
                let _ = parse_elf_bytes(&elf, Path::new("/usr/lib/libssl.so.3"));
            }
        }
    }

    /// Deterministic robustness sweep: every truncation and a fixed set of byte
    /// mutations over the headers. The parser may reject the input; it may not
    /// panic.
    #[test]
    fn truncated_and_mutated_input_never_panics() {
        let base = make_test_elf64("libssl.so.3", &["libc.so.6"], Some("OpenSSL 3.0.2 15 Mar 2022"));
        let path = Path::new("/usr/lib/libssl.so.3");
        for len in 0..=base.len() {
            let _ = parse_elf_bytes(&base[..len], path);
        }
        let header_end = (64 + 64 * 4).min(base.len());
        for i in 0..header_end {
            for b in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                let mut m = base.clone();
                m[i] = b;
                let _ = parse_elf_bytes(&m, path);
            }
        }
        // Same sweep as a 32-bit and as a big-endian file, so those field
        // layouts are exercised too.
        for (class, data) in [(1u8, 1u8), (2, 2), (1, 2)] {
            let mut m = base.clone();
            m[4] = class;
            m[5] = data;
            for len in (0..=m.len()).step_by(7) {
                let _ = parse_elf_bytes(&m[..len], path);
            }
            for i in 0..header_end {
                let mut n = m.clone();
                n[i] = 0xFF;
                let _ = parse_elf_bytes(&n, path);
            }
        }
    }

    #[test]
    fn parses_elf64_soname_and_needed() {
        let elf_bytes = make_test_elf64(
            "libssl.so.3",
            &["libcrypto.so.3", "libc.so.6"],
            Some("OpenSSL 3.0.7 1 Nov 2022"),
        );
        let path = PathBuf::from("/usr/lib/libssl.so.3");
        let results = parse_elf_bytes(&elf_bytes, &path).expect("should parse elf");

        assert!(!results.is_empty());
        let openssl = results.iter().find(|s| s.name == "OpenSSL").unwrap();
        assert_eq!(openssl.version.as_deref(), Some("3.0.7"));
        assert_eq!(openssl.architecture, Architecture::X64);
        assert_eq!(openssl.registry_key, "elf:///usr/lib/libssl.so.3");
    }

    #[test]
    fn parses_soname_version_fallback() {
        let elf_bytes = make_test_elf64("libcurl.so.4.8.0", &[], None);
        let path = PathBuf::from("/usr/lib/libcurl.so.4.8.0");
        let results = parse_elf_bytes(&elf_bytes, &path).expect("should parse elf");

        let curl = results.iter().find(|s| s.name == "cURL").unwrap();
        assert_eq!(curl.version.as_deref(), Some("4.8.0"));
        assert_eq!(curl.architecture, Architecture::X64);
    }

    #[test]
    fn extracts_version_from_soname_function() {
        assert_eq!(extract_version_from_soname("libssl.so.1.1"), Some("1.1".to_string()));
        assert_eq!(extract_version_from_soname("libsqlite3.so.0.8.6"), Some("0.8.6".to_string()));
        assert_eq!(extract_version_from_soname("libxml2.so.2.9.14"), Some("2.9.14".to_string()));
        assert_eq!(extract_version_from_soname("libfoo.so"), None);
    }
}

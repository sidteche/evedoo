// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! RPM package database and DNF module states scanner.
//!
//! Scans modern RPM SQLite databases (`/var/lib/rpm/rpmdb.sqlite` and
//! `/usr/lib/sysimage/rpm/rpmdb.sqlite`) and DNF module states (`/var/lib/dnf/module_states.json`).
//!
//! Only the SQLite backend (rpm >= 4.16: RHEL/Rocky/Alma 9+, Fedora 33+) is
//! read. The Berkeley DB backend (`Packages`, RHEL/CentOS 7-8, Amazon Linux 2)
//! and the NDB backend (`Packages.db`, SUSE) are detected and reported with a
//! warning rather than silently yielding an empty inventory.
//!
//! Emits `DetectedSoftware` entries with `rpm://{package}` registry keys.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use tracing::{debug, warn};

use crate::models::{Architecture, DetectedSoftware};

// RPM Tag numbers (RFC / LSB RPM Header specification)
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;
const RPMTAG_VENDOR: u32 = 1011;
const RPMTAG_ARCH: u32 = 1022;

#[allow(dead_code)]
pub struct RpmScanner {
    rpmdb_paths: Vec<PathBuf>,
    dnf_module_path: PathBuf,
    /// Open the database as an immutable file. Set for offline rootfs / image
    /// scans, where nothing else writes the database and the scan must not
    /// create `-wal`/`-shm` files inside the image.
    immutable: bool,
}

#[allow(dead_code)]
impl RpmScanner {
    pub fn new() -> Self {
        Self {
            rpmdb_paths: vec![
                PathBuf::from("/var/lib/rpm/rpmdb.sqlite"),
                PathBuf::from("/usr/lib/sysimage/rpm/rpmdb.sqlite"),
            ],
            dnf_module_path: PathBuf::from("/var/lib/dnf/module_states.json"),
            immutable: false,
        }
    }

    pub fn with_paths(rpmdb_paths: Vec<PathBuf>, dnf_module_path: PathBuf) -> Self {
        Self {
            rpmdb_paths,
            dnf_module_path,
            immutable: false,
        }
    }

    /// Scan installed RPM packages and DNF modules from a custom rootfs path.
    pub fn scan_rootfs(root: &Path) -> Vec<DetectedSoftware> {
        let mut scanner = Self::with_paths(
            vec![
                root.join("var/lib/rpm/rpmdb.sqlite"),
                root.join("usr/lib/sysimage/rpm/rpmdb.sqlite"),
            ],
            root.join("var/lib/dnf/module_states.json"),
        );
        scanner.immutable = true;
        scanner.scan()
    }

    /// Scan installed RPM packages and active DNF modules.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let mut results = Vec::new();

        // 1. Scan RPM SQLite database
        let mut found_sqlite = false;
        for db_path in &self.rpmdb_paths {
            if db_path.exists() {
                debug!("Scanning RPM database at {:?}", db_path);
                results.extend(read_rpm_db_sqlite(db_path, self.immutable));
                found_sqlite = true;
                break; // Found primary rpmdb
            }
        }

        // A host can have RPM packages in a database this scanner cannot read.
        // Say so: an empty inventory would otherwise look like a clean host.
        if !found_sqlite {
            for dir in self.rpmdb_paths.iter().filter_map(|p| p.parent()) {
                if let Some((format, path)) = unsupported_rpmdb_format(dir) {
                    warn!(
                        "RPM database at {} uses the {} backend, which is not supported; \
                         RPM packages on this system are NOT inventoried (only rpmdb.sqlite is read)",
                        path.display(),
                        format
                    );
                    break;
                }
            }
        }

        // 2. Scan DNF module states if present
        if self.dnf_module_path.exists() {
            if let Ok(content) = fs::read_to_string(&self.dnf_module_path) {
                debug!("Scanning DNF module states at {:?}", self.dnf_module_path);
                results.extend(parse_dnf_module_states(&content));
            }
        }

        results
    }
}

impl Default for RpmScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// The legacy RPM database file in `dir`, if there is one: the backend name
/// and the file that identifies it.
fn unsupported_rpmdb_format(dir: &Path) -> Option<(&'static str, PathBuf)> {
    [("Berkeley DB", "Packages"), ("NDB", "Packages.db")]
        .into_iter()
        .map(|(format, file)| (format, dir.join(file)))
        .find(|(_, path)| path.is_file())
}

/// A SQLite URI for `path` that opens it as an immutable file: no locking and
/// no `-wal`/`-shm`/`-journal` side files are ever created.
fn immutable_uri(path: &Path) -> String {
    let mut uri = String::from("file:");
    let text = path.to_string_lossy().replace('\\', "/");
    // "C:/..." needs a leading slash to be an absolute URI path.
    if text.as_bytes().get(1) == Some(&b':') {
        uri.push('/');
    }
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'-' | b'_' | b'~' | b':' => uri.push(byte as char),
            other => uri.push_str(&format!("%{other:02X}")),
        }
    }
    uri.push_str("?immutable=1");
    uri
}

/// Parse an RPM SQLite database at `path`.
pub fn parse_rpm_db_sqlite(path: &Path) -> Vec<DetectedSoftware> {
    read_rpm_db_sqlite(path, false)
}

fn read_rpm_db_sqlite(path: &Path, immutable: bool) -> Vec<DetectedSoftware> {
    let opened = if immutable {
        Connection::open_with_flags(
            immutable_uri(path),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
    } else {
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    };
    let conn = match opened {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to open RPM SQLite database at {}: {}", path.display(), e);
            return Vec::new();
        }
    };

    parse_rpm_db_sqlite_conn(&conn)
}

/// Parse RPM packages from an open SQLite connection.
///
/// rpm's SQLite backend stores one row per installed package in
/// `Packages(hnum INTEGER PRIMARY KEY, blob BLOB)`, where `blob` is the package
/// header (see [`parse_rpm_header_blob`]).
pub fn parse_rpm_db_sqlite_conn(conn: &Connection) -> Vec<DetectedSoftware> {
    let mut results = Vec::new();

    let mut stmt = match conn.prepare("SELECT blob FROM Packages") {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!("RPM database has no readable Packages table: {}", e);
            return results;
        }
    };
    let rows = match stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)) {
        Ok(rows) => rows,
        Err(e) => {
            warn!("Failed to read the RPM Packages table: {}", e);
            return results;
        }
    };

    let mut unreadable = 0usize;
    for row in rows {
        match row.ok().as_deref().and_then(parse_rpm_header_blob) {
            // Imported signing keys are stored as pseudo-packages.
            Some(pkg) if pkg.name == "gpg-pubkey" => {}
            Some(pkg) => results.push(pkg),
            None => unreadable += 1,
        }
    }
    if unreadable > 0 {
        warn!("{} RPM package header(s) could not be parsed and were skipped", unreadable);
    }

    results
}

fn format_rpm_version(epoch: Option<u32>, version: &str, release: &str) -> String {
    let ep = epoch.unwrap_or(0);
    if ep > 0 {
        if release.is_empty() {
            format!("{}:{}", ep, version)
        } else {
            format!("{}:{}-{}", ep, version, release)
        }
    } else if release.is_empty() {
        version.to_string()
    } else {
        format!("{}-{}", version, release)
    }
}

fn map_architecture(arch: Option<&str>) -> Architecture {
    match arch {
        Some("x86_64" | "amd64") => Architecture::X64,
        Some("i386" | "i686" | "i586") => Architecture::X86,
        _ => Architecture::Unknown,
    }
}

/// `bytes[offset..offset + len]`, or `None` when that range does not lie
/// entirely inside `bytes`.
fn sub_slice(bytes: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(len)?)
}

fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(sub_slice(bytes, offset, 4)?.try_into().ok()?))
}

/// Pure Rust parser for an RPM header.
///
/// Layout (all integers big-endian): index entry count `il` (u32), data length
/// `dl` (u32), `il` index entries of 16 bytes each `{tag, type, offset, count}`,
/// then `dl` bytes of data that the entry offsets point into. This is the form
/// stored in `rpmdb.sqlite`. A header taken from a `.rpm` package file is the
/// same thing preceded by an 8-byte intro (magic `8E AD E8`, version, four
/// reserved bytes), which is accepted too.
pub fn parse_rpm_header_blob(bytes: &[u8]) -> Option<DetectedSoftware> {
    let bytes = match bytes.get(..3) {
        Some([0x8E, 0xAD, 0xE8]) => bytes.get(8..)?,
        _ => bytes,
    };

    let nindex = be_u32(bytes, 0)? as usize;
    let data_len = be_u32(bytes, 4)? as usize;

    let index_start = 8usize;
    let data_start = nindex.checked_mul(16)?.checked_add(index_start)?;
    // The declared data length may not exceed what is actually there.
    let data_section = sub_slice(bytes, data_start, data_len)?;

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut release: Option<String> = None;
    let mut epoch: Option<u32> = None;
    let mut arch: Option<String> = None;
    let mut vendor: Option<String> = None;

    for i in 0..nindex {
        // In bounds: data_start = index_start + nindex * 16 was validated above.
        let entry_off = index_start + i * 16;
        let tag = be_u32(bytes, entry_off)?;
        let entry_type = be_u32(bytes, entry_off + 4)?;
        let offset = be_u32(bytes, entry_off + 8)? as usize;

        let Some(value) = data_section.get(offset..).filter(|v| !v.is_empty()) else {
            continue;
        };
        // STRING (6) and I18NSTRING (9) are NUL-terminated.
        let is_string = entry_type == 6 || entry_type == 9;

        match tag {
            RPMTAG_NAME if is_string => name = read_null_terminated_string(value),
            RPMTAG_VERSION if is_string => version = read_null_terminated_string(value),
            RPMTAG_RELEASE if is_string => release = read_null_terminated_string(value),
            RPMTAG_ARCH if is_string => arch = read_null_terminated_string(value),
            RPMTAG_VENDOR if is_string => vendor = read_null_terminated_string(value),
            RPMTAG_EPOCH if entry_type == 4 => epoch = be_u32(value, 0),
            _ => {}
        }
    }

    let name = name?;
    let version_str = version.unwrap_or_default();
    let release_str = release.unwrap_or_default();
    let full_ver = format_rpm_version(epoch, &version_str, &release_str);
    let architecture = map_architecture(arch.as_deref());
    let publisher = vendor.or_else(|| Some("rpm".to_string()));

    Some(DetectedSoftware {
        name: name.clone(),
        version: if full_ver.is_empty() { None } else { Some(full_ver) },
        publisher,
        install_location: None,
        install_date: None,
        registry_key: format!("rpm://{}", name),
        architecture,
    })
}

fn read_null_terminated_string(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}

/// Pure Rust parser for `/var/lib/dnf/module_states.json`.
pub fn parse_dnf_module_states(content: &str) -> Vec<DetectedSoftware> {
    let mut results = Vec::new();

    let json: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return results,
    };

    if let Value::Object(map) = json {
        for (module_name, val) in map {
            // Module entry could be object with stream, state, etc.
            if let Value::Object(mod_info) = val {
                let is_active = mod_info
                    .get("active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let state = mod_info
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if is_active || state == "enabled" {
                    let stream = mod_info
                        .get("stream")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);

                    results.push(DetectedSoftware {
                        name: format!("module:{}", module_name),
                        version: stream,
                        publisher: Some("dnf-module".to_string()),
                        install_location: None,
                        install_date: None,
                        registry_key: format!("rpm://module:{}", module_name),
                        architecture: Architecture::Unknown,
                    });
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory removed on drop (no dev-dependency needed).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "evedoo-rpmdb-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Encode a header the way rpm stores it in `rpmdb.sqlite`: index count
    /// and data length (both big-endian u32), then 16-byte index entries, then
    /// the data store. There is no `8E AD E8` magic in the database form.
    fn rpmdb_blob(name: &str, epoch: Option<u32>, version: &str, release: &str, arch: &str) -> Vec<u8> {
        let mut index: Vec<(u32, u32, u32, u32)> = Vec::new(); // tag, type, offset, count
        let mut data: Vec<u8> = Vec::new();
        // A region tag comes first in real headers; the reader must ignore it.
        index.push((63, 7, 0, 16));
        data.extend_from_slice(&[0u8; 16]);
        for (tag, value) in [
            (RPMTAG_NAME, name),
            (RPMTAG_VERSION, version),
            (RPMTAG_RELEASE, release),
            (RPMTAG_ARCH, arch),
        ] {
            index.push((tag, 6, data.len() as u32, 1));
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        if let Some(epoch) = epoch {
            while data.len() & 3 != 0 {
                data.push(0);
            }
            index.push((RPMTAG_EPOCH, 4, data.len() as u32, 1));
            data.extend_from_slice(&epoch.to_be_bytes());
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&(index.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
        for (tag, ty, offset, count) in index {
            for field in [tag, ty, offset, count] {
                blob.extend_from_slice(&field.to_be_bytes());
            }
        }
        blob.extend_from_slice(&data);
        blob
    }

    /// The schema rpm >= 4.16 really creates.
    fn real_schema_db(blobs: &[Vec<u8>]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)",
            [],
        )
        .unwrap();
        for blob in blobs {
            conn.execute("INSERT INTO Packages (blob) VALUES (?1)", rusqlite::params![blob])
                .unwrap();
        }
        conn
    }

    #[test]
    fn reads_packages_from_a_real_schema_rpmdb() {
        let conn = real_schema_db(&[
            rpmdb_blob("openssl", Some(1), "3.0.7", "18.el9_2", "x86_64"),
            rpmdb_blob("kernel", None, "5.14.0", "362.8.1.el9_3", "x86_64"),
        ]);

        let pkgs = parse_rpm_db_sqlite_conn(&conn);
        assert_eq!(pkgs.len(), 2);

        let openssl = pkgs.iter().find(|p| p.name == "openssl").unwrap();
        assert_eq!(openssl.version.as_deref(), Some("1:3.0.7-18.el9_2"));
        assert_eq!(openssl.registry_key, "rpm://openssl");
        assert_eq!(openssl.architecture, Architecture::X64);

        let kernel = pkgs.iter().find(|p| p.name == "kernel").unwrap();
        assert_eq!(kernel.version.as_deref(), Some("5.14.0-362.8.1.el9_3"));
    }

    #[test]
    fn header_with_the_package_file_magic_is_also_accepted() {
        let mut blob = vec![0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0];
        blob.extend_from_slice(&rpmdb_blob("zlib", None, "1.2.11", "40.el9", "i686"));
        let pkg = parse_rpm_header_blob(&blob).unwrap();
        assert_eq!(pkg.name, "zlib");
        assert_eq!(pkg.version.as_deref(), Some("1.2.11-40.el9"));
        assert_eq!(pkg.architecture, Architecture::X86);
    }

    /// Imported signing keys are stored as pseudo-packages; they are not software.
    #[test]
    fn gpg_pubkey_pseudo_packages_are_skipped() {
        let conn = real_schema_db(&[
            rpmdb_blob("gpg-pubkey", None, "fd431d51", "4ae0493b", "(none)"),
            rpmdb_blob("bash", None, "5.1.8", "9.el9", "x86_64"),
        ]);
        let pkgs = parse_rpm_db_sqlite_conn(&conn);
        assert_eq!(pkgs.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["bash"]);
    }

    #[test]
    fn truncated_and_mutated_header_blobs_never_panic() {
        let base = rpmdb_blob("openssl", Some(1), "3.0.7", "18.el9_2", "x86_64");
        for len in 0..=base.len() {
            let _ = parse_rpm_header_blob(&base[..len]);
        }
        for i in 0..base.len() {
            for b in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                let mut m = base.clone();
                m[i] = b;
                let _ = parse_rpm_header_blob(&m);
            }
        }
        for i in (0..base.len().saturating_sub(3)).step_by(4) {
            for v in [u32::MAX, u32::MAX / 16, 0x8000_0000, 0x1000_0000] {
                let mut m = base.clone();
                m[i..i + 4].copy_from_slice(&v.to_be_bytes());
                let _ = parse_rpm_header_blob(&m);
            }
        }
    }

    #[test]
    fn rootfs_database_is_read_without_writing_into_the_image() {
        let dir = Scratch::new();
        let db_dir = dir.path().join("var/lib/rpm");
        fs::create_dir_all(&db_dir).unwrap();
        let db_path = db_dir.join("rpmdb.sqlite");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute(
                "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO Packages (blob) VALUES (?1)",
                rusqlite::params![rpmdb_blob("curl", None, "7.76.1", "26.el9", "x86_64")],
            )
            .unwrap();
        }

        let pkgs = RpmScanner::scan_rootfs(dir.path());
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "curl");

        let files: Vec<_> = fs::read_dir(&db_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(files, ["rpmdb.sqlite"], "the scan must not create -wal/-shm/-journal files");
    }

    #[test]
    fn unsupported_database_formats_are_named() {
        let dir = Scratch::new();
        let db_dir = dir.path().join("var/lib/rpm");
        fs::create_dir_all(&db_dir).unwrap();
        assert_eq!(unsupported_rpmdb_format(&db_dir), None);
        fs::write(db_dir.join("Packages"), b"bdb").unwrap();
        assert_eq!(unsupported_rpmdb_format(&db_dir), Some(("Berkeley DB", db_dir.join("Packages"))));
        fs::remove_file(db_dir.join("Packages")).unwrap();
        fs::write(db_dir.join("Packages.db"), b"ndb").unwrap();
        assert_eq!(unsupported_rpmdb_format(&db_dir), Some(("NDB", db_dir.join("Packages.db"))));
    }

    #[test]
    fn parses_dnf_module_states_json() {
        let json = r#"{
            "nodejs": {
                "stream": "18",
                "profiles": ["default"],
                "state": "enabled",
                "active": true
            },
            "python38": {
                "stream": "3.8",
                "profiles": ["common"],
                "state": "enabled",
                "active": true
            },
            "disabled_module": {
                "stream": "1.0",
                "state": "disabled",
                "active": false
            }
        }"#;

        let modules = parse_dnf_module_states(json);
        assert_eq!(modules.len(), 2);

        let node = modules.iter().find(|m| m.name == "module:nodejs").unwrap();
        assert_eq!(node.version.as_deref(), Some("18"));
        assert_eq!(node.registry_key, "rpm://module:nodejs");

        let py = modules.iter().find(|m| m.name == "module:python38").unwrap();
        assert_eq!(py.version.as_deref(), Some("3.8"));
        assert_eq!(py.registry_key, "rpm://module:python38");

        assert!(!modules.iter().any(|m| m.name == "module:disabled_module"));
    }

    #[test]
    fn scanner_handles_nonexistent_databases() {
        let scanner = RpmScanner::with_paths(
            vec![PathBuf::from("/nonexistent/rpmdb.sqlite")],
            PathBuf::from("/nonexistent/module_states.json"),
        );
        let pkgs = scanner.scan();
        assert!(pkgs.is_empty());
    }
}

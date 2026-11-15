// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Mac App Store (MAS) receipt scanner.
//!
//! Scans for applications installed via the Mac App Store by detecting
//! `Contents/_MASReceipt/receipt` within `.app` bundles and extracting
//! metadata and App Store item IDs (`mas://{id}`).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};
use super::bundle::{parse_plist, walk_app_bundles};

/// Scanner for Mac App Store applications.
pub struct MasScanner {
    custom_roots: Vec<PathBuf>,
}

impl MasScanner {
    pub fn new() -> Self {
        Self {
            custom_roots: Vec::new(),
        }
    }

    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { custom_roots: roots }
    }

    /// Default application roots to check for MAS receipts.
    pub fn default_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for dir in &["/Applications", "/System/Applications"] {
            let p = PathBuf::from(dir);
            if p.exists() {
                roots.push(p);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let user_apps = PathBuf::from(home).join("Applications");
            if user_apps.exists() {
                roots.push(user_apps);
            }
        }
        roots
    }

    /// Scan application directories for `_MASReceipt/receipt`.
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
            debug!("MAS scanner: walking {}", root.display());
            let app_paths = walk_app_bundles(&root, 4, 10_000);
            for app_dir in app_paths {
                let receipt_path = app_dir.join("Contents").join("_MASReceipt").join("receipt");
                if receipt_path.is_file() {
                    if let Some(sw) = Self::scan_mas_bundle(&app_dir, &receipt_path) {
                        let key = (sw.name.to_lowercase(), sw.version.clone());
                        if seen.insert(key) {
                            results.push(sw);
                        }
                    }
                }
            }
        }

        debug!("MAS scanner: found {} Mac App Store applications", results.len());
        results
    }

    /// Parse MAS bundle and its receipt.
    pub fn scan_mas_bundle(app_dir: &Path, receipt_path: &Path) -> Option<DetectedSoftware> {
        let plist_path = app_dir.join("Contents").join("Info.plist");
        let plist_meta = if plist_path.is_file() {
            fs::read_to_string(&plist_path).ok().and_then(|c| parse_plist(&c))
        } else {
            None
        };

        // Try reading and parsing receipt ASN.1 for Adam ID / Item ID
        let adam_id = fs::read(receipt_path).ok().and_then(|bytes| parse_adam_id_from_receipt(&bytes));

        let name = plist_meta
            .as_ref()
            .and_then(|m| m.bundle_display_name.clone().or_else(|| m.bundle_name.clone()))
            .or_else(|| app_dir.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()))?;

        let version = plist_meta
            .as_ref()
            .and_then(|m| m.bundle_short_version_string.clone().or_else(|| m.bundle_version.clone()));

        let id = if let Some(aid) = adam_id {
            aid.to_string()
        } else if let Some(bid) = plist_meta.as_ref().and_then(|m| m.bundle_identifier.clone()) {
            bid
        } else {
            name.clone()
        };

        Some(DetectedSoftware {
            name,
            version,
            publisher: Some("Mac App Store".to_string()),
            install_location: Some(app_dir.to_string_lossy().to_string()),
            install_date: None,
            registry_key: format!("mas://{}", id),
            architecture: Architecture::Unknown,
        })
    }
}

impl Default for MasScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure Rust ASN.1 scanner to locate Adam ID / Item ID (type 1708) in Mac App Store receipt payloads.
pub fn parse_adam_id_from_receipt(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }

    // Scan for ASN.1 sequence containing type 1708 (0x06, 0xAC in integer representation or DER encoded).
    // In MAS ASN.1 receipts, attributes are SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }.
    // Type 1708 in DER INTEGER is: 0x02, 0x02, 0x06, 0xAC.
    let pattern = [0x02, 0x02, 0x06, 0xAC];
    for (i, window) in bytes.windows(4).enumerate() {
        if window == pattern {
            // Found Type 1708!
            // Next should be version INTEGER (e.g. 0x02, 0x01, 0x01), then OCTET STRING (0x04, length).
            let rest = &bytes[i + 4..];

            let mut offset = 0usize;
            // Skip version INTEGER
            if rest.first() == Some(&0x02) {
                let Some(&vlen) = rest.get(1) else { continue };
                offset = 2 + vlen as usize;
            }

            if rest.get(offset) == Some(&0x04) {
                // OCTET STRING: every length byte comes from the file, so each
                // read is bounds-checked.
                let Some(&octet_len) = rest.get(offset + 1) else { continue };
                if let Some(octet_data) = rest.get(offset + 2..offset + 2 + octet_len as usize) {
                    // Inside OCTET STRING is an ASN.1 INTEGER containing the Adam ID
                    if octet_data.len() >= 2 && octet_data[0] == 0x02 {
                        let int_len = octet_data[1] as usize;
                        let int_bytes = &octet_data[2..2 + int_len.min(octet_data.len() - 2)];
                        let mut id: u64 = 0;
                        for &b in int_bytes {
                            id = (id << 8) | (b as u64);
                        }
                        if id > 0 {
                            return Some(id);
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OCTET STRING tag may be the last byte of the receipt: its length
    /// byte must not be read past the end.
    #[test]
    fn receipt_truncated_after_octet_string_tag_does_not_panic() {
        // type 1708, then a version INTEGER whose length skips to the final byte, which is 0x04.
        let receipt = [0x02, 0x02, 0x06, 0xAC, 0x02, 0x03, 0x00, 0x00, 0x00, 0x04];
        assert_eq!(parse_adam_id_from_receipt(&receipt), None);
    }

    #[test]
    fn truncated_and_mutated_receipts_never_panic() {
        let base = [
            0x30, 0x10, 0x02, 0x02, 0x06, 0xAC, 0x02, 0x01, 0x01, 0x04, 0x06, 0x02, 0x04, 0x1D, 0xCD, 0x65, 0x00, 0x00,
        ];
        assert_eq!(parse_adam_id_from_receipt(&base), Some(0x1DCD_6500));
        for len in 0..=base.len() {
            let _ = parse_adam_id_from_receipt(&base[..len]);
        }
        for i in 0..base.len() {
            for b in 0..=255u8 {
                let mut m = base;
                m[i] = b;
                let _ = parse_adam_id_from_receipt(&m);
                let _ = parse_adam_id_from_receipt(&m[..base.len() - 1]);
                let _ = parse_adam_id_from_receipt(&m[..base.len() - 4]);
            }
        }
    }

    #[test]
    fn parses_adam_id_from_synthetic_mas_receipt() {
        // Construct a synthetic ASN.1 DER sequence for Item ID 497799835 (0x1DABD29B)
        let mut receipt_data = vec![0x30, 0x20]; // SEQUENCE
        // Attribute Type 1708: 0x02, 0x02, 0x06, 0xAC
        receipt_data.extend_from_slice(&[0x02, 0x02, 0x06, 0xAC]);
        // Version 1: 0x02, 0x01, 0x01
        receipt_data.extend_from_slice(&[0x02, 0x01, 0x01]);
        // OCTET STRING containing INTEGER 497799835 (4 bytes: 0x1D, 0xAB, 0xD2, 0x9B)
        receipt_data.extend_from_slice(&[0x04, 0x06, 0x02, 0x04, 0x1D, 0xAB, 0xD2, 0x9B]);

        let id = parse_adam_id_from_receipt(&receipt_data);
        assert_eq!(id, Some(497799835));
    }

    #[test]
    fn scans_mock_mas_app() {
        let tmp = std::env::temp_dir().join("evedoo_mas_scan_test");
        let _ = fs::remove_dir_all(&tmp);

        let app_dir = tmp.join("Xcode.app");
        let contents = app_dir.join("Contents");
        let receipt_dir = contents.join("_MASReceipt");
        fs::create_dir_all(&receipt_dir).unwrap();

        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.apple.dt.Xcode</string>
    <key>CFBundleDisplayName</key>
    <string>Xcode</string>
    <key>CFBundleShortVersionString</key>
    <string>16.1</string>
</dict>
</plist>"#;
        fs::write(contents.join("Info.plist"), plist).unwrap();

        let receipt_data = vec![0x30, 0x20, 0x02, 0x02, 0x06, 0xAC, 0x02, 0x01, 0x01, 0x04, 0x06, 0x02, 0x04, 0x1D, 0xAB, 0xD2, 0x9B];
        fs::write(receipt_dir.join("receipt"), &receipt_data).unwrap();

        let scanner = MasScanner::with_roots(vec![tmp.clone()]);
        let results = scanner.scan();

        assert_eq!(results.len(), 1);
        let xcode = &results[0];
        assert_eq!(xcode.name, "Xcode");
        assert_eq!(xcode.version.as_deref(), Some("16.1"));
        assert_eq!(xcode.registry_key, "mas://497799835");
        assert_eq!(xcode.publisher.as_deref(), Some("Mac App Store"));

        let _ = fs::remove_dir_all(&tmp);
    }
}

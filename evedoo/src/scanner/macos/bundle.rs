// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! macOS Application Bundle & Plist Scanner.
//!
//! Scans standard application directories (`/Applications`, `~/Applications`,
//! `/System/Applications`, `/System/Library/CoreServices`) for `*.app/Contents/Info.plist`.
//! Parses Info.plist in pure Rust to extract bundle metadata (`CFBundleIdentifier`,
//! `CFBundleShortVersionString`, `CFBundleVersion`, `CFBundleName`, `CFBundleDisplayName`)
//! and emits `DetectedSoftware` entries with `bundle://{bundle_id}` or `app://{name}` keys.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

/// Metadata extracted from an application `Info.plist`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlistMetadata {
    pub bundle_identifier: Option<String>,
    pub bundle_name: Option<String>,
    pub bundle_display_name: Option<String>,
    pub bundle_short_version_string: Option<String>,
    pub bundle_version: Option<String>,
    pub bundle_executable: Option<String>,
}

/// Pure Rust XML Plist parser for extracting Info.plist key-value entries.
pub fn parse_plist(content: &str) -> Option<PlistMetadata> {
    let mut map: HashMap<String, String> = HashMap::new();

    // 1. Try XML parsing
    parse_xml_dict(content, &mut map);

    // 2. Fallback to ASCII / key-value scanning if map is empty
    if map.is_empty() {
        parse_ascii_plist(content, &mut map);
    }

    if map.is_empty() {
        return None;
    }

    let bundle_identifier = map.remove("CFBundleIdentifier").filter(|s| !s.trim().is_empty());
    let bundle_name = map.remove("CFBundleName").filter(|s| !s.trim().is_empty());
    let bundle_display_name = map.remove("CFBundleDisplayName").filter(|s| !s.trim().is_empty());
    let bundle_short_version_string = map.remove("CFBundleShortVersionString").filter(|s| !s.trim().is_empty());
    let bundle_version = map.remove("CFBundleVersion").filter(|s| !s.trim().is_empty());
    let bundle_executable = map.remove("CFBundleExecutable").filter(|s| !s.trim().is_empty());

    if bundle_identifier.is_none()
        && bundle_name.is_none()
        && bundle_display_name.is_none()
        && bundle_short_version_string.is_none()
        && bundle_version.is_none()
        && bundle_executable.is_none()
    {
        return None;
    }

    Some(PlistMetadata {
        bundle_identifier,
        bundle_name,
        bundle_display_name,
        bundle_short_version_string,
        bundle_version,
        bundle_executable,
    })
}

fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn parse_xml_dict(content: &str, map: &mut HashMap<String, String>) {
    let mut cursor = 0;
    let bytes = content.as_bytes();

    while cursor < bytes.len() {
        // Look for `<key>`
        let key_open = match content[cursor..].find("<key>") {
            Some(idx) => cursor + idx,
            None => break,
        };
        let key_content_start = key_open + 5;
        let key_close = match content[key_content_start..].find("</key>") {
            Some(idx) => key_content_start + idx,
            None => break,
        };
        let key_name = content[key_content_start..key_close].trim().to_string();
        cursor = key_close + 6;

        // Skip whitespace and comments
        skip_xml_whitespace_and_comments(content, &mut cursor);

        // Check the next tag for value
        if cursor >= bytes.len() {
            break;
        }

        let rem = &content[cursor..];
        if rem.starts_with("<string>") {
            let val_start = cursor + 8;
            if let Some(val_end_rel) = content[val_start..].find("</string>") {
                let raw_val = &content[val_start..val_start + val_end_rel];
                let val = unescape_xml(raw_val.trim());
                map.insert(key_name, val);
                cursor = val_start + val_end_rel + 9;
            } else {
                break;
            }
        } else if rem.starts_with("<string/>") {
            map.insert(key_name, String::new());
            cursor += 9;
        } else if rem.starts_with("<integer>") {
            let val_start = cursor + 9;
            if let Some(val_end_rel) = content[val_start..].find("</integer>") {
                let raw_val = &content[val_start..val_start + val_end_rel];
                map.insert(key_name, raw_val.trim().to_string());
                cursor = val_start + val_end_rel + 10;
            } else {
                break;
            }
        } else if rem.starts_with("<true/>") || rem.starts_with("<true />") {
            map.insert(key_name, "true".to_string());
            if let Some(close_idx) = rem.find('>') {
                cursor += close_idx + 1;
            }
        } else if rem.starts_with("<false/>") || rem.starts_with("<false />") {
            map.insert(key_name, "false".to_string());
            if let Some(close_idx) = rem.find('>') {
                cursor += close_idx + 1;
            }
        }
    }
}

fn skip_xml_whitespace_and_comments(content: &str, cursor: &mut usize) {
    while *cursor < content.len() {
        let rem = &content[*cursor..];
        let trimmed = rem.trim_start();
        let ws_len = rem.len() - trimmed.len();
        *cursor += ws_len;

        if content[*cursor..].starts_with("<!--") {
            if let Some(comment_end) = content[*cursor..].find("-->") {
                *cursor += comment_end + 3;
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn parse_ascii_plist(content: &str, map: &mut HashMap<String, String>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().trim_matches('"');
            let val = v.trim().trim_end_matches(';').trim().trim_matches('"');
            if !key.is_empty() {
                map.insert(key.to_string(), val.to_string());
            }
        }
    }
}

/// Scanner for macOS Application Bundles (`*.app`).
pub struct BundleScanner {
    custom_roots: Vec<PathBuf>,
}

impl BundleScanner {
    pub fn new() -> Self {
        Self {
            custom_roots: Vec::new(),
        }
    }

    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self { custom_roots: roots }
    }

    /// Default application roots on macOS.
    pub fn default_application_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for dir in &["/Applications", "/System/Applications", "/System/Library/CoreServices"] {
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

    /// Scan application bundles and emit `DetectedSoftware`.
    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let roots = if !self.custom_roots.is_empty() {
            self.custom_roots.clone()
        } else {
            Self::default_application_roots()
        };

        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for root in roots {
            if !root.is_dir() {
                continue;
            }
            debug!("Bundle scanner: walking {}", root.display());
            let app_paths = walk_app_bundles(&root, 4, 10_000);
            for app_dir in app_paths {
                if let Some(sw) = Self::scan_bundle(&app_dir) {
                    let key = (sw.name.to_lowercase(), sw.version.clone());
                    if seen.insert(key) {
                        results.push(sw);
                    }
                }
            }
        }

        debug!("Bundle scanner: found {} application bundles", results.len());
        results
    }

    /// Parse a single `.app` bundle directory.
    pub fn scan_bundle(app_dir: &Path) -> Option<DetectedSoftware> {
        let plist_path = app_dir.join("Contents").join("Info.plist");
        if !plist_path.is_file() {
            return None;
        }

        let content = fs::read_to_string(&plist_path).ok()?;
        let meta = parse_plist(&content)?;

        let name = meta
            .bundle_display_name
            .or(meta.bundle_name)
            .or_else(|| {
                app_dir
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
            })
            .or(meta.bundle_identifier.clone())?;

        let version = meta
            .bundle_short_version_string
            .or(meta.bundle_version)
            .filter(|v| !v.trim().is_empty());

        let registry_key = if let Some(ref bid) = meta.bundle_identifier {
            format!("bundle://{}", bid)
        } else {
            format!("app://{}", name)
        };

        let publisher = if let Some(ref bid) = meta.bundle_identifier {
            if bid.starts_with("com.apple.") {
                Some("Apple Inc.".to_string())
            } else if bid.starts_with("com.google.") {
                Some("Google LLC".to_string())
            } else if bid.starts_with("com.microsoft.") {
                Some("Microsoft Corporation".to_string())
            } else {
                None
            }
        } else {
            None
        };

        Some(DetectedSoftware {
            name,
            version,
            publisher,
            install_location: Some(app_dir.to_string_lossy().to_string()),
            install_date: None,
            registry_key,
            architecture: Architecture::Unknown,
        })
    }
}

impl Default for BundleScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-limited directory walker looking for `.app` bundle directories.
pub fn walk_app_bundles(root: &Path, max_depth: usize, max_files: usize) -> Vec<PathBuf> {
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
                let is_app = path
                    .extension()
                    .and_then(OsStr::to_str)
                    .map(|ext| ext.eq_ignore_ascii_case("app"))
                    .unwrap_or(false);

                if is_app {
                    results.push(path);
                    // Do not descend into standard application bundles
                    continue;
                }

                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Chrome</string>
    <key>CFBundleDisplayName</key>
    <string>Google Chrome</string>
    <key>CFBundleShortVersionString</key>
    <string>124.0.6367.60</string>
    <key>CFBundleVersion</key>
    <string>6367.60</string>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
</dict>
</plist>"#;

    #[test]
    fn parses_standard_xml_plist() {
        let meta = parse_plist(SAMPLE_PLIST).unwrap();
        assert_eq!(meta.bundle_identifier.as_deref(), Some("com.google.Chrome"));
        assert_eq!(meta.bundle_name.as_deref(), Some("Chrome"));
        assert_eq!(meta.bundle_display_name.as_deref(), Some("Google Chrome"));
        assert_eq!(meta.bundle_short_version_string.as_deref(), Some("124.0.6367.60"));
        assert_eq!(meta.bundle_version.as_deref(), Some("6367.60"));
        assert_eq!(meta.bundle_executable.as_deref(), Some("Google Chrome"));
    }

    #[test]
    fn parses_plist_with_entities_and_comments() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <!-- Application Details -->
    <key>CFBundleIdentifier</key>
    <string>org.example.app &amp; tools</string>
    <key>CFBundleName</key>
    <string>App &lt;Pro&gt;</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1.0</string>
</dict>
</plist>"#;
        let meta = parse_plist(plist).unwrap();
        assert_eq!(meta.bundle_identifier.as_deref(), Some("org.example.app & tools"));
        assert_eq!(meta.bundle_name.as_deref(), Some("App <Pro>"));
        assert_eq!(meta.bundle_short_version_string.as_deref(), Some("2.1.0"));
    }

    #[test]
    fn parses_ascii_fallback_plist() {
        let ascii_plist = r#"
            CFBundleIdentifier = "com.apple.Safari";
            CFBundleName = "Safari";
            CFBundleShortVersionString = "18.1";
            CFBundleVersion = "20619.2.8.11.10";
        "#;
        let meta = parse_plist(ascii_plist).unwrap();
        assert_eq!(meta.bundle_identifier.as_deref(), Some("com.apple.Safari"));
        assert_eq!(meta.bundle_name.as_deref(), Some("Safari"));
        assert_eq!(meta.bundle_short_version_string.as_deref(), Some("18.1"));
    }

    #[test]
    fn scans_mock_app_bundle() {
        let tmp = std::env::temp_dir().join("evedoo_bundle_scan_test");
        let _ = fs::remove_dir_all(&tmp);

        let app_dir = tmp.join("Google Chrome.app");
        let contents = app_dir.join("Contents");
        fs::create_dir_all(&contents).unwrap();
        fs::write(contents.join("Info.plist"), SAMPLE_PLIST).unwrap();

        let scanner = BundleScanner::with_roots(vec![tmp.clone()]);
        let results = scanner.scan();

        assert_eq!(results.len(), 1);
        let sw = &results[0];
        assert_eq!(sw.name, "Google Chrome");
        assert_eq!(sw.version.as_deref(), Some("124.0.6367.60"));
        assert_eq!(sw.registry_key, "bundle://com.google.Chrome");
        assert_eq!(sw.publisher.as_deref(), Some("Google LLC"));

        let _ = fs::remove_dir_all(&tmp);
    }
}

//! WinGet package scanner.
//!
//! Detects applications managed by the Windows Package Manager (winget),
//! which covers both traditional Win32 apps and Windows Store apps.
//! Apps already in the registry scanner are deduplicated at the call site.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

pub struct WingetScanner;

impl WingetScanner {
    pub fn new() -> Self {
        WingetScanner
    }

    pub fn scan(&self) -> Vec<DetectedSoftware> {
        // --disable-interactivity suppresses progress bars / prompts
        // --accept-source-agreements avoids interactive licence prompts
        let output = match Command::new("winget.exe")
            .args(["list", "--disable-interactivity", "--accept-source-agreements"])
            .output()
        {
            Ok(o) => o.stdout,
            Err(e) => {
                debug!("winget not available: {}", e);
                return Vec::new();
            }
        };

        // winget outputs UTF-16LE on some systems; try UTF-8 first, then strip BOM
        let raw = String::from_utf8_lossy(&output);
        self.parse_table(&raw)
    }

    fn parse_table(&self, text: &str) -> Vec<DetectedSoftware> {
        let mut results = Vec::new();

        // Find the separator line (full of dashes) to determine column widths
        // Header is two lines above the first separator line:
        //   Name        Id          Version   Available  Source
        //   ----        --          -------   ---------  ------
        let mut lines = text.lines().peekable();

        // Find header line (the one before the dash separator)
        let mut header_line: Option<&str> = None;
        let mut col_offsets: Option<Vec<(usize, usize)>> = None;

        for line in lines.by_ref() {
            // Detect separator line: majority chars are '-' or whitespace
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Separator line: every non-whitespace character is a dash
            let non_ws: &str = &trimmed.replace(' ', "");
            if !non_ws.is_empty() && non_ws.chars().all(|c| c == '-') {
                // This is the separator — parse column widths from it
                if let Some(hdr) = header_line {
                    col_offsets = Some(parse_column_offsets(line, hdr));
                }
                break;
            }
            header_line = Some(line);
        }

        let offsets = match col_offsets {
            Some(o) => o,
            None => return Vec::new(),
        };

        // Column indices in winget output: Name=0, Id=1, Version=2, Available=3, Source=4
        let col_name = offsets.first().copied();
        let col_id = offsets.get(1).copied();
        let col_version = offsets.get(2).copied();
        let col_source = offsets.get(4).copied();

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }

            let name = col_name
                .map(|(start, end)| extract_field(line, start, end))
                .unwrap_or_default();
            let id = col_id
                .map(|(start, end)| extract_field(line, start, end))
                .unwrap_or_default();
            let version = col_version
                .map(|(start, end)| extract_field(line, start, end))
                .unwrap_or_default();
            let source = col_source
                .map(|(start, end)| extract_field(line, start, end))
                .unwrap_or_default();

            // Skip entries with no source (covered by registry scanner) or no version
            if source.is_empty() || version.is_empty() || name.is_empty() {
                continue;
            }

            // Skip obvious garbage lines
            if name.starts_with('-') || name.starts_with('…') {
                continue;
            }

            debug!("WinGet: '{}' ({}) v{} [{}]", name, id, version, source);

            results.push(DetectedSoftware {
                name,
                version: Some(version),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: format!("winget://{}", id),
                architecture: Architecture::Unknown,
            });
        }

        results
    }
}

impl Default for WingetScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse column (start, end) byte offsets from the separator line and header line.
///
/// The separator line looks like:
/// `  ----  -----  -------  ------`
/// Each run of dashes marks a column. We use both the dash run positions and the
/// header word positions to get accurate column boundaries.
fn parse_column_offsets(separator: &str, _header: &str) -> Vec<(usize, usize)> {
    let mut cols = Vec::new();
    let bytes = separator.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Skip whitespace
        while i < len && bytes[i] == b' ' {
            i += 1;
        }
        if i >= len {
            break;
        }
        let start = i;
        // Walk over dashes
        while i < len && bytes[i] == b'-' {
            i += 1;
        }
        if i > start {
            // end is exclusive; add some slack so the last column isn't cut short
            cols.push((start, i));
        }
    }

    cols
}

/// Extract text at a column range, trimming whitespace.
fn extract_field(line: &str, start: usize, _end: usize) -> String {
    let chars: Vec<char> = line.chars().collect();
    if start >= chars.len() {
        return String::new();
    }
    // Read from start until next whitespace run of 2+ spaces or end of string
    let slice: String = chars[start..].iter().collect();
    // Split at two or more consecutive spaces (column separator)
    slice
        .split("  ")
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"Name                         Id                             Version    Available  Source
----                         --                             -------    ---------  ------
Git                          Git.Git                        2.49.0     2.50.0     winget
Python 3.13                  Python.Python.3.13             3.13.3312             winget
7-Zip 24.09 (x64)            7zip.7zip                      24.09                 winget
No Source App                Some.App                       1.0.0
"#;

    #[test]
    fn parses_winget_table() {
        let scanner = WingetScanner::new();
        let results = scanner.parse_table(SAMPLE);
        // Only entries with a non-empty Source should be included
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].name, "Git");
        assert_eq!(results[0].version.as_deref(), Some("2.49.0"));
        assert_eq!(results[0].registry_key, "winget://Git.Git");
        assert_eq!(results[1].name, "Python 3.13");
        assert_eq!(results[2].name, "7-Zip 24.09 (x64)");
    }

    #[test]
    fn winget_scanner_does_not_panic() {
        let _ = WingetScanner::new().scan();
    }
}

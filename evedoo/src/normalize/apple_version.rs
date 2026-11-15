// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Apple macOS, Build ID, and Darwin version parser and comparator.
//!
//! Handles:
//! - Standard dotted triplets / pairs: `15.1.1`, `14.5`, `13.6.7`
//! - Apple Build IDs: e.g. `24B91`, `21G115`, `20G1427` parsed into `(major_build, letter, minor_build)`
//! - Darwin versions: e.g. `Darwin 24.1.0` mapped to macOS `15.1.0`
//! - Combined version strings: `15.1 (24B91)`, `macOS 15.1 [24B91]`, `15.0 24A335`
//! - Complete ordering: `Ord`, `PartialOrd`, `PartialEq`, `Eq`

use std::cmp::Ordering;
use std::fmt;

/// Parsed Apple Build ID (e.g. `24B91` -> major=24, letter='B', minor=91).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppleBuildId {
    pub major: u32,
    pub letter: char,
    pub minor: u32,
    pub extra: Option<char>,
}

impl AppleBuildId {
    /// Parse an Apple Build ID string (e.g. "24B91", "21G115", "20G1427", "24A5264n").
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        if s.is_empty() {
            return None;
        }

        // Find the index of the first ASCII letter
        let first_letter_idx = s.find(|c: char| c.is_ascii_alphabetic())?;
        if first_letter_idx == 0 {
            // Must have a leading numeric major build (e.g. 24 in 24B91)
            return None;
        }

        let major_str = &s[..first_letter_idx];
        let major: u32 = major_str.parse().ok()?;

        let mut chars = s[first_letter_idx..].chars();
        let letter = chars.next()?.to_ascii_uppercase();

        let rest: String = chars.collect();
        if rest.is_empty() {
            return None;
        }

        // The rest should start with digits (minor build) and may end with an optional letter (e.g. beta/seed)
        let minor_digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if minor_digits.is_empty() {
            return None;
        }
        let minor: u32 = minor_digits.parse().ok()?;

        let extra_str = &rest[minor_digits.len()..];
        let extra = if extra_str.is_empty() {
            None
        } else if extra_str.len() == 1 {
            let ch = extra_str.chars().next().unwrap();
            if ch.is_ascii_alphabetic() {
                Some(ch.to_ascii_lowercase())
            } else {
                return None;
            }
        } else {
            return None;
        };

        Some(AppleBuildId {
            major,
            letter,
            minor,
            extra,
        })
    }

    /// Infer the macOS major/minor version from this build ID major if possible.
    /// Darwin 20+ corresponds to macOS 11+ (macOS major = Darwin major - 9).
    /// Darwin 5..19 corresponds to macOS 10.x (macOS minor = Darwin major - 4).
    pub fn to_macos_version(self) -> (u32, u32, u32) {
        darwin_major_to_macos(self.major)
    }
}

impl Ord for AppleBuildId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.letter.cmp(&other.letter))
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| match (self.extra, other.extra) {
                (None, None) => Ordering::Equal,
                (Some(a), Some(b)) => a.cmp(&b),
                // A release without a seed/beta letter is final release: "24A500" > "24A500a"
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
            })
    }
}

impl PartialOrd for AppleBuildId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for AppleBuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(extra) = self.extra {
            write!(f, "{}{}{}{}", self.major, self.letter, self.minor, extra)
        } else {
            write!(f, "{}{}{}", self.major, self.letter, self.minor)
        }
    }
}

/// Convert Darwin major number to (macOS major, minor, patch).
pub fn darwin_major_to_macos(darwin_major: u32) -> (u32, u32, u32) {
    if darwin_major >= 20 {
        // Darwin 24 -> macOS 15, Darwin 23 -> macOS 14, Darwin 20 -> macOS 11
        (darwin_major - 9, 0, 0)
    } else if darwin_major >= 5 {
        // Darwin 19 -> macOS 10.15, Darwin 18 -> macOS 10.14, Darwin 5 -> macOS 10.1
        (10, darwin_major - 4, 0)
    } else {
        (10, 0, 0)
    }
}

/// Convert Darwin triplet (major, minor, patch) to macOS (major, minor, patch).
pub fn darwin_to_macos(d_major: u32, d_minor: u32, d_patch: u32) -> (u32, u32, u32) {
    if d_major >= 20 {
        // Darwin 24.1.0 -> macOS 15.1.0
        (d_major - 9, d_minor, d_patch)
    } else if d_major >= 5 {
        // Darwin 19.6.0 -> macOS 10.15.6
        (10, d_major - 4, d_minor)
    } else {
        (10, 0, d_minor)
    }
}

/// Parsed Apple / macOS version representation.
#[derive(Debug, Clone, Eq)]
pub struct AppleVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub build: Option<AppleBuildId>,
}

impl AppleVersion {
    pub fn new(major: u32, minor: u32, patch: u32, build: Option<AppleBuildId>) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }

    /// Parse a version string. Handles:
    /// - Dotted triplets: "15.1.1", "14.5", "13.6.7"
    /// - Version with build ID: "15.1 (24B91)", "macOS 15.1 [24B91]", "15.1 24B91"
    /// - Standalone Build ID: "24B91", "21G115", "20G1427"
    /// - Darwin kernel version: "Darwin 24.1.0", "Darwin Kernel Version 24.1.0"
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        if s.is_empty() {
            return None;
        }

        // 1. Check for Darwin string
        let lower = s.to_ascii_lowercase();
        if lower.starts_with("darwin") {
            let darwin_str = &s[6..];
            return Self::parse_darwin(darwin_str);
        }

        // Clean common prefixes ("macOS ", "OS X ", "Mac OS X ", "v", "V")
        let cleaned = strip_apple_os_prefix(s);

        // Check if the entire string is a standalone Build ID (e.g. "24B91")
        if let Some(build_id) = AppleBuildId::parse(cleaned) {
            let (maj, min, pat) = build_id.to_macos_version();
            return Some(AppleVersion {
                major: maj,
                minor: min,
                patch: pat,
                build: Some(build_id),
            });
        }

        // Check for combined version + build ID, e.g. "15.1 (24B91)" or "15.1 [24B91]" or "15.1 24B91"
        let (version_part, build_part) = split_version_and_build(cleaned);

        let (major, minor, patch) = parse_dotted_triplet(version_part)?;
        let build = build_part.and_then(AppleBuildId::parse);

        Some(AppleVersion {
            major,
            minor,
            patch,
            build,
        })
    }

    fn parse_darwin(s: &str) -> Option<Self> {
        // String might be " 24.1.0" or " kernel version 24.1.0: ..."
        let s = s.trim();
        let s = if s.to_ascii_lowercase().starts_with("kernel version") {
            s[14..].trim()
        } else {
            s
        };
        // Take the first whitespace or colon separated token
        let token = s.split([' ', ':', ';', ',']).next()?.trim();
        let parts: Vec<&str> = token.split('.').collect();
        if parts.is_empty() {
            return None;
        }
        let d_major: u32 = parts[0].parse().ok()?;
        let d_minor: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let d_patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        let (maj, min, pat) = darwin_to_macos(d_major, d_minor, d_patch);
        Some(AppleVersion {
            major: maj,
            minor: min,
            patch: pat,
            build: None,
        })
    }
}

impl Ord for AppleVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.build, &other.build) {
                (Some(a), Some(b)) => a.cmp(b),
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
                (None, None) => Ordering::Equal,
            })
    }
}

impl PartialOrd for AppleVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for AppleVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl fmt::Display for AppleVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(build) = &self.build {
            if self.patch > 0 {
                write!(f, "{}.{}.{} ({})", self.major, self.minor, self.patch, build)
            } else {
                write!(f, "{}.{} ({})", self.major, self.minor, build)
            }
        } else if self.patch > 0 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

fn strip_apple_os_prefix(s: &str) -> &str {
    let mut curr = s.trim();
    for prefix in &[
        "macos", "mac os x", "mac os", "os x", "mac", "version", "ver", "v",
    ] {
        if curr.to_ascii_lowercase().starts_with(prefix) {
            curr = curr[prefix.len()..].trim();
        }
    }
    curr
}

fn split_version_and_build(s: &str) -> (&str, Option<&str>) {
    // 1. Parenthesized build: "15.1 (24B91)"
    if let (Some(start), Some(end)) = (s.find('('), s.rfind(')')) {
        if start < end {
            let ver = s[..start].trim();
            let build = s[start + 1..end].trim();
            return (ver, Some(build));
        }
    }

    // 2. Bracketed build: "15.1 [24B91]"
    if let (Some(start), Some(end)) = (s.find('['), s.rfind(']')) {
        if start < end {
            let ver = s[..start].trim();
            let build = s[start + 1..end].trim();
            return (ver, Some(build));
        }
    }

    // 3. Space-separated build: "15.1 24B91"
    let mut parts = s.split_whitespace();
    if let (Some(first), Some(second)) = (parts.next(), parts.next()) {
        if AppleBuildId::parse(second).is_some() {
            return (first, Some(second));
        }
    }

    (s, None)
}

fn parse_dotted_triplet(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches(['v', 'V']).trim();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return None;
    }

    let major: u32 = parts[0].parse().ok()?;
    let minor: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_dotted_versions() {
        let v1 = AppleVersion::parse("15.1.1").unwrap();
        assert_eq!(v1.major, 15);
        assert_eq!(v1.minor, 1);
        assert_eq!(v1.patch, 1);
        assert_eq!(v1.build, None);

        let v2 = AppleVersion::parse("14.5").unwrap();
        assert_eq!(v2.major, 14);
        assert_eq!(v2.minor, 5);
        assert_eq!(v2.patch, 0);

        let v3 = AppleVersion::parse("13.6.7").unwrap();
        assert_eq!(v3.major, 13);
        assert_eq!(v3.minor, 6);
        assert_eq!(v3.patch, 7);
    }

    #[test]
    fn parses_apple_build_ids() {
        let b1 = AppleBuildId::parse("24B91").unwrap();
        assert_eq!(b1.major, 24);
        assert_eq!(b1.letter, 'B');
        assert_eq!(b1.minor, 91);
        assert_eq!(b1.extra, None);

        let b2 = AppleBuildId::parse("21G115").unwrap();
        assert_eq!(b2.major, 21);
        assert_eq!(b2.letter, 'G');
        assert_eq!(b2.minor, 115);

        let b3 = AppleBuildId::parse("20G1427").unwrap();
        assert_eq!(b3.major, 20);
        assert_eq!(b3.letter, 'G');
        assert_eq!(b3.minor, 1427);

        let b4 = AppleBuildId::parse("24A5264n").unwrap();
        assert_eq!(b4.major, 24);
        assert_eq!(b4.letter, 'A');
        assert_eq!(b4.minor, 5264);
        assert_eq!(b4.extra, Some('n'));
    }

    #[test]
    fn compares_apple_build_ids() {
        let b_24b91 = AppleBuildId::parse("24B91").unwrap();
        let b_24a335 = AppleBuildId::parse("24A335").unwrap();
        let b_23f79 = AppleBuildId::parse("23F79").unwrap();

        assert!(b_24b91 > b_24a335);
        assert!(b_24a335 > b_23f79);
        assert!(b_24b91 > b_23f79);
    }

    #[test]
    fn parses_combined_version_and_build_ids() {
        let v1 = AppleVersion::parse("15.1 (24B91)").unwrap();
        assert_eq!(v1.major, 15);
        assert_eq!(v1.minor, 1);
        assert_eq!(v1.patch, 0);
        assert_eq!(
            v1.build,
            Some(AppleBuildId {
                major: 24,
                letter: 'B',
                minor: 91,
                extra: None
            })
        );

        let v2 = AppleVersion::parse("macOS 15.0 [24A335]").unwrap();
        assert_eq!(v2.major, 15);
        assert_eq!(v2.minor, 0);
        assert_eq!(v2.build.unwrap().letter, 'A');
    }

    #[test]
    fn version_comparison_matrix() {
        let v_15_1 = AppleVersion::parse("15.1 (24B91)").unwrap();
        let v_15_0 = AppleVersion::parse("15.0 (24A335)").unwrap();
        let v_14_5 = AppleVersion::parse("14.5 (23F79)").unwrap();

        assert!(v_15_1 > v_15_0);
        assert!(v_15_0 > v_14_5);
        assert!(v_15_1 > v_14_5);
    }

    #[test]
    fn parses_darwin_kernel_versions() {
        let d1 = AppleVersion::parse("Darwin 24.1.0").unwrap();
        assert_eq!(d1.major, 15);
        assert_eq!(d1.minor, 1);
        assert_eq!(d1.patch, 0);

        let d2 = AppleVersion::parse("Darwin Kernel Version 23.5.0: Wed May  1 20:09:52 PDT 2024").unwrap();
        assert_eq!(d2.major, 14);
        assert_eq!(d2.minor, 5);
        assert_eq!(d2.patch, 0);

        let d3 = AppleVersion::parse("Darwin 19.6.0").unwrap();
        assert_eq!(d3.major, 10);
        assert_eq!(d3.minor, 15);
        assert_eq!(d3.patch, 6);
    }

    #[test]
    fn parses_standalone_build_ids_as_apple_version() {
        let v = AppleVersion::parse("24B91").unwrap();
        assert_eq!(v.major, 15);
        assert_eq!(v.build.unwrap().letter, 'B');

        let v_old = AppleVersion::parse("21G115").unwrap();
        assert_eq!(v_old.major, 12);
        assert_eq!(v_old.build.unwrap().minor, 115);
    }

    #[test]
    fn displays_nicely() {
        let v1 = AppleVersion::parse("15.1 (24B91)").unwrap();
        assert_eq!(v1.to_string(), "15.1 (24B91)");

        let v2 = AppleVersion::parse("15.1.1").unwrap();
        assert_eq!(v2.to_string(), "15.1.1");
    }

    #[test]
    fn test_apple_version_constructor() {
        let v = AppleVersion::new(
            15,
            1,
            0,
            Some(AppleBuildId {
                major: 24,
                letter: 'B',
                minor: 91,
                extra: None,
            }),
        );
        assert_eq!(v.major, 15);
        assert_eq!(v.minor, 1);
        assert_eq!(v.to_string(), "15.1 (24B91)");
    }
}

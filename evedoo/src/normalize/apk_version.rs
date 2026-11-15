// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Alpine Linux `apk` package version parsing and comparison.
//!
//! Implements Alpine APK version ordering per apk-tools `version.c`:
//! - Format: `base[_suffix*][-rN]`
//! - Suffixes: `_alpha < _beta < _pre < _rc < (release) < _cvs < _svn < _git < _hg < _p`
//! - Letter suffixes: `1.2.3 < 1.2.3a < 1.2.3b`
//! - Package revisions: `-r0 < -r1 < -r2` (default `-r0` if omitted)

use std::cmp::Ordering;
use std::fmt;
use serde::{Deserialize, Serialize};

/// Suffix kind with its ordering rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ApkSuffixKind {
    Alpha = 0,
    Beta = 1,
    Pre = 2,
    Rc = 3,
    Cvs = 5,
    Svn = 6,
    Git = 7,
    Hg = 8,
    Patch = 9, // _p
}

impl ApkSuffixKind {
    pub fn rank(self) -> u8 {
        self as u8
    }

    pub fn from_str(s: &str) -> Option<(Self, &str)> {
        let s_lower = s.to_ascii_lowercase();
        if s_lower.starts_with("alpha") {
            Some((ApkSuffixKind::Alpha, &s[5..]))
        } else if s_lower.starts_with("beta") {
            Some((ApkSuffixKind::Beta, &s[4..]))
        } else if s_lower.starts_with("pre") {
            Some((ApkSuffixKind::Pre, &s[3..]))
        } else if s_lower.starts_with("rc") {
            Some((ApkSuffixKind::Rc, &s[2..]))
        } else if s_lower.starts_with("cvs") {
            Some((ApkSuffixKind::Cvs, &s[3..]))
        } else if s_lower.starts_with("svn") {
            Some((ApkSuffixKind::Svn, &s[3..]))
        } else if s_lower.starts_with("git") {
            Some((ApkSuffixKind::Git, &s[3..]))
        } else if s_lower.starts_with("hg") {
            Some((ApkSuffixKind::Hg, &s[2..]))
        } else if s_lower.starts_with('p') {
            Some((ApkSuffixKind::Patch, &s[1..]))
        } else {
            None
        }
    }
}

/// Suffix entry with its kind and optional numeric value (e.g. `_rc2` -> (Rc, 2)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkSuffix {
    pub kind: ApkSuffixKind,
    pub num: u32,
}

/// Numeric component with optional single letter suffix (e.g. `3a` -> (3, Some('a'))).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkComponent {
    pub num: u32,
    pub letter: Option<char>,
}

/// Parsed Alpine apk version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkVersion {
    pub raw: String,
    pub components: Vec<ApkComponent>,
    pub suffixes: Vec<ApkSuffix>,
    pub revision: u32,
}

impl PartialEq for ApkVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ApkVersion {}

impl ApkVersion {
    /// Parse an Alpine apk version string.
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        if s.is_empty() {
            return None;
        }

        // 1. Extract revision `-rN` at the end
        let (without_rev, revision) = if let Some(idx) = s.rfind("-r") {
            let rev_str = &s[idx + 2..];
            if !rev_str.is_empty() && rev_str.chars().all(|c| c.is_ascii_digit()) {
                let rev: u32 = rev_str.parse().ok()?;
                (&s[..idx], rev)
            } else {
                (s, 0)
            }
        } else {
            (s, 0)
        };

        // 2. Split base and suffixes on `_`
        let parts: Vec<&str> = without_rev.split('_').collect();
        let base_str = parts.first()?;
        if base_str.is_empty() {
            return None;
        }

        // Parse base components (dot-separated)
        let mut components = Vec::new();
        for comp_str in base_str.split('.') {
            if comp_str.is_empty() {
                return None;
            }
            let (num_str, letter) = split_comp_letter(comp_str)?;
            let num: u32 = num_str.parse().ok()?;
            components.push(ApkComponent { num, letter });
        }

        if components.is_empty() {
            return None;
        }

        // Parse suffixes
        let mut suffixes = Vec::new();
        for suffix_str in &parts[1..] {
            if suffix_str.is_empty() {
                continue;
            }
            if let Some((kind, rest)) = ApkSuffixKind::from_str(suffix_str) {
                let num = if rest.is_empty() {
                    0
                } else {
                    rest.parse::<u32>().unwrap_or(0)
                };
                suffixes.push(ApkSuffix { kind, num });
            }
        }

        Some(ApkVersion {
            raw: s.to_string(),
            components,
            suffixes,
            revision,
        })
    }
}

fn split_comp_letter(s: &str) -> Option<(&str, Option<char>)> {
    let last_char = s.chars().last()?;
    if last_char.is_ascii_alphabetic() {
        let num_part = &s[..s.len() - last_char.len_utf8()];
        if num_part.is_empty() || !num_part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        Some((num_part, Some(last_char.to_ascii_lowercase())))
    } else if s.chars().all(|c| c.is_ascii_digit()) {
        Some((s, None))
    } else {
        None
    }
}

impl fmt::Display for ApkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Ord for ApkVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // 1. Compare base components
        let max_len = self.components.len().max(other.components.len());
        for i in 0..max_len {
            let c1 = self.components.get(i);
            let c2 = other.components.get(i);
            match (c1, c2) {
                (Some(a), Some(b)) => {
                    match a.num.cmp(&b.num) {
                        Ordering::Equal => {}
                        non_eq => return non_eq,
                    }
                    match (a.letter, b.letter) {
                        (Some(l1), Some(l2)) => match l1.cmp(&l2) {
                            Ordering::Equal => {}
                            non_eq => return non_eq,
                        },
                        (Some(_), None) => return Ordering::Greater, // 1.0a > 1.0
                        (None, Some(_)) => return Ordering::Less,    // 1.0 < 1.0a
                        (None, None) => {}
                    }
                }
                (Some(a), None) => {
                    if a.num > 0 || a.letter.is_some() {
                        return Ordering::Greater;
                    }
                }
                (None, Some(b)) => {
                    if b.num > 0 || b.letter.is_some() {
                        return Ordering::Less;
                    }
                }
                (None, None) => {}
            }
        }

        // 2. Compare suffixes
        let release_rank = 4u8;
        let mut idx = 0;
        loop {
            let s1 = self.suffixes.get(idx);
            let s2 = other.suffixes.get(idx);

            match (s1, s2) {
                (Some(a), Some(b)) => {
                    match a.kind.rank().cmp(&b.kind.rank()) {
                        Ordering::Equal => match a.num.cmp(&b.num) {
                            Ordering::Equal => {}
                            non_eq => return non_eq,
                        },
                        non_eq => return non_eq,
                    }
                }
                (Some(a), None) => {
                    return a.kind.rank().cmp(&release_rank);
                }
                (None, Some(b)) => {
                    return release_rank.cmp(&b.kind.rank());
                }
                (None, None) => break,
            }
            idx += 1;
        }

        // 3. Compare package revision
        self.revision.cmp(&other.revision)
    }
}

impl PartialOrd for ApkVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apk(s: &str) -> ApkVersion {
        ApkVersion::parse(s).unwrap_or_else(|| panic!("failed to parse apk version: {}", s))
    }

    #[test]
    fn parses_basic_version() {
        let v = apk("1.2.3-r1");
        assert_eq!(v.revision, 1);
        assert_eq!(v.components.len(), 3);
        assert_eq!(v.components[0].num, 1);
        assert_eq!(v.components[1].num, 2);
        assert_eq!(v.components[2].num, 3);
    }

    #[test]
    fn parses_suffixes() {
        let v = apk("1.0_rc2_p1-r0");
        assert_eq!(v.suffixes.len(), 2);
        assert_eq!(v.suffixes[0].kind, ApkSuffixKind::Rc);
        assert_eq!(v.suffixes[0].num, 2);
        assert_eq!(v.suffixes[1].kind, ApkSuffixKind::Patch);
        assert_eq!(v.suffixes[1].num, 1);
    }

    #[test]
    fn suffix_ordering_complete_chain() {
        assert!(apk("1.0_alpha1") < apk("1.0_beta1"));
        assert!(apk("1.0_beta1") < apk("1.0_pre1"));
        assert!(apk("1.0_pre1") < apk("1.0_rc1"));
        assert!(apk("1.0_rc1") < apk("1.0"));
        assert!(apk("1.0") < apk("1.0_cvs1"));
        assert!(apk("1.0_cvs1") < apk("1.0_svn1"));
        assert!(apk("1.0_svn1") < apk("1.0_git1"));
        assert!(apk("1.0_git1") < apk("1.0_hg1"));
        assert!(apk("1.0_hg1") < apk("1.0_p1"));
    }

    #[test]
    fn suffix_numbers() {
        assert!(apk("1.0_rc1") < apk("1.0_rc2"));
        assert!(apk("1.0_p1") < apk("1.0_p2"));
    }

    #[test]
    fn revisions() {
        assert!(apk("1.0-r0") == apk("1.0"));
        assert!(apk("1.0-r0") < apk("1.0-r1"));
        assert!(apk("1.0-r1") < apk("1.0-r2"));
    }

    #[test]
    fn letter_suffixes() {
        assert!(apk("1.2.3") < apk("1.2.3a"));
        assert!(apk("1.2.3a") < apk("1.2.3b"));
    }

    #[test]
    fn complex_apk_comparison() {
        assert!(apk("2.0_p1-r1") > apk("2.0-r5"));
        assert!(apk("2.0_rc1-r1") < apk("2.0-r0"));
    }
}

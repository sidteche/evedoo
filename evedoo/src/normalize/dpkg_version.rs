// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Debian package version parsing and comparison (Debian Policy §5.6.12).
//!
//! Handles:
//! - `[epoch:]upstream_version[-debian_revision]`
//! - Epoch ordering (`2:1.0 > 1:2.0`)
//! - Tilde `~` pre-release sorting before everything, including empty string (`1.0~beta < 1.0`)
//! - Alternating digit / non-digit lexical and numeric comparison
//! - Ubuntu extensions (`2:1.18.0-0ubuntu1.4`, `+esm2`)

use std::cmp::Ordering;
use std::fmt;
use serde::{Deserialize, Serialize};

/// Parsed Debian package version implementing Debian Policy §5.6.12 comparison rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpkgVersion {
    pub epoch: u32,
    pub upstream_version: String,
    pub debian_revision: String,
}

impl PartialEq for DpkgVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DpkgVersion {}

impl DpkgVersion {
    /// Parse a dpkg version string into its epoch, upstream_version, and debian_revision components.
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        if s.is_empty() {
            return None;
        }

        // 1. Extract optional epoch (digits followed by ':')
        let (epoch, rest) = if let Some((epoch_str, remainder)) = s.split_once(':') {
            let ep: u32 = epoch_str.parse().ok()?;
            (ep, remainder)
        } else {
            (0, s)
        };

        if rest.is_empty() {
            return None;
        }

        // 2. Extract optional debian revision (after the last '-')
        let (upstream_version, debian_revision) = if let Some(last_dash) = rest.rfind('-') {
            let up = &rest[..last_dash];
            let rev = &rest[last_dash + 1..];
            (up.to_string(), rev.to_string())
        } else {
            (rest.to_string(), String::new())
        };

        if upstream_version.is_empty() {
            return None;
        }

        Some(DpkgVersion {
            epoch,
            upstream_version,
            debian_revision,
        })
    }
}

impl fmt::Display for DpkgVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch > 0 {
            write!(f, "{}:", self.epoch)?;
        }
        write!(f, "{}", self.upstream_version)?;
        if !self.debian_revision.is_empty() {
            write!(f, "-{}", self.debian_revision)?;
        }
        Ok(())
    }
}

impl Ord for DpkgVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // 1. Compare epoch
        self.epoch
            .cmp(&other.epoch)
            // 2. Compare upstream version
            .then_with(|| verrevcmp(&self.upstream_version, &other.upstream_version))
            // 3. Compare debian revision
            .then_with(|| verrevcmp(&self.debian_revision, &other.debian_revision))
    }
}

impl PartialOrd for DpkgVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Character ordering for Debian Policy §5.6.12 non-digit comparisons:
/// - '~' sorts before anything, even empty string (order -1)
/// - letters ('A'..='Z', 'a'..='z') sort before all non-letters (except '~')
/// - other non-digit characters sort after letters, in ASCII order (+256 offset)
/// - '\0' (end of string) is 0
fn order_char(c: char) -> i32 {
    if c == '~' {
        -1
    } else if c.is_ascii_alphabetic() {
        c as i32
    } else if c != '\0' {
        (c as i32) + 256
    } else {
        0
    }
}

/// Compare two Debian version strings (upstream or revision) according to §5.6.12.
pub fn verrevcmp(mut s1: &str, mut s2: &str) -> Ordering {
    while !s1.is_empty() || !s2.is_empty() {
        // 1. Compare non-digit characters
        while (!s1.is_empty() && !s1.chars().next().unwrap().is_ascii_digit())
            || (!s2.is_empty() && !s2.chars().next().unwrap().is_ascii_digit())
        {
            let c1 = s1.chars().next().unwrap_or('\0');
            let c2 = s2.chars().next().unwrap_or('\0');
            let o1 = order_char(c1);
            let o2 = order_char(c2);
            if o1 != o2 {
                return o1.cmp(&o2);
            }
            if !s1.is_empty() {
                s1 = &s1[c1.len_utf8()..];
            }
            if !s2.is_empty() {
                s2 = &s2[c2.len_utf8()..];
            }
        }

        // 2. Compare digit sequences numerically
        let d1_len = s1.chars().take_while(|c| c.is_ascii_digit()).count();
        let d2_len = s2.chars().take_while(|c| c.is_ascii_digit()).count();

        let digits1 = &s1[..d1_len];
        let digits2 = &s2[..d2_len];

        // Strip leading zeros for numerical comparison
        let num1 = digits1.trim_start_matches('0');
        let num2 = digits2.trim_start_matches('0');

        match num1.len().cmp(&num2.len()) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {
                match num1.cmp(num2) {
                    Ordering::Greater => return Ordering::Greater,
                    Ordering::Less => return Ordering::Less,
                    Ordering::Equal => {
                        // Advance both strings past the entire digit chunk
                        s1 = &s1[d1_len..];
                        s2 = &s2[d2_len..];
                    }
                }
            }
        }
    }

    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dpkg(s: &str) -> DpkgVersion {
        DpkgVersion::parse(s).unwrap_or_else(|| panic!("failed to parse dpkg version: {}", s))
    }

    #[test]
    fn parses_epoch_upstream_revision() {
        let v = dpkg("2:1.18.0-0ubuntu1.4");
        assert_eq!(v.epoch, 2);
        assert_eq!(v.upstream_version, "1.18.0");
        assert_eq!(v.debian_revision, "0ubuntu1.4");
        assert_eq!(v.to_string(), "2:1.18.0-0ubuntu1.4");
    }

    #[test]
    fn parses_no_epoch() {
        let v = dpkg("1.2.3-1");
        assert_eq!(v.epoch, 0);
        assert_eq!(v.upstream_version, "1.2.3");
        assert_eq!(v.debian_revision, "1");
        assert_eq!(v.to_string(), "1.2.3-1");
    }

    #[test]
    fn parses_no_revision() {
        let v = dpkg("1.2.3");
        assert_eq!(v.epoch, 0);
        assert_eq!(v.upstream_version, "1.2.3");
        assert_eq!(v.debian_revision, "");
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn epoch_ordering() {
        assert!(dpkg("2:1.0") > dpkg("1:2.0"));
        assert!(dpkg("1:1.0") > dpkg("1.0"));
        assert!(dpkg("0:1.0") == dpkg("1.0"));
    }

    #[test]
    fn tilde_sorts_before_empty() {
        assert!(dpkg("1.0~beta1") < dpkg("1.0"));
        assert!(dpkg("1.0~rc1") < dpkg("1.0"));
        assert!(dpkg("1.0~~") < dpkg("1.0~"));
        assert!(dpkg("1.0~a") < dpkg("1.0~b"));
        assert!(dpkg("1.0~1") < dpkg("1.0~2"));
    }

    #[test]
    fn debian_revision_ordering() {
        assert!(dpkg("1.0") < dpkg("1.0-1"));
        assert!(dpkg("1.0-1") < dpkg("1.0-2"));
        assert!(dpkg("1.0-1.1") > dpkg("1.0-1"));
        assert!(dpkg("1.0-2~bpo10+1") < dpkg("1.0-2"));
    }

    #[test]
    fn numeric_segments_compared_by_value() {
        assert!(dpkg("1.10") > dpkg("1.9"));
        assert!(dpkg("1.02") == dpkg("1.2"));
        assert!(dpkg("1.0.10-1") > dpkg("1.0.2-1"));
    }

    #[test]
    fn ubuntu_esm_and_security_versions() {
        assert!(dpkg("2:1.18.0-0ubuntu1") < dpkg("2:1.18.0-0ubuntu1.4"));
        assert!(dpkg("2:1.18.0-0ubuntu1.4") < dpkg("2:1.18.0-0ubuntu1.4+esm2"));
        assert!(dpkg("2:1.18.0-0ubuntu1.4+esm2") < dpkg("2:1.18.0-0ubuntu1.4+esm3"));
    }

    #[test]
    fn letters_sort_before_non_letters() {
        // 'a' (letters) sort earlier than non-letters like '+' or '.'
        assert!(dpkg("1.0a") < dpkg("1.0+1"));
        assert!(dpkg("1.0.a") < dpkg("1.0.+1"));
    }
}

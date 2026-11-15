// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! RPM EVR (Epoch-Version-Release) parsing and `rpmvercmp` comparison.
//!
//! Implements the RPM comparison algorithm used by RPM, DNF, YUM, and Zypper:
//! - Format: `[epoch:]version[-release]`
//! - Epoch ordering: compared as integers
//! - `rpmvercmp`: handles `~` (pre-release), `^` (post-release), alphanumeric segments,
//!   and separator stripping.
//! - Digits sort higher than letters (e.g. `1.0.1 > 1.0.a`).

use std::cmp::Ordering;
use std::fmt;
use serde::{Deserialize, Serialize};

/// Parsed RPM package version implementing RPM EVR `rpmvercmp` comparison rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpmVersion {
    pub epoch: u32,
    pub version: String,
    pub release: String,
}

impl PartialEq for RpmVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RpmVersion {}

impl RpmVersion {
    /// Parse an RPM EVR string `[epoch:]version[-release]`.
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

        // 2. Extract version and optional release (separated by '-')
        let (version, release) = if let Some((ver, rel)) = rest.split_once('-') {
            (ver.to_string(), rel.to_string())
        } else {
            (rest.to_string(), String::new())
        };

        if version.is_empty() {
            return None;
        }

        Some(RpmVersion {
            epoch,
            version,
            release,
        })
    }
}

impl fmt::Display for RpmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch > 0 {
            write!(f, "{}:", self.epoch)?;
        }
        write!(f, "{}", self.version)?;
        if !self.release.is_empty() {
            write!(f, "-{}", self.release)?;
        }
        Ok(())
    }
}

impl Ord for RpmVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // 1. Compare epoch
        self.epoch
            .cmp(&other.epoch)
            // 2. Compare version
            .then_with(|| rpmvercmp(&self.version, &other.version))
            // 3. Compare release
            .then_with(|| rpmvercmp(&self.release, &other.release))
    }
}

impl PartialOrd for RpmVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Pure Rust implementation of RPM's `rpmvercmp` algorithm.
pub fn rpmvercmp(mut s1: &str, mut s2: &str) -> Ordering {
    if s1 == s2 {
        return Ordering::Equal;
    }

    while !s1.is_empty() || !s2.is_empty() {
        // 1. Trim non-alphanumeric delimiters, keeping '~' and '^'
        let trim_fn = |c: char| !c.is_ascii_alphanumeric() && c != '~' && c != '^';
        s1 = s1.trim_start_matches(trim_fn);
        s2 = s2.trim_start_matches(trim_fn);

        // 2. Handle '~' (pre-release: sorts before everything, including empty string)
        let s1_tilde = s1.starts_with('~');
        let s2_tilde = s2.starts_with('~');
        if s1_tilde || s2_tilde {
            if s1_tilde && !s2_tilde {
                return Ordering::Less;
            }
            if !s1_tilde && s2_tilde {
                return Ordering::Greater;
            }
            // Both start with '~'
            s1 = &s1[1..];
            s2 = &s2[1..];
            continue;
        }

        // 3. Handle '^' (post-release: sorts after empty string, but before alphanumeric)
        let s1_caret = s1.starts_with('^');
        let s2_caret = s2.starts_with('^');
        if s1_caret || s2_caret {
            if s1_caret && s2_caret {
                s1 = &s1[1..];
                s2 = &s2[1..];
                continue;
            }
            if s1_caret {
                return if s2.is_empty() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            if s2_caret {
                return if s1.is_empty() {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
        }

        // 4. Check for exhaustion
        if s1.is_empty() || s2.is_empty() {
            return if s1.is_empty() && !s2.is_empty() {
                Ordering::Less
            } else if !s1.is_empty() && s2.is_empty() {
                Ordering::Greater
            } else {
                Ordering::Equal
            };
        }

        // 5. Compare segment: numeric or alpha
        let c1 = s1.chars().next().unwrap();
        let c2 = s2.chars().next().unwrap();

        if c1.is_ascii_digit() {
            if !c2.is_ascii_digit() {
                // Digits sort higher than letters in RPM
                return Ordering::Greater;
            }

            let len1 = s1.chars().take_while(|c| c.is_ascii_digit()).count();
            let len2 = s2.chars().take_while(|c| c.is_ascii_digit()).count();

            let seg1 = &s1[..len1];
            let seg2 = &s2[..len2];

            let num1 = seg1.trim_start_matches('0');
            let num2 = seg2.trim_start_matches('0');

            match num1.len().cmp(&num2.len()) {
                Ordering::Greater => return Ordering::Greater,
                Ordering::Less => return Ordering::Less,
                Ordering::Equal => match num1.cmp(num2) {
                    Ordering::Greater => return Ordering::Greater,
                    Ordering::Less => return Ordering::Less,
                    Ordering::Equal => {
                        s1 = &s1[len1..];
                        s2 = &s2[len2..];
                    }
                },
            }
        } else {
            if c2.is_ascii_digit() {
                // Letters sort lower than digits in RPM
                return Ordering::Less;
            }

            let len1 = s1.chars().take_while(|c| c.is_ascii_alphabetic()).count();
            let len2 = s2.chars().take_while(|c| c.is_ascii_alphabetic()).count();

            let seg1 = &s1[..len1];
            let seg2 = &s2[..len2];

            match seg1.cmp(seg2) {
                Ordering::Greater => return Ordering::Greater,
                Ordering::Less => return Ordering::Less,
                Ordering::Equal => {
                    s1 = &s1[len1..];
                    s2 = &s2[len2..];
                }
            }
        }
    }

    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpm(s: &str) -> RpmVersion {
        RpmVersion::parse(s).unwrap_or_else(|| panic!("failed to parse rpm version: {}", s))
    }

    #[test]
    fn parses_epoch_version_release() {
        let v = rpm("1:3.0.7-18.el9_2");
        assert_eq!(v.epoch, 1);
        assert_eq!(v.version, "3.0.7");
        assert_eq!(v.release, "18.el9_2");
        assert_eq!(v.to_string(), "1:3.0.7-18.el9_2");
    }

    #[test]
    fn parses_no_epoch() {
        let v = rpm("3.0.7-18.el9_2");
        assert_eq!(v.epoch, 0);
        assert_eq!(v.version, "3.0.7");
        assert_eq!(v.release, "18.el9_2");
    }

    #[test]
    fn parses_no_release() {
        let v = rpm("3.0.7");
        assert_eq!(v.epoch, 0);
        assert_eq!(v.version, "3.0.7");
        assert_eq!(v.release, "");
    }

    #[test]
    fn rhel9_openssl_evr_ordering() {
        assert!(rpm("3.0.7-18.el9_2") < rpm("3.0.7-18.el9_3"));
        assert!(rpm("3.0.7-18.el9_2") < rpm("3.0.7-24.el9"));
        assert!(rpm("3.0.1-43.el9_0") < rpm("3.0.7-18.el9_2"));
    }

    #[test]
    fn rhel9_kernel_evr_ordering() {
        assert!(rpm("5.14.0-362.8.1.el9_3") < rpm("5.14.0-362.13.1.el9_3"));
        assert!(rpm("5.14.0-362.8.1.el9_3") < rpm("5.14.0-427.el9"));
        assert!(rpm("5.14.0-70.el9") < rpm("5.14.0-362.8.1.el9_3"));
    }

    #[test]
    fn rhel7_and_rhel8_examples() {
        // RHEL 7 glibc
        assert!(rpm("2.17-317.el7") < rpm("2.17-326.el7_9"));
        // RHEL 8 python38
        assert!(rpm("3.8.13-1.module+el8.7.0+16982+1022beec") < rpm("3.8.16-1.module+el8.8.0+18780+3ee0347a"));
        // RHEL 10 prototype
        assert!(rpm("6.8.0-0.rc0.20240112git1.el10") < rpm("6.8.0-1.el10"));
    }

    #[test]
    fn epoch_dominates() {
        assert!(rpm("2:1.0-1") > rpm("1:2.0-1"));
        assert!(rpm("1:1.0-1") > rpm("1.0-1"));
        assert!(rpm("0:1.0-1") == rpm("1.0-1"));
    }

    #[test]
    fn tilde_prerelease() {
        assert!(rpm("1.0~rc1-1") < rpm("1.0-1"));
        assert!(rpm("1.0~alpha-1") < rpm("1.0~beta-1"));
        assert!(rpm("1.0~beta-1") < rpm("1.0~rc1-1"));
    }

    #[test]
    fn caret_postrelease() {
        assert!(rpm("1.0^post1-1") > rpm("1.0-1"));
        assert!(rpm("1.0^post1-1") < rpm("1.0.1-1"));
        assert!(rpm("1.0~rc1") < rpm("1.0"));
        assert!(rpm("1.0") < rpm("1.0^20230101"));
        assert!(rpm("1.0^20230101") < rpm("1.1"));
    }

    #[test]
    fn digits_sort_higher_than_alpha() {
        assert!(rpm("1.0.1") > rpm("1.0.a"));
        assert!(rpm("1.0a") > rpm("1.0"));
    }
}

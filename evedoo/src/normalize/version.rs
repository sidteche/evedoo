//! Structured version comparison for vulnerability matching.
//!
//! Handles:
//! - Semver-style versions (`1.2.3`, `1.2.3-beta`, `1.2.3+build.1`)
//! - Windows 4-component versions (`1.2.3.4`)
//! - Calendar versions (`2023.10.5`)
//! - Leading `v` prefix (`v1.2.3`)
//! - Padding (`5.0` equals `5.0.0`)
//! - Pre-release ordering (`alpha < beta < rc < release`)
//! - Letter suffixes (`1.0a < 1.0b < 1.0`)
//!
//! SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;

/// Pre-release designator. Ordered: Alpha < Beta < Rc < (no pre-release).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreRelease {
    kind: PreKind,
    num: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreKind {
    Alpha,
    Beta,
    Rc,
    Dev,
    Post,
    /// Unknown / custom pre-release string — ordered alphabetically.
    Other(&'static str),
}

impl PreKind {
    fn rank(self) -> u8 {
        match self {
            PreKind::Dev => 0,
            PreKind::Alpha => 1,
            PreKind::Beta => 2,
            PreKind::Rc => 3,
            PreKind::Other(_) => 4,
            PreKind::Post => 5,
        }
    }
}

impl Ord for PreKind {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (PreKind::Other(a), PreKind::Other(b)) => a.cmp(b),
            _ => self.rank().cmp(&other.rank()),
        }
    }
}

impl PartialOrd for PreKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PreRelease {
    fn cmp(&self, other: &Self) -> Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.num.unwrap_or(0).cmp(&other.num.unwrap_or(0)))
    }
}

impl PartialOrd for PreRelease {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A parsed, comparable version.
#[derive(Debug, Clone)]
pub struct Version {
    /// Numeric release components, e.g. `[1, 2, 3]` for `1.2.3`.
    release: Vec<u32>,
    /// Letter suffix attached to the final component, e.g. `a` in `1.0a`.
    /// Present suffix sorts *before* no suffix (`1.0a < 1.0`).
    letter: Option<char>,
    /// Pre-release designator. A version with pre-release sorts *before* the
    /// same version without one (`1.0.0-beta < 1.0.0`).
    pre: Option<PreRelease>,
    /// Build metadata — parsed but ignored in comparisons.
    #[allow(dead_code)]
    build: Option<String>,
}

impl Version {
    /// Parse a version string. Returns `None` if no numeric component is found.
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        if s.is_empty() {
            return None;
        }

        // Strip leading `v` or `V`
        let s = s.strip_prefix(['v', 'V']).unwrap_or(s);

        // Split off build metadata at `+`, or at `_` — NVD publishes bounds
        // like `4.5.2_build_8848` (VMware). Treating `_` as build metadata is
        // not cosmetic: `is_version_vulnerable_fn` SILENTLY DISCARDS a bound
        // it cannot parse and then reports the finding as vulnerable, so an
        // unparsed bound becomes a false positive against every installed
        // version.
        let (s, build) = match s.split_once(['+', '_']) {
            Some((v, b)) => (v, Some(b.to_string())),
            None => (s, None),
        };

        // NVD also publishes bounds with a trailing dot (`52.0.` for Firefox
        // CVE-2017-5421, live in this database). Strip it: `52.0.` and `52.0`
        // denote the same version, and rejecting the former reported Firefox
        // 154.0.1 as vulnerable to a CVE fixed in 52.0.
        //
        // Only trailing separators go — a string with no numeric core at all
        // (`.`, `...`) must still fail, so the caller can treat it as
        // undetermined rather than inventing a comparison.
        let s = s.trim_end_matches('.');

        // Split off pre-release at `-` or at the first alpha token that follows a digit
        let (core, pre_str) = split_pre_release(s);

        let pre = pre_str.and_then(parse_pre_release);

        // Parse the numeric core and optional trailing letter
        let (release, letter) = parse_release(core)?;

        if release.is_empty() {
            return None;
        }

        Some(Version {
            release,
            letter,
            pre,
            build,
        })
    }

    /// Pad release vector to `len` components by appending zeros.
    fn padded(&self, len: usize) -> Vec<u32> {
        let mut v = self.release.clone();
        if v.len() < len {
            v.resize(len, 0);
        }
        v
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // 1. Compare release tuples, right-padded with zeros
        let len = self.release.len().max(other.release.len());
        let a = self.padded(len);
        let b = other.padded(len);
        match a.cmp(&b) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }

        // 2. Compare letter suffix: present letter sorts before absent
        //    (1.0a < 1.0b < 1.0)
        match (self.letter, other.letter) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            },
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (None, None) => {}
        }

        // 3. Compare pre-release: present pre-release sorts before absent
        //    (1.0.0-beta < 1.0.0)
        match (&self.pre, &other.pre) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

// ── Parsing helpers ───────────────────────────────────────────────────────────

fn split_pre_release(s: &str) -> (&str, Option<&str>) {
    // Prefer explicit `-` separator (semver style)
    if let Some(idx) = s.find('-') {
        return (&s[..idx], Some(&s[idx + 1..]));
    }

    // Look for alphabetic token after a digit: "1.0.0beta1", "1.2.3rc1"
    // Skip single trailing letters (those are the Version.letter field)
    let bytes = s.as_bytes();
    for i in 1..bytes.len() {
        let c = bytes[i] as char;
        let prev = bytes[i - 1] as char;
        if c.is_ascii_alphabetic() && prev.is_ascii_digit() {
            // Check that this is a multi-char token (pre-release), not a single letter suffix
            let rest = &s[i..];
            let first_word_len = rest
                .chars()
                .take_while(|ch| ch.is_ascii_alphabetic())
                .count();
            if first_word_len >= 2 {
                return (&s[..i], Some(rest));
            }
        }
    }

    (s, None)
}

fn parse_pre_release(s: &str) -> Option<PreRelease> {
    // Extract leading alpha word + optional number
    let lower = s.to_ascii_lowercase();
    let word: String = lower.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
    let rest = &lower[word.len()..];

    // Strip a possible `.` separator before the number: "rc.1" → "rc" + "1"
    let num_part = rest.trim_start_matches(|c: char| !c.is_ascii_digit());
    let num: Option<u32> = num_part
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok();

    let kind = match word.as_str() {
        "a" | "alpha" => PreKind::Alpha,
        "b" | "beta" => PreKind::Beta,
        "c" | "rc" | "pre" | "preview" => PreKind::Rc,
        "dev" => PreKind::Dev,
        "post" => PreKind::Post,
        "" => return None,
        "snapshot" => PreKind::Other("snapshot"),
        "m" | "milestone" => PreKind::Other("milestone"),
        _ => return None, // Unknown pre-release word — ignore
    };

    Some(PreRelease { kind, num })
}

/// Parse the release core: numeric components separated by `.`, with an
/// optional single trailing letter on the last component (e.g. `1.0a`).
fn parse_release(s: &str) -> Option<(Vec<u32>, Option<char>)> {
    if s.is_empty() {
        return None;
    }

    let mut components = Vec::new();
    let mut letter: Option<char> = None;

    for (i, part) in s.split('.').enumerate() {
        if part.is_empty() {
            return None;
        }

        // The final component may have a trailing letter (e.g. "0a")
        let is_last = i == s.split('.').count() - 1;

        let (num_str, suffix) = split_trailing_letter(part);

        let num: u32 = num_str.parse().ok()?;
        components.push(num);

        if let Some(c) = suffix {
            if !is_last {
                // Letters only allowed on the last component
                return None;
            }
            letter = Some(c);
        }
    }

    Some((components, letter))
}

fn split_trailing_letter(part: &str) -> (&str, Option<char>) {
    let chars: Vec<char> = part.chars().collect();
    if chars.len() >= 2 {
        let last = chars[chars.len() - 1];
        let second_last = chars[chars.len() - 2];
        if last.is_ascii_alphabetic() && second_last.is_ascii_digit() {
            // Single trailing letter on a numeric part
            let num_end = part.len() - last.len_utf8();
            return (&part[..num_end], Some(last.to_ascii_lowercase()));
        }
    }
    (part, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("failed to parse {:?}", s))
    }

    #[test]
    fn parses_basic_semver() {
        let x = v("1.2.3");
        assert_eq!(x.release, vec![1, 2, 3]);
        assert_eq!(x.letter, None);
        assert_eq!(x.pre, None);
    }

    #[test]
    fn parses_leading_v_prefix() {
        assert_eq!(v("v1.2.3"), v("1.2.3"));
        assert_eq!(v("V2.0"), v("2.0"));
    }

    #[test]
    fn parses_windows_4_component() {
        let x = v("1.2.3.4");
        assert_eq!(x.release, vec![1, 2, 3, 4]);
    }

    #[test]
    fn padding_equality() {
        assert_eq!(v("5.0"), v("5.0.0"));
        assert_eq!(v("1"), v("1.0.0"));
        assert_eq!(v("1.2.3.0"), v("1.2.3"));
    }

    #[test]
    fn prerelease_less_than_release() {
        assert!(v("1.2.0-beta") < v("1.2.0"));
        assert!(v("1.2.0-rc.1") < v("1.2.0"));
        assert!(v("1.0.0-alpha") < v("1.0.0-beta"));
        assert!(v("1.0.0-beta") < v("1.0.0-rc.1"));
    }

    #[test]
    fn prerelease_numeric_ordering() {
        assert!(v("1.0.0-rc.1") < v("1.0.0-rc.2"));
        assert!(v("1.0.0-beta.1") < v("1.0.0-beta.10"));
    }

    #[test]
    fn prerelease_without_dash() {
        // "1.2.3rc1" — pre-release attached without a dash
        assert!(v("1.2.3rc1") < v("1.2.3"));
        assert!(v("1.2.3alpha") < v("1.2.3beta"));
    }

    #[test]
    fn letter_suffix_ordering() {
        assert!(v("1.0a") < v("1.0b"));
        assert!(v("1.0b") < v("1.0"));
        assert_eq!(v("1.0a").letter, Some('a'));
    }

    #[test]
    fn calendar_version() {
        assert!(v("2023.10.5") > v("2023.9.10"));
        assert!(v("2024.1.1") > v("2023.12.31"));
    }

    #[test]
    fn build_metadata_ignored() {
        assert_eq!(v("1.0.0+build.1"), v("1.0.0+build.2"));
        assert_eq!(v("1.0.0+abc"), v("1.0.0"));
    }

    #[test]
    fn invalid_input_returns_none() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse("abc").is_none());
        assert!(Version::parse("not.a.version").is_none());
    }

    #[test]
    fn whitespace_trimmed() {
        assert_eq!(v("  1.2.3  "), v("1.2.3"));
    }

    #[test]
    fn release_component_ordering() {
        assert!(v("1.10.0") > v("1.9.0"));
        assert!(v("2.0.0") > v("1.99.99"));
    }

    #[test]
    fn dev_sorts_before_alpha() {
        assert!(v("1.0.0-dev") < v("1.0.0-alpha"));
        assert!(v("1.0.0-alpha") < v("1.0.0-beta"));
    }
    /// NVD publishes version bounds with a trailing dot — `cpe_matches` in the
    /// live database holds `version_end_excluding = "52.0."` for CVE-2017-5421
    /// (Firefox). Rejecting it is not a cosmetic parser gap: the caller,
    /// `is_version_vulnerable_fn`, SILENTLY DISCARDS a bound it cannot parse
    /// and then reports the finding as vulnerable. That is how Firefox 154.0.1
    /// was reported against a CVE fixed in 52.0.
    #[test]
    fn trailing_dot_bound_parses_and_compares() {
        let fixed = Version::parse("52.0.").expect("NVD really publishes this form");
        assert_eq!(fixed, Version::parse("52.0").unwrap());

        let installed = Version::parse("154.0.1").unwrap();
        assert!(
            installed >= fixed,
            "Firefox 154.0.1 is far above the 52.0 fix and must not be flagged"
        );
    }

    /// Same failure, different shape: VMware bounds carry an underscore build
    /// suffix. `4.5.2_build_8848` is version 4.5.2 with build metadata, and
    /// must compare as such rather than being dropped.
    #[test]
    fn underscore_build_metadata_parses_as_build_not_failure() {
        let fixed = Version::parse("4.5.2_build_8848").expect("underscore build suffix");
        assert_eq!(fixed.release, vec![4, 5, 2]);

        let installed = Version::parse("26.0.0").unwrap();
        assert!(
            installed >= fixed,
            "VMware 26.0.0 is far above 4.5.2 and must not be flagged"
        );
    }

    /// The fix must not turn genuinely meaningless strings into versions —
    /// a bound we cannot understand has to stay unparseable so the caller can
    /// treat it as undetermined rather than inventing a comparison.
    #[test]
    fn still_rejects_input_with_no_numeric_core() {
        assert!(Version::parse(".").is_none());
        assert!(Version::parse("...").is_none());
        assert!(Version::parse("_build_1").is_none());
        assert!(Version::parse("").is_none());
    }

}

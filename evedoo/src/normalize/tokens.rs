//! Lightweight tokeniser and set helpers for CPE matching.
//!
//! Splits display names into lowercase alphanumeric tokens, drops a small
//! set of English stopwords and architecture noise, and provides a subset
//! check used by the curated-mapping scorer.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

const STOPWORDS: &[&str] = &[
    "the", "for", "and", "of", "a", "an", "to",
    "x64", "x86", "amd64", "arm64", "ia32",
    "32", "64", "bit", "32bit", "64bit",
    "v",
];

/// Edition/variant words. An extra qualifier token in a display name
/// ("Pro", "Enterprise", "DC") usually still refers to the same CPE
/// product, so the scorer penalises it only lightly.
const QUALIFIERS: &[&str] = &[
    "pro", "professional", "enterprise", "standard", "home",
    "ultimate", "premium", "community", "lts", "dc", "edition",
    "personal", "free", "plus", "lite", "portable", "stable",
];

/// Packaging cruft that never carries product identity
/// ("Redistributable", "Runtime"). Extra noise tokens cost nothing.
///
/// Deliberately excludes installer/updater words — see [`ARTIFACT`].
const NOISE: &[&str] = &[
    "redistributable", "runtime", "version", "build", "release",
    "package", "bundle",
];

/// Words identifying a *companion artifact* rather than the product itself:
/// the installer, updater, or uninstaller shipped alongside it.
///
/// These carry the parent product's display name but their own version
/// stream — "Google Chrome Installer" reports 127.0.6512.0 while the real
/// Chrome is 151.x — so matching them against the product's CPE flags every
/// CVE fixed in between. Observed as 73% of one real scan's findings.
///
/// When such a word appears as an *extra* token (in the software name but
/// not in the matched pattern), the match is vetoed outright. A product
/// whose own name contains one of these (e.g. "Inno Setup") is unaffected,
/// because the word is then part of the pattern and never counted as extra.
const ARTIFACT: &[&str] = &[
    "installer", "setup", "updater", "update", "uninstall", "uninstaller",
    "helper", "bootstrapper", "launcher",
];

/// Scoring class of an extra display-name token (one present in the
/// software name but absent from the curated pattern).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenClass {
    /// Identity-bearing word — probably a different product. Full penalty.
    Core,
    /// Edition/variant word — probably the same product. Light penalty.
    Qualifier,
    /// Packaging cruft — no penalty.
    Noise,
    /// Installer/updater/uninstaller word — this is a companion artifact,
    /// not the product. Vetoes the match entirely.
    Artifact,
}

/// Classify an extra token for the curated-mapping scorer. Assumes the
/// token came out of `tokenize`, so stopwords never reach here.
pub fn classify_token(token: &str) -> TokenClass {
    if ARTIFACT.contains(&token) {
        TokenClass::Artifact
    } else if NOISE.contains(&token) {
        TokenClass::Noise
    } else if QUALIFIERS.contains(&token) {
        TokenClass::Qualifier
    } else {
        TokenClass::Core
    }
}

/// Tokenise a display name into lowercase alphanumeric tokens, dropping
/// stopwords and empty tokens.
pub fn tokenize(name: &str) -> Vec<String> {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .filter(|t| !t.is_empty() && !STOPWORDS.contains(t))
        .map(|t| t.to_string())
        .collect()
}

/// Is every token in `needle` also present in `haystack`? (Subset check.)
pub fn is_subset(needle: &[String], haystack: &[String]) -> bool {
    let haystack_set: HashSet<&String> = haystack.iter().collect();
    needle.iter().all(|t| haystack_set.contains(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<String> {
        tokenize(s)
    }

    #[test]
    fn tokenize_basic_two_words() {
        assert_eq!(toks("Google Chrome"), vec!["google", "chrome"]);
    }

    #[test]
    fn tokenize_strips_parens_and_arch() {
        assert_eq!(toks("Microsoft 365 (x64)"), vec!["microsoft", "365"]);
        assert_eq!(toks("Git for Windows (64-bit)"), vec!["git", "windows"]);
    }

    #[test]
    fn tokenize_splits_on_punctuation() {
        assert_eq!(toks("7-Zip"), vec!["7", "zip"]);
        assert_eq!(toks("Notepad++"), vec!["notepad"]);
    }

    #[test]
    fn tokenize_lowercases() {
        assert_eq!(toks("VLC Media Player"), vec!["vlc", "media", "player"]);
    }

    #[test]
    fn tokenize_drops_stopwords() {
        // "for", "and", "the" dropped; architecture tokens dropped
        assert_eq!(
            toks("The Apache and HTTP Server for x64"),
            vec!["apache", "http", "server"]
        );
    }

    #[test]
    fn tokenize_empty_input() {
        assert!(toks("").is_empty());
        assert!(toks("   ").is_empty());
        assert!(toks("()-").is_empty());
    }

    #[test]
    fn is_subset_true_when_all_needle_tokens_present() {
        let needle = toks("python");
        let haystack = toks("Python Launcher");
        assert!(is_subset(&needle, &haystack));
    }

    #[test]
    fn is_subset_false_when_needle_has_extra() {
        let needle = toks("Google Chrome Beta");
        let haystack = toks("Google Chrome");
        assert!(!is_subset(&needle, &haystack));
    }

    #[test]
    fn classify_token_qualifiers() {
        for q in ["pro", "professional", "enterprise", "dc", "lts", "edition"] {
            assert_eq!(classify_token(q), TokenClass::Qualifier, "{q}");
        }
    }

    #[test]
    fn classify_token_noise() {
        for n in ["redistributable", "runtime", "version", "build", "package"] {
            assert_eq!(classify_token(n), TokenClass::Noise, "{n}");
        }
    }

    /// Companion-artifact words outrank noise: "Google Chrome Installer" is
    /// not Chrome, so these must veto rather than score.
    #[test]
    fn classify_token_artifact() {
        for a in [
            "installer", "setup", "updater", "update", "uninstall", "launcher",
        ] {
            assert_eq!(classify_token(a), TokenClass::Artifact, "{a}");
        }
    }

    #[test]
    fn classify_token_core_by_default() {
        for c in ["acrobat", "server", "studio", "chrome", "reader"] {
            assert_eq!(classify_token(c), TokenClass::Core, "{c}");
        }
    }
}

//! Decoding of CPE 2.3 formatted-string escapes in vendor/product names.
//!
//! The CPE 2.3 formatted string backslash-quotes punctuation inside a
//! component: NVD publishes Notepad++ as `notepad\+\+` and Erlang/OTP as
//! `erlang\/otp`. cve-db-builder stored those components verbatim, so 36,175
//! `cpe_matches` rows across 7,014 products carried the escapes, and no
//! installed-software name or curated mapping could ever equal them — every
//! CVE for those products was silently unmatched.
//!
//! The matcher decodes at load time, so databases built before the
//! cve-db-builder fix match correctly without a rebuild; decoding an already
//! decoded name is a no-op.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

/// Decode CPE 2.3 backslash escapes: `\x` becomes `x`. A trailing lone
/// backslash is kept rather than dropped. Borrows when there is nothing to
/// decode, which is the case for the overwhelming majority of rows.
pub fn unescape(component: &str) -> Cow<'_, str> {
    if !component.contains('\\') {
        return Cow::Borrowed(component);
    }
    let mut out = String::with_capacity(component.len());
    let mut chars = component.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backslash_quoted_character_is_decoded() {
        // NVD stores Notepad++ as `notepad\+\+`. Matched against undecoded,
        // every Notepad++ CVE was invisible — 5 on one host alone.
        assert_eq!(unescape("notepad\\+\\+"), "notepad++");
        assert_eq!(unescape("erlang\\/otp"), "erlang/otp");
        assert_eq!(unescape("1\\&1_online_storage"), "1&1_online_storage");
    }

    #[test]
    fn an_escaped_backslash_decodes_to_one_backslash() {
        assert_eq!(unescape("a\\\\b"), "a\\b");
    }

    #[test]
    fn a_trailing_lone_backslash_is_kept() {
        // Malformed input must not lose characters silently.
        assert_eq!(unescape("1c\\"), "1c\\");
    }

    #[test]
    fn plain_names_are_returned_unchanged_and_borrowed() {
        for plain in ["vm_virtualbox", "postgresql", "", "notepad++"] {
            assert!(matches!(unescape(plain), std::borrow::Cow::Borrowed(_)));
            assert_eq!(unescape(plain), plain);
        }
    }
}

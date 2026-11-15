//! Display-name and package-name cleanup.
//!
//! These helpers translate the messy strings we get from Windows sources
//! (AppX package ids, Uninstall registry display names, WinGet output) into
//! the flattened forms the curated mapping scorer and CPE lookups expect.
//!
//! Moved out of `scanner::appx` and `matcher::cpe` in Phase 6 so there's one
//! place to reach for when a new edge case shows up.
//!
//! SPDX-License-Identifier: Apache-2.0

/// Normalize an AppX package name to a human-readable display name.
///
/// Algorithm:
/// 1. Split on `.`
/// 2. Drop the first segment (publisher prefix, e.g. `PythonSoftwareFoundation`)
/// 3. Drop trailing segments that are purely numeric (version components like `3`, `13`)
/// 4. Join remaining segments with a space, expanding CamelCase to words
pub fn normalize_appx_name(name: &str) -> String {
    let segments: Vec<&str> = name.split('.').collect();

    if segments.len() < 2 {
        return camel_to_words(name);
    }

    let product_segments: Vec<&str> = segments[1..]
        .iter()
        .rev()
        .skip_while(|s| s.chars().all(|c| c.is_ascii_digit()))
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    if product_segments.is_empty() {
        return camel_to_words(segments[1]);
    }

    let words: Vec<String> = product_segments
        .iter()
        .flat_map(|seg| {
            camel_to_words(seg)
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();

    words.join(" ")
}

/// Convert a CamelCase or PascalCase string to space-separated words.
///
/// `VisualStudioCode`    → `Visual Studio Code`
/// `NVIDIAControlPanel`  → `NVIDIA Control Panel`
pub fn camel_to_words(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 8);
    let chars: Vec<char> = s.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        if i == 0 {
            result.push(c);
            continue;
        }
        let prev = chars[i - 1];
        let next = chars.get(i + 1).copied();

        // Insert space before uppercase if:
        // - previous char is lowercase (VisualStudio → Visual Studio)
        // - previous char is uppercase AND next char is lowercase (NVIDIAControl → NVIDIA Control)
        let insert_space = c.is_uppercase()
            && (prev.is_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_uppercase() && next.is_some_and(|n| n.is_lowercase())));

        if insert_space {
            result.push(' ');
        }
        result.push(c);
    }

    result
}

/// Normalize an AppX / MSIX publisher string.
///
/// `CN=Microsoft Corporation, O=Microsoft Corporation, ...` → `Microsoft Corporation`
pub fn normalize_publisher(publisher: &str) -> Option<String> {
    if publisher.is_empty() {
        return None;
    }
    let s = publisher.trim_start_matches("CN=");
    let name = s.split(',').next().unwrap_or(s).trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Extract a clean, underscore-joined product name from a Windows display
/// name, suitable for use in Layer 3 (product-only) CPE lookups.
///
/// Strips architecture noise, collapses version-looking trailing tokens, and
/// falls back to the first two tokens when the heuristic clears the name out.
pub fn extract_product_name(display_name: &str) -> String {
    let name = display_name.to_lowercase();

    let name = name
        .replace(" (x64)", "")
        .replace(" (x86)", "")
        .replace(" (64-bit)", "")
        .replace(" (32-bit)", "")
        .replace(" - ", " ");

    let parts: Vec<&str> = name.split_whitespace().collect();
    let mut product_parts = Vec::new();
    for part in &parts {
        // Stop at version-like tokens (digit-leading with a dot)
        if part.chars().next().map(|c| c.is_numeric()).unwrap_or(false)
            && part.contains('.')
        {
            break;
        }
        // Stop at common VC++ major-version markers
        if ["v14", "v12", "v8", "v9", "v10", "v11"].contains(part) {
            break;
        }
        product_parts.push(*part);
    }

    if product_parts.is_empty() {
        product_parts = parts.into_iter().take(2).collect();
    }

    product_parts.join("_").replace(' ', "_")
}

/// Replace a tagged `DisplayVersion` with the release the `DisplayName` states,
/// but only when that release *extends* the version's numeric prefix.
///
/// Python's install manager writes `DisplayVersion = "3.14-64"` (release plus
/// architecture tag) beside `DisplayName = "Python 3.14.7"`. Parsed as a
/// version, `-64` becomes a component and the comparison against CPE bounds is
/// meaningless. The rule is deliberately narrow so a name can never override a
/// real version:
///
/// - it acts only when `DisplayVersion` carries a non-numeric tail (`3.14-64`);
///   a clean `24.08` or `16.1` is never touched; and
/// - the replacement must be a dotted version from the name that starts with
///   the version's numeric prefix plus `.` — `3.14.7` extends `3.14`, while
///   `3.13.1` does not and is ignored.
// Only the Windows registry scanner calls this; it stays compiled (and tested)
// on every platform, so tell the non-Windows builds it is not dead by mistake.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn refine_version_from_name(name: &str, version: Option<&str>) -> Option<String> {
    let version = version?;
    let prefix_len = version
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(version.len());
    let prefix = version[..prefix_len].trim_end_matches('.');
    let has_tag = prefix_len < version.len();

    if has_tag && prefix.contains('.') {
        let wanted = format!("{prefix}.");
        let from_name = name
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .map(|t| t.trim_end_matches('.'))
            .find(|t| t.starts_with(&wanted) && t[wanted.len()..].chars().all(|c| c.is_ascii_digit() || c == '.') && t.len() > wanted.len());
        if let Some(v) = from_name {
            return Some(v.to_string());
        }
    }
    Some(version.to_string())
}

/// The identity two scanners must agree on for one install to be counted once.
///
/// Sources spell the same product differently: the registry's Uninstall entry
/// carries the release in the display name — `PostgreSQL 16 ` — while the PE
/// fingerprint of `uninstall-postgresql.exe` in that same directory reads
/// `PostgreSQL` off the version resource. Keyed on the raw name those look like
/// two installs, and PostgreSQL 16.1's 45 CVEs were reported as 90 findings.
///
/// A trailing release token is therefore dropped from the name. The version is
/// kept in the key and is what still separates products that share a stem —
/// `Windows 10` and `Windows 11` both reduce to `windows` and are told apart by
/// their OS build, never by the name alone.
pub fn dedup_key(name: &str, version: Option<&str>) -> String {
    let mut stem = name.trim();

    // Drop a trailing parenthetical made only of architecture words: the
    // registry's "Notepad++ (64-bit x64)" is the PE fingerprint's "Notepad++".
    // Anything else in the parentheses — "(Click-to-Run)" — may name a
    // different edition, so it stays.
    if let Some(open) = stem.rfind('(') {
        if let Some(inner) = stem[open + 1..].strip_suffix(')') {
            const ARCH: &[&str] = &[
                "x64", "x86", "64-bit", "32-bit", "64bit", "32bit", "amd64", "arm64", "x86_64",
            ];
            let is_arch = !inner.trim().is_empty()
                && inner
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .filter(|w| !w.is_empty())
                    .all(|w| ARCH.contains(&w.to_ascii_lowercase().as_str()));
            if is_arch && !stem[..open].trim().is_empty() {
                stem = stem[..open].trim();
            }
        }
    }

    // Peel trailing release tokens: "PostgreSQL 16 " and "Python 3.14.7" are
    // the product plus its release, not distinct products.
    while let Some((head, tail)) = stem.rsplit_once(' ') {
        let tail = tail.trim();
        if tail.is_empty() || tail.chars().all(|c| c.is_ascii_digit() || c == '.') {
            let head = head.trim();
            // Never strip a name down to nothing: "2048" is a product, and an
            // empty stem would bucket every all-digit name together.
            if head.is_empty() {
                break;
            }
            stem = head;
        } else {
            break;
        }
    }

    format!("{}|{}", stem.to_lowercase(), version.unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tagged_display_version_is_refined_from_the_display_name() {
        // Python's install manager writes DisplayVersion "3.14-64" (release
        // plus architecture tag) while DisplayName carries "Python 3.14.7".
        // "-64" parsed as a version component produced 13 findings of
        // unknown accuracy.
        assert_eq!(
            refine_version_from_name("Python 3.14.7", Some("3.14-64")).as_deref(),
            Some("3.14.7")
        );
        assert_eq!(
            refine_version_from_name("Python 3.13.12 (32-bit)", Some("3.13-32")).as_deref(),
            Some("3.13.12")
        );
    }

    #[test]
    fn a_name_version_that_does_not_extend_the_display_version_is_ignored() {
        // A different release in the name must never override the registry.
        assert_eq!(
            refine_version_from_name("Python 3.13.1", Some("3.14-64")).as_deref(),
            Some("3.14-64")
        );
    }

    #[test]
    fn a_clean_display_version_is_left_alone() {
        assert_eq!(
            refine_version_from_name("7-Zip 24.08 (x64)", Some("24.08")).as_deref(),
            Some("24.08")
        );
        assert_eq!(
            refine_version_from_name("PostgreSQL 16 ", Some("16.1")).as_deref(),
            Some("16.1")
        );
        assert_eq!(refine_version_from_name("Python 3.14.7", None), None);
    }

    #[test]
    fn dedup_key_drops_a_trailing_architecture_parenthetical() {
        // The registry names it "Notepad++ (64-bit x64)", the PE fingerprint
        // of notepad++.exe "Notepad++": one install, reported twice per CVE.
        assert_eq!(
            dedup_key("Notepad++ (64-bit x64)", Some("8.9.1")),
            dedup_key("Notepad++", Some("8.9.1"))
        );
        assert_eq!(
            dedup_key("PuTTY release 0.82 (64-bit)", Some("0.82.0.0")),
            dedup_key("PuTTY release 0.82", Some("0.82.0.0"))
        );
        assert_eq!(dedup_key("7-Zip 24.08 (x64)", Some("24.08")), "7-zip|24.08");
    }

    #[test]
    fn dedup_key_keeps_a_parenthetical_that_names_an_edition() {
        // Only architecture words are packaging noise; anything else in the
        // parentheses may distinguish a different product.
        assert_ne!(
            dedup_key("Microsoft Office (Click-to-Run)", Some("16.0")),
            dedup_key("Microsoft Office", Some("16.0"))
        );
    }

    #[test]
    fn dedup_key_collapses_one_install_named_two_ways() {
        // The registry calls it "PostgreSQL 16 " and the PE fingerprint of
        // uninstall-postgresql.exe in the same directory calls it "PostgreSQL".
        // Keyed on the raw name those are two installs, and 45 CVEs were
        // reported as 90 findings.
        assert_eq!(
            dedup_key("PostgreSQL 16 ", Some("16.1")),
            dedup_key("PostgreSQL", Some("16.1"))
        );
        assert_eq!(
            dedup_key("Python 3.14.7", Some("3.14.7")),
            dedup_key("Python", Some("3.14.7"))
        );
    }

    #[test]
    fn dedup_key_separates_products_sharing_a_stem_by_their_version() {
        // "Windows 10" and "Windows 11" both reduce to the stem "windows", so
        // the version is what keeps them apart — which is why the key is the
        // pair and never the name alone.
        assert_ne!(
            dedup_key("Windows 10", Some("10.0.19045")),
            dedup_key("Windows 11", Some("10.0.26200"))
        );
    }

    #[test]
    fn dedup_key_keeps_digits_that_are_part_of_the_name() {
        // A digit inside the name, rather than a release number appended to it,
        // must survive.
        assert_eq!(dedup_key("7-Zip", Some("24.0")), "7-zip|24.0");
        assert_eq!(
            dedup_key("Visual Studio Code", Some("1.9")),
            "visual studio code|1.9"
        );
    }

    #[test]
    fn dedup_key_never_strips_a_name_down_to_nothing() {
        // Clearing the stem out entirely would collapse every all-digit product
        // into one bucket. The trimmed original stands instead.
        assert_eq!(dedup_key("2048", Some("1.0")), "2048|1.0");
        assert_eq!(dedup_key("  ", None), "|");
    }

    #[test]
    fn camel_to_words_basic() {
        assert_eq!(camel_to_words("VisualStudioCode"), "Visual Studio Code");
        assert_eq!(camel_to_words("NVIDIAControlPanel"), "NVIDIA Control Panel");
        assert_eq!(camel_to_words("Python"), "Python");
        assert_eq!(camel_to_words("Firefox"), "Firefox");
    }

    #[test]
    fn normalize_appx_name_strips_publisher() {
        assert_eq!(
            normalize_appx_name("PythonSoftwareFoundation.Python.3.13"),
            "Python"
        );
        assert_eq!(
            normalize_appx_name("Microsoft.VisualStudioCode"),
            "Visual Studio Code"
        );
        assert_eq!(
            normalize_appx_name("NVIDIACorp.NVIDIAControlPanel"),
            "NVIDIA Control Panel"
        );
        assert_eq!(normalize_appx_name("NotepadPlusPlus"), "Notepad Plus Plus");
        assert_eq!(
            normalize_appx_name("AppleInc.AppleMusicWin"),
            "Apple Music Win"
        );
    }

    #[test]
    fn normalize_publisher_strips_cn() {
        assert_eq!(
            normalize_publisher("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond"),
            Some("Microsoft Corporation".to_string())
        );
        assert_eq!(
            normalize_publisher("CN=Python Software Foundation"),
            Some("Python Software Foundation".to_string())
        );
        assert_eq!(normalize_publisher(""), None);
    }

    #[test]
    fn extract_product_name_strips_arch_and_version() {
        assert_eq!(extract_product_name("Git 2.43.0"), "git");
        assert_eq!(extract_product_name("Google Chrome (x64)"), "google_chrome");
        assert_eq!(
            extract_product_name("Microsoft Visual C++ v14 Redistributable"),
            "microsoft_visual_c++"
        );
    }

    #[test]
    fn extract_product_name_falls_back_when_all_tokens_stripped() {
        // Pure version-only input → falls back to the first two tokens.
        assert_eq!(extract_product_name("1.0.0 2.0.0"), "1.0.0_2.0.0");
    }
}

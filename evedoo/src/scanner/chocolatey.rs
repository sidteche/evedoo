//! Chocolatey package scanner.
//!
//! Detects packages installed by Chocolatey by reading the `.nuspec` metadata
//! file for each package under `%ChocolateyInstall%\lib\<pkg>\<pkg>.nuspec`
//! (default `C:\ProgramData\chocolatey`). Filesystem-based so it works even
//! when the `choco` CLI is not on PATH — important for service accounts and
//! machines where the user running the scan hasn't imported Chocolatey's PATH
//! fragment.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::path::PathBuf;

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};

pub struct ChocolateyScanner;

impl ChocolateyScanner {
    pub fn new() -> Self {
        ChocolateyScanner
    }

    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let install_dir = match Self::install_dir() {
            Some(p) => p,
            None => {
                debug!("Chocolatey install directory not found");
                return Vec::new();
            }
        };

        let lib_dir = install_dir.join("lib");
        if !lib_dir.is_dir() {
            debug!("Chocolatey lib dir missing: {}", lib_dir.display());
            return Vec::new();
        }

        let entries = match fs::read_dir(&lib_dir) {
            Ok(e) => e,
            Err(e) => {
                debug!("Failed to read {}: {}", lib_dir.display(), e);
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        for entry in entries.flatten() {
            let pkg_dir = entry.path();
            if !pkg_dir.is_dir() {
                continue;
            }
            let pkg_name = match pkg_dir.file_name().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let nuspec = pkg_dir.join(format!("{}.nuspec", pkg_name));
            if !nuspec.is_file() {
                continue;
            }

            let xml = match fs::read_to_string(&nuspec) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to read {}: {}", nuspec.display(), e);
                    continue;
                }
            };

            let (id, version) = match parse_nuspec(&xml) {
                Some(pair) => pair,
                None => continue,
            };

            debug!("Chocolatey: {} v{}", id, version);
            results.push(DetectedSoftware {
                name: id.clone(),
                version: Some(version),
                publisher: Some("chocolatey".to_string()),
                install_location: Some(pkg_dir.to_string_lossy().into_owned()),
                install_date: None,
                registry_key: format!("chocolatey://{}", id),
                architecture: Architecture::Unknown,
            });
        }

        results
    }

    /// Locate the Chocolatey install directory. Honours the `ChocolateyInstall`
    /// env var set by the Chocolatey installer, falls back to the documented
    /// default `C:\ProgramData\chocolatey`.
    fn install_dir() -> Option<PathBuf> {
        if let Ok(p) = env::var("ChocolateyInstall") {
            let path = PathBuf::from(p);
            if path.is_dir() {
                return Some(path);
            }
        }
        let default = PathBuf::from(r"C:\ProgramData\chocolatey");
        if default.is_dir() {
            return Some(default);
        }
        None
    }
}

impl Default for ChocolateyScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract `<id>` and `<version>` from a nuspec XML body.
///
/// The first occurrence of each tag is always the one inside `<metadata>` —
/// `<dependency>` entries use attribute form (`id="foo" version="1.0"`) which
/// extract_tag will not match.
fn parse_nuspec(xml: &str) -> Option<(String, String)> {
    let id = extract_tag(xml, "id")?;
    let version = extract_tag(xml, "version")?;
    if id.is_empty() || version.is_empty() {
        return None;
    }
    Some((id, version))
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let rel_end = xml[start..].find(&close)?;
    Some(xml[start..start + rel_end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>git</id>
    <version>2.44.0</version>
    <title>Git (Install)</title>
    <authors>Johannes Schindelin</authors>
    <dependencies>
      <dependency id="chocolatey-core.extension" version="1.3.3" />
    </dependencies>
  </metadata>
</package>"#;

    #[test]
    fn parses_id_and_version_from_metadata() {
        let (id, version) = parse_nuspec(SAMPLE).unwrap();
        assert_eq!(id, "git");
        assert_eq!(version, "2.44.0");
    }

    #[test]
    fn ignores_dependency_attribute_id_and_version() {
        // Even though <dependency id="..." version="..." /> appears after the
        // metadata block, extract_tag matches literal <id> / <version> tags
        // only, so the first (metadata) occurrence wins.
        let (id, version) = parse_nuspec(SAMPLE).unwrap();
        assert_ne!(id, "chocolatey-core.extension");
        assert_ne!(version, "1.3.3");
    }

    #[test]
    fn returns_none_on_missing_tags() {
        let xml = r#"<package><metadata><title>x</title></metadata></package>"#;
        assert!(parse_nuspec(xml).is_none());
    }

    #[test]
    fn trims_whitespace_inside_tags() {
        let xml = "<metadata><id>\n  git\n  </id><version>\t2.44.0\t</version></metadata>";
        let (id, version) = parse_nuspec(xml).unwrap();
        assert_eq!(id, "git");
        assert_eq!(version, "2.44.0");
    }

    #[test]
    fn chocolatey_scanner_does_not_panic() {
        // On Linux CI and machines without Chocolatey, scan() must return an
        // empty Vec rather than panicking.
        let _ = ChocolateyScanner::new().scan();
    }
}

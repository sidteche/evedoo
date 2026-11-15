//! Windows Store / AppX / MSIX package scanner.
//!
//! Detects applications installed via the Microsoft Store or MSIX packaging,
//! which do not appear in the standard Uninstall registry keys.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use tracing::debug;

use crate::models::{Architecture, DetectedSoftware};
use crate::normalize::names::{normalize_appx_name, normalize_publisher};

pub struct AppxScanner;

impl AppxScanner {
    pub fn new() -> Self {
        AppxScanner
    }

    pub fn scan(&self) -> Vec<DetectedSoftware> {
        let output = match Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-AppxPackage | Select-Object Name,Version,Publisher,InstallLocation | ConvertTo-Json -Compress",
            ])
            .output()
        {
            Ok(o) if o.status.success() => o.stdout,
            Ok(o) => {
                debug!(
                    "Get-AppxPackage failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
                return Vec::new();
            }
            Err(e) => {
                debug!("Could not run powershell: {}", e);
                return Vec::new();
            }
        };

        let json_str = String::from_utf8_lossy(&output);
        self.parse_json(&json_str)
    }

    fn parse_json(&self, json: &str) -> Vec<DetectedSoftware> {
        let value: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(e) => {
                debug!("Failed to parse Get-AppxPackage JSON: {}", e);
                return Vec::new();
            }
        };

        // Output is either a single object or an array
        let arr = match value {
            serde_json::Value::Array(a) => a,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => return Vec::new(),
        };

        let mut results = Vec::new();
        for item in arr {
            let name = match item["Name"].as_str() {
                Some(n) => n.to_string(),
                None => continue,
            };
            let version_raw = item["Version"].as_str().unwrap_or("").to_string();
            let publisher_raw = item["Publisher"].as_str().unwrap_or("").to_string();

            if should_skip(&name) {
                continue;
            }

            let normalized = normalize_appx_name(&name);
            if normalized.len() < 2 {
                continue;
            }

            let install_location = item["InstallLocation"].as_str().map(str::to_string);

            let version = match resolve_payload_version(
                &normalized,
                install_location.as_deref(),
                trim_version(&version_raw),
            ) {
                PayloadVerdict::Stub => {
                    debug!(
                        "AppX: {} has no executable payload — Store stub, skipping",
                        name
                    );
                    continue;
                }
                PayloadVerdict::Version(v) => v,
            };

            let publisher = normalize_publisher(&publisher_raw);

            debug!(
                "AppX: {} => '{}' v{}",
                name,
                normalized,
                version.as_deref().unwrap_or("?")
            );

            results.push(DetectedSoftware {
                name: normalized,
                version,
                publisher,
                install_location,
                install_date: None,
                registry_key: format!("appx://{}", name),
                architecture: Architecture::Unknown,
            });
        }

        results
    }
}

impl Default for AppxScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true for framework/runtime/system packages that aren't worth scanning for CVEs.
fn should_skip(name: &str) -> bool {
    // GUID-style names (no dots, all hex + hyphens)
    if !name.contains('.') {
        let inner = name.replace('-', "");
        if inner.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    const SKIP_PATTERNS: &[&str] = &[
        "Runtime",
        "Framework",
        "VCLibs",
        "UI.Xaml",
        "WindowsAppRuntime",
        "NET.Native",
        "DirectXRuntime",
        "WindowsStore",
        "StorePurchaseApp",
        "DesktopAppInstaller",
        "WinAppRuntime",
        "AppRuntime",
    ];

    for pat in SKIP_PATTERNS {
        if name.contains(pat) {
            return true;
        }
    }

    false
}

/// Trim AppX version to at most 3 components (e.g., `3.13.3312.0` → `3.13.3312`).
fn trim_version(v: &str) -> Option<String> {
    if v.is_empty() {
        return None;
    }
    let parts: Vec<&str> = v.splitn(5, '.').collect();
    let trimmed = parts[..parts.len().min(3)].join(".");
    Some(trimmed)
}

/// What a Store package's contents say about it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PayloadVerdict {
    /// The package contains no executable code, so it cannot carry a
    /// vulnerability. `Microsoft.VisualStudioCode` is one: three XML/signature
    /// files and nothing else, whose Store version `1.0.137` sorts below every
    /// VS Code CPE bound and therefore matched every VS Code CVE ever filed.
    Stub,
    /// The package contains code. The version is the primary executable's
    /// product version when one is readable, otherwise the Store version —
    /// absence of a version resource is not grounds to drop a real package.
    Version(Option<String>),
}

/// Decide a Store package's version from what it actually installs.
///
/// A Store package's `Version` is the *packaging* number and need not track
/// the product: `PythonSoftwareFoundation.Python.3.13` reports `3.13.3824`
/// while its `python313.dll` reports the true `3.13.14`. Reading the payload
/// fixes matching in both directions — `3.13.3824` sorts *above* real CPE
/// bounds like `< 3.13.6`, so the Store number was causing false negatives
/// there, just as it caused false positives for VS Code.
pub(crate) fn resolve_payload_version(
    product_name: &str,
    install_location: Option<&str>,
    appx_version: Option<String>,
) -> PayloadVerdict {
    let Some(root) = install_location else {
        return PayloadVerdict::Version(appx_version);
    };

    // A directory that cannot be read yields zero executables for the same
    // reason a genuine stub does. Only a *successful* read that finds no code
    // is evidence of a stub; a permission failure is evidence of nothing.
    let Some(executables) = collect_executables(std::path::Path::new(root)) else {
        debug!("AppX: {} unreadable, keeping Store version", root);
        return PayloadVerdict::Version(appx_version);
    };

    if executables.is_empty() {
        return PayloadVerdict::Stub;
    }

    let names: Vec<&str> = executables
        .iter()
        .filter_map(|(p, _)| p.file_name().and_then(|n| n.to_str()))
        .collect();

    let primary = primary_executable_name(product_name, &names).and_then(|chosen| {
        executables
            .iter()
            .find(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some(chosen))
            .map(|(p, _)| p)
    });

    // Trim to three components exactly as the Store version is trimmed, so the
    // two sources cannot disagree on spelling alone: wsl.exe's PE resource
    // reads "2.6.3.0" where the Store reports "2.6.3", and a version that
    // changes shape depending on which source won would churn the `registry_key`
    // history and exceptions key on.
    let from_payload = primary
        .and_then(|p| crate::scanner::pe_fingerprint::version_info::query(p))
        .map(|info| info.product_version)
        .filter(|v| !v.trim().is_empty())
        .and_then(|v| trim_version(&v));

    PayloadVerdict::Version(from_payload.or(appx_version))
}

/// The executable that *is* the product, out of everything the package ships.
///
/// A Store package carries the product plus whatever it vendors, and the
/// vendored copies are usually the bigger files: `Microsoft.Paint` ships a
/// 15 MB `ps-onnxruntime.dll` beside its 4 MB `mspaint.exe`. Reading a version
/// off the largest file therefore reports a bundled library's version as the
/// product's — for Paint that meant `1.23.20260526`, which falls below the
/// Paint 3D CVE bound and invented two findings against a current install.
///
/// Sharing a name with the package is what identifies the product. Returns
/// `None` when nothing does, leaving the Store version to stand rather than
/// guessing — vendored libraries are already inventoried in their own right by
/// the PE fingerprint scanner, so nothing is lost by declining to pick one.
fn primary_executable_name<'a>(product_name: &str, executables: &[&'a str]) -> Option<&'a str> {
    fn squash(s: &str) -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }

    let product = squash(product_name);
    if product.is_empty() {
        return None;
    }

    executables.iter().copied().find(|name| {
        let stem = squash(name.rsplit_once('.').map_or(*name, |(stem, _)| stem));
        !stem.is_empty() && (stem.contains(&product) || product.contains(&stem))
    })
}

/// Every `.exe`/`.dll` under `root`, with its size, walked without recursing
/// through symlinks. Depth is capped because a Store package is shallow and an
/// unbounded walk of a reparse-point loop would hang the scan.
///
/// Returns `None` when `root` itself cannot be read, so the caller can tell a
/// package that contains no code from one whose ACLs hid its contents.
/// Unreadable *sub*directories are skipped rather than failing the whole walk —
/// finding code anywhere in the package is enough to prove it is not a stub.
fn collect_executables(root: &std::path::Path) -> Option<Vec<(std::path::PathBuf, u64)>> {
    fn walk(dir: &std::path::Path, depth: u32, out: &mut Vec<(std::path::PathBuf, u64)>) {
        if depth > 6 || out.len() > 4096 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_symlink() {
                continue;
            }
            let path = entry.path();
            if meta.is_dir() {
                walk(&path, depth + 1, out);
            } else if matches!(
                path.extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("exe") | Some("dll")
            ) {
                out.push((path, meta.len()));
            }
        }
    }

    // Probe the root separately: this is the read whose failure is ambiguous.
    std::fs::read_dir(root).ok()?;

    let mut out = Vec::new();
    walk(root, 0, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_version_three_components() {
        assert_eq!(trim_version("3.13.3312.0"), Some("3.13.3312".to_string()));
        assert_eq!(trim_version("1.99.0.0"), Some("1.99.0".to_string()));
        assert_eq!(trim_version(""), None);
    }

    #[test]
    fn skip_runtime_packages() {
        assert!(should_skip("Microsoft.NET.Native.Runtime.2.2"));
        assert!(should_skip("Microsoft.VCLibs.140.00"));
        assert!(should_skip("Microsoft.UI.Xaml.2.7"));
        assert!(should_skip("Microsoft.WindowsAppRuntime.1.5"));
        assert!(!should_skip("Mozilla.Firefox"));
        assert!(!should_skip("NVIDIACorp.NVIDIAControlPanel"));
    }

    #[test]
    fn appx_scanner_does_not_panic() {
        let _ = AppxScanner::new().scan();
    }

    struct TempPkg(std::path::PathBuf);

    impl TempPkg {
        fn path_str(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TempPkg {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A throwaway package directory holding `files`. Contents are irrelevant —
    /// the payload check keys on the extension, and a stand-in with an `.exe`
    /// name has no version resource to read, which is itself a case under test.
    fn tempdir_with(files: &[&str]) -> TempPkg {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "evedoo-appx-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for name in files {
            std::fs::write(dir.join(name), b"stand-in").unwrap();
        }
        TempPkg(dir)
    }

    #[test]
    fn a_package_with_no_executable_payload_is_a_stub() {
        // Microsoft.VisualStudioCode ships exactly three files —
        // AppxBlockMap.xml, AppxManifest.xml, AppxSignature.p7x — and no code.
        // Its "1.0.137" is the Store stub's own number, unrelated to VS Code
        // product versions (1.9x-1.13x). Because it sorts below every VS Code
        // CPE bound it matched all 60 VS Code CVEs, including ones fixed in
        // 1.55.2 back in 2021. A package with no code carries no vulnerability.
        let dir = tempdir_with(&["AppxManifest.xml", "AppxBlockMap.xml", "AppxSignature.p7x"]);
        assert_eq!(
            resolve_payload_version("Visual Studio Code", Some(dir.path_str()), Some("1.0.137".into())),
            PayloadVerdict::Stub
        );
    }

    #[test]
    fn a_package_with_executables_is_not_a_stub() {
        // wsl.exe is real code, so the package must survive even though this
        // test's stand-in carries no readable version resource.
        let dir = tempdir_with(&["wsl.exe"]);
        assert!(matches!(
            resolve_payload_version("Windows Subsystem For Linux", Some(dir.path_str()), Some("2.6.3".into())),
            PayloadVerdict::Version(_)
        ));
    }

    #[test]
    fn the_products_own_executable_is_preferred_over_a_bigger_vendored_one() {
        // Microsoft.Paint bundles ps-onnxruntime.dll (15 MB, version
        // 1.23.20260526) alongside mspaint.exe (4 MB, version 11.2605.81.0).
        // Taking the largest executable read the vendored ML runtime's version
        // as Paint's, and 1.23.x sits below the < 6.2305.16087.0 bound of the
        // Paint 3D CVEs — inventing two findings against an up-to-date Paint.
        // Vendored libraries are the PE fingerprint scanner's job; the AppX
        // entry must describe the product itself.
        assert_eq!(
            primary_executable_name("Paint", &["ps-onnxruntime.dll", "mspaint.exe"]),
            Some("mspaint.exe")
        );
    }

    #[test]
    fn a_package_whose_executables_all_look_vendored_has_no_primary() {
        // Windows Subsystem For Linux ships wsl.exe, whose name does not
        // resemble the package name. No executable is identifiable as the
        // product, so the Store version stands — which for WSL is correct.
        assert_eq!(
            primary_executable_name("Windows Subsystem For Linux", &["wsl.exe"]),
            None
        );
    }

    #[test]
    fn an_executable_matches_when_either_name_contains_the_other() {
        assert_eq!(
            primary_executable_name("Python", &["libcrypto-3.dll", "python313.dll"]),
            Some("python313.dll")
        );
        assert_eq!(
            primary_executable_name("qBittorrent", &["qbittorrent.exe"]),
            Some("qbittorrent.exe")
        );
    }

    #[test]
    fn an_unreadable_version_resource_falls_back_to_the_appx_version() {
        // WSL is the control case: its AppX version 2.6.3.0 genuinely equals
        // wsl.exe's 2.6.3.0, so falling back must not change WSL's result.
        let dir = tempdir_with(&["wsl.exe"]);
        assert_eq!(
            resolve_payload_version("Windows Subsystem For Linux", Some(dir.path_str()), Some("2.6.3".into())),
            PayloadVerdict::Version(Some("2.6.3".into()))
        );
    }

    #[test]
    fn a_package_with_no_install_location_keeps_its_appx_version() {
        // Get-AppxPackage can return a null InstallLocation for a partially
        // staged package. Absence of evidence is not evidence of a stub —
        // dropping it there would be a false negative.
        assert_eq!(
            resolve_payload_version("Anything", None, Some("1.2.3".into())),
            PayloadVerdict::Version(Some("1.2.3".into()))
        );
    }

    #[test]
    fn an_unreadable_install_location_is_not_treated_as_a_stub() {
        // C:\Program Files\WindowsApps is heavily ACL'd. A directory that
        // cannot be read yields zero executables for the same reason a genuine
        // stub does, and the two must not be confused: treating a permission
        // failure as "no code here" would silently drop every Store package on
        // a machine whose ACLs differ from the one this was measured on.
        assert_eq!(
            resolve_payload_version("Anything", Some(r"C:\definitely\not\a\real\path"), Some("9.9".into())),
            PayloadVerdict::Version(Some("9.9".into()))
        );
    }
}

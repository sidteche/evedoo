//! Remote scanner variants — each mirrors a local scanner but executes
//! via `Invoke-Command` or SMB UNC paths on a remote machine.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::fs;

use tracing::{debug, info, warn};

use super::session::RemoteSession;
use crate::error::Result;
use crate::models::{Architecture, DetectedSoftware};
use crate::normalize::names::{normalize_appx_name, normalize_publisher};

/// Scan the remote registry `Uninstall` keys.
pub fn scan_registry(session: &RemoteSession) -> Result<Vec<DetectedSoftware>> {
    info!("Remote: scanning registry Uninstall keys");

    let script = r#"
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $all = foreach ($p in $paths) {
            Get-ItemProperty $p -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, InstallDate, PSPath, @{N='Arch';E={ if ($p -match 'WOW6432Node') { 'x86' } else { 'x64' } }}
        }
        $all | ConvertTo-Json -Compress
    "#;

    let output = session.execute(script)?;
    Ok(parse_registry_json(&output))
}

/// Parse the JSON output from remote registry scan.
fn parse_registry_json(json_str: &str) -> Vec<DetectedSoftware> {
    let trimmed = json_str.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // PowerShell returns a single object (not array) when there's exactly one result
    let items: Vec<serde_json::Value> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).unwrap_or_default()
    } else {
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(v) => vec![v],
            Err(_) => return Vec::new(),
        }
    };

    items
        .iter()
        .filter_map(|item| {
            let name = item.get("DisplayName")?.as_str()?.to_string();
            if name.is_empty() {
                return None;
            }

            let version = item
                .get("DisplayVersion")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let publisher = item
                .get("Publisher")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let install_location = item
                .get("InstallLocation")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let install_date = item
                .get("InstallDate")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let registry_key = format!(
                "registry://remote/{}",
                item.get("PSPath")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&name)
            );

            let arch = match item.get("Arch").and_then(|v| v.as_str()) {
                Some("x86") => Architecture::X86,
                _ => Architecture::X64,
            };

            Some(DetectedSoftware {
                name,
                version,
                publisher,
                install_location,
                install_date,
                registry_key,
                architecture: arch,
            })
        })
        .collect()
}

/// Scan remote AppX / MSIX packages.
pub fn scan_appx(session: &RemoteSession) -> Result<Vec<DetectedSoftware>> {
    info!("Remote: scanning AppX packages");

    let script =
        "Get-AppxPackage | Select-Object Name,Version,Publisher | ConvertTo-Json -Compress";

    let output = session.execute(script)?;
    Ok(parse_appx_json(&output))
}

/// Parse AppX JSON from remote.
fn parse_appx_json(json_str: &str) -> Vec<DetectedSoftware> {
    let trimmed = json_str.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let items: Vec<serde_json::Value> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).unwrap_or_default()
    } else {
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(v) => vec![v],
            Err(_) => return Vec::new(),
        }
    };

    items
        .iter()
        .filter_map(|item| {
            let raw_name = item.get("Name")?.as_str()?;
            let name = normalize_appx_name(raw_name);

            let version = item
                .get("Version")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let publisher = item
                .get("Publisher")
                .and_then(|v| v.as_str())
                .and_then(normalize_publisher);

            Some(DetectedSoftware {
                name,
                version,
                publisher,
                install_location: None,
                install_date: None,
                registry_key: format!("appx://remote/{}", raw_name),
                architecture: Architecture::Unknown,
            })
        })
        .collect()
}

/// Scan remote WinGet packages via `winget list`.
pub fn scan_winget(session: &RemoteSession) -> Result<Vec<DetectedSoftware>> {
    info!("Remote: scanning WinGet packages");

    let script = "winget list --disable-interactivity --accept-source-agreements";

    let output = session.execute(script)?;
    Ok(parse_winget_table(&output))
}

/// Parse winget table output (same format as local).
fn parse_winget_table(text: &str) -> Vec<DetectedSoftware> {
    let mut results = Vec::new();

    let mut lines = text.lines().peekable();
    let mut header_line: Option<&str> = None;
    let mut separator_found = false;
    let mut name_start = 0usize;
    let mut name_end = 0usize;
    let mut ver_start = 0usize;
    let mut ver_end = 0usize;

    // Find the separator line to determine column widths
    for line in lines.by_ref() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let non_ws = trimmed.replace(' ', "");
        if !non_ws.is_empty() && non_ws.chars().all(|c| c == '-') {
            if let Some(hdr) = header_line {
                // Parse column positions from header
                if let Some(name_pos) = hdr.find("Name") {
                    name_start = name_pos;
                }
                if let Some(id_pos) = hdr.find("Id") {
                    name_end = id_pos;
                }
                if let Some(vp) = hdr.find("Version") {
                    ver_start = vp;
                }
                // Version column ends at "Available" or "Source" or end of line
                if let Some(ap) = hdr.find("Available") {
                    ver_end = ap;
                } else if let Some(sp) = hdr.find("Source") {
                    ver_end = sp;
                } else {
                    ver_end = hdr.len();
                }
                separator_found = true;
            }
            break;
        }
        header_line = Some(line);
    }

    if !separator_found {
        return results;
    }

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        let len = chars.len();

        let name: String = chars[name_start..len.min(name_end)]
            .iter()
            .collect::<String>()
            .trim()
            .to_string();

        let version: String = if ver_start < len {
            chars[ver_start..len.min(ver_end)]
                .iter()
                .collect::<String>()
                .trim()
                .to_string()
        } else {
            String::new()
        };

        if name.is_empty() {
            continue;
        }

        results.push(DetectedSoftware {
            name,
            version: if version.is_empty() {
                None
            } else {
                Some(version)
            },
            publisher: None,
            install_location: None,
            install_date: None,
            registry_key: format!("winget://remote/{}", line.trim()),
            architecture: Architecture::Unknown,
        });
    }

    results
}

/// Scan remote Chocolatey packages via SMB (UNC path to nuspec files).
pub fn scan_chocolatey(session: &RemoteSession) -> Result<Vec<DetectedSoftware>> {
    info!("Remote: scanning Chocolatey packages via SMB");

    // First, find the Chocolatey install dir on the remote host
    let script = r#"
        $chocoDir = if ($env:ChocolateyInstall) { $env:ChocolateyInstall }
                    elseif (Test-Path 'C:\ProgramData\chocolatey') { 'C:\ProgramData\chocolatey' }
                    else { '' }
        $chocoDir
    "#;

    let output = session.execute(script)?;
    let remote_dir = output.trim();

    if remote_dir.is_empty() {
        debug!("Chocolatey not found on remote host");
        return Ok(Vec::new());
    }

    let unc_base = match session.unc_path(remote_dir) {
        Some(p) => p,
        None => {
            warn!("Rejected unsafe Chocolatey path from remote host: {}", remote_dir);
            return Ok(Vec::new());
        }
    };
    let unc_lib = format!(r"{}\lib", unc_base);
    debug!("Scanning Chocolatey packages at {}", unc_lib);

    let entries = match fs::read_dir(&unc_lib) {
        Ok(e) => e,
        Err(e) => {
            warn!("Cannot read remote Chocolatey dir {}: {}", unc_lib, e);
            return Ok(Vec::new());
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

        // Look for <pkg>.nuspec
        let nuspec_path = pkg_dir.join(format!("{}.nuspec", pkg_name));
        if !nuspec_path.exists() {
            continue;
        }

        if let Ok(content) = fs::read_to_string(&nuspec_path) {
            if let Some(sw) = parse_nuspec(&content, &pkg_name) {
                results.push(sw);
            }
        }
    }

    Ok(results)
}

/// Minimal nuspec XML parser (same approach as local chocolatey scanner).
fn parse_nuspec(xml: &str, fallback_name: &str) -> Option<DetectedSoftware> {
    let id = extract_xml_tag(xml, "id").unwrap_or_else(|| fallback_name.to_string());
    let version = extract_xml_tag(xml, "version");
    let title = extract_xml_tag(xml, "title");
    let authors = extract_xml_tag(xml, "authors");

    let display_name = title.unwrap_or(id);

    Some(DetectedSoftware {
        name: display_name,
        version,
        publisher: authors,
        install_location: None,
        install_date: None,
        registry_key: format!("chocolatey://remote/{}", fallback_name),
        architecture: Architecture::Unknown,
    })
}

/// Scan remote Scoop packages via SMB.
pub fn scan_scoop(session: &RemoteSession) -> Result<Vec<DetectedSoftware>> {
    info!("Remote: scanning Scoop packages via SMB");

    // Find Scoop install dir on the remote host
    let script = r#"
        $scoopDir = if ($env:SCOOP) { $env:SCOOP }
                    elseif (Test-Path "$env:USERPROFILE\scoop") { "$env:USERPROFILE\scoop" }
                    else { '' }
        $scoopDir
    "#;

    let output = session.execute(script)?;
    let remote_dir = output.trim();

    if remote_dir.is_empty() {
        debug!("Scoop not found on remote host");
        return Ok(Vec::new());
    }

    let unc_base = match session.unc_path(remote_dir) {
        Some(p) => p,
        None => {
            warn!("Rejected unsafe Scoop path from remote host: {}", remote_dir);
            return Ok(Vec::new());
        }
    };
    let unc_apps = format!(r"{}\apps", unc_base);
    debug!("Scanning Scoop packages at {}", unc_apps);

    let entries = match fs::read_dir(&unc_apps) {
        Ok(e) => e,
        Err(e) => {
            warn!("Cannot read remote Scoop dir {}: {}", unc_apps, e);
            return Ok(Vec::new());
        }
    };

    let mut results = Vec::new();
    for entry in entries.flatten() {
        let app_dir = entry.path();
        if !app_dir.is_dir() {
            continue;
        }
        let app_name = match app_dir.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Read current/manifest.json
        let manifest = app_dir.join("current").join("manifest.json");
        if !manifest.exists() {
            continue;
        }

        if let Ok(content) = fs::read_to_string(&manifest) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                let version = parsed
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                results.push(DetectedSoftware {
                    name: app_name.clone(),
                    version,
                    publisher: None,
                    install_location: None,
                    install_date: None,
                    registry_key: format!("scoop://remote/{}", app_name),
                    architecture: Architecture::Unknown,
                });
            }
        }
    }

    Ok(results)
}

/// Scan remote pip/npm/cargo packages via CLI.
pub fn scan_packages(session: &RemoteSession) -> Result<Vec<DetectedSoftware>> {
    info!("Remote: scanning ecosystem packages (pip/npm/cargo)");

    let mut results = Vec::new();

    // pip
    if let Ok(output) = session.execute("pip list --format=json 2>$null") {
        let trimmed = output.trim();
        if trimmed.starts_with('[') {
            if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                for item in &items {
                    if let (Some(name), Some(version)) = (
                        item.get("name").and_then(|v| v.as_str()),
                        item.get("version").and_then(|v| v.as_str()),
                    ) {
                        results.push(DetectedSoftware {
                            name: name.to_string(),
                            version: Some(version.to_string()),
                            publisher: None,
                            install_location: None,
                            install_date: None,
                            registry_key: format!("pip://remote/{}", name),
                            architecture: Architecture::Unknown,
                        });
                    }
                }
            }
        }
    }

    // npm global
    if let Ok(output) = session.execute("npm list -g --json 2>$null") {
        let trimmed = output.trim();
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(deps) = parsed.get("dependencies").and_then(|d| d.as_object()) {
                for (name, info) in deps {
                    let version = info
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    results.push(DetectedSoftware {
                        name: name.clone(),
                        version,
                        publisher: None,
                        install_location: None,
                        install_date: None,
                        registry_key: format!("npm://remote/{}", name),
                        architecture: Architecture::Unknown,
                    });
                }
            }
        }
    }

    // cargo
    if let Ok(output) = session.execute("cargo install --list 2>$null") {
        for line in output.lines() {
            let trimmed = line.trim();
            // Lines like "ripgrep v14.1.0:"
            if !trimmed.starts_with(' ') && trimmed.contains(' ') {
                let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    let name = parts[0].to_string();
                    let version = parts[1]
                        .trim_start_matches('v')
                        .trim_end_matches(':')
                        .to_string();
                    results.push(DetectedSoftware {
                        name,
                        version: if version.is_empty() {
                            None
                        } else {
                            Some(version)
                        },
                        publisher: None,
                        install_location: None,
                        install_date: None,
                        registry_key: format!("cargo://remote/{}", parts[0]),
                        architecture: Architecture::Unknown,
                    });
                }
            }
        }
    }

    Ok(results)
}

/// Simple XML tag extractor (no full parser, avoids dependencies).
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_registry_json_array() {
        let json = r#"[
            {"DisplayName":"Chrome","DisplayVersion":"120.0","Publisher":"Google","InstallLocation":"C:\\Chrome","InstallDate":"20240101","PSPath":"HKLM:\\chrome","Arch":"x64"},
            {"DisplayName":"Firefox","DisplayVersion":"115.0","Publisher":"Mozilla","InstallLocation":null,"InstallDate":null,"PSPath":"HKLM:\\ff","Arch":"x86"}
        ]"#;

        let results = parse_registry_json(json);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "Chrome");
        assert_eq!(results[0].version.as_deref(), Some("120.0"));
        assert_eq!(results[0].architecture, Architecture::X64);
        assert_eq!(results[1].name, "Firefox");
        assert_eq!(results[1].architecture, Architecture::X86);
    }

    #[test]
    fn parse_registry_json_single_object() {
        let json = r#"{"DisplayName":"Notepad++","DisplayVersion":"8.7","Publisher":"Notepad++ Team","InstallLocation":null,"InstallDate":null,"PSPath":"reg","Arch":"x64"}"#;

        let results = parse_registry_json(json);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Notepad++");
    }

    #[test]
    fn parse_registry_json_empty() {
        assert_eq!(parse_registry_json("").len(), 0);
        assert_eq!(parse_registry_json("  ").len(), 0);
    }

    #[test]
    fn parse_appx_json_works() {
        let json = r#"[{"Name":"Microsoft.WindowsCalculator","Version":"11.0.0.0","Publisher":"CN=Microsoft Corporation"}]"#;
        let results = parse_appx_json(json);
        assert_eq!(results.len(), 1);
        assert!(results[0].registry_key.starts_with("appx://remote/"));
    }

    #[test]
    fn parse_winget_table_works() {
        let table = "\
Name            Id              Version  Available  Source\n\
--------------  --------------  -------  ---------  ------\n\
Google Chrome   Google.Chrome   120.0    121.0      winget\n\
Firefox         Mozilla.FF      115.0               winget\n";

        let results = parse_winget_table(table);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "Google Chrome");
        assert_eq!(results[0].version.as_deref(), Some("120.0"));
    }

    #[test]
    fn parse_nuspec_extracts_fields() {
        let xml = r#"<?xml version="1.0"?>
<package>
  <metadata>
    <id>git</id>
    <version>2.43.0</version>
    <title>Git</title>
    <authors>Git SCM</authors>
  </metadata>
</package>"#;

        let sw = parse_nuspec(xml, "git").unwrap();
        assert_eq!(sw.name, "Git");
        assert_eq!(sw.version.as_deref(), Some("2.43.0"));
        assert_eq!(sw.publisher.as_deref(), Some("Git SCM"));
    }

    #[test]
    fn extract_xml_tag_works() {
        assert_eq!(
            extract_xml_tag("<id>test</id>", "id"),
            Some("test".to_string())
        );
        assert_eq!(extract_xml_tag("<id></id>", "id"), None);
        assert_eq!(extract_xml_tag("no tags here", "id"), None);
    }

    #[test]
    fn parse_pip_json() {
        let json = r#"[{"name":"numpy","version":"1.26.0"},{"name":"pip","version":"24.0"}]"#;
        let items: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["name"], "numpy");
    }
}

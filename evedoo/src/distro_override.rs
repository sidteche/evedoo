// SPDX-License-Identifier: Apache-2.0

//! Distribution-specific security advisory overrides.
//!
//! Applies package-level verdicts from distribution security advisories stored
//! in `vulndb.sqlite` (today: Ubuntu security notices, experimental) to refine
//! generic NVD CPE matches.
//!
//! A verdict can remove a finding, so it is applied only when the advisory is
//! known to be about this host: same distribution and same release. Anything
//! unknown leaves the finding in place.

use rusqlite::Connection;

use crate::models::{DetectedSoftware, Finding};
use crate::normalize::{ApkVersion, DpkgVersion, RpmVersion};

#[derive(Debug, Clone)]
pub struct DistroVerdict {
    pub advisory_id: Option<String>,
    pub fixed_version: Option<String>,
    #[allow(dead_code)]
    pub distro_family: String,
}

/// Determine whether an installed package version satisfies a distro's fixed version.
pub fn is_distro_patched(distro_family: &str, installed: &str, fixed: &str) -> Option<bool> {
    if installed.trim().is_empty() || fixed.trim().is_empty() {
        return None;
    }

    match distro_family.to_ascii_lowercase().as_str() {
        "ubuntu" | "debian" => {
            let inst = DpkgVersion::parse(installed)?;
            let fix = DpkgVersion::parse(fixed)?;
            Some(inst >= fix)
        }
        "rhel" | "fedora" | "centos" => {
            let inst = RpmVersion::parse(installed);
            let fix = RpmVersion::parse(fixed);
            Some(inst >= fix)
        }
        "alpine" => {
            let inst = ApkVersion::parse(installed)?;
            let fix = ApkVersion::parse(fixed)?;
            Some(inst >= fix)
        }
        _ => None,
    }
}

/// The distribution and release of the scanned system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDistro {
    /// os-release `ID`, lower-case: "ubuntu", "debian", "rhel", "alpine", ...
    pub family: String,
    /// The release name advisories are keyed by (Ubuntu: the codename).
    /// `None` when it cannot be determined; nothing is suppressed then.
    pub release: Option<String>,
}

impl HostDistro {
    /// From os-release `ID` and `VERSION_ID`.
    pub fn from_os_release(id: &str, version_id: Option<&str>) -> Option<Self> {
        let family = id.trim().to_ascii_lowercase();
        if family.is_empty() {
            return None;
        }
        let release = match family.as_str() {
            "ubuntu" => version_id.and_then(ubuntu_codename).map(str::to_string),
            _ => None,
        };
        Some(Self { family, release })
    }

    /// From the inventory's OS entry (`os://linux/<id>`), which for a
    /// `--rootfs` scan describes the scanned image, not the machine running
    /// the scan.
    pub fn from_inventory(software: &[DetectedSoftware]) -> Option<Self> {
        software.iter().find_map(|sw| {
            let id = sw.registry_key.strip_prefix("os://linux/")?;
            Self::from_os_release(id, sw.version.as_deref())
        })
    }
}

/// Ubuntu `VERSION_ID` to the release codename its security notices use.
fn ubuntu_codename(version_id: &str) -> Option<&'static str> {
    Some(match version_id.trim() {
        "14.04" => "trusty",
        "16.04" => "xenial",
        "18.04" => "bionic",
        "20.04" => "focal",
        "22.04" => "jammy",
        "23.10" => "mantic",
        "24.04" => "noble",
        "24.10" => "oracular",
        "25.04" => "plucky",
        "25.10" => "questing",
        _ => return None,
    })
}

/// Advisory rows for one CVE, package and release of one distribution.
fn lookup(
    conn: &Connection,
    cve_id: &str,
    distro_family: &str,
    release: &str,
    package_name: &str,
) -> Vec<DistroVerdict> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT advisory_id, fixed_version, distro_family
           FROM distro_advisories
          WHERE cve_id = ?1 AND distro_family = ?2 AND package_name = ?3 AND release_codename = ?4",
    ) else {
        return Vec::new();
    };

    let rows = stmt.query_map(
        rusqlite::params![
            cve_id,
            distro_family.to_ascii_lowercase(),
            package_name.to_ascii_lowercase(),
            release.to_ascii_lowercase()
        ],
        |r| {
            Ok(DistroVerdict {
                advisory_id: r.get(0)?,
                fixed_version: r.get(1)?,
                distro_family: r.get(2)?,
            })
        },
    );
    match rows {
        Ok(rows) => rows.flatten().collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Debug, Default)]
pub struct DistroOverrideOutcome {
    pub suppressed: usize,
    pub enriched: usize,
}

/// The package scheme a distribution family's advisories apply to.
fn package_scheme(family: &str) -> Option<&'static str> {
    match family {
        "ubuntu" | "debian" => Some("dpkg"),
        "rhel" | "fedora" | "centos" => Some("rpm"),
        "alpine" => Some("apk"),
        _ => None,
    }
}

/// Apply distribution security advisory verdicts to findings.
///
/// A finding is suppressed only when an advisory for this host's distribution
/// and release exists and the installed version is at or above every fix
/// version it lists. Below that, the finding is kept and enriched with the fix
/// version and advisory ID. With an unknown host or release (`host` is `None`
/// or has no `release`), nothing is changed.
pub fn apply(
    findings: &mut Vec<Finding>,
    conn: &Connection,
    host: Option<&HostDistro>,
) -> DistroOverrideOutcome {
    let mut out = DistroOverrideOutcome::default();

    let Some(host) = host else { return out };
    let Some(release) = host.release.as_deref() else { return out };
    let Some(scheme) = package_scheme(&host.family) else { return out };
    let family = host.family.as_str();

    // Check if table exists in database first
    let table_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='distro_advisories'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !table_exists {
        return out;
    }

    let prefix = format!("{scheme}://");
    findings.retain_mut(|f| {
        let Some(pkg_name) = f.software.registry_key.strip_prefix(prefix.as_str()) else {
            return true;
        };
        let Some(installed) = f.software.version.as_deref() else {
            return true;
        };

        // Decide against the highest fix version, compared as versions.
        let mut verdicts = lookup(conn, &f.vulnerability.cve_id, family, release, pkg_name);
        let mut highest: Option<(String, Option<String>)> = None;
        for v in verdicts.drain(..) {
            let Some(fixed) = v.fixed_version else { continue };
            let is_higher = match &highest {
                None => true,
                // `fixed` is higher when the current highest does not satisfy it.
                Some((current, _)) => is_distro_patched(family, current, &fixed) == Some(false),
            };
            if is_higher {
                highest = Some((fixed, v.advisory_id));
            }
        }
        let Some((fixed, advisory_id)) = highest else {
            return true;
        };

        match is_distro_patched(family, installed, &fixed) {
            Some(true) => {
                out.suppressed += 1;
                false
            }
            Some(false) => {
                // Below the fix: keep finding and enrich with exact advisory
                if let Some(adv) = advisory_id {
                    f.vulnerability.remediation.vendor_advisory = Some(adv);
                }
                f.vulnerability.remediation.fixed_version = Some(fixed);
                out.enriched += 1;
                true
            }
            None => true,
        }
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Architecture, DetectedSoftware, MatchConfidence, Remediation, Severity, Vulnerability};

    fn make_test_finding(key: &str, name: &str, version: &str, cve_id: &str) -> Finding {
        Finding {
            software: DetectedSoftware {
                name: name.to_string(),
                version: Some(version.to_string()),
                publisher: None,
                install_location: None,
                install_date: None,
                registry_key: key.to_string(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: cve_id.to_string(),
                description: "Test vuln".to_string(),
                cvss_score: Some(7.5),
                severity: Severity::High,
                published_date: None,
                references: Vec::new(),
                remediation: Remediation::default(),
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::High,
            vendor: Some("test".to_string()),
            status: crate::models::FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        }
    }

    #[test]
    fn test_is_distro_patched_dpkg() {
        // Equal or newer version is patched
        assert_eq!(
            is_distro_patched("ubuntu", "1.59.0-1ubuntu0.1", "1.59.0-1ubuntu0.1"),
            Some(true)
        );
        assert_eq!(
            is_distro_patched("ubuntu", "1.59.0-1ubuntu0.2", "1.59.0-1ubuntu0.1"),
            Some(true)
        );
        // Older version is not patched
        assert_eq!(
            is_distro_patched("ubuntu", "1.59.0-1", "1.59.0-1ubuntu0.1"),
            Some(false)
        );
    }

    #[test]
    fn test_is_distro_patched_rpm() {
        assert_eq!(
            is_distro_patched("rhel", "7.76.1-26.el9_2.1", "7.76.1-26.el9_2.1"),
            Some(true)
        );
        assert_eq!(
            is_distro_patched("rhel", "7.76.1-26.el9_2.2", "7.76.1-26.el9_2.1"),
            Some(true)
        );
        assert_eq!(
            is_distro_patched("rhel", "7.76.1-26.el9_2", "7.76.1-26.el9_2.1"),
            Some(false)
        );
    }

    fn advisory_db(rows: &str) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE distro_advisories (
                cve_id TEXT NOT NULL,
                advisory_id TEXT,
                distro_family TEXT NOT NULL,
                package_name TEXT NOT NULL,
                release_codename TEXT NOT NULL DEFAULT '',
                fixed_version TEXT NOT NULL,
                status TEXT NOT NULL,
                modularity_stream TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (cve_id, distro_family, package_name, release_codename, modularity_stream)
            );
            INSERT INTO distro_advisories VALUES {rows};"
        ))
        .unwrap();
        conn
    }

    fn host(id: &str, version: &str) -> HostDistro {
        HostDistro::from_os_release(id, Some(version)).unwrap()
    }

    #[test]
    fn host_distro_is_read_from_the_inventory_os_entry() {
        let mut os = make_test_finding("os://linux/ubuntu", "Ubuntu 24.04.1 LTS", "24.04", "CVE-0").software;
        os.registry_key = "os://linux/ubuntu".into();
        let host = HostDistro::from_inventory(std::slice::from_ref(&os)).unwrap();
        assert_eq!(host.family, "ubuntu");
        assert_eq!(host.release.as_deref(), Some("noble"));

        let windows = make_test_finding("os://windows", "Windows 11", "10.0.26100", "CVE-0").software;
        assert!(HostDistro::from_inventory(std::slice::from_ref(&windows)).is_none());
        assert!(HostDistro::from_inventory(&[]).is_none());
    }

    #[test]
    fn matching_distro_and_release_suppresses_a_patched_package() {
        let conn = advisory_db("('CVE-2023-44487', 'USN-6427-1', 'ubuntu', 'nghttp2', 'noble', '1.59.0-1ubuntu0.1', 'fixed', '')");
        let mut findings = vec![
            make_test_finding("dpkg://nghttp2", "nghttp2", "1.59.0-1ubuntu0.1", "CVE-2023-44487"),
            make_test_finding("pe://app.exe", "app", "1.0.0", "CVE-2023-99999"),
        ];
        let outcome = apply(&mut findings, &conn, Some(&host("ubuntu", "24.04")));
        assert_eq!(outcome.suppressed, 1);
        assert_eq!(findings.len(), 1);
    }

    /// The jammy fix version says nothing about a noble host. The lookup used
    /// to ignore the release, so a noble package at or above jammy's fix
    /// version was reported as patched.
    #[test]
    fn an_advisory_for_another_release_never_suppresses() {
        let conn = advisory_db("('CVE-2023-44487', 'USN-6427-1', 'ubuntu', 'nghttp2', 'jammy', '1.43.0-1ubuntu0.2', 'fixed', '')");
        let mut findings = vec![make_test_finding("dpkg://nghttp2", "nghttp2", "1.59.0-1build1", "CVE-2023-44487")];
        let outcome = apply(&mut findings, &conn, Some(&host("ubuntu", "24.04")));
        assert_eq!(outcome.suppressed, 0);
        assert_eq!(outcome.enriched, 0);
        assert_eq!(findings.len(), 1);
    }

    /// Every dpkg package used to be treated as Ubuntu's, so a Debian (or Mint,
    /// or Kali) host got Ubuntu verdicts.
    #[test]
    fn an_ubuntu_advisory_never_applies_to_a_debian_host() {
        let conn = advisory_db("('CVE-2023-44487', 'USN-6427-1', 'ubuntu', 'nghttp2', 'bookworm', '1.52.0-1', 'fixed', '')");
        let mut findings = vec![make_test_finding("dpkg://nghttp2", "nghttp2", "1.52.0-1+deb12u2", "CVE-2023-44487")];
        let outcome = apply(&mut findings, &conn, Some(&host("debian", "12")));
        assert_eq!((outcome.suppressed, outcome.enriched, findings.len()), (0, 0, 1));
    }

    #[test]
    fn unknown_host_or_release_never_suppresses() {
        let conn = advisory_db("('CVE-2023-44487', 'USN-6427-1', 'ubuntu', 'nghttp2', 'noble', '1.59.0-1ubuntu0.1', 'fixed', '')");
        let patched = || vec![make_test_finding("dpkg://nghttp2", "nghttp2", "1.59.0-1ubuntu0.1", "CVE-2023-44487")];

        let mut findings = patched();
        assert_eq!(apply(&mut findings, &conn, None).suppressed, 0);
        assert_eq!(findings.len(), 1);

        // An Ubuntu version with no known codename.
        let unknown_release = host("ubuntu", "99.04");
        assert!(unknown_release.release.is_none());
        let mut findings = patched();
        assert_eq!(apply(&mut findings, &conn, Some(&unknown_release)).suppressed, 0);
        assert_eq!(findings.len(), 1);
    }

    /// With several rows for one release the fix version was chosen by SQL
    /// text ordering, where '9.1' sorts above '10.0'. The package must clear
    /// the highest fix version by real version comparison.
    #[test]
    fn the_highest_fix_version_is_chosen_by_version_order_not_text_order() {
        let conn = advisory_db(
            "('CVE-2024-1', 'USN-1-1', 'ubuntu', 'pkg', 'noble', '9.1-1', 'fixed', ''),
             ('CVE-2024-1', 'USN-1-2', 'ubuntu', 'pkg', 'noble', '10.0-1', 'fixed', 'stream')",
        );
        // 9.5 is above 9.1 but below 10.0: still vulnerable.
        let mut findings = vec![make_test_finding("dpkg://pkg", "pkg", "9.5-1", "CVE-2024-1")];
        let outcome = apply(&mut findings, &conn, Some(&host("ubuntu", "24.04")));
        assert_eq!((outcome.suppressed, outcome.enriched), (0, 1));
        assert_eq!(findings[0].vulnerability.remediation.fixed_version.as_deref(), Some("10.0-1"));
        assert_eq!(findings[0].vulnerability.remediation.vendor_advisory.as_deref(), Some("USN-1-2"));
    }
}

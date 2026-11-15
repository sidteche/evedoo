// Persistent application configuration stored in %APPDATA%.
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub nvd_api_key: String,
    #[serde(default = "default_db_path")]
    pub default_db_path: String,
    #[serde(default)]
    pub evedoo_exe_path: String,
    #[serde(default)]
    pub cve_db_builder_exe_path: String,
}

fn default_db_path() -> String {
    "vulndb.sqlite".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        let (evedoo, builder) = detect_exe_paths();
        let nvd_key = load_env_api_key().unwrap_or_default();
        Self {
            nvd_api_key: nvd_key,
            default_db_path: default_db_path(),
            evedoo_exe_path: evedoo,
            cve_db_builder_exe_path: builder,
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        let mut config: Self = match std::fs::read_to_string(config_file_path()) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        };

        // If no API key in saved config, try .env / environment
        if config.nvd_api_key.is_empty() {
            if let Some(key) = load_env_api_key() {
                config.nvd_api_key = key;
            }
        }

        // If exe paths are bare names (not found), re-detect
        if !PathBuf::from(&config.evedoo_exe_path).exists() {
            let (evedoo, builder) = detect_exe_paths();
            config.evedoo_exe_path = evedoo;
            config.cve_db_builder_exe_path = builder;
        }

        config
    }

    pub fn save(&self) {
        let path = config_file_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
    }
}

/// `NVD_API_KEY` from the real environment, else from a `.env` in the working
/// directory or beside the GUI executable.
///
/// This used `dotenvy::dotenv()`, which searched the working directory and
/// every parent for a `.env` and exported *every* key in it into the GUI's
/// environment — which each spawned `evedoo.exe` and `cve-db-builder.exe`
/// then inherited. Now only `NVD_API_KEY` is read, only from those two
/// directories, and nothing is exported. Mirrors `cve-db-builder/src/env_file.rs`.
fn load_env_api_key() -> Option<String> {
    if let Ok(key) = std::env::var("NVD_API_KEY") {
        if !key.trim().is_empty() {
            return Some(key);
        }
    }
    let cwd = std::env::current_dir().ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));
    nvd_api_key_from_files(&env_file_candidates(cwd.as_deref(), exe_dir.as_deref()))
}

/// The `.env` files consulted, in order: the working directory itself, the
/// executable's directory, and — only when the executable sits in a cargo
/// build directory — that workspace's root. Never any other parent.
fn env_file_candidates(
    cwd: Option<&std::path::Path>,
    exe_dir: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    let workspace = exe_dir.and_then(cargo_workspace_root);
    let mut out: Vec<PathBuf> = Vec::with_capacity(3);
    for dir in [cwd, exe_dir, workspace.as_deref()].into_iter().flatten() {
        let candidate = dir.join(".env");
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out
}

/// `<root>` when `exe_dir` is `<root>/target/<profile>` or
/// `<root>/target/<triple>/<profile>`. Derived from the executable's location
/// only — never the working directory, which is the attacker-steerable input.
/// Mirrors `cve-db-builder/src/env_file.rs`.
fn cargo_workspace_root(exe_dir: &std::path::Path) -> Option<PathBuf> {
    exe_dir
        .ancestors()
        .skip(1)
        .take(2)
        .find(|dir| dir.file_name() == Some(std::ffi::OsStr::new("target")))
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
}

/// `NVD_API_KEY` from the first candidate file carrying a non-blank one,
/// without writing anything to the process environment.
fn nvd_api_key_from_files(candidates: &[PathBuf]) -> Option<String> {
    candidates.iter().find_map(|path| {
        dotenvy::from_path_iter(path)
            .ok()?
            .map_while(Result::ok)
            .find(|(k, _)| k == "NVD_API_KEY")
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn config_file_path() -> PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        PathBuf::from(appdata).join("evedoo-gui").join("config.json")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("evedoo-gui").join("config.json")
    } else {
        PathBuf::from("evedoo-gui-config.json")
    }
}

/// Locate `evedoo.exe` and `cve-db-builder.exe`.
///
/// Resolution is anchored to the GUI binary's own directory (SEC-7). The
/// current working directory is deliberately not searched: a CWD-relative
/// lookup lets anyone who can drop a file into the directory the GUI happens
/// to be launched from get their binary executed with the user's privileges —
/// and that binary is subsequently handed WinRM credentials. Returning an
/// absolute path also keeps `CreateProcess` from applying its own search
/// order, which includes the CWD.
///
/// Sibling `target/{debug,release}` directories are still probed so a
/// workspace dev build (`evedoo-gui` at `target/debug/`, siblings alongside
/// it) resolves without configuration — those are relative to the GUI binary,
/// not to the CWD. If nothing is found the user sets the path in Settings.
fn detect_exe_paths() -> (String, String) {
    let find = |name: &str| -> String {
        let Ok(exe) = std::env::current_exe() else {
            return name.to_string();
        };
        let Some(dir) = exe.parent() else {
            return name.to_string();
        };

        // 1. Alongside the GUI binary — the normal deployed layout.
        let candidate = dir.join(name);
        if candidate.exists() {
            return candidate.to_string_lossy().to_string();
        }

        // 2. Sibling build-profile directories, for running out of a
        //    workspace target dir.
        for profile in ["debug", "release"] {
            if let Some(parent) = dir.parent() {
                let candidate = parent.join(profile).join(name);
                if candidate.exists() {
                    return candidate.to_string_lossy().to_string();
                }
            }
        }

        // 3. Give up rather than guess. A bare name would be resolved by
        //    CreateProcess's search order, which starts with the CWD.
        //    Settings has an explicit path field for this case.
        name.to_string()
    };

    (find("evedoo.exe"), find("cve-db-builder.exe"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "evedoo-gui-envfile-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn write(&self, rel: &str, body: &str) -> PathBuf {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            p
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reads_only_the_nvd_key_and_exports_nothing() {
        // dotenvy::dotenv() exported every key into the GUI's environment, and
        // every evedoo.exe / cve-db-builder.exe the GUI spawns inherits it —
        // so a planted .env reached the scanner and the feed downloader too.
        let sentinel = format!("EVEDOO_GUI_ENVFILE_SENTINEL_{}", std::process::id());
        let s = Scratch::new();
        let f = s.write(
            ".env",
            &format!("NVD_API_KEY=gui-key\n{sentinel}=leaked\nEVEDOO_DB_PATH=planted.sqlite\n"),
        );

        assert_eq!(nvd_api_key_from_files(&[f]).as_deref(), Some("gui-key"));
        assert!(std::env::var_os(&sentinel).is_none());
    }

    #[test]
    fn candidates_never_include_a_parent_directory() {
        let cwd = Path::new("/work/project/sub");
        let exe = Path::new("/opt/evedoo");
        assert_eq!(
            env_file_candidates(Some(cwd), Some(exe)),
            vec![cwd.join(".env"), exe.join(".env")]
        );
    }

    #[test]
    fn a_gui_run_from_its_cargo_build_dir_reads_the_workspace_root() {
        // Double-clicking target\release\evedoo-gui.exe makes the working
        // directory the build dir. dotenvy's parent walk found the repo .env
        // from there; the workspace root is now derived from the exe location.
        let exe = Path::new("/repo/target/release");
        assert_eq!(
            env_file_candidates(Some(exe), Some(exe)),
            vec![exe.join(".env"), Path::new("/repo").join(".env")]
        );
    }

    #[test]
    fn only_the_exe_location_implies_a_workspace() {
        let cwd = Path::new("/shared/target/release");
        let exe = Path::new("/opt/evedoo");
        assert_eq!(
            env_file_candidates(Some(cwd), Some(exe)),
            vec![cwd.join(".env"), exe.join(".env")]
        );
    }

    #[test]
    fn a_parent_dotenv_is_not_read() {
        let s = Scratch::new();
        s.write(".env", "NVD_API_KEY=planted-in-parent\n");
        let cwd = s.0.join("project").join("sub");
        std::fs::create_dir_all(&cwd).unwrap();
        assert_eq!(
            nvd_api_key_from_files(&env_file_candidates(Some(&cwd), None)),
            None
        );
    }

    #[test]
    fn a_blank_key_falls_through_to_the_next_candidate() {
        let s = Scratch::new();
        let blank = s.write("a/.env", "NVD_API_KEY=\n");
        let real = s.write("b/.env", "NVD_API_KEY=real\n");
        assert_eq!(
            nvd_api_key_from_files(&[blank, real]).as_deref(),
            Some("real")
        );
    }
}

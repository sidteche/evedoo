//! The release binary must take configuration from the real environment and
//! its flags only — never from a `.env` file.
//!
//! `dotenvy::dotenv()` searches the working directory *and every parent
//! directory* for `.env`, and imports every key it finds. For a scanner that is
//! routinely run elevated, that let anyone able to write a `.env` anywhere
//! above the operator's working directory set `EVEDOO_DB_PATH`: swapping the
//! CVE database for one that reports the host clean, or pointing it at a UNC
//! path so the elevated process authenticates to an attacker's SMB server.
//!
//! These run the built binary rather than a function, because the defect was
//! one line in `main` that no unit test could see.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;

/// A throwaway directory tree, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "evedoo-envfile-{label}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `evedoo <args>` run from `cwd` with the variables under test scrubbed
/// from the inherited environment, so only what the test sets can reach it.
/// Returns stdout + stderr.
fn evedoo(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_evedoo"));
    cmd.args(args)
        .current_dir(cwd)
        .env_remove("EVEDOO_DB_PATH")
        .env_remove("EVEDOO_REMOTE_PASSWORD");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run evedoo");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_dotenv_in_the_working_directory_is_ignored() {
    let dir = Scratch::new("cwd");
    std::fs::write(
        dir.path().join(".env"),
        "EVEDOO_DB_PATH=PLANTED_IN_CWD.sqlite\n",
    )
    .unwrap();

    let help = evedoo(dir.path(), &["scan", "--help"], &[]);

    assert!(
        !help.contains("PLANTED_IN_CWD"),
        "a .env in the working directory configured the database path:\n{help}"
    );
}

#[test]
fn a_dotenv_in_a_parent_directory_is_ignored() {
    // The planted file sits two levels above where the operator runs the
    // scanner — the case that makes this an attack rather than a convenience.
    let root = Scratch::new("parent");
    let cwd = root.path().join("project").join("subdir");
    std::fs::create_dir_all(&cwd).unwrap();
    // Single-quoted: dotenvy reads backslashes in an unquoted value as escape
    // sequences, so an unquoted UNC path fails to parse and is never loaded —
    // which would make this test pass without testing anything.
    std::fs::write(
        root.path().join(".env"),
        "EVEDOO_DB_PATH='\\\\attacker\\share\\PLANTED_UNC.sqlite'\n",
    )
    .unwrap();

    let help = evedoo(&cwd, &["scan", "--help"], &[]);

    assert!(
        !help.contains("PLANTED_UNC"),
        "a .env two directories above the working directory configured the \
         database path:\n{help}"
    );
}

#[test]
fn the_real_environment_still_configures_the_database() {
    // Removing .env support must not remove the supported mechanism.
    let dir = Scratch::new("realenv");

    let help = evedoo(
        dir.path(),
        &["scan", "--help"],
        &[("EVEDOO_DB_PATH", "FROM_REAL_ENV.sqlite")],
    );

    assert!(
        help.contains("FROM_REAL_ENV.sqlite"),
        "EVEDOO_DB_PATH from the real environment was not honoured:\n{help}"
    );
}

#[test]
fn the_remote_password_is_never_echoed_in_help() {
    // clap prints live env values in --help unless hide_env_values is set. A
    // WinRM admin credential must never reach a terminal, CI log or
    // screenshot that way.
    let dir = Scratch::new("password");

    let help = evedoo(
        dir.path(),
        &["remote-scan", "--help"],
        &[("EVEDOO_REMOTE_PASSWORD", "S3CRET-SENTINEL")],
    );

    assert!(
        !help.contains("S3CRET-SENTINEL"),
        "the remote password was printed by --help:\n{help}"
    );
}

//! Text normalization used across scanning and matching.
//!
//! Three submodules, each responsible for one step in turning a messy
//! installed-software entry into something the CPE matcher can use:
//!
//! * [`names`] — display-name / package-name cleanup (AppX, Windows
//!   Uninstall, product-name extraction).
//! * [`tokens`] — lowercase alphanumeric tokenisation plus a subset helper
//!   used by the curated-mapping scorer.
//! * [`version`] — structured [`Version`] parser and comparison.
//!
//! Consolidating these here (they previously lived under `scanner::appx`,
//! `matcher::tokens`, `matcher::version`, and a method on `CveMatcher`) means
//! future tweaks to name-cleanup rules don't bounce around five call sites,
//! and unrelated modules don't accidentally introduce their own string
//! munging.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod apk_version;
pub mod apple_version;
pub mod cpe_name;
pub mod dpkg_version;
pub mod names;
pub mod rpm_version;
pub mod tokens;
pub mod version;

#[allow(unused_imports)]
pub use apk_version::ApkVersion;
#[allow(unused_imports)]
pub use apple_version::{AppleBuildId, AppleVersion};
#[allow(unused_imports)]
pub use dpkg_version::DpkgVersion;
#[allow(unused_imports)]
pub use rpm_version::RpmVersion;
pub use version::Version;

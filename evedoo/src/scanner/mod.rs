//! Windows Registry scanner module.
//!
//! SPDX-License-Identifier: Apache-2.0

mod appx;
mod chocolatey;
pub mod linux;
pub mod macos;
mod os_version;
mod packages;
mod pe_fingerprint;
mod registry;
mod scoop;
mod version_resolver;
mod winget;

pub use appx::AppxScanner;
pub use chocolatey::ChocolateyScanner;
#[allow(unused_imports)]
pub use linux::LinuxScanner;
#[allow(unused_imports)]
pub use macos::MacOsScanner;
pub use os_version::OsVersionScanner;
pub use packages::{site_packages_software, PackageScanner};
pub use pe_fingerprint::PeFingerprintScanner;
pub use registry::RegistryScanner;
pub use scoop::ScoopScanner;
pub use version_resolver::VersionResolver;
pub use winget::WingetScanner;

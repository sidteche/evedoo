//! Remote scanning module — agentless vulnerability scanning via WinRM.
//!
//! Uses PowerShell `Invoke-Command` to enumerate software on remote Windows
//! machines without deploying an agent. SMB-based scanners (Chocolatey, Scoop)
//! read remote filesystems via UNC paths.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod scanners;
pub mod session;

pub use session::{RemoteSession, RemoteTarget};

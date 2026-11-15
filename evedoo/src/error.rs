//! Error types for the Evedoo scanner.
//!
//! SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[allow(dead_code)]
    #[error("Registry access error: {0}")]
    RegistryError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// User-supplied input failed validation (e.g. an exception's CVE id or
    /// expiry date). Deliberately has no prefix, unlike the other variants:
    /// the message is already written for a CLI operator to read directly
    /// (`not a valid expiry date: soon (expected YYYY-MM-DD)`), and wrapping
    /// it in "Serialization error:" would misdescribe a rejected value as an
    /// internal (de)serialization failure.
    #[error("{0}")]
    ValidationError(String),

    #[error("Database not found: {0}")]
    DatabaseNotFound(String),

    #[error("Remote connection error: {0}")]
    RemoteError(String),

    #[error("Schedule error: {0}")]
    ScheduleError(String),
}

pub type Result<T> = std::result::Result<T, ScanError>;

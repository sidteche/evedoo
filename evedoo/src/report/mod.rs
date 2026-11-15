//! Report generation module.
//!
//! SPDX-License-Identifier: Apache-2.0

mod csv;
mod cyclonedx;
mod html;
mod json;
mod spdx;
mod text;

pub use cyclonedx::CycloneDxReporter;
pub use html::HtmlReporter;
pub use json::JsonReporter;
pub use spdx::SpdxReporter;

use crate::error::Result;
use crate::models::ScanResult;

/// Output format enum
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Json,
    Csv,
    Text,
    Html,
    CycloneDx,
    Spdx,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            "text" | "txt" => Ok(OutputFormat::Text),
            "html" => Ok(OutputFormat::Html),
            "cyclonedx" | "cdx" => Ok(OutputFormat::CycloneDx),
            "spdx" => Ok(OutputFormat::Spdx),
            _ => Err(format!(
                "Unknown format: {}. Use json, csv, text, html, cyclonedx, or spdx.",
                s
            )),
        }
    }
}

/// Report generator trait
/// Required by the NVD terms of use for any product built on NVD data; shown
/// in the text, HTML and JSON reports.
pub const NVD_NOTICE: &str = "This product uses the NVD API but is not endorsed or certified by the NVD.";

pub trait Reporter {
    fn generate(&self, result: &ScanResult) -> Result<String>;
}

/// Generate report in specified format. `show_risk` only affects the `Text`
/// format (FR-67: machine formats like CSV/JSON always carry the risk
/// score/priority fields, so there is nothing to gate there); every other
/// format ignores it.
pub fn generate_report(result: &ScanResult, format: OutputFormat, show_risk: bool) -> Result<String> {
    match format {
        OutputFormat::Json => JsonReporter.generate(result),
        OutputFormat::Csv => csv::generate_csv(result),
        OutputFormat::Text => text::generate_text(result, show_risk),
        OutputFormat::Html => HtmlReporter.generate(result),
        OutputFormat::CycloneDx => CycloneDxReporter.generate(result),
        OutputFormat::Spdx => SpdxReporter.generate(result),
    }
}

/// Neutralise spreadsheet formula injection (OWASP CSV injection / CWE-1236).
///
/// A CSV cell whose first character is `=`, `+`, `-`, `@`, TAB, CR, or LF is
/// executed as a formula by Excel and LibreOffice. Prefixing a single quote
/// forces the cell to be read as text. Values that don't start with a
/// dangerous character are returned unchanged.
pub(crate) fn sanitize_csv_cell(value: &str) -> std::borrow::Cow<'_, str> {
    match value.as_bytes().first() {
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r' | b'\n') => {
            std::borrow::Cow::Owned(format!("'{value}"))
        }
        _ => std::borrow::Cow::Borrowed(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_csv_cell_prefixes_every_dangerous_leader() {
        for lead in ["=cmd|' /c calc'!A1", "+1+1", "-1", "@SUM(A1)", "\tx", "\rx", "\nx"] {
            let out = sanitize_csv_cell(lead);
            assert!(out.starts_with('\''), "{lead:?} was not neutralised: {out:?}");
            assert!(out.ends_with(lead));
        }
    }

    #[test]
    fn sanitize_csv_cell_leaves_safe_values_untouched_and_borrowed() {
        for safe in ["Google Chrome", "1.2.3", "", "CVE-2024-1234", "cmd|'/c calc'"] {
            assert!(matches!(sanitize_csv_cell(safe), std::borrow::Cow::Borrowed(_)));
            assert_eq!(sanitize_csv_cell(safe), safe);
        }
    }
}


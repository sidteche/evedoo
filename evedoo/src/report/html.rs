//! HTML report generator with severity dashboard, top remediation actions,
//! and sortable findings table.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use super::Reporter;
use crate::error::Result;
use crate::models::{ScanResult, Severity};

pub struct HtmlReporter;

/// A grouped remediation action: one software upgrade that fixes N CVEs.
struct RemediationAction {
    software_name: String,
    current_version: String,
    fixed_version: Option<String>,
    upgrade_command: Option<String>,
    cve_count: usize,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    max_cvss: f32,
    kev_count: usize,
    max_epss: f32,
    cve_ids: Vec<String>,
    kb_articles: Vec<String>,
    /// Detection source (e.g. "registry://", "pip://")
    source: String,
    /// Install location if available
    install_location: Option<String>,
    /// Publisher name
    publisher: Option<String>,
}

impl Reporter for HtmlReporter {
    fn generate(&self, result: &ScanResult) -> Result<String> {
        let critical = result.findings.iter().filter(|f| f.vulnerability.severity == Severity::Critical).count();
        let high     = result.findings.iter().filter(|f| f.vulnerability.severity == Severity::High).count();
        let medium   = result.findings.iter().filter(|f| f.vulnerability.severity == Severity::Medium).count();
        let low      = result.findings.iter().filter(|f| f.vulnerability.severity == Severity::Low).count();
        let total    = result.findings.len();
        let kev_count = result.findings.iter().filter(|f| f.vulnerability.in_kev).count();

        let scan_time = result.scan_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();

        // ── Build Top Remediation Actions ──────────────────────────────
        let actions = build_remediation_actions(result);
        let actions_html = build_actions_html(&actions);

        // ── Build findings table rows (clickable for detail modal) ─────
        // Whether the Reachability column appears at all (FR-80). Computed
        // once over every finding: a column present for some rows and absent
        // for others would produce a malformed table.
        let show_reach = result
            .findings
            .iter()
            .any(|f| f.reachability != crate::reachability::Reachability::Unknown);

        let mut rows = String::new();
        for (idx, finding) in result.findings.iter().enumerate() {
            let sev_class = match finding.vulnerability.severity {
                Severity::Critical => "critical",
                Severity::High     => "high",
                Severity::Medium   => "medium",
                Severity::Low      => "low",
                Severity::Unknown  => "unknown",
            };
            let cvss = finding.vulnerability.cvss_score
                .map(|s| format!("{:.1}", s))
                .unwrap_or_else(|| "N/A".to_string());
            let version = finding.software.version.as_deref().unwrap_or("unknown");
            let vendor  = finding.vendor.as_deref().unwrap_or("\u{2014}");
            let pub_date = finding.vulnerability.published_date.as_deref()
                .map(|d| if d.len() >= 10 { &d[..10] } else { d })
                .unwrap_or("\u{2014}");
            let cve_url = format!(
                "https://nvd.nist.gov/vuln/detail/{}",
                finding.vulnerability.cve_id.to_lowercase()
            );
            let desc: String = finding.vulnerability.description.chars().take(200).collect();

            let kev_cell = if finding.vulnerability.in_kev {
                let due = finding
                    .vulnerability
                    .kev_due_date
                    .as_deref()
                    .unwrap_or("\u{2014}");
                format!(
                    r#"<span class="badge kev" title="CISA KEV — due {}">KEV</span>"#,
                    html_escape(due)
                )
            } else {
                "\u{2014}".to_string()
            };
            // EPSS as a magnitude bar plus the value: "0.00042" alone is
            // unreadable at a glance. Scores are heavily skewed toward zero,
            // so the bar uses a square-root curve to keep low values visible.
            let epss_cell = finding
                .vulnerability
                .epss_score
                .map(|s| {
                    let pct = (s.clamp(0.0, 1.0).sqrt() * 100.0).round() as u32;
                    format!(
                        r#"<span class="epss"><span class="epss-bar"><span class="epss-fill" style="width:{pct}%"></span></span><span class="epss-val">{s:.3}</span></span>"#
                    )
                })
                .unwrap_or_else(|| "\u{2014}".to_string());

            // Status-honesty gate (P21-HTML-RESIDUAL). `correlate()` stamps
            // every finding with the placeholder `FindingStatus::New` before
            // reconciliation, and on `--no-history` or a history-read failure
            // that placeholder is never replaced with a real comparison.
            // Rendering it would put a "New" badge on every row, asserting a
            // delta the tool never computed. `text.rs` skips its status line
            // entirely on that path (not shown with a caveat); the table's
            // equivalent is dropping the column, header and cells together.
            // Status is the last column, so the sort handler's `a.cells[col]`
            // indices 0..=10 stay valid when it goes.
            let status_cell = if result.delta_known {
                let badge = match finding.status {
                    // NewlyApplicable is grouped with New: both mean "this just
                    // showed up as something you need to act on," even though the
                    // underlying reason (new install vs. new CVE) differs.
                    crate::models::FindingStatus::New
                    | crate::models::FindingStatus::NewlyApplicable => {
                        r#"<span class="badge new">New</span>"#
                    }
                    crate::models::FindingStatus::Persisting => r#"<span class="badge persisting">Persisting</span>"#,
                    // NoLongerApplicable is grouped with Resolved: both mean "no
                    // action needed here anymore," even though the underlying
                    // reason (uninstalled vs. CVE data no longer matching) differs.
                    crate::models::FindingStatus::Resolved
                    | crate::models::FindingStatus::NoLongerApplicable => {
                        r#"<span class="badge resolved">Resolved</span>"#
                    }
                };
                format!("<td>{badge}</td>")
            } else {
                String::new()
            };

            // Reachability (FR-80). Gated on whether ANY finding in this
            // report has a determined value, not on this finding's own — a
            // column that appears and disappears per row is not a column.
            // Independent of `delta_known`: reachability is measured on this
            // run rather than compared against a previous one.
            let reach_cell = if show_reach {
                let badge = match finding.reachability {
                    crate::reachability::Reachability::Loaded => {
                        r#"<span class="badge new">Loaded</span>"#
                    }
                    crate::reachability::Reachability::NotObserved => {
                        r#"<span class="badge persisting">Not loaded</span>"#
                    }
                    crate::reachability::Reachability::Unknown => "\u{2014}",
                };
                format!("<td>{badge}</td>")
            } else {
                String::new()
            };

            // Same gate for the modal's data attribute. When it is absent the
            // modal's `if (d.status)` guard drops the field rather than
            // rendering an empty row.
            let status_attr = if result.delta_known {
                format!(r#"data-status="{}" "#, finding.status)
            } else {
                String::new()
            };

            let fixed_cell = finding
                .vulnerability
                .remediation
                .fixed_version
                .as_deref()
                .unwrap_or("\u{2014}");

            // Encode full detail data as data-* attributes for the modal
            let source = detect_source(&finding.software.registry_key);
            let location = finding.software.install_location.as_deref().unwrap_or("");
            let publisher = finding.software.publisher.as_deref().unwrap_or("");
            let recommendation = &finding.vulnerability.remediation.recommendation;
            let upgrade_cmd = finding.vulnerability.remediation.upgrade_command.as_deref().unwrap_or("");
            let kb_list = finding.vulnerability.remediation.kb_articles.join(", ");
            let ref_list = finding.vulnerability.references.join("\n");
            let kev_due = finding.vulnerability.kev_due_date.as_deref().unwrap_or("");
            let epss_pct = finding.vulnerability.epss_percentile.map(|p| format!("{:.1}%", p * 100.0)).unwrap_or_default();
            let ransomware = finding.vulnerability.kev_ransomware_use.as_deref().unwrap_or("");

            rows.push_str(&format!(
                r#"<tr class="row-{sev_class} finding-row" data-idx="{idx}"
  data-cve="{cve_id}" data-cvss="{cvss}" data-severity="{severity}"
  data-app="{app}" data-version="{version}" data-vendor="{vendor}"
  data-publisher="{publisher}" data-source="{source}" data-location="{location}"
  data-desc="{desc_full}" data-published="{pub_date}" data-confidence="{confidence}"
  {status_attr}data-fixed="{fixed}" data-recommendation="{recommendation}"
  data-upgrade="{upgrade_cmd}" data-kb="{kb_list}" data-refs="{ref_list}"
  data-kev="{kev}" data-kev-due="{kev_due}" data-epss="{epss_val}" data-epss-pct="{epss_pct}"
  data-ransomware="{ransomware}" data-cve-url="{cve_url}"
  data-has-fix="{has_fix}"
  style="cursor:pointer;" title="Click for details">
  <td><span class="badge {sev_class}">{severity}</span></td>
  <td>{kev_cell}</td>
  <td>{epss_display}</td>
  <td><a href="{cve_url}" target="_blank" rel="noopener" onclick="event.stopPropagation();">{cve_id}</a></td>
  <td>{cvss}</td>
  <td>{app} v{version}</td>
  <td>{vendor}</td>
  <td>{fixed}</td>
  <td class="desc" title="{desc_full}">{desc}&hellip;</td>
  <td>{pub_date}</td>
  <td>{confidence}</td>
  {status_cell}{reach_cell}
</tr>
"#,
                idx = idx,
                status_cell = status_cell,
                reach_cell = reach_cell,
                status_attr = status_attr,
                sev_class = sev_class,
                severity  = finding.vulnerability.severity,
                kev_cell  = kev_cell,
                epss_display = epss_cell,
                has_fix   = if finding.vulnerability.remediation.fixed_version.is_some() {
                    "yes"
                } else {
                    "no"
                },
                cve_url   = html_escape(&cve_url),
                cve_id    = html_escape(&finding.vulnerability.cve_id),
                cvss      = cvss,
                app       = html_escape(&finding.software.name),
                version   = html_escape(version),
                vendor    = html_escape(vendor),
                publisher = html_escape(publisher),
                source    = html_escape(&source),
                location  = html_escape(location),
                fixed     = html_escape(fixed_cell),
                desc      = html_escape(&desc),
                desc_full = html_escape(&finding.vulnerability.description),
                pub_date  = html_escape(pub_date),
                confidence = finding.confidence,
                recommendation = html_escape(recommendation),
                upgrade_cmd = html_escape(upgrade_cmd),
                kb_list   = html_escape(&kb_list),
                ref_list  = html_escape(&ref_list),
                kev       = finding.vulnerability.in_kev,
                kev_due   = html_escape(kev_due),
                // Plain value for the data attribute and the modal — the
                // cell version below is markup and would break out of the
                // quoted attribute.
                epss_val  = finding
                    .vulnerability
                    .epss_score
                    .map(|s| format!("{s:.3}"))
                    .unwrap_or_default(),
                epss_pct  = html_escape(&epss_pct),
                ransomware = html_escape(ransomware),
            ));
        }

        // Build resolved findings section
        let resolved_section = if result.resolved_findings.is_empty() {
            String::new()
        } else {
            let mut s = String::from(
                r#"<div class="table-wrap"><details><summary style="cursor:pointer;color:var(--fg-dim);padding:12px 0;font-size:13px;">&#9654; Resolved since last scan (click to expand)</summary><table style="margin-top:8px;opacity:.7"><thead><tr><th>CVE ID</th><th>Application</th><th>First Seen</th></tr></thead><tbody>"#,
            );
            for f in &result.resolved_findings {
                s.push_str(&format!(
                    "<tr><td><a href=\"https://nvd.nist.gov/vuln/detail/{cve_lc}\" target=\"_blank\">{cve}</a></td><td>{app}</td><td>{date}</td></tr>",
                    cve_lc = html_escape(&f.vulnerability.cve_id.to_lowercase()),
                    cve    = html_escape(&f.vulnerability.cve_id),
                    app    = html_escape(&f.software.name),
                    date   = html_escape(
                        f.vulnerability.published_date.as_deref().unwrap_or("\u{2014}")
                    ),
                ));
            }
            s.push_str("</tbody></table></details></div>");
            s
        };

        // ── Total impact score for the hero number ─────────────────────
        let total_impact: f32 = actions.iter().map(|a| a.max_cvss * a.cve_count as f32).sum();

        // The header half of the status-honesty gate. Dropped together with
        // the per-row cells so the table stays well-formed; Status is the last
        // column, so `data-col` indices 0..=10 are unaffected either way.
        let status_header = if result.delta_known {
            r#"          <th data-col="11">Status</th>"#
        } else {
            ""
        };

        // Header half of the reachability gate, appended after Status so
        // `data-col` indices 0..=10 stay valid in every combination of the
        // two independent gates.
        let reach_header = if show_reach {
            "
          <th data-col=\"12\">Reachability</th>"
        } else {
            ""
        };

        let html = format!(
            r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Evedoo Vulnerability Report — {hostname}</title>
<style>
  /* ── Design tokens ────────────────────────────────────────────────
     macOS-flavoured Material: Apple's dark system palette (systemGray
     surfaces, systemBlue accent, systemRed/Orange/Yellow semantics),
     Material-style elevation via layered soft shadows, generous corner
     radii, and vibrancy (backdrop blur) on floating surfaces. Rounded
     and layered rather than hairline-sharp. */
  :root {{
    /* Apple dark-mode background ramp */
    --ink-950: #1c1c1e;   /* window ground                */
    --ink-900: #242426;   /* section ground               */
    --ink-850: #2c2c2e;   /* card surface   (elevation 1) */
    --ink-800: #3a3a3c;   /* raised / hover (elevation 2) */
    --ink-700: #48484a;   /* fills, gaps                  */
    --ink-600: #5a5a5e;   /* strong separators            */

    /* Apple label colours */
    --fg:      #f5f5f7;
    --fg-mute: rgba(235,235,245,.62);
    --fg-dim:  rgba(235,235,245,.34);
    --hairline: rgba(255,255,255,.10);

    --signal:  #ff9f0a;   /* systemOrange — brand / attention */
    --link:    #0a84ff;   /* systemBlue   — interactive       */
    --ok:      #32d74b;   /* systemGreen                      */

    --crit:    #ff453a;   /* systemRed    */
    --high:    #ff9f0a;   /* systemOrange */
    --med:     #ffd60a;   /* systemYellow */
    --low:     #0a84ff;   /* systemBlue   */
    --unknown: #8e8e93;   /* systemGray   */
    --alarm:   #ff375f;   /* systemPink — KEV outranks critical */

    --mono: ui-monospace, "SF Mono", "Cascadia Code", "JetBrains Mono",
            Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI",
            Roboto, system-ui, sans-serif;

    /* Corner radii — Apple/Material scale */
    --r-sm: 6px;
    --r:    10px;
    --r-lg: 14px;
    --r-xl: 18px;

    /* Material elevation: ambient + key light, kept soft */
    --e1: 0 1px 2px rgba(0,0,0,.28), 0 0 0 .5px rgba(255,255,255,.06);
    --e2: 0 2px 8px rgba(0,0,0,.32), 0 0 0 .5px rgba(255,255,255,.07);
    --e3: 0 8px 24px rgba(0,0,0,.40), 0 0 0 .5px rgba(255,255,255,.08);
    --e4: 0 18px 48px rgba(0,0,0,.52), 0 0 0 .5px rgba(255,255,255,.10);
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: var(--sans);
    background: var(--ink-950);
    color: var(--fg);
    font-size: 13.5px;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
    letter-spacing: -0.005em;
  }}

  /* ── Header: translucent titlebar with vibrancy ─────────────────── */
  header {{
    background: rgba(36,36,38,.72);
    backdrop-filter: saturate(180%) blur(20px);
    -webkit-backdrop-filter: saturate(180%) blur(20px);
    border-bottom: 1px solid var(--hairline);
    padding: 22px 28px 20px;
    /* Deliberately not sticky: it is ~110px tall and its height varies with
       how the meta chips wrap, so pinning it would both eat the viewport on
       a dense table and make the sticky <th> offset unguessable. */
  }}
  header h1 {{
    font-size: 20px; font-weight: 640; letter-spacing: -0.02em; color: var(--fg);
    display: flex; align-items: center; gap: 9px;
  }}
  header h1::before {{
    content: ""; width: 11px; height: 11px; border-radius: 50%;
    background: var(--signal);
    box-shadow: 0 0 0 4px rgba(255,159,10,.16);
    flex: none;
  }}
  header p {{ color: var(--fg-mute); margin-top: 3px; font-size: 12.5px; }}
  .meta {{ display: flex; gap: 7px; margin-top: 14px; flex-wrap: wrap; }}
  .meta span {{
    background: rgba(255,255,255,.07);
    border-radius: 980px;                /* Apple capsule */
    padding: 3.5px 11px;
    font-size: 11.5px; color: var(--fg-mute);
  }}
  .meta span b {{
    color: var(--fg); font-weight: 590; margin-left: 4px;
  }}

  /* ── Stat cards: elevated tiles ─────────────────────────────────── */
  .cards {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px; padding: 20px 28px 4px;
  }}
  .card {{
    background: var(--ink-850); border-radius: var(--r-lg);
    padding: 15px 17px 14px; box-shadow: var(--e1);
    transition: transform .16s ease, box-shadow .16s ease;
  }}
  .card:hover {{ transform: translateY(-1px); box-shadow: var(--e2); }}
  .card .num {{
    font-size: 27px; font-weight: 640; line-height: 1.15;
    letter-spacing: -0.03em; font-variant-numeric: tabular-nums;
  }}
  .card .lbl {{
    font-size: 11.5px; color: var(--fg-mute); margin-top: 2px; font-weight: 500;
  }}
  .card-kev .num      {{ color: var(--alarm); }}
  .card-kev.is-clear .num {{ color: var(--ok); font-size: 21px; }}
  .card-critical .num {{ color: var(--crit); }}
  .card-high .num     {{ color: var(--high); }}
  .card-medium .num   {{ color: var(--med); }}
  .card-low .num      {{ color: var(--low); }}
  .card-total .num    {{ color: var(--fg); }}

  /* ── Tabs: segmented control ────────────────────────────────────── */
  .tab-bar {{
    display: inline-flex; gap: 2px; margin: 18px 28px 0;
    background: rgba(255,255,255,.06); border-radius: var(--r);
    padding: 3px;
  }}
  .tab-btn {{
    background: none; border: none; border-radius: var(--r-sm);
    color: var(--fg-mute); font-family: inherit; font-size: 12.5px;
    font-weight: 560; padding: 6px 15px; cursor: pointer;
    transition: background .15s, color .15s;
  }}
  .tab-btn:hover {{ color: var(--fg); }}
  .tab-btn.active {{
    background: var(--ink-800); color: var(--fg); box-shadow: var(--e1);
  }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}

  /* ── Solutions ──────────────────────────────────────────────────── */
  .solutions {{ padding: 20px 28px 36px; }}
  .solutions h2 {{
    font-size: 17px; font-weight: 640; letter-spacing: -0.02em; color: var(--fg);
  }}
  .sol-grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(345px, 1fr));
    gap: 14px;
  }}
  .sol-card {{
    background: var(--ink-850); border-radius: var(--r-lg);
    padding: 16px 18px; position: relative; box-shadow: var(--e1);
    transition: transform .16s ease, box-shadow .16s ease;
    overflow: hidden;
  }}
  .sol-card::before {{
    content: ""; position: absolute; inset: 0 auto 0 0; width: 4px;
    background: var(--ink-700);
  }}
  .sol-card:hover {{ transform: translateY(-2px); box-shadow: var(--e3); }}
  .sol-card.crit::before {{ background: var(--crit); }}
  .sol-card.high::before {{ background: var(--high); }}
  .sol-card.med::before  {{ background: var(--med); }}
  .sol-card.low::before  {{ background: var(--low); }}
  .sol-rank {{
    position: absolute; top: 14px; right: 16px;
    font-size: 11.5px; color: var(--fg-dim); font-variant-numeric: tabular-nums;
  }}
  .sol-name {{
    font-size: 15px; font-weight: 620; letter-spacing: -0.015em;
    padding-right: 38px; word-break: break-word;
  }}
  .sol-ver {{
    font-family: var(--mono); font-size: 11.5px; color: var(--fg-mute);
    margin-top: 4px;
  }}
  .sol-stats {{ display: flex; gap: 14px; flex-wrap: wrap; margin: 12px 0 10px; }}
  .sol-stat {{ font-size: 11.5px; color: var(--fg-dim); }}
  .sol-stat b, .sol-stat .n {{
    font-weight: 620; font-variant-numeric: tabular-nums;
  }}
  .sol-stat .crit, .sol-stat.crit b {{ color: var(--crit); }}
  .sol-stat .high, .sol-stat.high b {{ color: var(--high); }}
  .sol-stat .med,  .sol-stat.med  b {{ color: var(--med); }}
  .sol-stat .low,  .sol-stat.low  b {{ color: var(--low); }}
  .sol-stat .tot,  .sol-stat.tot  b {{ color: var(--fg); }}
  .sol-stat .l {{ font-size: 10.5px; color: var(--fg-dim); }}
  .sol-impact {{ font-size: 12px; color: var(--fg-mute); }}
  .impact-bar {{
    height: 5px; background: rgba(255,255,255,.08);
    border-radius: 980px; overflow: hidden; margin: 10px 0;
  }}
  .impact-bar-fill {{ height: 100%; border-radius: 980px; }}
  .sol-cves {{ font-size: 11.5px; margin-top: 10px; line-height: 1.9; }}
  .sol-cves a {{
    color: var(--link); text-decoration: none; font-family: var(--mono);
    background: rgba(10,132,255,.10); border-radius: var(--r-sm);
    padding: 2px 6px;
  }}
  .sol-cves a:hover {{ background: rgba(10,132,255,.20); }}
  .sol-kb {{ font-size: 11.5px; margin-top: 8px; }}
  .sol-kb a {{ color: var(--link); text-decoration: none; }}
  .sol-kev {{
    display: inline-block; background: rgba(255,55,95,.16);
    color: var(--alarm); border-radius: 980px; padding: 2px 9px;
    font-size: 10.5px; font-weight: 640; margin-top: 8px;
  }}
  .sol-cmd, .modal-cmd {{
    background: rgba(0,0,0,.28); border-radius: var(--r);
    padding: 9px 12px; margin-top: 10px;
    font-family: var(--mono); font-size: 11.5px; color: var(--ok);
    word-break: break-all; position: relative;
    padding-right: 62px; min-height: 34px;
  }}
  .sol-cmd::before, .modal-cmd::before {{ content: "$ "; color: var(--fg-dim); }}
  /* Always visible: hover-gated controls are undiscoverable. */
  .copy-btn {{
    position: absolute; top: 6px; right: 6px;
    background: rgba(255,255,255,.10); border: none;
    color: var(--fg-mute); border-radius: 980px;
    font-family: var(--sans); font-size: 10.5px; font-weight: 560;
    padding: 3px 10px; cursor: pointer; transition: background .15s, color .15s;
  }}
  .copy-btn:hover {{ background: rgba(255,255,255,.18); color: var(--fg); }}
  .copy-btn.copied {{ background: rgba(50,215,75,.20); color: var(--ok); }}
  .copy-btn.failed {{ background: rgba(255,69,58,.20); color: var(--crit); }}

  /* ── Toolbar / filters ──────────────────────────────────────────── */
  .table-wrap {{ padding: 18px 28px 44px; }}
  .toolbar {{
    display: flex; gap: 8px; align-items: center;
    flex-wrap: wrap; margin-bottom: 14px;
  }}
  #search {{
    flex: 1 1 260px; min-width: 200px;
    background: rgba(255,255,255,.07); border: none;
    border-radius: var(--r); padding: 8px 13px;
    color: var(--fg); font-family: inherit; font-size: 13px;
  }}
  #search::placeholder {{ color: var(--fg-dim); }}
  #search:focus {{
    outline: none; background: rgba(255,255,255,.10);
    box-shadow: 0 0 0 3px rgba(10,132,255,.35);
  }}
  .filter-btn {{
    background: rgba(255,255,255,.07); border: none;
    border-radius: 980px; color: var(--fg-mute);
    font-family: inherit; font-size: 12px; font-weight: 560;
    padding: 6px 14px; cursor: pointer; transition: background .15s, color .15s;
  }}
  .filter-btn:hover {{ background: rgba(255,255,255,.12); color: var(--fg); }}
  .filter-btn.active {{ background: var(--link); color: #fff; }}
  .filter-btn.active[data-sev="critical"] {{ background: var(--crit); }}
  .filter-btn.active[data-sev="high"]     {{ background: var(--high); color: #1c1c1e; }}
  .filter-btn.active[data-sev="medium"]   {{ background: var(--med);  color: #1c1c1e; }}
  .filter-btn.active[data-sev="low"]      {{ background: var(--low); }}
  .filter-btn.active[data-flag="kev"]     {{ background: var(--alarm); }}
  .row-count {{
    font-size: 12px; color: var(--fg-mute);
    margin-left: auto; white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }}
  .row-count b {{ color: var(--fg); font-weight: 620; }}

  /* ── Findings table: inset grouped list ─────────────────────────── */
  .table-wrap table {{
    width: 100%; border-collapse: separate; border-spacing: 0;
    background: var(--ink-850); border-radius: var(--r-lg);
    overflow: hidden; box-shadow: var(--e1);
  }}
  thead th {{
    position: sticky; top: 0; z-index: 2;
    background: rgba(58,58,60,.92);
    backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    text-align: left; font-size: 11.5px; font-weight: 590;
    color: var(--fg-mute);
    padding: 10px 12px; border-bottom: 1px solid var(--hairline);
    cursor: pointer; user-select: none; white-space: nowrap;
  }}
  thead th:hover {{ color: var(--fg); }}
  thead th::after {{ content: ""; color: var(--link); font-size: 9px; margin-left: 5px; }}
  thead th.sort-asc::after  {{ content: "▲"; }}
  thead th.sort-desc::after {{ content: "▼"; }}
  tbody td {{
    padding: 9px 12px; border-bottom: 1px solid var(--hairline);
    vertical-align: top;
  }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr {{ transition: background .12s; }}
  tbody tr:hover {{ background: rgba(255,255,255,.05); }}
  tbody tr.row-critical td:first-child {{ box-shadow: inset 3px 0 var(--crit); }}
  tbody tr.row-high     td:first-child {{ box-shadow: inset 3px 0 var(--high); }}
  tbody tr.row-medium   td:first-child {{ box-shadow: inset 3px 0 var(--med); }}
  tbody tr.row-low      td:first-child {{ box-shadow: inset 3px 0 var(--low); }}
  tbody tr.row-unknown  td:first-child {{ box-shadow: inset 3px 0 var(--unknown); }}
  td a {{ color: var(--link); text-decoration: none; font-family: var(--mono); }}
  td a:hover {{ text-decoration: underline; }}
  .desc {{
    color: var(--fg-mute); font-size: 12px; max-width: 380px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}

  /* ── Badges: capsules ───────────────────────────────────────────── */
  .badge {{
    display: inline-block; border-radius: 980px;
    padding: 2px 9px; font-size: 10.5px; font-weight: 620;
    white-space: nowrap;
  }}
  .badge.critical {{ background: rgba(255,69,58,.18);  color: var(--crit); }}
  .badge.high     {{ background: rgba(255,159,10,.18); color: var(--high); }}
  .badge.medium   {{ background: rgba(255,214,10,.18); color: var(--med); }}
  .badge.low      {{ background: rgba(10,132,255,.20); color: var(--low); }}
  .badge.unknown  {{ background: rgba(142,142,147,.20); color: var(--unknown); }}
  .badge.kev      {{ background: rgba(255,55,95,.20);  color: var(--alarm); }}
  .badge.new        {{ background: rgba(255,159,10,.18); color: var(--signal); }}
  .badge.persisting {{ background: rgba(255,255,255,.10); color: var(--fg-mute); }}
  .badge.resolved   {{ background: rgba(50,215,75,.18); color: var(--ok); }}

  .epss {{ display: flex; align-items: center; gap: 7px; }}
  .epss-bar {{
    width: 36px; height: 5px; background: rgba(255,255,255,.10);
    border-radius: 980px; overflow: hidden; flex: none;
  }}
  .epss-fill {{ height: 100%; background: var(--signal); border-radius: 980px; }}
  .epss-val {{
    font-size: 11.5px; color: var(--fg-mute);
    font-variant-numeric: tabular-nums;
  }}

  /* ── Modal: sheet with vibrancy ─────────────────────────────────── */
  .modal-overlay {{
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,.45); z-index: 100;
    align-items: flex-start; justify-content: center; padding: 48px 20px;
    overflow-y: auto;
    backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
  }}
  .modal-overlay.open {{ display: flex; }}
  .modal {{
    background: rgba(44,44,46,.92);
    backdrop-filter: saturate(180%) blur(30px);
    -webkit-backdrop-filter: saturate(180%) blur(30px);
    border-radius: var(--r-xl); max-width: 880px; width: 100%;
    box-shadow: var(--e4);
    animation: sheet-in .22s cubic-bezier(.32,.72,0,1);
  }}
  @keyframes sheet-in {{
    from {{ opacity: 0; transform: scale(.97) translateY(8px); }}
    to   {{ opacity: 1; transform: none; }}
  }}
  .modal-header {{
    display: flex; align-items: center; justify-content: space-between;
    gap: 12px; padding: 17px 22px;
    border-bottom: 1px solid var(--hairline);
    position: sticky; top: 0;
    background: rgba(44,44,46,.86);
    backdrop-filter: blur(30px); -webkit-backdrop-filter: blur(30px);
    border-radius: var(--r-xl) var(--r-xl) 0 0;
  }}
  .modal-header h3 {{ font-size: 16px; font-weight: 620; letter-spacing: -0.02em; }}
  .modal-close {{
    background: rgba(255,255,255,.10); border: none; color: var(--fg-mute);
    border-radius: 50%; width: 26px; height: 26px;
    font-size: 15px; line-height: 1; cursor: pointer; flex: none;
  }}
  .modal-close:hover {{ background: rgba(255,255,255,.18); color: var(--fg); }}
  .modal-body {{ padding: 20px 22px 24px; }}
  .modal-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));
    gap: 16px 22px;
  }}
  .modal-field.full {{ grid-column: 1 / -1; }}
  .modal-field .mf-label {{
    font-size: 11px; color: var(--fg-dim); margin-bottom: 3px; font-weight: 500;
  }}
  .modal-field .mf-value {{ font-size: 13.5px; color: var(--fg); word-break: break-word; }}
  .modal-section {{
    border-top: 1px solid var(--hairline); margin-top: 18px; padding-top: 16px;
  }}
  .modal-section h4 {{
    font-size: 12.5px; color: var(--fg-mute); margin-bottom: 11px; font-weight: 590;
  }}
  .modal-refs {{ list-style: none; padding: 0; }}
  .modal-refs li {{
    font-size: 11.5px; margin-bottom: 5px; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap;
  }}
  .modal-refs a {{ color: var(--link); font-family: var(--mono); }}

  /* ── Print: reports get shared as PDF ───────────────────────────── */
  @media print {{
    :root {{
      --ink-950: #fff; --ink-900: #fff; --ink-850: #fff;
      --ink-800: #f2f2f2; --ink-700: #ddd; --ink-600: #aaa;
      --fg: #000; --fg-mute: #444; --fg-dim: #666;
      --hairline: #ddd;
      --e1: none; --e2: none; --e3: none; --e4: none;
    }}
    body {{ font-size: 10pt; }}
    header {{ position: static; background: #fff; backdrop-filter: none; }}
    .toolbar, .tab-bar, .copy-btn, .modal-overlay {{ display: none !important; }}
    .tab-panel {{ display: block !important; }}
    thead th {{ position: static; background: #f2f2f2; backdrop-filter: none; }}
    .card, .sol-card, .table-wrap table {{ box-shadow: none; border: 1px solid #ddd; }}
    tbody tr, .sol-card {{ page-break-inside: avoid; }}
    a {{ color: #000 !important; text-decoration: underline; }}
  }}
</style>
</head>
<body>

<header>
  <h1>Evedoo Vulnerability Report</h1>
  <p>CVE data: NIST National Vulnerability Database (NVD)</p>
  <div class="meta">
    <span>Host: <b>{hostname}</b></span>
    <span>Mode: <b>{scan_mode}</b></span>
    <span>Scan time: <b>{scan_time}</b></span>
    <span>Software scanned: <b>{total_software}</b></span>
    <span>Vulnerabilities: <b>{total}</b></span>
  </div>
</header>

<div class="cards">
  <div class="card card-kev{kev_clear_class}">
    <div class="num">{kev_display}</div><div class="lbl">{kev_label}</div>
  </div>
  <div class="card card-critical">
    <div class="num">{critical}</div><div class="lbl">Critical</div>
  </div>
  <div class="card card-high">
    <div class="num">{high}</div><div class="lbl">High</div>
  </div>
  <div class="card card-medium">
    <div class="num">{medium}</div><div class="lbl">Medium</div>
  </div>
  <div class="card card-low">
    <div class="num">{low}</div><div class="lbl">Low</div>
  </div>
  <div class="card card-total">
    <div class="num">{total}</div><div class="lbl">Total</div>
  </div>
</div>

<nav class="tab-bar">
  <button class="tab-btn active" data-tab="solutions">Top Solutions</button>
  <button class="tab-btn" data-tab="findings">All Findings</button>
</nav>

<!-- ═══ Tab 1: Top Solutions ═══ -->
<div id="tab-solutions" class="tab-panel active">
  <div class="solutions">
    <h2>Top Remediation Actions &mdash; Highest Impact First</h2>
    <p style="color:var(--fg-dim);font-size:13px;margin-bottom:16px;">
      Each card represents a single software upgrade. Ranked by the number of
      CVEs resolved &times; max CVSS score. Fix the top items first for the
      biggest risk reduction.
      <span style="color:var(--ink-600);margin-left:8px;">
        Combined impact score: <b style="color:var(--link);">{total_impact:.0}</b>
      </span>
    </p>
    <div class="sol-grid">
{actions_html}
    </div>
  </div>
</div>

<!-- ═══ Tab 2: All Findings ═══ -->
<div id="tab-findings" class="tab-panel">
  <div class="table-wrap" style="padding-top:24px;">
    <div class="toolbar">
      <input type="text" id="search" placeholder="Search CVE, app, description...">
      <button class="filter-btn active" data-sev="all">All</button>
      <button class="filter-btn" data-sev="critical">Critical</button>
      <button class="filter-btn" data-sev="high">High</button>
      <button class="filter-btn" data-sev="medium">Medium</button>
      <button class="filter-btn" data-sev="low">Low</button>
      <button class="filter-btn" data-flag="kev" title="Only CISA known-exploited">KEV</button>
      <button class="filter-btn" data-flag="fix" title="Only findings with a known fixed version">Has Fix</button>
      <span class="row-count" id="row-count"></span>
    </div>
    <table id="findings">
      <thead>
        <tr>
          <th data-col="0">Severity</th>
          <th data-col="1">KEV</th>
          <th data-col="2">EPSS</th>
          <th data-col="3">CVE ID</th>
          <th data-col="4">CVSS</th>
          <th data-col="5">Application</th>
          <th data-col="6">Vendor</th>
          <th data-col="7">Fixed In</th>
          <th data-col="8">Description</th>
          <th data-col="9">Published</th>
          <th data-col="10">Confidence</th>
{status_header}{reach_header}
        </tr>
      </thead>
      <tbody id="tbody">
{rows}
      </tbody>
    </table>
  </div>

  {resolved_section}
</div>

<!-- ═══ Detail Modal ═══ -->
<div class="modal-overlay" id="modal-overlay">
  <div class="modal">
    <div class="modal-header">
      <h3 id="modal-title">Finding Detail</h3>
      <button class="modal-close" id="modal-close">&times;</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<footer>Generated by Evedoo v{version} &middot; {scan_time}<br>{nvd_notice}</footer>

<script>
(function() {{
  // ── Tab switching ──
  document.querySelectorAll('.tab-btn').forEach(function(btn) {{
    btn.addEventListener('click', function() {{
      document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
      document.querySelectorAll('.tab-panel').forEach(function(p) {{ p.classList.remove('active'); }});
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    }});
  }});

  // ── Findings table: sort + filter ──
  var tbody = document.getElementById('tbody');
  if (!tbody) return;
  var rows  = Array.from(tbody.querySelectorAll('tr'));
  var sortCol = -1, sortAsc = true;
  var activeFilter = 'all';
  var searchTerm = '';
  // Flag filters combine with the severity filter (AND), so "Critical +
  // Has Fix" answers "what can I actually act on right now?".
  var flags = {{ kev: false, fix: false }};

  document.querySelectorAll('#findings thead th').forEach(function(th) {{
    th.addEventListener('click', function() {{
      var col = parseInt(th.dataset.col);
      if (sortCol === col) {{ sortAsc = !sortAsc; }} else {{ sortCol = col; sortAsc = true; }}
      document.querySelectorAll('#findings thead th').forEach(function(t) {{
        t.classList.remove('sort-asc','sort-desc');
      }});
      th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
      rows.sort(function(a, b) {{
        var av = a.cells[col] ? a.cells[col].innerText : '';
        var bv = b.cells[col] ? b.cells[col].innerText : '';
        return sortAsc ? av.localeCompare(bv, undefined, {{numeric:true}})
                       : bv.localeCompare(av, undefined, {{numeric:true}});
      }});
      rows.forEach(function(r) {{ tbody.appendChild(r); }});
      applyFilter();
    }});
  }});

  document.querySelectorAll('.filter-btn').forEach(function(btn) {{
    btn.addEventListener('click', function() {{
      if (btn.dataset.flag) {{
        // Flag chips toggle independently of the severity group.
        flags[btn.dataset.flag] = !flags[btn.dataset.flag];
        btn.classList.toggle('active', flags[btn.dataset.flag]);
      }} else {{
        document.querySelectorAll('.filter-btn[data-sev]').forEach(function(b) {{
          b.classList.remove('active');
        }});
        btn.classList.add('active');
        activeFilter = btn.dataset.sev;
      }}
      applyFilter();
    }});
  }});

  var searchInput = document.getElementById('search');
  if (searchInput) {{
    searchInput.addEventListener('input', function(e) {{
      searchTerm = e.target.value.toLowerCase();
      applyFilter();
    }});
  }}

  var rowCount = document.getElementById('row-count');

  function applyFilter() {{
    var shown = 0;
    rows.forEach(function(r) {{
      var sevMatch = (activeFilter === 'all') || r.classList.contains('row-' + activeFilter);
      var textMatch = !searchTerm || r.innerText.toLowerCase().includes(searchTerm);
      var kevMatch = !flags.kev || (r.dataset.kev && r.dataset.kev !== '' && r.dataset.kev !== 'false');
      var fixMatch = !flags.fix || r.dataset.hasFix === 'yes';
      var visible = sevMatch && textMatch && kevMatch && fixMatch;
      r.style.display = visible ? '' : 'none';
      if (visible) shown++;
    }});
    if (rowCount) {{
      rowCount.innerHTML = shown === rows.length
        ? '<b>' + rows.length + '</b> findings'
        : '<b>' + shown + '</b> of ' + rows.length + ' findings';
    }}
  }}
  applyFilter();

  // ── Copy buttons on shell commands ──
  document.querySelectorAll('.sol-cmd, .modal-cmd').forEach(addCopyButton);

  /// Copy `text`, resolving true on success. navigator.clipboard is absent
  /// or rejects in several real contexts (older browsers, some file://
  /// origins, denied permission) and this report is routinely opened
  /// straight off disk — so fall back to the textarea + execCommand trick
  /// rather than failing silently.
  function copyText(text) {{
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      return navigator.clipboard.writeText(text).then(function() {{ return true; }},
                                                      function() {{ return legacyCopy(text); }});
    }}
    return Promise.resolve(legacyCopy(text));
  }}
  function legacyCopy(text) {{
    try {{
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:0;left:-9999px;opacity:0;';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    }} catch (e) {{ return false; }}
  }}

  function addCopyButton(el) {{
    if (el.querySelector('.copy-btn')) return;
    var btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = 'copy';
    btn.type = 'button';
    btn.addEventListener('click', function(e) {{
      e.stopPropagation();
      // Prefer the exact command from the data attribute; scraping
      // textContent would also pick up the button's own label.
      var text = el.dataset.cmd || el.textContent.replace(/copy$|copied$|failed$/, '').trim();
      copyText(text).then(function(ok) {{
        btn.textContent = ok ? 'copied' : 'select manually';
        btn.classList.add(ok ? 'copied' : 'failed');
        setTimeout(function() {{
          btn.textContent = 'copy';
          btn.classList.remove('copied', 'failed');
        }}, ok ? 1400 : 2600);
      }});
    }});
    el.appendChild(btn);
  }}

  // ── Detail modal ──
  var overlay = document.getElementById('modal-overlay');
  var modalBody = document.getElementById('modal-body');
  var modalTitle = document.getElementById('modal-title');

  // Text-context escaper. The textContent -> innerHTML round-trip escapes
  // & < > only, which is correct for text nodes but NOT for attributes.
  function esc(s) {{ var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }}

  // Attribute-context escaper (SEC-1). Quotes must be encoded here: values
  // read back via dataset have already been HTML-decoded by the parser, so
  // the Rust-side html_escape() is undone by the time we see them.
  function escAttr(s) {{ return esc(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }}

  // Only http(s) URLs may reach an href (SEC-1) — blocks javascript: etc.
  function safeUrl(u) {{
    var t = String(u == null ? '' : u).trim();
    return /^https?:\/\//i.test(t) ? escAttr(t) : '#';
  }}

  document.querySelectorAll('.finding-row').forEach(function(row) {{
    row.addEventListener('click', function() {{
      var d = row.dataset;
      modalTitle.innerHTML = '<span class="badge ' + escAttr(d.severity).toLowerCase() + '">' + esc(d.severity) + '</span> ' + esc(d.cve);

      var html = '<div class="modal-grid">';
      html += field('CVE ID', '<a href="' + safeUrl(d.cveUrl) + '" target="_blank" rel="noopener">' + esc(d.cve) + '</a>');
      html += field('CVSS Score', esc(d.cvss));
      html += field('Application', esc(d.app) + ' v' + esc(d.version));
      html += field('Vendor', esc(d.vendor));
      html += field('Publisher', esc(d.publisher) || '\u2014');
      html += field('Confidence', esc(d.confidence));
      html += field('Detection Source', esc(d.source));
      if (d.status) html += field('Status', esc(d.status));
      if (d.location) html += field('Install Location', '<code style="font-size:12px;color:var(--fg-mute);">' + esc(d.location) + '</code>');
      html += field('Published', esc(d.published));
      html += field('Fixed In', esc(d.fixed) || '\u2014');

      // KEV / EPSS row
      if (d.kev === 'true') {{
        html += field('CISA KEV', '<span class="badge kev">Known Exploited</span>' + (d.kevDue ? ' \u2014 Due: ' + esc(d.kevDue) : ''));
        if (d.ransomware) html += field('Ransomware Use', esc(d.ransomware));
      }}
      if (d.epss && d.epss !== '\u2014') {{
        html += field('EPSS Score', esc(d.epss) + (d.epssPct ? ' (' + esc(d.epssPct) + ' percentile)' : ''));
      }}
      html += '</div>';

      // Description
      html += '<div class="modal-section"><h4>Description</h4>';
      html += '<p style="font-size:13px;color:var(--fg-mute);line-height:1.6;">' + esc(d.desc) + '</p></div>';

      // Remediation
      html += '<div class="modal-section"><h4>Remediation</h4>';
      html += '<p style="font-size:13px;color:var(--fg-mute);">' + esc(d.recommendation) + '</p>';
      if (d.upgrade) html += '<div class="modal-cmd" data-cmd="' + escAttr(d.upgrade) + '">' + esc(d.upgrade) + '</div>';
      if (d.kb) {{
        var kbs = d.kb.split(', ');
        html += '<p style="font-size:12px;color:var(--fg-mute);margin-top:8px;">KB Patches: ';
        html += kbs.map(function(kb) {{
          var kbNum = escAttr(kb.replace('KB',''));
          return '<a href="https://support.microsoft.com/help/' + kbNum + '" target="_blank" rel="noopener">' + esc(kb) + '</a>';
        }}).join(', ');
        html += '</p>';
      }}
      html += '</div>';

      // References
      if (d.refs) {{
        var refs = d.refs.split('\n').filter(function(r) {{ return r.trim(); }});
        if (refs.length > 0) {{
          html += '<div class="modal-section"><h4>References</h4><ul class="modal-refs">';
          refs.forEach(function(ref) {{
            html += '<li><a href="' + safeUrl(ref) + '" target="_blank" rel="noopener">' + esc(ref) + '</a></li>';
          }});
          html += '</ul></div>';
        }}
      }}

      modalBody.innerHTML = html;
      modalBody.querySelectorAll('.modal-cmd').forEach(addCopyButton);
      overlay.classList.add('open');
    }});
  }});

  function field(label, value) {{
    return '<div class="modal-field"><div class="mf-label">' + label + '</div><div class="mf-value">' + value + '</div></div>';
  }}

  // ── Solution cards open the full CVE list ──
  // The card body truncates at 10 CVEs ("+48 more"); clicking shows all of
  // them plus the remediation detail.
  document.querySelectorAll('.sol-card').forEach(function(card) {{
    card.style.cursor = 'pointer';
    card.addEventListener('click', function(e) {{
      // Let links and the copy button do their own thing.
      if (e.target.closest('a') || e.target.closest('.copy-btn')) return;
      var d = card.dataset;
      modalTitle.innerHTML = esc(d.solName) + ' <span class="badge persisting">' +
                             esc(d.solCount) + ' CVEs</span>';
      var html = '<div class="modal-grid">';
      html += field('Installed version', esc(d.solVer));
      html += field('Remediation', esc(d.solFix));
      html += field('Detection source', esc(d.solSource));
      html += field('Impact score', esc(d.solImpact));
      if (d.solLoc) html += field('Install location', esc(d.solLoc));
      html += '</div>';
      if (d.solCmd) {{
        html += '<div class="modal-section"><h4>Upgrade command</h4>' +
                '<div class="modal-cmd" data-cmd="' + escAttr(d.solCmd) + '">' + esc(d.solCmd) + '</div></div>';
      }}
      var cves = (d.solCves || '').split(' ').filter(Boolean);
      if (cves.length) {{
        html += '<div class="modal-section"><h4>All ' + cves.length + ' CVEs</h4>' +
                '<div class="sol-cves">' + cves.map(function(c) {{
                  return '<a href="https://nvd.nist.gov/vuln/detail/' +
                         escAttr(c.toLowerCase()) + '" target="_blank" rel="noopener">' +
                         esc(c) + '</a>';
                }}).join(', ') + '</div></div>';
      }}
      modalBody.innerHTML = html;
      // Commands rendered into the modal need their own copy button.
      modalBody.querySelectorAll('.modal-cmd').forEach(addCopyButton);
      overlay.classList.add('open');
    }});
  }});

  document.getElementById('modal-close').addEventListener('click', function() {{
    overlay.classList.remove('open');
  }});
  overlay.addEventListener('click', function(e) {{
    if (e.target === overlay) overlay.classList.remove('open');
  }});
  document.addEventListener('keydown', function(e) {{
    if (e.key === 'Escape') overlay.classList.remove('open');
  }});
}})();
</script>
</body>
</html>
"##,
            hostname     = html_escape(&result.hostname),
            scan_mode    = result.scan_mode,
            scan_time    = scan_time,
            total_software = result.total_software,
            total        = total,
            // Zero KEV is a result worth stating, not a blank stat.
            kev_display = if kev_count == 0 {
                "CLEAR".to_string()
            } else {
                kev_count.to_string()
            },
            kev_label = if kev_count == 0 {
                "No known-exploited CVEs"
            } else {
                "In CISA KEV"
            },
            kev_clear_class = if kev_count == 0 { " is-clear" } else { "" },
            critical     = critical,
            high         = high,
            medium       = medium,
            low          = low,
            total_impact = total_impact,
            actions_html = actions_html,
            rows             = rows,
            status_header    = status_header,
            reach_header     = reach_header,
            resolved_section = resolved_section,
            version          = env!("CARGO_PKG_VERSION"),
            nvd_notice       = super::NVD_NOTICE,
        );

        Ok(html)
    }
}

/// Group findings by software name + version to produce ranked remediation actions.
fn build_remediation_actions(result: &ScanResult) -> Vec<RemediationAction> {
    let mut map: HashMap<String, RemediationAction> = HashMap::new();

    for finding in &result.findings {
        let key = format!(
            "{}|{}",
            finding.software.name.to_lowercase(),
            finding.software.version.as_deref().unwrap_or(""),
        );

        let entry = map.entry(key).or_insert_with(|| RemediationAction {
            software_name: finding.software.name.clone(),
            current_version: finding.software.version.clone().unwrap_or_else(|| "unknown".into()),
            fixed_version: None,
            upgrade_command: None,
            cve_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            max_cvss: 0.0,
            kev_count: 0,
            max_epss: 0.0,
            cve_ids: Vec::new(),
            kb_articles: Vec::new(),
            source: detect_source(&finding.software.registry_key),
            install_location: finding.software.install_location.clone(),
            publisher: finding.software.publisher.clone(),
        });

        entry.cve_count += 1;
        match finding.vulnerability.severity {
            Severity::Critical => entry.critical_count += 1,
            Severity::High     => entry.high_count += 1,
            Severity::Medium   => entry.medium_count += 1,
            Severity::Low      => entry.low_count += 1,
            Severity::Unknown  => {}
        }

        if let Some(cvss) = finding.vulnerability.cvss_score {
            if cvss > entry.max_cvss {
                entry.max_cvss = cvss;
            }
        }
        if finding.vulnerability.in_kev {
            entry.kev_count += 1;
        }
        if let Some(epss) = finding.vulnerability.epss_score {
            if epss > entry.max_epss {
                entry.max_epss = epss;
            }
        }

        entry.cve_ids.push(finding.vulnerability.cve_id.clone());

        // Take the highest fixed_version (latest) and any upgrade command
        if entry.fixed_version.is_none() {
            entry.fixed_version = finding.vulnerability.remediation.fixed_version.clone();
        }
        if entry.upgrade_command.is_none() {
            entry.upgrade_command = finding.vulnerability.remediation.upgrade_command.clone();
        }

        for kb in &finding.vulnerability.remediation.kb_articles {
            if !entry.kb_articles.contains(kb) {
                entry.kb_articles.push(kb.clone());
            }
        }
    }

    let mut actions: Vec<RemediationAction> = map.into_values().collect();
    // Sort by impact: cve_count * max_cvss descending, then kev_count, then cve_count
    actions.sort_by(|a, b| {
        let impact_a = a.cve_count as f32 * a.max_cvss;
        let impact_b = b.cve_count as f32 * b.max_cvss;
        impact_b
            .partial_cmp(&impact_a)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.kev_count.cmp(&a.kev_count))
            .then_with(|| b.cve_count.cmp(&a.cve_count))
    });

    actions
}

/// Render the Top Solutions cards as HTML.
fn build_actions_html(actions: &[RemediationAction]) -> String {
    if actions.is_empty() {
        return r#"<div style="color:var(--fg-dim);padding:24px;">No vulnerabilities found — nothing to remediate.</div>"#.to_string();
    }

    let max_impact = actions
        .first()
        .map(|a| a.cve_count as f32 * a.max_cvss)
        .unwrap_or(1.0)
        .max(1.0);

    let mut html = String::new();

    for (i, action) in actions.iter().enumerate() {
        let impact_score = action.cve_count as f32 * action.max_cvss;
        let bar_pct = (impact_score / max_impact * 100.0).min(100.0);

        let bar_color = if action.critical_count > 0 {
            "var(--crit)"
        } else if action.high_count > 0 {
            "var(--high)"
        } else if action.medium_count > 0 {
            "var(--med)"
        } else {
            "var(--ok)"
        };

        let fix_label = match &action.fixed_version {
            Some(v) => format!("Upgrade to v{}", html_escape(v)),
            None => "Update to latest version".to_string(),
        };

        let kev_badge = if action.kev_count > 0 {
            format!(r#"<span class="sol-kev">KEV &times; {}</span>"#, action.kev_count)
        } else {
            String::new()
        };

        let cmd_html = match &action.upgrade_command {
            Some(cmd) => format!(
                r#"<div class="sol-cmd" data-cmd="{c}">{c}</div>"#,
                c = html_escape(cmd)
            ),
            None => String::new(),
        };

        let kb_html = if action.kb_articles.is_empty() {
            String::new()
        } else {
            let links: Vec<String> = action.kb_articles.iter().map(|kb| {
                format!(
                    r#"<a href="https://support.microsoft.com/help/{kb}" target="_blank" rel="noopener">{kb}</a>"#,
                    kb = html_escape(kb)
                )
            }).collect();
            format!(r#"<div class="sol-kb">KB patches: {}</div>"#, links.join(", "))
        };

        let cve_links: Vec<String> = action.cve_ids.iter().take(10).map(|id| {
            format!(
                r#"<a href="https://nvd.nist.gov/vuln/detail/{id_lc}" target="_blank">{id}</a>"#,
                id_lc = html_escape(&id.to_lowercase()),
                id = html_escape(id),
            )
        }).collect();
        let mut cve_list = cve_links.join(", ");
        if action.cve_ids.len() > 10 {
            cve_list.push_str(&format!(" +{} more", action.cve_ids.len() - 10));
        }

        let publisher_html = match &action.publisher {
            Some(p) if !p.is_empty() => format!("<span>{}</span>", html_escape(p)),
            _ => String::new(),
        };
        let location_html = match &action.install_location {
            Some(l) if !l.is_empty() => format!(
                r#" <span style="color:var(--ink-600);">&bull;</span> <span style="color:var(--fg-mute);font-family:monospace;font-size:11px;">{}</span>"#,
                html_escape(l)
            ),
            _ => String::new(),
        };

        html.push_str(&format!(
            r##"      <div class="sol-card" data-sol-name="{name}" data-sol-ver="{current}"
        data-sol-fix="{fix_label}" data-sol-source="{source}" data-sol-loc="{location_plain}"
        data-sol-cmd="{cmd_plain}" data-sol-cves="{all_cves}" data-sol-count="{cve_count}"
        data-sol-impact="{impact:.0}" title="Click for all {cve_count} CVEs">
        <div class="sol-rank">#{rank}</div>
        <div class="sol-name">{name}</div>
        <div class="sol-ver">v{current} &rarr; {fix_label}</div>
        <div style="font-size:11px;color:var(--fg-dim);margin-bottom:8px;">
          <span style="background:rgba(255,255,255,.08);border-radius:980px;padding:2px 9px;margin-right:6px;">{source}</span>
          {publisher_html}{location_html}
        </div>
        <span class="sol-impact">Impact: {impact:.0} ({cve_count} CVEs &times; {max_cvss:.1} max CVSS)</span>
        {kev_badge}
        <div class="sol-stats">
          <div class="sol-stat"><div class="n crit">{crit}</div><div class="l">Critical</div></div>
          <div class="sol-stat"><div class="n high">{high}</div><div class="l">High</div></div>
          <div class="sol-stat"><div class="n med">{med}</div><div class="l">Medium</div></div>
          <div class="sol-stat"><div class="n low">{low}</div><div class="l">Low</div></div>
          <div class="sol-stat"><div class="n tot">{cve_count}</div><div class="l">Total</div></div>
        </div>
        <div class="impact-bar"><div class="impact-bar-fill" style="width:{bar_pct:.0}%;background:{bar_color};"></div></div>
        {cmd_html}
        {kb_html}
        <div class="sol-cves">{cve_list}</div>
      </div>
"##,
            rank      = i + 1,
            name      = html_escape(&action.software_name),
            current   = html_escape(&action.current_version),
            fix_label = fix_label,
            source    = html_escape(&action.source),
            // Plain (attribute-safe) payloads for the detail modal — the
            // card body truncates the CVE list at 10.
            location_plain = html_escape(action.install_location.as_deref().unwrap_or("")),
            cmd_plain = html_escape(action.upgrade_command.as_deref().unwrap_or("")),
            all_cves = html_escape(&action.cve_ids.join(" ")),
            publisher_html = publisher_html,
            location_html = location_html,
            impact    = impact_score,
            cve_count = action.cve_count,
            max_cvss  = action.max_cvss,
            kev_badge = kev_badge,
            crit      = action.critical_count,
            high      = action.high_count,
            med       = action.medium_count,
            low       = action.low_count,
            bar_pct   = bar_pct,
            bar_color = bar_color,
            cmd_html  = cmd_html,
            kb_html   = kb_html,
            cve_list  = cve_list,
        ));
    }

    html
}

/// Minimal HTML escaping for user-controlled strings.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}

/// Derive a human-readable detection source from the registry_key scheme prefix.
fn detect_source(registry_key: &str) -> String {
    if registry_key.starts_with("registry://") {
        "Registry".into()
    } else if registry_key.starts_with("appx://") {
        "AppX / MSIX".into()
    } else if registry_key.starts_with("winget://") {
        "WinGet".into()
    } else if registry_key.starts_with("chocolatey://") {
        "Chocolatey".into()
    } else if registry_key.starts_with("scoop://") {
        "Scoop".into()
    } else if registry_key.starts_with("pe://") {
        "PE Fingerprint".into()
    } else if registry_key.starts_with("pip://") {
        "pip".into()
    } else if registry_key.starts_with("npm://") {
        "npm".into()
    } else if registry_key.starts_with("cargo://") {
        "cargo".into()
    } else {
        "Unknown".into()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    fn mk_result() -> ScanResult {
        let mut r = ScanResult::new("testhost".into());
        r.total_software = 50;

        // 3 CVEs for Chrome, 1 for Node
        let chrome_sw = DetectedSoftware {
            name: "Google Chrome".into(),
            version: Some("120.0.0".into()),
            publisher: Some("Google LLC".into()),
            install_location: None,
            install_date: None,
            registry_key: "registry://chrome".into(),
            architecture: Architecture::X64,
        };

        for (cve, cvss, sev) in [
            ("CVE-2024-0001", 9.8, Severity::Critical),
            ("CVE-2024-0002", 7.5, Severity::High),
            ("CVE-2024-0003", 5.0, Severity::Medium),
        ] {
            r.findings.push(Finding {
                software: chrome_sw.clone(),
                vulnerability: Vulnerability {
                    cve_id: cve.into(),
                    description: "Test vuln".into(),
                    cvss_score: Some(cvss),
                    severity: sev,
                    published_date: Some("2024-01-01".into()),
                    references: vec![],
                    remediation: Remediation {
                        recommendation: "Upgrade".into(),
                        fixed_version: Some("121.0.0".into()),
                        vendor_advisory: None,
                        kb_articles: vec![],
                        upgrade_command: Some("winget upgrade Google.Chrome".into()),
                    },
                    epss_score: Some(0.5),
                    epss_percentile: None,
                    in_kev: false,
                    kev_due_date: None,
                    kev_ransomware_use: None,
                },
                confidence: MatchConfidence::Exact,
                vendor: Some("google".into()),
                status: FindingStatus::New,
                risk: None,
                excepted: None,
                reachability: Default::default(),
            });
        }

        let node_sw = DetectedSoftware {
            name: "Node.js".into(),
            version: Some("18.0.0".into()),
            publisher: Some("Node.js Foundation".into()),
            install_location: None,
            install_date: None,
            registry_key: "registry://nodejs".into(),
            architecture: Architecture::X64,
        };
        r.findings.push(Finding {
            software: node_sw,
            vulnerability: Vulnerability {
                cve_id: "CVE-2024-0010".into(),
                description: "Node vuln".into(),
                cvss_score: Some(6.0),
                severity: Severity::Medium,
                published_date: Some("2024-02-01".into()),
                references: vec![],
                remediation: Remediation {
                    recommendation: "Upgrade".into(),
                    fixed_version: Some("18.1.0".into()),
                    vendor_advisory: None,
                    kb_articles: vec![],
                    upgrade_command: Some("winget upgrade OpenJS.NodeJS".into()),
                },
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::High,
            vendor: Some("nodejs".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        });

        r.total_vulnerabilities = r.findings.len();
        r
    }

    #[test]
    fn html_report_carries_the_nvd_notice_and_does_not_claim_nvd_backing() {
        let html = HtmlReporter.generate(&ScanResult::new("host".into())).unwrap();
        assert!(html.contains(crate::report::NVD_NOTICE));
        assert!(!html.contains("powered by NVD"));
    }

    #[test]
    fn actions_grouped_and_ranked_by_impact() {
        let result = mk_result();
        let actions = build_remediation_actions(&result);

        assert_eq!(actions.len(), 2);
        // Chrome (3 CVEs * 9.8 max) should rank above Node (1 * 6.0)
        assert_eq!(actions[0].software_name, "Google Chrome");
        assert_eq!(actions[0].cve_count, 3);
        assert_eq!(actions[0].critical_count, 1);
        assert_eq!(actions[0].high_count, 1);
        assert_eq!(actions[0].medium_count, 1);
        assert!(actions[0].max_cvss > 9.0);

        assert_eq!(actions[1].software_name, "Node.js");
        assert_eq!(actions[1].cve_count, 1);
    }

    #[test]
    fn html_contains_top_solutions_tab() {
        let result = mk_result();
        let html = HtmlReporter.generate(&result).unwrap();
        assert!(html.contains("Top Solutions"));
        assert!(html.contains("Top Remediation Actions"));
        assert!(html.contains("Google Chrome"));
        assert!(html.contains("winget upgrade Google.Chrome"));
    }

    #[test]
    fn html_contains_findings_table() {
        let result = mk_result();
        let html = HtmlReporter.generate(&result).unwrap();
        assert!(html.contains("CVE-2024-0001"));
        assert!(html.contains("CVE-2024-0010"));
        assert!(html.contains("All Findings"));
    }


    /// `(header cells, first body row cells)` for the findings table. A table
    /// whose two halves disagree is malformed HTML, and no assertion about a
    /// single badge would notice — removing the `<th>` while leaving the `<td>`
    /// passes every content check and still ships a broken report.
    fn column_counts(html: &str) -> (usize, usize) {
        let header = html.matches("<th data-col=").count();
        let first_row = html
            .split(r#"<tr class="row-"#)
            .nth(1)
            .expect("expected at least one finding row")
            .split("</tr>")
            .next()
            .expect("finding row must be closed");
        (header, first_row.matches("<td").count())
    }

    /// Status-honesty (P21-HTML-RESIDUAL). `correlate()` stamps every finding
    /// with the placeholder `FindingStatus::New` before reconciliation, and on
    /// `--no-history` or a history-read failure that placeholder is never
    /// replaced with a real comparison. Rendering it anyway would put a "New"
    /// badge on every row, asserting a delta the tool never computed.
    /// `text.rs` already skips its status line entirely on this path; the
    /// table's equivalent is dropping the column, header and cells together.
    ///
    /// Status is the last column (`data-col="11"`) and the sort handler indexes
    /// `a.cells[col]`, so removing it leaves indices 0..=10 valid.
    #[test]
    fn html_report_omits_status_column_when_delta_not_known() {
        let result = mk_result();
        assert!(
            !result.delta_known,
            "fixture precondition: ScanResult::new leaves delta_known false"
        );

        let html = HtmlReporter.generate(&result).unwrap();

        assert!(
            !html.contains(">Status</th>"),
            "the Status column header must be absent when the delta was never computed"
        );
        assert!(
            !html.contains(r#"<span class="badge new">New</span>"#),
            "no row may carry a New badge when the delta was never computed"
        );
        assert!(
            !html.contains("data-status="),
            "the modal's data-status attribute must not carry the placeholder either"
        );

        assert_eq!(
            column_counts(&html),
            (11, 11),
            "header and body must agree on column count, or the table is malformed"
        );
    }

    /// The other half of the gate: when the delta *is* known the status is
    /// real and must still be shown. Without this, "always omit the column"
    /// would satisfy the test above while destroying the feature.
    #[test]
    fn html_report_shows_status_column_when_delta_known() {
        let mut result = mk_result();
        result.delta_known = true;

        let html = HtmlReporter.generate(&result).unwrap();

        assert!(
            html.contains(">Status</th>"),
            "a real delta must still render the Status column header"
        );
        assert!(
            html.contains(r#"<span class="badge new">New</span>"#),
            "a real delta must still render per-row status badges"
        );
        assert!(
            html.contains("data-status="),
            "a real delta must still populate the modal's status field"
        );

        assert_eq!(
            column_counts(&html),
            (12, 12),
            "header and body must agree on column count, or the table is malformed"
        );
    }

    #[test]
    fn empty_result_shows_no_remediation_message() {
        let result = ScanResult::new("empty".into());
        let html = HtmlReporter.generate(&result).unwrap();
        assert!(html.contains("No vulnerabilities found"));
    }

    #[test]
    fn actions_html_includes_rank_numbers() {
        let result = mk_result();
        let actions = build_remediation_actions(&result);
        let html = build_actions_html(&actions);
        assert!(html.contains("#1"));
        assert!(html.contains("#2"));
    }

    #[test]
    fn kb_articles_appear_in_action_cards() {
        let mut result = ScanResult::new("h".into());
        let sw = DetectedSoftware {
            name: "Windows".into(),
            version: Some("10.0".into()),
            publisher: Some("Microsoft".into()),
            install_location: None,
            install_date: None,
            registry_key: "registry://win".into(),
            architecture: Architecture::X64,
        };
        result.findings.push(Finding {
            software: sw,
            vulnerability: Vulnerability {
                cve_id: "CVE-2024-9999".into(),
                description: "Win vuln".into(),
                cvss_score: Some(8.0),
                severity: Severity::High,
                published_date: None,
                references: vec![],
                remediation: Remediation {
                    recommendation: "Apply KB".into(),
                    fixed_version: None,
                    vendor_advisory: None,
                    kb_articles: vec!["KB5001234".into(), "KB5005678".into()],
                    upgrade_command: None,
                },
                epss_score: None,
                epss_percentile: None,
                in_kev: true,
                kev_due_date: Some("2024-06-01".into()),
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::High,
            vendor: Some("microsoft".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        });
        result.total_vulnerabilities = 1;

        let actions = build_remediation_actions(&result);
        let html = build_actions_html(&actions);
        assert!(html.contains("KB5001234"));
        assert!(html.contains("KB5005678"));
        assert!(html.contains("KEV"));
    }

    // ── SEC-1 / SEC-2: XSS regression ────────────────────────────────

    /// Build a report whose CVE database fields carry attribute-breaking
    /// payloads, as a tampered mirror feed or malicious CNA reference could.
    fn mk_hostile_result() -> ScanResult {
        let mut r = ScanResult::new("testhost".into());
        r.total_software = 1;
        r.findings.push(Finding {
            software: DetectedSoftware {
                name: r#"Evil" onmouseover="alert(1)"#.into(),
                version: Some(r#"1.0" autofocus onfocus="alert(2)"#.into()),
                publisher: Some("<script>alert(3)</script>".into()),
                install_location: Some(r#"C:\a" onload="alert(4)"#.into()),
                install_date: None,
                registry_key: "registry://evil".into(),
                architecture: Architecture::X64,
            },
            vulnerability: Vulnerability {
                cve_id: r#"CVE-2024-0001" onmouseover="alert(5)"#.into(),
                description: r#"desc" onmouseover="alert(6)"#.into(),
                cvss_score: Some(9.8),
                severity: Severity::Critical,
                published_date: Some(r#"2024-01-01" onmouseover="alert(7)"#.into()),
                references: vec![
                    r#"https://x/" onmouseover="alert(8)"#.into(),
                    "javascript:alert(9)".into(),
                ],
                remediation: Remediation {
                    recommendation: r#"fix" onmouseover="alert(10)"#.into(),
                    fixed_version: None,
                    vendor_advisory: None,
                    kb_articles: vec![],
                    upgrade_command: None,
                },
                epss_score: None,
                epss_percentile: None,
                in_kev: false,
                kev_due_date: None,
                kev_ransomware_use: None,
            },
            confidence: MatchConfidence::Exact,
            vendor: Some("evil".into()),
            status: FindingStatus::New,
            risk: None,
            excepted: None,
            reachability: Default::default(),
        });
        r.total_vulnerabilities = 1;
        r
    }

    #[test]
    fn hostile_cve_data_is_escaped_in_html_output() {
        let html = HtmlReporter.generate(&mk_hostile_result()).unwrap();

        // No raw event-handler injection survives anywhere in the document.
        for probe in [
            r#"" onmouseover=""#,
            r#"" autofocus"#,
            r#"" onfocus=""#,
            r#"" onload=""#,
            "<script>alert(3)</script>",
        ] {
            assert!(
                !html.contains(probe),
                "unescaped payload {probe:?} reached the HTML output"
            );
        }

        // The payload is present, but only in escaped form.
        assert!(html.contains("&quot;"), "escaped quotes must appear");
    }

    #[test]
    fn report_ships_console_theme_and_ux_affordances() {
        let html = HtmlReporter.generate(&mk_result()).unwrap();

        // Theme is token-driven, not the stock Chakra/Tailwind gray ramp.
        assert!(html.contains("--signal:"), "design tokens present");
        assert!(html.contains("--ink-950:"));
        for stock in ["#1a202c", "#2d3748", "#4a5568", "#718096", "#63b3ed"] {
            assert!(
                !html.contains(stock),
                "stock palette colour {stock} still present"
            );
        }

        // Sticky header, sort indicators, print stylesheet.
        assert!(html.contains("position: sticky"));
        assert!(html.contains(".sort-asc::after"));
        assert!(html.contains("@media print"));

        // Filter chips, row counter, copy affordance, EPSS magnitude bar.
        assert!(html.contains(r#"data-flag="kev""#));
        assert!(html.contains(r#"data-flag="fix""#));
        assert!(html.contains(r#"id="row-count""#));
        assert!(html.contains("copy-btn"));
        assert!(html.contains("epss-fill"));

        // Rows expose what the filters need.
        assert!(html.contains("data-has-fix="));
    }

    /// A `data-*` value containing a quote or a tag terminates its attribute
    /// and dumps the rest of the row into the page as text. This shipped
    /// once: `data-epss` was bound to the cell's markup rather than the raw
    /// score, which broke the entire All Findings table.
    #[test]
    fn data_attributes_never_contain_markup() {
        let html = HtmlReporter.generate(&mk_result()).unwrap();
        for row in html.split("<tr ").skip(1) {
            let tag = row.split('>').next().unwrap_or("");
            for attr in tag.split("data-").skip(1) {
                let value = attr
                    .split_once("=\"")
                    .and_then(|(_, rest)| rest.split_once('"'))
                    .map(|(v, _)| v)
                    .unwrap_or("");
                assert!(
                    !value.contains('<') && !value.contains("span"),
                    "data attribute carries markup: {value:?}"
                );
            }
        }
    }

    /// The copy affordance shipped once but was hover-gated, missing from the
    /// findings modal, and failed silently — i.e. effectively absent.
    #[test]
    fn copy_buttons_are_discoverable_and_robust() {
        let html = HtmlReporter.generate(&mk_result()).unwrap();

        // Not hover-gated: the reveal rules must be gone.
        assert!(
            !html.contains(".sol-cmd:hover .copy-btn"),
            "copy button is still hidden behind hover"
        );
        assert!(
            !html.contains("cursor: pointer; opacity: 0"),
            "copy button still starts invisible"
        );

        // Commands carry their text in a data attribute rather than being
        // scraped out of the DOM alongside the button label.
        assert!(html.contains(r#"class="sol-cmd" data-cmd="#));
        assert!(html.contains("el.dataset.cmd"));

        // Both modals wire copy buttons, not just the solutions one.
        assert_eq!(
            html.matches("querySelectorAll('.modal-cmd').forEach(addCopyButton)")
                .count(),
            2,
            "findings-row and solution-card modals must both wire copy buttons"
        );

        // Clipboard failure is handled rather than swallowed.
        assert!(html.contains("execCommand('copy')"), "needs a fallback path");
        assert!(html.contains("select manually"), "needs failure feedback");
        assert!(html.contains(".copy-btn.failed"));
    }

    #[test]
    fn kev_card_states_zero_as_a_result() {
        // mk_result() has no KEV findings.
        let html = HtmlReporter.generate(&mk_result()).unwrap();
        assert!(html.contains("card-kev is-clear"));
        assert!(html.contains("No known-exploited CVEs"));
        assert!(html.contains(">CLEAR<"));
    }

    #[test]
    fn js_helpers_are_attribute_safe_and_scheme_gated() {
        let html = HtmlReporter.generate(&mk_hostile_result()).unwrap();

        // The attribute escaper exists and encodes both quote characters.
        assert!(html.contains("function escAttr("));
        assert!(html.contains(r#".replace(/"/g, '&quot;')"#));

        // href sinks go through the scheme allowlist, not the text escaper.
        assert!(html.contains("function safeUrl("));
        assert!(
            html.contains(r#"'<li><a href="' + safeUrl(ref)"#),
            "reference hrefs must use safeUrl"
        );
        assert!(
            html.contains(r#"'<a href="' + safeUrl(d.cveUrl)"#),
            "CVE hrefs must use safeUrl"
        );
        // No attribute sink may still use the text-only escaper.
        assert!(
            !html.contains(r#"href="' + esc("#),
            "an href still uses the text-context escaper"
        );
    }

    /// FR-80. Nothing determined means no column at all — the same treatment
    /// the Status column gets when `delta_known` is false.
    #[test]
    fn html_omits_reachability_column_when_nothing_is_determined() {
        let result = mk_result(); // every finding defaults to Unknown
        let html = HtmlReporter.generate(&result).unwrap();
        assert!(!html.contains(">Reachability</th>"));
    }

    #[test]
    fn html_shows_reachability_column_when_any_finding_is_determined() {
        let mut result = mk_result();
        result.findings[0].reachability = crate::reachability::Reachability::Loaded;
        let html = HtmlReporter.generate(&result).unwrap();
        assert!(html.contains(">Reachability</th>"));
        assert!(html.contains("Loaded"));

        // The header and body must still agree — the same invariant the
        // status column gate needed, and the one no content assertion catches.
        let (header, body) = column_counts(&html);
        assert_eq!(
            header, body,
            "header and body must agree on column count"
        );
    }
}

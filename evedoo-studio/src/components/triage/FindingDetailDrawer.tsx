// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import {
  X,
  ShieldAlert,
  ExternalLink,
  ShieldCheck,
  Copy,
  AlertTriangle,
} from 'lucide-react';
import { Finding } from '../../types/scanner';

interface FindingDetailDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onAcceptRisk: (finding: Finding) => void;
}

export const FindingDetailDrawer: React.FC<FindingDetailDrawerProps> = ({
  finding,
  onClose,
  onAcceptRisk,
}) => {
  if (!finding) return null;

  // Parse CVSS Vector elements
  const vectorParts = finding.risk.cvss_v3_vector.split('/').slice(1);

  const copyAdvisory = () => {
    if (finding.vulnerability.references.length > 0) {
      navigator.clipboard.writeText(finding.vulnerability.references[0]);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div
        className="w-full max-w-2xl bg-light-surface dark:bg-dark-surface border-l border-light-border dark:border-dark-border h-full flex flex-col shadow-2xl overflow-hidden animate-in slide-in-from-right duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-5 border-b border-light-border dark:border-dark-border bg-light-header/90 dark:bg-dark-header/90 backdrop-blur-xl flex items-start justify-between">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border ${
                  finding.priority === 'P1'
                    ? 'bg-p1/10 text-p1-light dark:text-p1-dark border-p1/30'
                    : finding.priority === 'P2'
                    ? 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30'
                    : finding.priority === 'P3'
                    ? 'bg-p3/10 text-p3-light dark:text-p3-dark border-p3/30'
                    : 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30'
                }`}
              >
                {finding.priority} TIER
              </span>
              <span className="text-sm font-mono font-bold text-light-text dark:text-dark-text">
                {finding.cve_id}
              </span>
              {finding.risk.cisa_kev && (
                <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-p1/10 text-p1-light dark:text-p1-dark border border-p1/30 flex items-center gap-1">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  CISA KEV ACTIVE
                </span>
              )}
            </div>
            <h2 className="text-base font-semibold text-light-text dark:text-dark-text mt-1">
              {finding.vulnerability.title}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Drawer Content */}
        <div className="flex-1 p-6 space-y-6 overflow-y-auto font-sans text-xs">
          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-light-hover/60 dark:bg-dark-card p-4 rounded-xl border border-light-border dark:border-dark-border shadow-sm">
              <div className="text-light-muted dark:text-dark-muted font-mono text-[10px] uppercase font-semibold">CVSS v3.1 Base</div>
              <div className="text-2xl font-mono font-bold text-p1-light dark:text-p1-dark mt-1">
                {finding.risk.cvss_v3_score.toFixed(1)}
              </div>
              <div className="text-[10px] text-light-muted dark:text-dark-muted mt-0.5 font-mono">
                {finding.vulnerability.severity} Severity
              </div>
            </div>

            <div className="bg-light-hover/60 dark:bg-dark-card p-4 rounded-xl border border-light-border dark:border-dark-border shadow-sm">
              <div className="text-light-muted dark:text-dark-muted font-mono text-[10px] uppercase font-semibold">EPSS Probability</div>
              <div className="text-2xl font-mono font-bold text-p2-light dark:text-p2-dark mt-1">
                {(finding.risk.epss_score * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] text-light-muted dark:text-dark-muted mt-0.5 font-mono">
                {(finding.risk.epss_percentile * 100).toFixed(0)}th Percentile
              </div>
            </div>

            <div className="bg-light-hover/60 dark:bg-dark-card p-4 rounded-xl border border-light-border dark:border-dark-border shadow-sm">
              <div className="text-light-muted dark:text-dark-muted font-mono text-[10px] uppercase font-semibold">Exploit Maturity</div>
              <div className="text-lg font-mono font-bold text-light-text dark:text-dark-text mt-1.5">
                {finding.risk.exploit_maturity}
              </div>
              <div className="text-[10px] text-light-muted dark:text-dark-muted mt-0.5 font-mono">
                AC: {finding.risk.attack_complexity}
              </div>
            </div>
          </div>

          {/* CISA KEV Threat Callout if present */}
          {finding.risk.cisa_kev && (
            <div className="p-4 rounded-xl bg-p1/10 border border-p1/30 space-y-1.5">
              <div className="flex items-center gap-2 text-p1-light dark:text-p1-dark font-bold font-mono">
                <AlertTriangle className="w-4 h-4" />
                <span>Known Exploited In The Wild (CISA BOD 22-01)</span>
              </div>
              <div className="text-light-muted dark:text-dark-muted text-[11px] leading-relaxed">
                This vulnerability is actively exploited by threat actors in targeted campaigns.
                {finding.risk.ransomware_campaign && (
                  <span className="block mt-1 font-semibold text-rose-700 dark:text-rose-300">
                    Associated campaign: {finding.risk.ransomware_campaign}
                  </span>
                )}
                {finding.risk.cisa_due_date && (
                  <span className="block text-light-muted dark:text-dark-muted font-mono mt-0.5">
                    Federal Remediation Due Date: {finding.risk.cisa_due_date}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Vulnerability Description */}
          <div className="space-y-2">
            <h3 className="font-bold text-light-text dark:text-dark-text font-mono uppercase tracking-wider text-[11px]">
              Vulnerability Description
            </h3>
            <div className="p-4 rounded-xl bg-light-hover/40 dark:bg-dark-card border border-light-border dark:border-dark-border text-light-text dark:text-dark-text leading-relaxed">
              {finding.vulnerability.description}
            </div>
          </div>

          {/* CVSS Vector Breakdown */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-light-text dark:text-dark-text font-mono uppercase tracking-wider text-[11px]">
                CVSS v3.1 Vector
              </h3>
              <span className="text-[10px] font-mono text-light-muted dark:text-dark-muted">
                {finding.risk.cvss_v3_vector}
              </span>
            </div>
            <div className="grid grid-cols-4 gap-2 font-mono text-[11px]">
              {vectorParts.map((part) => {
                const [metric, val] = part.split(':');
                return (
                  <div key={metric} className="p-2 rounded-lg bg-light-hover/60 dark:bg-dark-card border border-light-border dark:border-dark-border text-center">
                    <div className="text-light-muted dark:text-dark-muted text-[9px] font-semibold">{metric}</div>
                    <div className="font-bold text-light-text dark:text-dark-text mt-0.5">{val}</div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Affected Software Provenance */}
          <div className="space-y-2">
            <h3 className="font-bold text-light-text dark:text-dark-text font-mono uppercase tracking-wider text-[11px]">
              Component Provenance & Probe Origin
            </h3>
            <div className="p-4 rounded-xl bg-light-hover/40 dark:bg-dark-card border border-light-border dark:border-dark-border space-y-2.5 font-mono">
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-light-muted dark:text-dark-muted">Product: </span>
                  <span className="text-light-text dark:text-dark-text font-semibold">{finding.software.product}</span>
                </div>
                <div>
                  <span className="text-light-muted dark:text-dark-muted">Vendor: </span>
                  <span className="text-light-text dark:text-dark-text">{finding.software.vendor}</span>
                </div>
                <div>
                  <span className="text-light-muted dark:text-dark-muted">Detected Version: </span>
                  <span className="text-p1-light dark:text-p1-dark font-bold">{finding.software.version}</span>
                </div>
                <div>
                  <span className="text-light-muted dark:text-dark-muted">Patched Version: </span>
                  <span className="text-p4-light dark:text-p4-dark font-bold">
                    {finding.vulnerability.patched_in_version || 'N/A'}
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-light-border/60 dark:border-dark-border/60 text-[10px] space-y-1">
                <div>
                  <span className="text-light-muted dark:text-dark-muted">Probe Source: </span>
                  <span className="text-p3 dark:text-p3-dark font-semibold">{finding.software.source}</span>
                </div>
                {finding.software.path && (
                  <div className="truncate">
                    <span className="text-light-muted dark:text-dark-muted">Executable Path: </span>
                    <span className="text-light-text dark:text-dark-text">{finding.software.path}</span>
                  </div>
                )}
                <div className="truncate">
                  <span className="text-light-muted dark:text-dark-muted">CPE: </span>
                  <span className="text-light-muted/90 dark:text-dark-muted/90">{finding.software.cpe}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Advisory & References */}
          <div className="space-y-2">
            <h3 className="font-bold text-light-text dark:text-dark-text font-mono uppercase tracking-wider text-[11px]">
              Advisories & References
            </h3>
            <div className="space-y-1.5 font-mono text-[11px]">
              {finding.vulnerability.references.map((url, idx) => (
                <a
                  key={idx}
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between p-2.5 rounded-lg bg-light-hover/60 dark:bg-dark-card border border-light-border dark:border-dark-border text-p3 dark:text-p3-dark hover:underline truncate"
                >
                  <span className="truncate">{url}</span>
                  <ExternalLink className="w-3.5 h-3.5 shrink-0 ml-2 text-light-muted dark:text-dark-muted" />
                </a>
              ))}
            </div>
          </div>
        </div>

        {/* Drawer Action Footer */}
        <div className="p-4 border-t border-light-border dark:border-dark-border bg-light-header/90 dark:bg-dark-header/90 backdrop-blur-xl flex items-center justify-between gap-3 shrink-0">
          <button
            onClick={copyAdvisory}
            className="px-3.5 py-2 rounded-xl bg-light-hover dark:bg-dark-card border border-light-border dark:border-dark-border text-xs text-light-text dark:text-dark-text hover:bg-light-surface dark:hover:bg-dark-hover flex items-center gap-1.5 font-mono transition-colors shadow-sm"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>Copy Advisory URL</span>
          </button>

          <div className="flex items-center gap-2">
            {finding.status !== 'Excepted' && (
              <button
                onClick={() => {
                  onAcceptRisk(finding);
                  onClose();
                }}
                className="px-3.5 py-2 rounded-xl bg-p4/10 border border-p4/30 text-p4-light dark:text-p4-dark hover:bg-p4/20 text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Accept Risk</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-p3 text-white font-semibold text-xs hover:brightness-110 transition-colors shadow-md"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};



// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import {
  ExternalLink,
  ChevronRight,
  Flame,
  Radio,
} from 'lucide-react';
import { Finding } from '../../types/scanner';

interface KevThreatRadarProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export const KevThreatRadar: React.FC<KevThreatRadarProps> = ({
  findings,
  onSelectFinding,
}) => {
  const kevFindings = findings.filter((f) => f.risk.cisa_kev);

  return (
    <div className="glass-panel rounded-2xl p-5 flex flex-col h-full shadow-sm">
      {/* Section Header */}
      <div className="flex items-center justify-between pb-3 border-b border-light-border dark:border-dark-border">
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Radio className="w-4 h-4 text-p1 animate-pulse" />
            <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 bg-p1 rounded-full animate-ping" />
          </div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-light-text dark:text-dark-text flex items-center gap-2 font-mono">
            CISA KEV Active Threat Radar
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-p1/10 text-p1-light dark:text-p1-dark border border-p1/30 font-semibold">
              {kevFindings.length} Exploited In Wild
            </span>
          </h2>
        </div>
        <a
          href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[11px] text-light-muted dark:text-dark-muted hover:text-p3 dark:hover:text-p3-dark flex items-center gap-1 font-mono transition-colors"
        >
          Catalog Spec
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>

      {/* Threat List */}
      <div className="mt-3.5 space-y-2.5 overflow-y-auto max-h-[380px] pr-1">
        {kevFindings.length === 0 ? (
          <div className="p-8 text-center text-xs text-light-muted dark:text-dark-muted font-mono bg-light-hover/40 dark:bg-dark-surface/40 rounded-xl border border-dashed border-light-border dark:border-dark-border">
            No active CISA KEV threats detected in current scope.
          </div>
        ) : (
          kevFindings.map((finding) => (
            <div
              key={finding.id}
              onClick={() => onSelectFinding(finding)}
              className="p-3.5 rounded-xl bg-light-surface/90 dark:bg-dark-surface/70 border border-light-border dark:border-dark-border hover:border-p1/60 dark:hover:border-p1/60 hover:bg-light-hover dark:hover:bg-dark-hover transition-all cursor-pointer group shadow-sm hover:shadow"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-bold text-p1-light dark:text-p1-dark group-hover:underline">
                      {finding.cve_id}
                    </span>
                    <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-p1/10 text-p1-light dark:text-p1-dark border border-p1/30">
                      CVSS {finding.risk.cvss_v3_score.toFixed(1)}
                    </span>
                    <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-p2/10 text-p2-light dark:text-p2-dark border border-p2/30 flex items-center gap-1">
                      <Flame className="w-2.5 h-2.5" />
                      EPSS {(finding.risk.epss_score * 100).toFixed(1)}%
                    </span>
                    {finding.risk.ransomware_campaign && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-700 dark:text-rose-300 border border-rose-500/30 font-medium">
                        {finding.risk.ransomware_campaign}
                      </span>
                    )}
                  </div>

                  <h3 className="text-xs font-semibold text-light-text dark:text-dark-text truncate group-hover:text-p3 dark:group-hover:text-p3-dark transition-colors">
                    {finding.vulnerability.title}
                  </h3>

                  <div className="flex items-center gap-2 text-[11px] text-light-muted dark:text-dark-muted font-mono">
                    <span className="text-light-text/90 dark:text-dark-text/90 font-medium">{finding.software.product}</span>
                    <span>v{finding.software.version}</span>
                    <span>•</span>
                    <span className="text-light-muted dark:text-dark-muted">{finding.host}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-center">
                  <ChevronRight className="w-4 h-4 text-light-muted dark:text-dark-muted group-hover:text-light-text dark:group-hover:text-dark-text group-hover:translate-x-0.5 transition-all" />
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};



// SPDX-License-Identifier: Apache-2.0
import React, { useState, useMemo } from 'react';
import {
  Package2,
  Filter,
  CheckCircle2,
  AlertTriangle,
  FileCode,
} from 'lucide-react';
import { DetectedSoftware, Finding } from '../../types/scanner';

interface SbomTableProps {
  softwareInventory: DetectedSoftware[];
  findings: Finding[];
  onExport: (format: 'cyclonedx' | 'csv') => void;
  searchQuery: string;
}

export const SbomTable: React.FC<SbomTableProps> = ({
  softwareInventory,
  findings,
  onExport,
  searchQuery,
}) => {
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');

  // Map vulnerable products to quick lookup
  const vulnerableCpes = useMemo(() => {
    const map = new Map<string, number>();
    findings.forEach((f) => {
      map.set(f.software.cpe, (map.get(f.software.cpe) || 0) + 1);
    });
    return map;
  }, [findings]);

  // Extract unique probe schemes
  const sourceSchemes = useMemo(() => {
    const set = new Set<string>();
    softwareInventory.forEach((s) => {
      const scheme = s.source.split('://')[0];
      if (scheme) set.add(scheme);
    });
    return ['ALL', ...Array.from(set)];
  }, [softwareInventory]);

  const filteredInventory = useMemo(() => {
    return softwareInventory.filter((item) => {
      const scheme = item.source.split('://')[0];
      if (sourceFilter !== 'ALL' && scheme !== sourceFilter) {
        return false;
      }
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          item.product.toLowerCase().includes(q) ||
          item.vendor.toLowerCase().includes(q) ||
          item.cpe.toLowerCase().includes(q) ||
          (item.path && item.path.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [softwareInventory, sourceFilter, searchQuery]);

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="glass-panel p-3.5 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-light-muted dark:text-dark-muted font-mono mr-2">
            <Filter className="w-3.5 h-3.5" />
            <span>Probe Source:</span>
          </div>

          <div className="flex rounded-xl border border-light-border dark:border-dark-border bg-light-surface dark:bg-dark-surface p-0.5 text-xs flex-wrap">
            {sourceSchemes.map((s) => (
              <button
                key={s}
                onClick={() => setSourceFilter(s)}
                className={`px-3 py-1 rounded-lg font-mono font-medium uppercase text-[11px] transition-all ${
                  sourceFilter === s
                    ? 'bg-light-hover dark:bg-dark-card text-light-text dark:text-dark-text font-bold shadow-sm'
                    : 'text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => onExport('cyclonedx')}
            className="px-3.5 py-1.5 rounded-xl bg-p2/10 border border-p2/30 text-p2-light dark:text-p2-dark hover:bg-p2/20 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all shadow-sm"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>CycloneDX 1.5 JSON</span>
          </button>
          <div className="text-xs font-mono text-light-muted dark:text-dark-muted">
            {filteredInventory.length} Components
          </div>
        </div>
      </div>

      {/* Inventory Table */}
      <div className="glass-panel rounded-2xl overflow-hidden border border-light-border dark:border-dark-border shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-light-border dark:border-dark-border bg-light-hover/60 dark:bg-dark-surface/80 text-light-muted dark:text-dark-muted font-mono uppercase text-[11px]">
                <th className="py-3.5 px-4">Component Product</th>
                <th className="py-3.5 px-4">Vendor</th>
                <th className="py-3.5 px-4">Version</th>
                <th className="py-3.5 px-4">Arch</th>
                <th className="py-3.5 px-4">Probe Origin</th>
                <th className="py-3.5 px-4">Filesystem Path</th>
                <th className="py-3.5 px-4 text-right">Security Match</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-light-border/60 dark:divide-dark-border/60 font-sans">
              {filteredInventory.map((item, idx) => {
                const cveCount = vulnerableCpes.get(item.cpe) || 0;
                const isVuln = cveCount > 0;
                const scheme = item.source.split('://')[0];

                return (
                  <tr key={idx} className="hover:bg-light-hover/70 dark:hover:bg-dark-hover/70 transition-colors">
                    {/* Product Name */}
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-light-text dark:text-dark-text flex items-center gap-2">
                        <Package2 className="w-3.5 h-3.5 text-p3 dark:text-p3-dark shrink-0" />
                        <span>{item.product}</span>
                      </div>
                      <div className="text-[10px] font-mono text-light-muted dark:text-dark-muted truncate max-w-[240px] mt-0.5">
                        {item.cpe}
                      </div>
                    </td>

                    {/* Vendor */}
                    <td className="py-3.5 px-4 text-light-muted dark:text-dark-muted">{item.vendor}</td>

                    {/* Version */}
                    <td className="py-3.5 px-4 font-mono font-medium text-light-text dark:text-dark-text">
                      v{item.version}
                    </td>

                    {/* Arch */}
                    <td className="py-3.5 px-4 font-mono text-light-muted dark:text-dark-muted text-[11px]">
                      {item.architecture || 'x64'}
                    </td>

                    {/* Probe Scheme */}
                    <td className="py-3.5 px-4 font-mono">
                      <span className="px-2 py-0.5 rounded-md text-[10px] bg-light-hover dark:bg-dark-card border border-light-border dark:border-dark-border text-p3 dark:text-p3-dark font-medium">
                        {scheme}://
                      </span>
                    </td>

                    {/* Path */}
                    <td className="py-3.5 px-4 font-mono text-light-muted dark:text-dark-muted text-[11px] max-w-[200px] truncate">
                      {item.path || '—'}
                    </td>

                    {/* Status Match */}
                    <td className="py-3.5 px-4 text-right font-mono">
                      {isVuln ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-p1/10 text-p1-light dark:text-p1-dark border border-p1/30 font-bold text-[10px]">
                          <AlertTriangle className="w-3 h-3" />
                          {cveCount} CVE{cveCount > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-p4/10 text-p4-light dark:text-p4-dark border border-p4/30 text-[10px] font-semibold">
                          <CheckCircle2 className="w-3 h-3" />
                          Clean
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};



// SPDX-License-Identifier: Apache-2.0
import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Flame,
  Filter,
  ArrowUpDown,
  ChevronRight,
} from 'lucide-react';
import { Finding, PriorityTier, FindingStatus } from '../../types/scanner';

interface FindingsTableProps {
  findings: Finding[];
  searchQuery: string;
  onSelectFinding: (finding: Finding) => void;
  onAcceptRisk: (finding: Finding) => void;
}

type SortField = 'priority' | 'cvss' | 'epss' | 'cve' | 'status' | 'host';
type SortOrder = 'asc' | 'desc';

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  searchQuery,
  onSelectFinding,
  onAcceptRisk,
}) => {
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [kevOnly, setKevOnly] = useState<boolean>(false);
  const [sortField, setSortField] = useState<SortField>('cvss');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Global search query
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchesCve = f.cve_id.toLowerCase().includes(q);
        const matchesProd = f.software.product.toLowerCase().includes(q);
        const matchesVendor = f.software.vendor.toLowerCase().includes(q);
        const matchesHost = f.host.toLowerCase().includes(q);
        const matchesTitle = f.vulnerability.title.toLowerCase().includes(q);
        if (!matchesCve && !matchesProd && !matchesVendor && !matchesHost && !matchesTitle) {
          return false;
        }
      }

      // Priority filter
      if (priorityFilter !== 'ALL' && f.priority !== priorityFilter) {
        return false;
      }

      // Status filter
      if (statusFilter !== 'ALL' && f.status !== statusFilter) {
        return false;
      }

      // KEV filter
      if (kevOnly && !f.risk.cisa_kev) {
        return false;
      }

      return true;
    });
  }, [findings, searchQuery, priorityFilter, statusFilter, kevOnly]);

  const sortedFindings = useMemo(() => {
    return [...filteredFindings].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'cvss':
          comparison = a.risk.cvss_v3_score - b.risk.cvss_v3_score;
          break;
        case 'epss':
          comparison = a.risk.epss_score - b.risk.epss_score;
          break;
        case 'cve':
          comparison = a.cve_id.localeCompare(b.cve_id);
          break;
        case 'status':
          comparison = a.status.localeCompare(b.status);
          break;
        case 'host':
          comparison = a.host.localeCompare(b.host);
          break;
        case 'priority': {
          const rank = { P1: 4, P2: 3, P3: 2, P4: 1 };
          comparison = rank[a.priority] - rank[b.priority];
          break;
        }
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });
  }, [filteredFindings, sortField, sortOrder]);

  const getPriorityBadge = (priority: PriorityTier) => {
    switch (priority) {
      case 'P1':
        return 'bg-p1/10 text-p1-light dark:text-p1-dark border-p1/30';
      case 'P2':
        return 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30';
      case 'P3':
        return 'bg-p3/10 text-p3-light dark:text-p3-dark border-p3/30';
      case 'P4':
        return 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30';
    }
  };

  const getStatusBadge = (status: FindingStatus) => {
    switch (status) {
      case 'New':
        return 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/30';
      case 'Persisting':
        return 'bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/30';
      case 'Resolved':
        return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
      case 'Excepted':
        return 'bg-purple-500/10 text-purple-700 dark:text-purple-300 border-purple-500/30';
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters Bar */}
      <div className="glass-panel p-3.5 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-light-muted dark:text-dark-muted font-mono mr-2">
            <Filter className="w-3.5 h-3.5" />
            <span>Filters:</span>
          </div>

          {/* Priority Pill Filters */}
          <div className="flex rounded-xl border border-light-border dark:border-dark-border bg-light-surface dark:bg-dark-surface p-0.5 text-xs">
            {['ALL', 'P1', 'P2', 'P3', 'P4'].map((p) => (
              <button
                key={p}
                onClick={() => setPriorityFilter(p)}
                className={`px-3 py-1 rounded-lg font-mono font-medium transition-all ${
                  priorityFilter === p
                    ? 'bg-light-hover dark:bg-dark-card text-light-text dark:text-dark-text font-bold shadow-sm'
                    : 'text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text'
                }`}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Status Pill Filters */}
          <div className="flex rounded-xl border border-light-border dark:border-dark-border bg-light-surface dark:bg-dark-surface p-0.5 text-xs">
            {['ALL', 'New', 'Persisting', 'Excepted'].map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`px-3 py-1 rounded-lg font-mono font-medium transition-all ${
                  statusFilter === s
                    ? 'bg-light-hover dark:bg-dark-card text-light-text dark:text-dark-text font-bold shadow-sm'
                    : 'text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text'
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          {/* KEV Toggle */}
          <button
            onClick={() => setKevOnly(!kevOnly)}
            className={`px-3 py-1.5 rounded-xl border text-xs font-mono font-medium flex items-center gap-1.5 transition-all shadow-sm ${
              kevOnly
                ? 'bg-p1/10 border-p1/40 text-p1-light dark:text-p1-dark font-bold'
                : 'border-light-border dark:border-dark-border text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text bg-light-surface dark:bg-dark-surface'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>CISA KEV Only</span>
          </button>
        </div>

        <div className="text-xs font-mono text-light-muted dark:text-dark-muted">
          Showing <span className="text-light-text dark:text-dark-text font-bold">{sortedFindings.length}</span> of{' '}
          {findings.length} findings
        </div>
      </div>

      {/* Findings Table */}
      <div className="glass-panel rounded-2xl overflow-hidden border border-light-border dark:border-dark-border shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-light-border dark:border-dark-border bg-light-hover/60 dark:bg-dark-surface/80 text-light-muted dark:text-dark-muted font-mono uppercase text-[11px]">
                <th
                  onClick={() => handleSort('priority')}
                  className="py-3.5 px-4 cursor-pointer hover:text-light-text dark:hover:text-dark-text transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>Tier</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('cve')}
                  className="py-3.5 px-4 cursor-pointer hover:text-light-text dark:hover:text-dark-text transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>Vulnerability / CVE</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3.5 px-4">Component & Path</th>
                <th
                  onClick={() => handleSort('host')}
                  className="py-3.5 px-4 cursor-pointer hover:text-light-text dark:hover:text-dark-text transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>Target Host</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('cvss')}
                  className="py-3.5 px-4 cursor-pointer hover:text-light-text dark:hover:text-dark-text transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>CVSS v3</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('epss')}
                  className="py-3.5 px-4 cursor-pointer hover:text-light-text dark:hover:text-dark-text transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>EPSS</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('status')}
                  className="py-3.5 px-4 cursor-pointer hover:text-light-text dark:hover:text-dark-text transition-colors"
                >
                  <div className="flex items-center gap-1">
                    <span>Status</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-light-border/60 dark:divide-dark-border/60 font-sans">
              {sortedFindings.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-light-muted dark:text-dark-muted font-mono">
                    No findings match the selected filter criteria.
                  </td>
                </tr>
              ) : (
                sortedFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="hover:bg-light-hover/70 dark:hover:bg-dark-hover/70 transition-colors group cursor-pointer"
                    onClick={() => onSelectFinding(finding)}
                  >
                    {/* Priority Tier */}
                    <td className="py-3.5 px-4 font-mono">
                      <span
                        className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${getPriorityBadge(
                          finding.priority
                        )}`}
                      >
                        {finding.priority}
                      </span>
                    </td>

                    {/* CVE & Title */}
                    <td className="py-3.5 px-4 max-w-[280px]">
                      <div className="font-mono font-bold text-light-text dark:text-dark-text group-hover:text-p3 dark:group-hover:text-p3-dark transition-colors flex items-center gap-1.5">
                        {finding.cve_id}
                        {finding.risk.cisa_kev && (
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded-full bg-p1/10 text-p1-light dark:text-p1-dark border border-p1/30 font-semibold">
                            KEV
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-light-muted dark:text-dark-muted truncate mt-0.5 font-normal">
                        {finding.vulnerability.title}
                      </div>
                    </td>

                    {/* Component */}
                    <td className="py-3.5 px-4 max-w-[220px]">
                      <div className="font-medium text-light-text dark:text-dark-text truncate">
                        {finding.software.product}
                      </div>
                      <div className="text-[11px] font-mono text-light-muted dark:text-dark-muted truncate">
                        v{finding.software.version} • {finding.software.source.split('://')[0]}
                      </div>
                    </td>

                    {/* Target Host */}
                    <td className="py-3.5 px-4 font-mono text-light-muted dark:text-dark-muted text-[11px] truncate max-w-[160px]">
                      {finding.host}
                    </td>

                    {/* CVSS */}
                    <td className="py-3.5 px-4 font-mono">
                      <span
                        className={`font-bold ${
                          finding.risk.cvss_v3_score >= 9.0
                            ? 'text-p1-light dark:text-p1-dark'
                            : finding.risk.cvss_v3_score >= 7.0
                            ? 'text-p2-light dark:text-p2-dark'
                            : 'text-p3-light dark:text-p3-dark'
                        }`}
                      >
                        {finding.risk.cvss_v3_score.toFixed(1)}
                      </span>
                    </td>

                    {/* EPSS */}
                    <td className="py-3.5 px-4 font-mono text-light-muted dark:text-dark-muted">
                      <div className="flex items-center gap-1">
                        <Flame
                          className={`w-3.5 h-3.5 ${
                            finding.risk.epss_score > 0.5 ? 'text-p2-light dark:text-p2-dark' : 'text-light-muted/60 dark:text-dark-muted/60'
                          }`}
                        />
                        <span>{(finding.risk.epss_score * 100).toFixed(1)}%</span>
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3.5 px-4 font-mono">
                      <span
                        className={`inline-block px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${getStatusBadge(
                          finding.status
                        )}`}
                      >
                        {finding.status}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-4 text-right space-x-2">
                      {finding.status !== 'Excepted' && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onAcceptRisk(finding);
                          }}
                          className="px-2.5 py-1 rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border text-[11px] text-light-muted dark:text-dark-muted hover:text-p4-light dark:hover:text-p4-dark hover:border-p4/50 transition-all font-mono shadow-sm"
                          title="Accept Risk with audit ticket"
                        >
                          Accept
                        </button>
                      )}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(finding);
                        }}
                        className="p-1.5 rounded-lg text-light-muted dark:text-dark-muted group-hover:text-light-text dark:group-hover:text-dark-text transition-colors"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};



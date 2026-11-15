// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import {
  ShieldCheck,
  Plus,
  Trash2,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { ExceptionRef } from '../../types/scanner';

interface ExceptionsTableProps {
  exceptions: ExceptionRef[];
  onOpenCreateModal: () => void;
  onDeleteException: (ruleId: string) => void;
}

export const ExceptionsTable: React.FC<ExceptionsTableProps> = ({
  exceptions,
  onOpenCreateModal,
  onDeleteException,
}) => {
  const getDaysUntilExpiry = (expiresAt: string) => {
    const diff = new Date(expiresAt).getTime() - Date.now();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  };

  return (
    <div className="space-y-4">
      {/* Header Bar */}
      <div className="glass-panel p-5 rounded-2xl flex items-center justify-between shadow-sm">
        <div>
          <h2 className="text-sm font-bold text-light-text dark:text-dark-text flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-p4-light dark:text-p4-dark" />
            Accepted Risk Policy Rules
          </h2>
          <p className="text-xs text-light-muted dark:text-dark-muted mt-0.5">
            Audit-backed exception rules preventing false alarm alerts across scans.
          </p>
        </div>

        <button
          onClick={onOpenCreateModal}
          className="px-3.5 py-2 rounded-xl bg-p4/10 border border-p4/30 text-p4-light dark:text-p4-dark hover:bg-p4/20 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all shadow-sm"
        >
          <Plus className="w-4 h-4" />
          <span>New Accepted-Risk Rule</span>
        </button>
      </div>

      {/* Exceptions Table */}
      <div className="glass-panel rounded-2xl overflow-hidden border border-light-border dark:border-dark-border shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-light-border dark:border-dark-border bg-light-hover/60 dark:bg-dark-surface/80 text-light-muted dark:text-dark-muted font-mono uppercase text-[11px]">
                <th className="py-3.5 px-4">Rule ID</th>
                <th className="py-3.5 px-4">Scope Pattern</th>
                <th className="py-3.5 px-4">Target CVE</th>
                <th className="py-3.5 px-4">Host Scope</th>
                <th className="py-3.5 px-4">Specificity</th>
                <th className="py-3.5 px-4">Audit Ticket</th>
                <th className="py-3.5 px-4">Expiration</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-light-border/60 dark:divide-dark-border/60 font-sans">
              {exceptions.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-light-muted dark:text-dark-muted font-mono">
                    No active accepted-risk rules defined.
                  </td>
                </tr>
              ) : (
                exceptions.map((rule) => {
                  const daysLeft = getDaysUntilExpiry(rule.expires_at);
                  const isExpiringSoon = daysLeft <= 30 && daysLeft > 0;
                  const isExpired = daysLeft <= 0;

                  return (
                    <tr key={rule.rule_id} className="hover:bg-light-hover/70 dark:hover:bg-dark-hover/70 transition-colors">
                      {/* Rule ID */}
                      <td className="py-3.5 px-4 font-mono font-bold text-light-text dark:text-dark-text">
                        {rule.rule_id}
                      </td>

                      {/* Scope Pattern */}
                      <td className="py-3.5 px-4 font-mono text-p3 dark:text-p3-dark truncate max-w-[220px]">
                        {rule.scope_pattern}
                      </td>

                      {/* CVE Scope */}
                      <td className="py-3.5 px-4 font-mono text-light-text dark:text-dark-text font-medium">
                        {rule.cve_scope || '* (All CVEs)'}
                      </td>

                      {/* Host Scope */}
                      <td className="py-3.5 px-4 font-mono text-light-muted dark:text-dark-muted text-[11px]">
                        {rule.host_scope || 'all'}
                      </td>

                      {/* Specificity Score */}
                      <td className="py-3.5 px-4 font-mono">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                            rule.specificity_score >= 90
                              ? 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30'
                              : 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30'
                          }`}
                        >
                          {rule.specificity_score}% Strict
                        </span>
                      </td>

                      {/* Audit Ticket */}
                      <td className="py-3.5 px-4 font-mono">
                        <span className="px-2 py-0.5 rounded-lg bg-light-hover dark:bg-dark-card text-light-text dark:text-dark-text border border-light-border dark:border-dark-border text-[11px]">
                          {rule.ticket_ref}
                        </span>
                      </td>

                      {/* Expiration */}
                      <td className="py-3.5 px-4 font-mono">
                        <div className="flex items-center gap-1.5">
                          {isExpired ? (
                            <span className="text-p1-light dark:text-p1-dark font-bold flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" />
                              Expired
                            </span>
                          ) : isExpiringSoon ? (
                            <span className="text-p2-light dark:text-p2-dark font-bold flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {daysLeft}d left
                            </span>
                          ) : (
                            <span className="text-p4-light dark:text-p4-dark flex items-center gap-1 font-semibold">
                              <CheckCircle2 className="w-3 h-3" />
                              {daysLeft}d left
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Delete Action */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => onDeleteException(rule.rule_id)}
                          className="p-1.5 rounded-lg text-light-muted dark:text-dark-muted hover:text-p1-light dark:hover:text-p1-dark hover:bg-p1/10 transition-colors"
                          title="Revoke Exception Rule"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};



// SPDX-License-Identifier: Apache-2.0
import React, { useState } from 'react';
import {
  X,
  ShieldCheck,
  Calendar,
  FileText,
  AlertCircle,
  Info,
} from 'lucide-react';
import { Finding, ExceptionRef } from '../../types/scanner';

interface CreateExceptionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (rule: Omit<ExceptionRef, 'rule_id' | 'created_at'>) => void;
  initialFinding?: Finding | null;
}

export const CreateExceptionModal: React.FC<CreateExceptionModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  initialFinding,
}) => {
  const [scopePattern, setScopePattern] = useState<string>(
    initialFinding?.software.cpe || 'cpe:2.3:a:*:*'
  );
  const [cveScope, setCveScope] = useState<string>(initialFinding?.cve_id || '*');
  const [hostScope, setHostScope] = useState<string>(initialFinding?.host || 'all');
  const [rationale, setRationale] = useState<string>('');
  const [ticketRef, setTicketRef] = useState<string>('SEC-');
  const [acceptedBy, setAcceptedBy] = useState<string>('sec-analyst@corp.internal');
  const [expiresAt, setExpiresAt] = useState<string>(() => {
    const d = new Date();
    d.setDate(d.getDate() + 90);
    return d.toISOString().split('T')[0];
  });
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const calculateSpecificity = () => {
    let score = 50;
    if (scopePattern && !scopePattern.includes('*')) score += 20;
    else if (scopePattern && scopePattern.split('*').length <= 2) score += 10;
    if (cveScope && cveScope !== '*') score += 20;
    if (hostScope && hostScope !== 'all') score += 10;
    return Math.min(100, score);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!rationale.trim() || rationale.length < 10) {
      setError('A comprehensive technical or business rationale (>10 chars) is required.');
      return;
    }
    if (!ticketRef.trim() || ticketRef === 'SEC-') {
      setError('A valid audit ticket reference (e.g. SEC-8910 or JIRA-1234) is required.');
      return;
    }

    const specificity = calculateSpecificity();

    onSubmit({
      scope_pattern: scopePattern,
      cve_scope: cveScope === '*' ? undefined : cveScope,
      host_scope: hostScope,
      accepted_by: acceptedBy,
      rationale: rationale.trim(),
      ticket_ref: ticketRef.trim(),
      expires_at: new Date(expiresAt).toISOString(),
      specificity_score: specificity,
    });

    onClose();
  };

  const specificity = calculateSpecificity();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div
        className="w-full max-w-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-2xl shadow-2xl overflow-hidden font-sans"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-light-border dark:border-dark-border bg-light-header/90 dark:bg-dark-header/90 backdrop-blur-xl flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-p4/10 border border-p4/30 text-p4-light dark:text-p4-dark">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-light-text dark:text-dark-text">Create Accepted-Risk Exception</h2>
              <p className="text-[11px] text-light-muted dark:text-dark-muted">
                Enforces automated suppression policy across scan cycles.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-xl text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-xl bg-p1/10 border border-p1/40 text-p1-light dark:text-p1-dark text-[11px] flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Scope Pattern */}
          <div className="space-y-1.5">
            <label className="font-mono font-semibold text-light-text dark:text-dark-text flex items-center justify-between">
              <span>CPE / Package Scope Pattern:</span>
              <span className="text-[10px] text-light-muted dark:text-dark-muted font-normal">Supports * wildcards</span>
            </label>
            <input
              type="text"
              value={scopePattern}
              onChange={(e) => setScopePattern(e.target.value)}
              placeholder="e.g. cpe:2.3:a:python:python:3.10.*"
              className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl px-3 py-2 text-xs text-light-text dark:text-dark-text font-mono placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 shadow-sm"
              required
            />
          </div>

          {/* Target CVE & Host Scope Grid */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="font-mono font-semibold text-light-text dark:text-dark-text">CVE Scope:</label>
              <input
                type="text"
                value={cveScope}
                onChange={(e) => setCveScope(e.target.value)}
                placeholder="CVE-2023-XXXX or *"
                className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl px-3 py-2 text-xs text-light-text dark:text-dark-text font-mono placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 shadow-sm"
                required
              />
            </div>
            <div className="space-y-1.5">
              <label className="font-mono font-semibold text-light-text dark:text-dark-text">Host / Tag Scope:</label>
              <input
                type="text"
                value={hostScope}
                onChange={(e) => setHostScope(e.target.value)}
                placeholder="all or WIN-PROD-DC01"
                className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl px-3 py-2 text-xs text-light-text dark:text-dark-text font-mono placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 shadow-sm"
                required
              />
            </div>
          </div>

          {/* Audit Ticket & Approved By */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="font-mono font-semibold text-light-text dark:text-dark-text flex items-center gap-1">
                <FileText className="w-3.5 h-3.5 text-p3 dark:text-p3-dark" />
                <span>Audit Ticket Ref:</span>
              </label>
              <input
                type="text"
                value={ticketRef}
                onChange={(e) => setTicketRef(e.target.value)}
                placeholder="SEC-8912"
                className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl px-3 py-2 text-xs text-light-text dark:text-dark-text font-mono placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 shadow-sm"
                required
              />
            </div>
            <div className="space-y-1.5">
              <label className="font-mono font-semibold text-light-text dark:text-dark-text flex items-center gap-1">
                <Calendar className="w-3.5 h-3.5 text-p4-light dark:text-p4-dark" />
                <span>Expiration Date:</span>
              </label>
              <input
                type="date"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl px-3 py-2 text-xs text-light-text dark:text-dark-text font-mono focus:outline-none focus:border-p3 shadow-sm"
                required
              />
            </div>
          </div>

          {/* Approver field */}
          <div className="space-y-1.5">
            <label className="font-mono font-semibold text-light-text dark:text-dark-text">Approved By (Identity):</label>
            <input
              type="text"
              value={acceptedBy}
              onChange={(e) => setAcceptedBy(e.target.value)}
              className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl px-3 py-2 text-xs text-light-text dark:text-dark-text font-mono placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 shadow-sm"
              required
            />
          </div>

          {/* Rationale */}
          <div className="space-y-1.5">
            <label className="font-mono font-semibold text-light-text dark:text-dark-text">
              Technical Rationale / Compensating Controls:
            </label>
            <textarea
              rows={3}
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              placeholder="Explain compensating security controls, network isolation, or temporary build sandbox exemption rationale..."
              className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl p-3 text-xs text-light-text dark:text-dark-text placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 leading-relaxed shadow-sm"
              required
            />
          </div>

          {/* Live Specificity Preview */}
          <div className="p-3.5 rounded-xl bg-light-hover/60 dark:bg-dark-card border border-light-border dark:border-dark-border flex items-center justify-between font-mono">
            <div className="flex items-center gap-1.5 text-[11px] text-light-muted dark:text-dark-muted">
              <Info className="w-3.5 h-3.5 text-p3 dark:text-p3-dark" />
              <span>Policy Specificity Rating:</span>
            </div>
            <span
              className={`px-2 py-0.5 rounded-full text-xs font-bold border ${
                specificity >= 90
                  ? 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30'
                  : 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30'
              }`}
            >
              {specificity}% Grade
            </span>
          </div>

          {/* Form Actions */}
          <div className="pt-3 border-t border-light-border dark:border-dark-border flex items-center justify-end gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-mono text-light-muted dark:text-dark-muted hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 rounded-xl bg-p4/20 border border-p4/40 text-p4-light dark:text-p4-dark hover:bg-p4/30 font-semibold text-xs font-mono transition-all shadow-sm"
            >
              Save Exception Rule
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};



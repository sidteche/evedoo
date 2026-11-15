// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import {
  ShieldAlert,
  Flame,
  GitCompare,
  ShieldCheck,
  TrendingUp,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
} from 'lucide-react';
import { ScanSummary } from '../../types/scanner';

interface MetricsGridProps {
  summary: ScanSummary;
  onFilterP1?: () => void;
  onFilterP2?: () => void;
  onFilterDelta?: () => void;
  onFilterExceptions?: () => void;
}

export const MetricsGrid: React.FC<MetricsGridProps> = ({
  summary,
  onFilterP1,
  onFilterP2,
  onFilterDelta,
  onFilterExceptions,
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* P1 Critical / KEV Card */}
      <div
        onClick={onFilterP1}
        className="glass-panel p-5 rounded-2xl cursor-pointer hover:border-p1/60 dark:hover:border-p1/60 transition-all relative overflow-hidden group glow-p1 hover:-translate-y-0.5 shadow-sm"
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-p1-light dark:text-p1-dark flex items-center gap-1.5 font-mono">
            <ShieldAlert className="w-4 h-4" />
            P1 Critical
          </span>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-p1/10 text-p1-light dark:text-p1-dark border border-p1/30 animate-pulse">
            {summary.kev_active} CISA KEV
          </span>
        </div>
        <div className="mt-3.5 flex items-baseline justify-between">
          <span className="text-3xl font-mono font-bold text-light-text dark:text-dark-text tracking-tight">
            {summary.p1}
          </span>
          <span className="text-xs text-light-muted dark:text-dark-muted font-mono">Weaponized RCE</span>
        </div>
        <div className="mt-2.5 text-[11px] text-light-muted dark:text-dark-muted flex items-center gap-1">
          <span className="text-p1-light dark:text-p1-dark font-semibold">Immediate Action:</span> Direct patch or isolate
        </div>
        <div className="absolute top-0 right-0 w-24 h-24 bg-p1/5 rounded-full blur-2xl -mr-6 -mt-6 group-hover:bg-p1/10 transition-colors" />
      </div>

      {/* P2 High / EPSS > 50% Card */}
      <div
        onClick={onFilterP2}
        className="glass-panel p-5 rounded-2xl cursor-pointer hover:border-p2/60 dark:hover:border-p2/60 transition-all relative overflow-hidden group glow-p2 hover:-translate-y-0.5 shadow-sm"
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-p2-light dark:text-p2-dark flex items-center gap-1.5 font-mono">
            <Flame className="w-4 h-4" />
            P2 High Severity
          </span>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-p2/10 text-p2-light dark:text-p2-dark border border-p2/30">
            EPSS &gt; 50%
          </span>
        </div>
        <div className="mt-3.5 flex items-baseline justify-between">
          <span className="text-3xl font-mono font-bold text-light-text dark:text-dark-text tracking-tight">
            {summary.p2}
          </span>
          <span className="text-xs text-light-muted dark:text-dark-muted font-mono">High Probability</span>
        </div>
        <div className="mt-2.5 text-[11px] text-light-muted dark:text-dark-muted flex items-center gap-1">
          <TrendingUp className="w-3.5 h-3.5 text-p2-light dark:text-p2-dark" />
          <span>Likely targeted in upcoming campaigns</span>
        </div>
        <div className="absolute top-0 right-0 w-24 h-24 bg-p2/5 rounded-full blur-2xl -mr-6 -mt-6 group-hover:bg-p2/10 transition-colors" />
      </div>

      {/* Delta Dynamics Card */}
      <div
        onClick={onFilterDelta}
        className="glass-panel p-5 rounded-2xl cursor-pointer hover:border-p3/60 dark:hover:border-p3/60 transition-all relative overflow-hidden group glow-p3 hover:-translate-y-0.5 shadow-sm"
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-p3-light dark:text-p3-dark flex items-center gap-1.5 font-mono">
            <GitCompare className="w-4 h-4" />
            Delta Dynamics
          </span>
          <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-light-hover dark:bg-dark-hover text-light-muted dark:text-dark-muted border border-light-border dark:border-dark-border">
            vs Baseline
          </span>
        </div>
        <div className="mt-3.5 grid grid-cols-3 gap-1.5 text-center font-mono">
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl py-1.5">
            <div className="text-xs font-bold text-amber-600 dark:text-amber-400 flex items-center justify-center">
              <ArrowUpRight className="w-3 h-3 mr-0.5" />+{summary.new}
            </div>
            <div className="text-[9px] text-light-muted dark:text-dark-muted font-medium">NEW</div>
          </div>
          <div className="bg-sky-500/10 border border-sky-500/30 rounded-xl py-1.5">
            <div className="text-xs font-bold text-sky-600 dark:text-sky-400 flex items-center justify-center">
              <Minus className="w-3 h-3 mr-0.5" />
              {summary.persisting}
            </div>
            <div className="text-[9px] text-light-muted dark:text-dark-muted font-medium">PERSIST</div>
          </div>
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl py-1.5">
            <div className="text-xs font-bold text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
              <ArrowDownRight className="w-3 h-3 mr-0.5" />-{summary.resolved}
            </div>
            <div className="text-[9px] text-light-muted dark:text-dark-muted font-medium">FIXED</div>
          </div>
        </div>
        <div className="mt-2.5 text-[11px] text-light-muted dark:text-dark-muted truncate">
          Tracking delta against scan_history.db
        </div>
      </div>

      {/* Accepted Risk Card */}
      <div
        onClick={onFilterExceptions}
        className="glass-panel p-5 rounded-2xl cursor-pointer hover:border-p4/60 dark:hover:border-p4/60 transition-all relative overflow-hidden group glow-p4 hover:-translate-y-0.5 shadow-sm"
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-p4-light dark:text-p4-dark flex items-center gap-1.5 font-mono">
            <ShieldCheck className="w-4 h-4" />
            Accepted Risk
          </span>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-p4/10 text-p4-light dark:text-p4-dark border border-p4/30">
            Active Rules
          </span>
        </div>
        <div className="mt-3.5 flex items-baseline justify-between">
          <span className="text-3xl font-mono font-bold text-light-text dark:text-dark-text tracking-tight">
            {summary.excepted}
          </span>
          <span className="text-xs text-light-muted dark:text-dark-muted font-mono">Suppressed</span>
        </div>
        <div className="mt-2.5 text-[11px] text-light-muted dark:text-dark-muted flex items-center justify-between">
          <span>Audit ticket validated</span>
          <span className="text-[10px] font-mono text-p4-light dark:text-p4-dark font-semibold">100% Policy OK</span>
        </div>
      </div>
    </div>
  );
};



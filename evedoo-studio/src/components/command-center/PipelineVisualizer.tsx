// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import {
  Layers,
  Cpu,
  ShieldCheck,
  GitCompare,
  Database,
  CheckCircle2,
} from 'lucide-react';
import { ScanResult } from '../../types/scanner';

interface PipelineVisualizerProps {
  scanResult: ScanResult;
}

export const PipelineVisualizer: React.FC<PipelineVisualizerProps> = ({
  scanResult,
}) => {
  const steps = [
    {
      id: 'step-1',
      number: '01',
      name: 'Inventory Probes',
      desc: 'Registry, PE, AppX, WinGet, Cargo',
      count: scanResult.software_inventory.length,
      unit: 'Components',
      icon: Database,
      color: 'border-p3/40 text-p3 dark:text-p3-dark bg-p3/10',
    },
    {
      id: 'step-2',
      number: '02',
      name: 'CpeIndex Correlator',
      desc: 'O(1) Token Scoring & Alias Resolution',
      count: scanResult.findings.length,
      unit: 'CVE Matches',
      icon: Cpu,
      color: 'border-p2/40 text-p2-light dark:text-p2-dark bg-p2/10',
    },
    {
      id: 'step-3',
      number: '03',
      name: 'Threat Scoring',
      desc: 'CISA KEV + EPSS v3 Prioritization',
      count: scanResult.summary.p1 + scanResult.summary.p2,
      unit: 'P1 / P2 Critical',
      icon: Layers,
      color: 'border-p1/40 text-p1-light dark:text-p1-dark bg-p1/10',
    },
    {
      id: 'step-4',
      number: '04',
      name: 'Policy & Exceptions',
      desc: 'Wildcard & Rationale Validation',
      count: scanResult.summary.excepted,
      unit: 'Excepted Rules',
      icon: ShieldCheck,
      color: 'border-p4/40 text-p4-light dark:text-p4-dark bg-p4/10',
    },
    {
      id: 'step-5',
      number: '05',
      name: 'Delta Reconciliation',
      desc: 'SQLite scan_history.db Diffing',
      count: scanResult.summary.new,
      unit: 'New Findings',
      icon: GitCompare,
      color: 'border-indigo-500/40 text-indigo-600 dark:text-indigo-400 bg-indigo-500/10',
    },
  ];

  return (
    <div className="glass-panel rounded-2xl p-5 shadow-sm flex flex-col justify-between h-full">
      <div>
        <div className="flex items-center justify-between pb-3 border-b border-light-border dark:border-dark-border mb-4">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-p3 dark:text-p3-dark" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-light-text dark:text-dark-text font-mono">
              Correlation Engine Pipeline
            </h2>
          </div>
          <div className="flex items-center gap-2 text-[11px] font-mono text-light-muted dark:text-dark-muted">
            <span>Latency:</span>
            <span className="text-p4-light dark:text-p4-dark font-bold">{scanResult.duration_ms}ms</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-p4" />
          </div>
        </div>

        <div className="space-y-3">
          {steps.map((step) => {
            const Icon = step.icon;
            return (
              <div
                key={step.id}
                className="p-3 rounded-xl bg-light-surface/90 dark:bg-dark-surface/70 border border-light-border dark:border-dark-border flex items-center justify-between gap-3 hover:border-p3/50 transition-all shadow-sm"
              >
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg border ${step.color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono font-bold text-light-muted dark:text-dark-muted">
                        STAGE {step.number}
                      </span>
                      <h3 className="text-xs font-semibold text-light-text dark:text-dark-text">{step.name}</h3>
                    </div>
                    <p className="text-[11px] text-light-muted dark:text-dark-muted leading-tight mt-0.5">{step.desc}</p>
                  </div>
                </div>

                <div className="text-right font-mono shrink-0">
                  <span className="text-base font-bold text-light-text dark:text-dark-text block">{step.count}</span>
                  <span className="text-[9px] text-light-muted dark:text-dark-muted uppercase font-medium">{step.unit}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};



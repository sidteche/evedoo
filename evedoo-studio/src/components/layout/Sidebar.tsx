// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import {
  ShieldAlert,
  LayoutDashboard,
  Target,
  Server,
  ShieldCheck,
  Bot,
  Package2,
  Settings,
  Zap,
  Radio,
  CheckCircle2,
  Loader2,
} from 'lucide-react';

export type TabId =
  | 'command-center'
  | 'triage'
  | 'fleet'
  | 'exceptions'
  | 'agent-state'
  | 'sbom'
  | 'settings';

interface SidebarProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  onTriggerScan: () => void;
  isScanning: boolean;
  counts: {
    findings: number;
    p1Count: number;
    fleet: number;
    exceptions: number;
    activePhase: string;
    inventory: number;
  };
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  onTriggerScan,
  isScanning,
  counts,
}) => {
  const navItems: { id: TabId; label: string; icon: React.ComponentType<{ className?: string }>; badge?: string | number; badgeColor?: string }[] = [
    {
      id: 'command-center',
      label: 'Command Center',
      icon: LayoutDashboard,
      badge: counts.p1Count > 0 ? `${counts.p1Count} P1` : undefined,
      badgeColor: 'bg-p1/10 text-p1-light dark:text-p1-dark border-p1/30',
    },
    {
      id: 'triage',
      label: 'Triage & Findings',
      icon: Target,
      badge: counts.findings,
      badgeColor: 'bg-light-hover dark:bg-dark-hover text-light-muted dark:text-dark-muted',
    },
    {
      id: 'fleet',
      label: 'Fleet Assets',
      icon: Server,
      badge: counts.fleet,
      badgeColor: 'bg-light-hover dark:bg-dark-hover text-light-muted dark:text-dark-muted',
    },
    {
      id: 'exceptions',
      label: 'Accepted Risk Rules',
      icon: ShieldCheck,
      badge: counts.exceptions,
      badgeColor: 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30',
    },
    {
      id: 'agent-state',
      label: 'Agent Task State',
      icon: Bot,
      badge: counts.activePhase,
      badgeColor: 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30',
    },
    {
      id: 'sbom',
      label: 'Software Inventory',
      icon: Package2,
      badge: counts.inventory,
      badgeColor: 'bg-light-hover dark:bg-dark-hover text-light-muted dark:text-dark-muted',
    },
    {
      id: 'settings',
      label: 'Settings & Database',
      icon: Settings,
    },
  ];

  return (
    <aside className="w-64 bg-light-sidebar/95 dark:bg-dark-sidebar/95 border-r border-light-border dark:border-dark-border flex flex-col h-screen select-none shrink-0 backdrop-blur-xl transition-colors duration-200">
      {/* Brand Header */}
      <div className="h-16 px-5 flex items-center justify-between border-b border-light-border dark:border-dark-border">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-p1/20 to-p2/20 border border-p1/30 flex items-center justify-center shadow-sm">
            <ShieldAlert className="w-5 h-5 text-p1" />
          </div>
          <div>
            <h1 className="font-bold text-sm text-light-text dark:text-dark-text tracking-wide flex items-center gap-1.5 font-sans">
              EVEDOO
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded-full bg-p3/10 text-p3 dark:text-p3-dark border border-p3/30 font-semibold">
                Studio
              </span>
            </h1>
            <p className="text-[11px] text-light-muted dark:text-dark-muted font-mono">SecOps Workspace</p>
          </div>
        </div>
      </div>

      {/* Quick Action Button */}
      <div className="p-3.5">
        <button
          onClick={onTriggerScan}
          disabled={isScanning}
          className={`w-full py-2.5 px-3.5 rounded-xl font-medium text-xs flex items-center justify-center gap-2 transition-all shadow-sm ${
            isScanning
              ? 'bg-p1/20 text-p1 border border-p1/40 cursor-not-allowed'
              : 'bg-gradient-to-r from-p1 to-red-600 text-white hover:brightness-110 active:scale-[0.98] shadow-md shadow-red-500/20'
          }`}
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-white" />
              <span>Scanning Host Probes...</span>
            </>
          ) : (
            <>
              <Zap className="w-4 h-4 fill-current" />
              <span>Run Localhost Scan</span>
            </>
          )}
        </button>
      </div>

      {/* Nav List */}
      <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
        <div className="px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-light-muted/70 dark:text-dark-muted/70">
          Navigation
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                isActive
                  ? 'bg-light-surface dark:bg-dark-card text-light-text dark:text-dark-text border border-light-border dark:border-dark-border shadow-sm font-semibold'
                  : 'text-light-muted dark:text-dark-muted hover:bg-light-hover dark:hover:bg-dark-hover hover:text-light-text dark:hover:text-dark-text'
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-p3 dark:text-p3-dark' : 'text-light-muted dark:text-dark-muted'}`} />
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                    item.badgeColor || 'bg-light-hover dark:bg-dark-hover text-light-muted dark:text-dark-muted border-light-border dark:border-dark-border'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Engine Status Footer */}
      <div className="p-3.5 border-t border-light-border dark:border-dark-border bg-light-surface/70 dark:bg-dark-header/70 text-[11px] space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-light-muted dark:text-dark-muted flex items-center gap-1.5">
            <Radio className="w-3 h-3 text-p4 animate-pulse" />
            Engine Daemon
          </span>
          <span className="font-mono text-light-text dark:text-dark-text text-[10px] font-semibold">v0.1.0</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-light-muted dark:text-dark-muted">NVD SQLite DB</span>
          <span className="font-mono text-p4-light dark:text-p4-dark flex items-center gap-1 text-[10px] font-semibold">
            <CheckCircle2 className="w-3 h-3" />
            92,000 CVEs
          </span>
        </div>
        <div className="text-[10px] text-light-muted/80 dark:text-dark-muted/80 font-mono truncate">
          CpeIndex O(1): Synced (OK)
        </div>
      </div>
    </aside>
  );
};



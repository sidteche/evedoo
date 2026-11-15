// SPDX-License-Identifier: Apache-2.0
import React, { useState, useMemo } from 'react';
import {
  Lock,
  Unlock,
  Play,
  Tag,
  Search,
  Loader2,
  Server,
} from 'lucide-react';
import { FleetHost } from '../../types/scanner';

interface FleetGridProps {
  hosts: FleetHost[];
  onTriggerScan: (hostId: string) => void;
  scanningHostId: string | null;
}

export const FleetGrid: React.FC<FleetGridProps> = ({
  hosts,
  onTriggerScan,
  scanningHostId,
}) => {
  const [selectedTag, setSelectedTag] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');

  // Collect unique tags
  const allTags = useMemo(() => {
    const set = new Set<string>();
    hosts.forEach((h) => h.tags.forEach((t) => set.add(t)));
    return ['ALL', ...Array.from(set)];
  }, [hosts]);

  const filteredHosts = useMemo(() => {
    return hosts.filter((h) => {
      if (selectedTag !== 'ALL' && !h.tags.includes(selectedTag)) {
        return false;
      }
      if (search) {
        const q = search.toLowerCase();
        return (
          h.hostname.toLowerCase().includes(q) ||
          h.ip.includes(q) ||
          h.os_name.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [hosts, selectedTag, search]);

  return (
    <div className="space-y-4">
      {/* Fleet Controls & Tags */}
      <div className="glass-panel p-3.5 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1 text-xs text-light-muted dark:text-dark-muted font-mono mr-1">
            <Tag className="w-3.5 h-3.5" />
            <span>Tag:</span>
          </div>

          <div className="flex rounded-xl border border-light-border dark:border-dark-border bg-light-surface dark:bg-dark-surface p-0.5 text-xs flex-wrap">
            {allTags.map((tag) => (
              <button
                key={tag}
                onClick={() => setSelectedTag(tag)}
                className={`px-3 py-1 rounded-lg font-mono font-medium uppercase text-[11px] transition-all ${
                  selectedTag === tag
                    ? 'bg-light-hover dark:bg-dark-card text-light-text dark:text-dark-text font-bold shadow-sm'
                    : 'text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text'
                }`}
              >
                {tag}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-light-muted dark:text-dark-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search hostname, IP..."
              className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl pl-9 pr-3 py-1.5 text-xs text-light-text dark:text-dark-text placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 font-mono shadow-sm"
            />
          </div>
          <div className="text-xs font-mono text-light-muted dark:text-dark-muted">
            {filteredHosts.length} of {hosts.length} Hosts
          </div>
        </div>
      </div>

      {/* Grid of Hosts */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredHosts.map((host) => {
          const isScanningThis = scanningHostId === host.id || host.agent_status === 'scanning';
          return (
            <div
              key={host.id}
              className={`glass-panel rounded-2xl p-5 border flex flex-col justify-between transition-all relative overflow-hidden shadow-sm hover:shadow-md ${
                host.open_p1_count > 0 ? 'hover:border-p1/60' : 'hover:border-p3/60'
              }`}
            >
              <div>
                {/* Host Card Header */}
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <Server className="w-4 h-4 text-p3 dark:text-p3-dark shrink-0" />
                      <span className="font-mono font-bold text-sm text-light-text dark:text-dark-text truncate max-w-[180px]">
                        {host.hostname.split('.')[0]}
                      </span>
                      <span
                        className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border uppercase ${
                          host.agent_status === 'online'
                            ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30'
                            : host.agent_status === 'scanning'
                            ? 'bg-p3/10 text-p3 dark:text-p3-dark border-p3/30 animate-pulse'
                            : 'bg-zinc-200 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 border-zinc-300 dark:border-zinc-700'
                        }`}
                      >
                        {host.agent_status}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-light-muted dark:text-dark-muted">{host.ip}</div>
                  </div>

                  {/* WinRM TLS Security Badge */}
                  <div
                    className={`flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                      host.winrm_tls
                        ? 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30'
                        : 'bg-p1/10 text-p1-light dark:text-p1-dark border-p1/30'
                    }`}
                    title={host.winrm_tls ? 'WinRM HTTPS (TLS 1.3 Verified)' : 'Unencrypted WinRM HTTP'}
                  >
                    {host.winrm_tls ? (
                      <>
                        <Lock className="w-3 h-3" />
                        <span>TLS :{host.winrm_port}</span>
                      </>
                    ) : (
                      <>
                        <Unlock className="w-3 h-3" />
                        <span>NO TLS</span>
                      </>
                    )}
                  </div>
                </div>

                {/* OS & Platform info */}
                <div className="mt-4 space-y-1 text-xs">
                  <div className="text-light-text dark:text-dark-text font-medium truncate">{host.os_name}</div>
                  <div className="text-[11px] font-mono text-light-muted dark:text-dark-muted">
                    Build {host.os_build} • {host.architecture}
                  </div>
                </div>

                {/* Tags */}
                <div className="mt-3 flex items-center gap-1.5 flex-wrap">
                  {host.tags.map((tag) => (
                    <span
                      key={tag}
                      className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-light-hover dark:bg-dark-hover text-light-muted dark:text-dark-muted border border-light-border dark:border-dark-border font-medium"
                    >
                      {tag}
                    </span>
                  ))}
                </div>

                {/* Findings Breakdown Bar */}
                <div className="mt-4 pt-3.5 border-t border-light-border/60 dark:border-dark-border/60">
                  <div className="flex items-center justify-between text-[11px] font-mono text-light-muted dark:text-dark-muted mb-1.5">
                    <span>Active Findings</span>
                    <span className="font-bold text-light-text dark:text-dark-text">{host.total_findings}</span>
                  </div>
                  <div className="flex items-center gap-1.5 font-mono text-[10px]">
                    <span className="px-2 py-0.5 rounded-full bg-p1/10 text-p1-light dark:text-p1-dark border border-p1/30 font-bold">
                      {host.open_p1_count} P1
                    </span>
                    <span className="px-2 py-0.5 rounded-full bg-p2/10 text-p2-light dark:text-p2-dark border border-p2/30 font-bold">
                      {host.open_p2_count} P2
                    </span>
                    <span className="text-light-muted dark:text-dark-muted ml-auto text-[10px]">
                      {new Date(host.last_scan_time).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>
                </div>
              </div>

              {/* Action Button */}
              <div className="mt-4 pt-3.5 border-t border-light-border/60 dark:border-dark-border/60">
                <button
                  onClick={() => onTriggerScan(host.id)}
                  disabled={isScanningThis || host.agent_status === 'offline'}
                  className={`w-full py-2.5 px-3 rounded-xl text-xs font-mono font-semibold flex items-center justify-center gap-1.5 transition-all shadow-sm ${
                    isScanningThis
                      ? 'bg-p3/10 text-p3 dark:text-p3-dark border border-p3/30 cursor-not-allowed'
                      : host.agent_status === 'offline'
                      ? 'bg-light-hover dark:bg-dark-hover text-light-muted/40 dark:text-dark-muted/40 border border-light-border dark:border-dark-border cursor-not-allowed'
                      : 'bg-light-surface dark:bg-dark-card hover:bg-light-hover dark:hover:bg-dark-hover border border-light-border dark:border-dark-border hover:border-p3 text-light-text dark:text-dark-text'
                  }`}
                >
                  {isScanningThis ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-p3" />
                      <span>Probing via WinRM...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 text-p4 fill-current" />
                      <span>Execute Remote Scan</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};



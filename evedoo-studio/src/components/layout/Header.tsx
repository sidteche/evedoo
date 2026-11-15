// SPDX-License-Identifier: Apache-2.0
import React, { useState, useEffect } from 'react';
import {
  Search,
  Download,
  FileCode,
  FileSpreadsheet,
  Server,
  Command,
  Sun,
  Moon,
  Laptop,
  Zap,
  Layers,
} from 'lucide-react';
import { TransportMode } from '../../api/adapter';

export type ThemeMode = 'dark' | 'light' | 'system';

interface HeaderProps {
  currentHost: string;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  transportMode: TransportMode;
  onTransportModeChange?: (mode: TransportMode) => void;
  onExport: (format: 'html' | 'cyclonedx' | 'csv') => void;
  isScanning: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentHost,
  searchQuery,
  onSearchChange,
  transportMode,
  onTransportModeChange,
  onExport,
  isScanning,
}) => {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('theme-mode') as ThemeMode | null;
      if (saved && (saved === 'dark' || saved === 'light' || saved === 'system')) {
        return saved;
      }
    }
    return 'dark';
  });

  // Apply theme to document
  useEffect(() => {
    const root = document.documentElement;
    const applyTheme = (mode: ThemeMode) => {
      if (mode === 'system') {
        const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (systemPrefersDark) {
          root.classList.add('dark');
        } else {
          root.classList.remove('dark');
        }
      } else if (mode === 'dark') {
        root.classList.add('dark');
      } else {
        root.classList.remove('dark');
      }
    };

    applyTheme(theme);
    localStorage.setItem('theme-mode', theme);

    // Listener for system preference changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => {
      if (theme === 'system') {
        applyTheme('system');
      }
    };
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme]);

  const cycleTheme = () => {
    if (theme === 'dark') setTheme('light');
    else if (theme === 'light') setTheme('system');
    else setTheme('dark');
  };

  const isLive = transportMode === 'live' || transportMode === 'rest';

  const toggleLiveDemo = () => {
    if (onTransportModeChange) {
      onTransportModeChange(isLive ? 'demo' : 'live');
    }
  };

  return (
    <header className="h-16 border-b border-light-border dark:border-dark-border bg-light-header/80 dark:bg-dark-header/80 backdrop-blur-xl px-6 flex items-center justify-between gap-4 select-none shrink-0 transition-colors duration-200">
      {/* Left: Active Target Host & Live/Demo Mode Switcher */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border shadow-sm">
          <Server className="w-3.5 h-3.5 text-p3 dark:text-p3-dark" />
          <span className="text-xs text-light-muted dark:text-dark-muted font-medium">Target:</span>
          <span className="text-xs font-mono font-semibold text-light-text dark:text-dark-text truncate max-w-[180px]">
            {currentHost}
          </span>
          {isScanning && (
            <span className="flex h-2 w-2 relative ml-1">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-p1 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-p1"></span>
            </span>
          )}
        </div>

        {/* Live Engine vs Demo Mode Toggle */}
        <button
          onClick={toggleLiveDemo}
          title={isLive ? "Currently using live local Evedoo scanner backend. Click for Demo simulation." : "Currently in Demo mode. Click to activate Live engine."}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-mono font-semibold border transition-all shadow-sm ${
            isLive
              ? 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30 hover:bg-p4/20'
              : 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30 hover:bg-p2/20'
          }`}
        >
          {isLive ? (
            <>
              <Zap className="w-3 h-3 text-p4 fill-current animate-pulse" />
              <span>LIVE ENGINE</span>
            </>
          ) : (
            <>
              <Layers className="w-3 h-3 text-p2" />
              <span>DEMO MODE</span>
            </>
          )}
        </button>
      </div>

      {/* Center: Global Search Bar */}
      <div className="flex-1 max-w-md relative">
        <Search className="w-4 h-4 text-light-muted dark:text-dark-muted absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Filter CVE, product, vendor, host, cpe..."
          className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg pl-9 pr-12 py-1.5 text-xs text-light-text dark:text-dark-text placeholder:text-light-muted/60 dark:placeholder:text-dark-muted/60 focus:outline-none focus:border-p3 focus:ring-2 focus:ring-p3/20 font-mono transition-all shadow-sm"
        />
        <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-0.5 text-[10px] text-light-muted dark:text-dark-muted bg-light-hover dark:bg-dark-hover px-1.5 py-0.5 rounded border border-light-border dark:border-dark-border">
          <Command className="w-3 h-3" />
          <span>K</span>
        </div>
      </div>

      {/* Right: Theme Mode Switcher & Export Buttons */}
      <div className="flex items-center gap-2.5">
        {/* Theme Toggle Button */}
        <button
          onClick={cycleTheme}
          title={`Theme: ${theme.toUpperCase()} (Click to toggle Light / System / Dark)`}
          className="p-2 rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text hover:bg-light-hover dark:hover:bg-dark-hover transition-all shadow-sm flex items-center gap-1.5 text-xs font-mono"
        >
          {theme === 'dark' && <Moon className="w-4 h-4 text-sky-400" />}
          {theme === 'light' && <Sun className="w-4 h-4 text-amber-500" />}
          {theme === 'system' && <Laptop className="w-4 h-4 text-emerald-400" />}
          <span className="hidden sm:inline text-[11px] capitalize">{theme}</span>
        </button>

        {/* Export Group */}
        <div className="flex rounded-lg shadow-sm border border-light-border dark:border-dark-border bg-light-surface dark:bg-dark-surface overflow-hidden">
          <button
            onClick={() => onExport('html')}
            title="Export interactive HTML Report"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-light-text dark:text-dark-text hover:bg-light-hover dark:hover:bg-dark-hover border-r border-light-border dark:border-dark-border transition-colors font-medium"
          >
            <Download className="w-3.5 h-3.5 text-p3 dark:text-p3-dark" />
            <span>HTML</span>
          </button>
          <button
            onClick={() => onExport('cyclonedx')}
            title="Export CycloneDX 1.5 JSON SBOM"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-light-text dark:text-dark-text hover:bg-light-hover dark:hover:bg-dark-hover border-r border-light-border dark:border-dark-border transition-colors font-medium"
          >
            <FileCode className="w-3.5 h-3.5 text-p2 dark:text-p2-dark" />
            <span className="hidden sm:inline">CycloneDX</span>
          </button>
          <button
            onClick={() => onExport('csv')}
            title="Export CSV findings sheet"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-light-text dark:text-dark-text hover:bg-light-hover dark:hover:bg-dark-hover transition-colors font-medium"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-p4 dark:text-p4-dark" />
            <span>CSV</span>
          </button>
        </div>
      </div>
    </header>
  );
};



// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect } from 'react';
import { Sidebar, TabId } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { MetricsGrid } from './components/command-center/MetricsGrid';
import { KevThreatRadar } from './components/command-center/KevThreatRadar';
import { PipelineVisualizer } from './components/command-center/PipelineVisualizer';
import { FindingsTable } from './components/triage/FindingsTable';
import { FindingDetailDrawer } from './components/triage/FindingDetailDrawer';
import { FleetGrid } from './components/fleet/FleetGrid';
import { ExceptionsTable } from './components/exceptions/ExceptionsTable';
import { CreateExceptionModal } from './components/exceptions/CreateExceptionModal';
import { AgentStateView } from './components/agent-state/AgentStateView';
import { SbomTable } from './components/sbom/SbomTable';
import { SettingsView } from './components/settings/SettingsView';
import { apiAdapter, TransportMode } from './api/adapter';
import { Finding, FleetHost, ExceptionRef, ScanResult } from './types/scanner';
import { State } from './types/taskstate';
import {
  CheckCircle2,
  AlertCircle,
  Info,
  X,
  Loader2,
} from 'lucide-react';

interface ToastNotification {
  id: string;
  message: string;
  type: 'success' | 'info' | 'error';
}

export function App() {
  const [activeTab, setActiveTab] = useState<TabId>('command-center');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [fleetHosts, setFleetHosts] = useState<FleetHost[]>([]);
  const [exceptions, setExceptions] = useState<ExceptionRef[]>([]);
  const [taskState, setTaskState] = useState<State | null>(null);
  const [transportMode, setTransportMode] = useState<TransportMode>(apiAdapter.mode);
  const [demoDataReason, setDemoDataReason] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isCreateExceptionOpen, setIsCreateExceptionOpen] = useState<boolean>(false);
  const [exceptionInitialFinding, setExceptionInitialFinding] = useState<Finding | null>(null);

  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanningHostId, setScanningHostId] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastNotification[]>([]);

  // Initial Data Fetch
  useEffect(() => {
    loadAllData();
  }, [transportMode]);

  const loadAllData = async () => {
    try {
      const [scan, hosts, rules, state] = await Promise.all([
        apiAdapter.getScanResult(),
        apiAdapter.getFleetHosts(),
        apiAdapter.getAcceptedRisks(),
        apiAdapter.getTaskState(),
      ]);
      setScanResult(scan);
      setDemoDataReason(apiAdapter.demoDataReason);
      setFleetHosts(hosts);
      setExceptions(rules);
      setTaskState(state);
    } catch (err) {
      showToast('Failed to load telemetry state', 'error');
    }
  };

  const showToast = (message: string, type: 'success' | 'info' | 'error' = 'info') => {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  };

  // Scan triggers
  const handleTriggerScan = async (hostId?: string) => {
    setIsScanning(true);
    if (hostId) setScanningHostId(hostId);
    showToast(
      hostId
        ? `Initiating remote WinRM probe on host ${hostId}...`
        : 'Running localhost inventory probe correlation...',
      'info'
    );

    try {
      const result = await apiAdapter.triggerScan(hostId);
      setScanResult(result);
      const hosts = await apiAdapter.getFleetHosts();
      setFleetHosts(hosts);
      showToast(
        `Scan complete in ${result.duration_ms}ms! ${result.summary.total} findings analyzed.`,
        'success'
      );
    } catch (err) {
      showToast('Scan execution failed.', 'error');
    } finally {
      setIsScanning(false);
      setScanningHostId(null);
    }
  };

  // Exceptions
  const handleOpenCreateException = (finding?: Finding) => {
    setExceptionInitialFinding(finding || null);
    setIsCreateExceptionOpen(true);
  };

  const handleCreateExceptionSubmit = async (
    rule: Omit<ExceptionRef, 'rule_id' | 'created_at'>
  ) => {
    try {
      const newRule = await apiAdapter.createAcceptedRisk(rule);
      setExceptions(await apiAdapter.getAcceptedRisks());
      setScanResult(await apiAdapter.getScanResult());
      showToast(`Accepted-risk rule ${newRule.rule_id} activated.`, 'success');
    } catch (err) {
      showToast('Failed to create exception rule.', 'error');
    }
  };

  const handleDeleteException = async (ruleId: string) => {
    try {
      await apiAdapter.deleteAcceptedRisk(ruleId);
      setExceptions(await apiAdapter.getAcceptedRisks());
      setScanResult(await apiAdapter.getScanResult());
      showToast(`Exception rule ${ruleId} revoked.`, 'info');
    } catch (err) {
      showToast('Failed to delete exception rule.', 'error');
    }
  };

  // Task state dispatch
  const handleDispatchTaskAction = async (
    action: 'start' | 'finish' | 'handoff',
    payload: { taskId?: string; toAgent?: string; notes?: string }
  ) => {
    try {
      await apiAdapter.dispatchTaskAction(action, payload);
      setTaskState(await apiAdapter.getTaskState());
      showToast(`Task action "${action}" dispatched to state store.`, 'success');
    } catch (err) {
      showToast('Failed to dispatch task action.', 'error');
    }
  };

  // Exports
  const handleExport = async (format: 'html' | 'cyclonedx' | 'csv') => {
    try {
      const content = await apiAdapter.exportReport(format);
      const mimeTypes = {
        html: 'text/html',
        cyclonedx: 'application/json',
        csv: 'text/csv',
      };
      const extensions = {
        html: 'html',
        cyclonedx: 'json',
        csv: 'csv',
      };

      const blob = new Blob([content], { type: mimeTypes[format] });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `evedoo-audit-${Date.now()}.${extensions[format]}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast(`Exported ${format.toUpperCase()} report successfully.`, 'success');
    } catch (err) {
      showToast(`Failed to export ${format} report.`, 'error');
    }
  };

  if (!scanResult || !taskState) {
    return (
      <div className="h-screen w-screen bg-light-bg dark:bg-dark-bg flex flex-col items-center justify-center text-light-text dark:text-dark-text font-mono space-y-4 transition-colors">
        <Loader2 className="w-8 h-8 animate-spin text-p1" />
        <div className="text-sm font-semibold tracking-wider">INITIALIZING EVEDOO STUDIO...</div>
      </div>
    );
  }

  const counts = {
    findings: scanResult.findings.length,
    p1Count: scanResult.summary.p1,
    fleet: fleetHosts.length,
    exceptions: exceptions.length,
    activePhase: taskState.active_phase.phase_id,
    inventory: scanResult.software_inventory.length,
  };

  return (
    <div className="flex h-screen w-screen bg-light-bg dark:bg-dark-bg text-light-text dark:text-dark-text overflow-hidden font-sans select-none transition-colors duration-200">
      {/* Left Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onTriggerScan={() => handleTriggerScan()}
        isScanning={isScanning}
        counts={counts}
      />

      {/* Main Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {demoDataReason && (
          <div
            role="alert"
            className="bg-amber-500 text-black text-sm font-semibold px-6 py-2 text-center"
          >
            DEMO DATA: these findings are samples, not a scan of this machine ({demoDataReason}).
          </div>
        )}

        {/* Top Header */}
        <Header
          currentHost={scanResult.target}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          transportMode={transportMode}
          onTransportModeChange={(mode) => {
            apiAdapter.setMode(mode);
            setTransportMode(mode);
          }}
          onExport={handleExport}
          isScanning={isScanning}
        />

        {/* Scrollable Viewport */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'command-center' && (
            <div className="space-y-6">
              {/* Key Metrics */}
              <MetricsGrid
                summary={scanResult.summary}
                onFilterP1={() => {
                  setActiveTab('triage');
                }}
                onFilterP2={() => {
                  setActiveTab('triage');
                }}
                onFilterDelta={() => {
                  setActiveTab('triage');
                }}
                onFilterExceptions={() => {
                  setActiveTab('exceptions');
                }}
              />

              {/* Threat Radar & Pipeline Visualization Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <KevThreatRadar
                    findings={scanResult.findings}
                    onSelectFinding={(f) => setSelectedFinding(f)}
                  />
                </div>
                <div className="lg:col-span-1">
                  <PipelineVisualizer scanResult={scanResult} />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'triage' && (
            <FindingsTable
              findings={scanResult.findings}
              searchQuery={searchQuery}
              onSelectFinding={(f) => setSelectedFinding(f)}
              onAcceptRisk={(f) => handleOpenCreateException(f)}
            />
          )}

          {activeTab === 'fleet' && (
            <FleetGrid
              hosts={fleetHosts}
              onTriggerScan={(hostId) => handleTriggerScan(hostId)}
              scanningHostId={scanningHostId}
            />
          )}

          {activeTab === 'exceptions' && (
            <ExceptionsTable
              exceptions={exceptions}
              onOpenCreateModal={() => handleOpenCreateException()}
              onDeleteException={handleDeleteException}
            />
          )}

          {activeTab === 'agent-state' && (
            <AgentStateView
              taskState={taskState}
              onDispatchAction={handleDispatchTaskAction}
            />
          )}

          {activeTab === 'sbom' && (
            <SbomTable
              softwareInventory={scanResult.software_inventory}
              findings={scanResult.findings}
              onExport={(fmt) => handleExport(fmt)}
              searchQuery={searchQuery}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              transportMode={transportMode}
              onSetTransportMode={(m) => {
                apiAdapter.setMode(m);
                setTransportMode(m);
              }}
              onShowToast={showToast}
            />
          )}
        </main>
      </div>

      {/* Flyout Finding Detail Drawer */}
      <FindingDetailDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onAcceptRisk={(f) => handleOpenCreateException(f)}
      />

      {/* Create Accepted-Risk Modal */}
      <CreateExceptionModal
        isOpen={isCreateExceptionOpen}
        onClose={() => setIsCreateExceptionOpen(false)}
        onSubmit={handleCreateExceptionSubmit}
        initialFinding={exceptionInitialFinding}
      />

      {/* Toast Notification Container */}
      <div className="fixed bottom-5 right-5 z-50 space-y-2 pointer-events-none">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto p-4 rounded-2xl border shadow-xl flex items-center gap-2.5 text-xs font-mono animate-in slide-in-from-bottom duration-200 backdrop-blur-xl ${
              toast.type === 'success'
                ? 'bg-light-surface/95 dark:bg-dark-surface/95 border-emerald-500/40 text-emerald-700 dark:text-emerald-300'
                : toast.type === 'error'
                ? 'bg-light-surface/95 dark:bg-dark-surface/95 border-p1/40 text-p1-light dark:text-p1-dark'
                : 'bg-light-surface/95 dark:bg-dark-surface/95 border-p3/40 text-p3 dark:text-p3-dark'
            }`}
          >
            {toast.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />}
            {toast.type === 'error' && <AlertCircle className="w-4 h-4 text-p1 shrink-0" />}
            {toast.type === 'info' && <Info className="w-4 h-4 text-p3 dark:text-p3-dark shrink-0" />}
            <span className="text-light-text dark:text-dark-text font-medium">{toast.message}</span>
            <button
              onClick={() => setToasts((prev) => prev.filter((t) => t.id !== toast.id))}
              className="ml-2 text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;



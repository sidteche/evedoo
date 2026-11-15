// SPDX-License-Identifier: Apache-2.0
import { ScanResult, FleetHost, ExceptionRef, Finding, DetectedSoftware, PriorityTier, FindingStatus, Architecture } from '../types/scanner';
import { State } from '../types/taskstate';
import {
  MOCK_SCAN_RESULT,
  MOCK_FLEET_HOSTS,
  MOCK_EXCEPTIONS,
  MOCK_TASK_STATE,
} from './mockData';

export type TransportMode = 'live' | 'demo' | 'tauri' | 'rest' | 'mock';

export interface TransportAdapter {
  mode: TransportMode;
  setMode(mode: TransportMode): void;
  getScanResult(): Promise<ScanResult>;
  getFleetHosts(): Promise<FleetHost[]>;
  triggerScan(hostId?: string): Promise<ScanResult>;
  getAcceptedRisks(): Promise<ExceptionRef[]>;
  createAcceptedRisk(rule: Omit<ExceptionRef, 'rule_id' | 'created_at'>): Promise<ExceptionRef>;
  deleteAcceptedRisk(ruleId: string): Promise<boolean>;
  getTaskState(): Promise<State>;
  dispatchTaskAction(
    action: 'start' | 'finish' | 'handoff',
    payload: { taskId?: string; toAgent?: string; notes?: string; summary?: string }
  ): Promise<boolean>;
  exportReport(format: 'html' | 'cyclonedx' | 'csv' | 'json'): Promise<string>;
}

// In-memory state for mock / demo mutation
let demoScanResult: ScanResult = JSON.parse(JSON.stringify(MOCK_SCAN_RESULT));
let demoFleetHosts: FleetHost[] = JSON.parse(JSON.stringify(MOCK_FLEET_HOSTS));
let demoExceptions: ExceptionRef[] = JSON.parse(JSON.stringify(MOCK_EXCEPTIONS));
let demoTaskState: State = JSON.parse(JSON.stringify(MOCK_TASK_STATE));

declare global {
  interface Window {
    __TAURI__?: {
      invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
    };
  }
}

/**
 * Normalizes raw CLI output from `evedoo scan -f json` into Studio ScanResult
 */
function mapRawCliScanToStudioResult(raw: any): ScanResult {
  if (raw.summary && raw.host_info && Array.isArray(raw.findings)) {
    // Already in Studio format
    return raw as ScanResult;
  }

  const hostname = raw.hostname || 'LOCALHOST';
  const scanTime = raw.scan_time || new Date().toISOString();
  const rawFindings = Array.isArray(raw.findings) ? raw.findings : [];
  const rawSoftwareWithoutCves = Array.isArray(raw.software_without_cves) ? raw.software_without_cves : [];

  // Build software inventory map
  const softwareInventory: DetectedSoftware[] = [];
  const seenSoftware = new Set<string>();

  const processSoftware = (s: any): DetectedSoftware => {
    const product = s.name || s.product || 'Unknown Package';
    const vendor = s.publisher || s.vendor || 'Unknown Vendor';
    const version = s.version || '0.0.0';
    const source = s.registry_key || s.source || 'registry://';
    const path = s.install_location || s.path;
    const architecture = (s.architecture === 'X64' || s.architecture === 'x64' ? 'x64' : s.architecture === 'X86' || s.architecture === 'x86' ? 'x86' : 'AnyCPU') as Architecture;
    const cleanVendor = vendor.toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_').slice(0, 30);
    const cleanProduct = product.toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+/g, '_').slice(0, 30);
    const cpe = s.cpe || `cpe:2.3:a:${cleanVendor || 'vendor'}:${cleanProduct || 'product'}:${version}:*:*:*:*:*:*:*`;

    return {
      cpe,
      vendor,
      product,
      version,
      source,
      path,
      architecture,
      install_date: s.install_date,
    };
  };

  // Map findings
  const mappedFindings: Finding[] = rawFindings.map((rf: any, idx: number) => {
    const s = processSoftware(rf.software || {});
    const v = rf.vulnerability || {};
    const risk = rf.risk || {};

    const cveId = v.cve_id || `CVE-UNKNOWN-${idx}`;
    const cvssScore = typeof v.cvss_score === 'number' ? v.cvss_score : risk.score ? Number((risk.score / 10).toFixed(1)) : 7.5;
    const epssScore = typeof v.epss_score === 'number' ? v.epss_score : 0.08;
    const epssPercentile = typeof v.epss_percentile === 'number' ? v.epss_percentile : 0.65;
    const isKev = Boolean(v.in_kev || v.cisa_kev);

    let priority: PriorityTier = 'P3';
    if (risk.tier) {
      priority = risk.tier as PriorityTier;
    } else if (isKev || cvssScore >= 9.0) {
      priority = 'P1';
    } else if (cvssScore >= 7.0 || epssScore >= 0.5) {
      priority = 'P2';
    } else if (cvssScore >= 4.0) {
      priority = 'P3';
    } else {
      priority = 'P4';
    }

    let status: FindingStatus = 'New';
    if (rf.status === 'Persisting') status = 'Persisting';
    else if (rf.status === 'Resolved' || rf.status === 'NoLongerApplicable') status = 'Resolved';
    else if (rf.status === 'Excepted' || rf.excepted) status = 'Excepted';
    else status = 'New';

    // Title generation
    let title = v.title;
    if (!title && v.description) {
      const firstSentence = v.description.split('.')[0];
      title = firstSentence.length > 90 ? firstSentence.slice(0, 87) + '...' : firstSentence;
    }
    if (!title) {
      title = `${s.product} ${cveId} Vulnerability`;
    }

    let exception: ExceptionRef | undefined = undefined;
    if (rf.excepted) {
      exception = {
        rule_id: `RULE-${rf.excepted.id || idx}`,
        scope_pattern: s.cpe,
        cve_scope: cveId,
        host_scope: hostname,
        accepted_by: rf.excepted.owner || 'Security Officer',
        rationale: rf.excepted.reason || 'Audit exception registered',
        ticket_ref: 'SEC-LIVE',
        expires_at: rf.excepted.expires_at || new Date(Date.now() + 90 * 86400000).toISOString(),
        created_at: scanTime,
        specificity_score: 95,
      };
    }

    const key = `${s.product}:${s.version}:${s.source}`;
    if (!seenSoftware.has(key)) {
      seenSoftware.add(key);
      softwareInventory.push(s);
    }

    return {
      id: `FIND-${idx + 1}-${cveId}`,
      cve_id: cveId,
      host: hostname,
      software: s,
      vulnerability: {
        cve_id: cveId,
        title,
        description: v.description || 'No detailed vulnerability advisory description provided.',
        references: Array.isArray(v.references) ? v.references : [],
        published_date: v.published_date || scanTime,
        last_modified_date: v.last_modified_date || scanTime,
        patched_in_version: v.remediation?.fixed_version || v.patched_in_version,
        severity: cvssScore >= 9.0 ? 'CRITICAL' : cvssScore >= 7.0 ? 'HIGH' : cvssScore >= 4.0 ? 'MEDIUM' : 'LOW',
      },
      risk: {
        cvss_v3_score: cvssScore,
        cvss_v3_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        epss_score: epssScore,
        epss_percentile: epssPercentile,
        cisa_kev: isKev,
        cisa_due_date: v.kev_due_date,
        ransomware_campaign: v.kev_ransomware_use && v.kev_ransomware_use !== 'Unknown' ? v.kev_ransomware_use : undefined,
        exploit_maturity: isKev ? 'High' : epssScore > 0.5 ? 'Functional' : 'PoC',
        attack_complexity: 'Low',
        privileges_required: 'None',
        user_interaction: 'None',
      },
      priority,
      status,
      first_detected: scanTime,
      last_detected: scanTime,
      exception,
    };
  });

  // Also collect software without CVEs
  for (const sw of rawSoftwareWithoutCves) {
    const s = processSoftware(sw);
    const key = `${s.product}:${s.version}:${s.source}`;
    if (!seenSoftware.has(key)) {
      seenSoftware.add(key);
      softwareInventory.push(s);
    }
  }

  const p1 = mappedFindings.filter((f) => f.priority === 'P1').length;
  const p2 = mappedFindings.filter((f) => f.priority === 'P2').length;
  const p3 = mappedFindings.filter((f) => f.priority === 'P3').length;
  const p4 = mappedFindings.filter((f) => f.priority === 'P4').length;
  const newCount = mappedFindings.filter((f) => f.status === 'New').length;
  const persisting = mappedFindings.filter((f) => f.status === 'Persisting').length;
  const resolved = Array.isArray(raw.resolved_findings) ? raw.resolved_findings.length : 0;
  const excepted = mappedFindings.filter((f) => f.status === 'Excepted').length;
  const kevActive = mappedFindings.filter((f) => f.risk.cisa_kev).length;

  return {
    scan_id: `SCAN-${Date.now().toString(36).toUpperCase()}`,
    target: hostname,
    timestamp: scanTime,
    duration_ms: raw.duration_ms || 420,
    host_info: {
      hostname,
      os: 'Windows 11 (25H2)',
      ip: '127.0.0.1',
    },
    summary: {
      total: mappedFindings.length,
      p1,
      p2,
      p3,
      p4,
      new: newCount,
      persisting,
      resolved,
      excepted,
      kev_active: kevActive,
    },
    findings: mappedFindings,
    software_inventory: softwareInventory,
  };
}

// Required by the dev-server bridge on every /api request (see vite.config.ts).
const API_HEADERS = { 'X-Evedoo-Studio': '1' };

class UniversalTransportAdapter implements TransportAdapter {
  public mode: TransportMode = 'live';

  // Why the scan data on screen is demo data, or null when it is a real scan.
  // The UI shows this so sample findings are never mistaken for the host's.
  public demoDataReason: string | null = null;

  constructor() {
    if (typeof window !== 'undefined') {
      if (window.__TAURI__) {
        this.mode = 'tauri';
      } else {
        const saved = localStorage.getItem('evedoo-transport-mode') as TransportMode | null;
        if (saved && (saved === 'live' || saved === 'demo' || saved === 'rest' || saved === 'mock' || saved === 'tauri')) {
          this.mode = saved;
        } else {
          this.mode = 'live';
        }
      }
    }
  }

  setMode(mode: TransportMode) {
    this.mode = mode;
    if (typeof window !== 'undefined') {
      localStorage.setItem('evedoo-transport-mode', mode);
    }
  }

  async getScanResult(): Promise<ScanResult> {
    if (this.mode === 'tauri' && window.__TAURI__) {
      try {
        const raw = await window.__TAURI__.invoke('get_latest_scan');
        return mapRawCliScanToStudioResult(raw);
      } catch (err) {
        console.warn('Tauri IPC failed, falling back to mock state:', err);
      }
    } else if (this.mode === 'live' || this.mode === 'rest') {
      try {
        const res = await fetch('/api/scan/latest', { headers: API_HEADERS });
        if (res.ok) {
          const raw = await res.json();
          this.demoDataReason = null;
          return mapRawCliScanToStudioResult(raw);
        }
        this.demoDataReason = `the scanner bridge answered HTTP ${res.status}`;
      } catch (err) {
        console.warn('Live API request failed, falling back to demo state:', err);
        this.demoDataReason = 'the scanner bridge could not be reached';
      }
    }
    if (this.demoDataReason === null) {
      this.demoDataReason = 'demo mode is selected';
    }
    await new Promise((r) => setTimeout(r, 60));
    return demoScanResult;
  }

  async getFleetHosts(): Promise<FleetHost[]> {
    if (this.mode === 'tauri' && window.__TAURI__) {
      try {
        return (await window.__TAURI__.invoke('get_fleet_hosts')) as FleetHost[];
      } catch (err) {
        console.warn('Tauri IPC failed:', err);
      }
    } else if (this.mode === 'live' || this.mode === 'rest') {
      try {
        const res = await fetch('/api/fleet', { headers: API_HEADERS });
        if (res.ok) return await res.json();
      } catch (err) {
        console.warn('Live fleet API failed:', err);
      }
    }
    await new Promise((r) => setTimeout(r, 50));
    return demoFleetHosts;
  }

  async triggerScan(hostId?: string): Promise<ScanResult> {
    if (this.mode === 'tauri' && window.__TAURI__) {
      try {
        const raw = await window.__TAURI__.invoke('run_scan', { hostId });
        return mapRawCliScanToStudioResult(raw);
      } catch (err) {
        console.warn('Tauri IPC scan failed:', err);
      }
    } else if (this.mode === 'live' || this.mode === 'rest') {
      try {
        const res = await fetch('/api/scan/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...API_HEADERS },
          body: JSON.stringify({ hostId }),
        });
        if (res.ok) {
          const raw = await res.json();
          this.demoDataReason = null;
          return mapRawCliScanToStudioResult(raw);
        }
        this.demoDataReason = `the scanner bridge answered HTTP ${res.status}`;
      } catch (err) {
        console.warn('Live API scan trigger failed, falling back to demo scan:', err);
        this.demoDataReason = 'the scanner bridge could not be reached';
      }
    }
    if (this.demoDataReason === null) {
      this.demoDataReason = 'demo mode is selected';
    }

    await new Promise((r) => setTimeout(r, 750));
    const targetHost = demoFleetHosts.find((h) => h.id === hostId) || demoFleetHosts[0];
    const timestamp = new Date().toISOString();

    demoScanResult = {
      ...demoScanResult,
      scan_id: `SCAN-${Date.now().toString(36).toUpperCase()}`,
      timestamp,
      target: targetHost.hostname,
      duration_ms: Math.floor(650 + Math.random() * 400),
      host_info: {
        hostname: targetHost.hostname,
        os: `${targetHost.os_name} ${targetHost.os_version} (Build ${targetHost.os_build})`,
        ip: targetHost.ip,
      },
    };

    return demoScanResult;
  }

  async getAcceptedRisks(): Promise<ExceptionRef[]> {
    if (this.mode === 'tauri' && window.__TAURI__) {
      try {
        return (await window.__TAURI__.invoke('get_exceptions')) as ExceptionRef[];
      } catch (err) {
        console.warn('Tauri IPC get_exceptions failed:', err);
      }
    }
    await new Promise((r) => setTimeout(r, 40));
    return demoExceptions;
  }

  async createAcceptedRisk(
    rule: Omit<ExceptionRef, 'rule_id' | 'created_at'>
  ): Promise<ExceptionRef> {
    const newRule: ExceptionRef = {
      ...rule,
      rule_id: `RULE-${new Date().getFullYear()}-${String(demoExceptions.length + 1).padStart(3, '0')}`,
      created_at: new Date().toISOString(),
    };

    if (this.mode === 'tauri' && window.__TAURI__) {
      try {
        await window.__TAURI__.invoke('add_exception', { rule: newRule });
      } catch (err) {
        console.warn('Tauri IPC add_exception failed:', err);
      }
    }

    demoExceptions = [newRule, ...demoExceptions];

    demoScanResult.findings = demoScanResult.findings.map((f) => {
      if (
        (newRule.cve_scope === '*' || newRule.cve_scope === f.cve_id) &&
        (newRule.host_scope === 'all' || f.host.includes(newRule.host_scope || ''))
      ) {
        return {
          ...f,
          status: 'Excepted',
          exception: newRule,
        };
      }
      return f;
    });

    demoScanResult.summary.excepted = demoScanResult.findings.filter(
      (f) => f.status === 'Excepted'
    ).length;

    return newRule;
  }

  async deleteAcceptedRisk(ruleId: string): Promise<boolean> {
    demoExceptions = demoExceptions.filter((r) => r.rule_id !== ruleId);
    demoScanResult.findings = demoScanResult.findings.map((f) => {
      if (f.exception?.rule_id === ruleId) {
        return {
          ...f,
          status: 'Persisting',
          exception: undefined,
        };
      }
      return f;
    });
    demoScanResult.summary.excepted = demoScanResult.findings.filter(
      (f) => f.status === 'Excepted'
    ).length;
    return true;
  }

  async getTaskState(): Promise<State> {
    if (this.mode === 'tauri' && window.__TAURI__) {
      try {
        return (await window.__TAURI__.invoke('get_task_state')) as State;
      } catch (err) {
        console.warn('Tauri IPC task state failed:', err);
      }
    } else if (this.mode === 'live' || this.mode === 'rest') {
      try {
        const res = await fetch('/api/taskstate', { headers: API_HEADERS });
        if (res.ok) return await res.json();
      } catch (err) {
        console.warn('Live task state API failed:', err);
      }
    }
    await new Promise((r) => setTimeout(r, 50));
    return demoTaskState;
  }

  async dispatchTaskAction(
    action: 'start' | 'finish' | 'handoff',
    payload: { taskId?: string; toAgent?: string; notes?: string; summary?: string }
  ): Promise<boolean> {
    if (this.mode === 'live' || this.mode === 'rest') {
      try {
        const res = await fetch('/api/taskstate/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...API_HEADERS },
          body: JSON.stringify({ action, ...payload }),
        });
        if (res.ok) return true;
      } catch (err) {
        console.warn('Live task action failed:', err);
      }
    }

    if (action === 'start' && payload.taskId) {
      demoTaskState.active_tasks = demoTaskState.active_tasks.map((t) => {
        if (t.task_id === payload.taskId) {
          return { ...t, status: 'in_progress', started_at: new Date().toISOString() };
        }
        return t;
      });
    } else if (action === 'finish' && payload.taskId) {
      demoTaskState.active_tasks = demoTaskState.active_tasks.map((t) => {
        if (t.task_id === payload.taskId) {
          return { ...t, status: 'done', completed_at: new Date().toISOString() };
        }
        return t;
      });
      const nextQ = demoTaskState.active_tasks.find((t) => t.status === 'queued');
      if (nextQ) {
        demoTaskState.next_task = nextQ;
      }
    } else if (action === 'handoff') {
      demoTaskState.handoffs.unshift({
        handoff_id: `HANDOFF-${Date.now().toString().slice(-4)}`,
        from_agent: 'Frontend Architect Subagent',
        to_agent: payload.toAgent || 'Parent Coordinator',
        context_summary: payload.notes || 'Handoff completed via Evedoo Studio workspace.',
        timestamp: new Date().toISOString(),
        active_task_id: payload.taskId || demoTaskState.next_task.task_id,
      });
    }

    demoTaskState.last_updated = new Date().toISOString();
    return true;
  }

  async exportReport(format: 'html' | 'cyclonedx' | 'csv' | 'json'): Promise<string> {
    const current = await this.getScanResult();
    if (format === 'csv') {
      const headers = 'CVE,Priority,Severity,CVSS,EPSS,KEV,Status,Host,Software,Version,Source\n';
      const rows = current.findings
        .map(
          (f) =>
            `"${f.cve_id}","${f.priority}","${f.vulnerability.severity}",${f.risk.cvss_v3_score},${(f.risk.epss_score * 100).toFixed(1)}%,${f.risk.cisa_kev},"${f.status}","${f.host}","${f.software.product}","${f.software.version}","${f.software.source}"`
        )
        .join('\n');
      return headers + rows;
    }

    if (format === 'cyclonedx') {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        serialNumber: `urn:uuid:${current.scan_id}`,
        version: 1,
        metadata: {
          timestamp: current.timestamp,
          tools: [{ vendor: 'Evedoo Security', name: 'Evedoo Engine', version: '0.9.4' }],
          component: {
            type: 'operating-system',
            name: current.host_info.hostname,
            version: current.host_info.os,
          },
        },
        components: current.software_inventory.map((s, idx) => ({
          type: 'application',
          'bom-ref': `comp-${idx}-${s.product}`,
          name: s.product,
          version: s.version,
          purl: `pkg:generic/${s.vendor}/${s.product}@${s.version}`,
          cpe: s.cpe,
          properties: [{ name: 'evedoo:source', value: s.source }],
        })),
        vulnerabilities: current.findings.map((f) => ({
          id: f.cve_id,
          source: { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${f.cve_id}` },
          ratings: [
            {
              score: f.risk.cvss_v3_score,
              severity: f.vulnerability.severity.toLowerCase(),
              method: 'CVSSv31',
              vector: f.risk.cvss_v3_vector,
            },
          ],
          description: f.vulnerability.description,
          advisories: f.vulnerability.references.map((url) => ({ url })),
          affects: [{ ref: `comp-0-${f.software.product}` }],
        })),
      };
      return JSON.stringify(sbom, null, 2);
    }

    if (format === 'json') {
      return JSON.stringify(current, null, 2);
    }

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Evedoo SecOps Audit Report - ${current.scan_id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #090a0f; color: #f0f3f8; padding: 30px; }
    h1, h2 { color: #ffffff; }
    .badge { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .p1 { background: #ef4444; color: #fff; }
    .p2 { background: #f59e0b; color: #fff; }
    .p3 { background: #0284c7; color: #fff; }
    .p4 { background: #10b981; color: #fff; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #161a26; }
    th, td { border: 1px solid #232838; padding: 10px; text-align: left; }
    th { background: #1d2232; color: #ffffff; }
  </style>
</head>
<body>
  <h1>Evedoo Security Scan Report</h1>
  <p><strong>Scan ID:</strong> ${current.scan_id} | <strong>Target:</strong> ${current.target} | <strong>Date:</strong> ${current.timestamp}</p>
  <h2>Findings (${current.findings.length})</h2>
  <table>
    <thead><tr><th>CVE</th><th>Priority</th><th>Product</th><th>Version</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Status</th></tr></thead>
    <tbody>
      ${current.findings
        .map(
          (f) =>
            `<tr><td><strong>${f.cve_id}</strong></td><td><span class="badge ${f.priority.toLowerCase()}">${f.priority}</span></td><td>${f.software.product}</td><td>${f.software.version}</td><td>${f.risk.cvss_v3_score}</td><td>${(f.risk.epss_score * 100).toFixed(1)}%</td><td>${f.risk.cisa_kev ? '🚨 YES' : 'No'}</td><td>${f.status}</td></tr>`
        )
        .join('')}
    </tbody>
  </table>
</body>
</html>`;
  }
}

export const apiAdapter = new UniversalTransportAdapter();



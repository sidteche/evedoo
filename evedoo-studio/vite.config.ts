// SPDX-License-Identifier: Apache-2.0
import { defineConfig, Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// Where the workspace build puts the CLI, in preference order. Repo-relative
// only: an absolute machine path here (this list once led with
// C:\cargo-target\..., a OneDrive-era build redirect) silently runs whatever
// stale binary is left at that path after the redirect is gone.
const EVEDOO_BINARY_NAME = process.platform === 'win32' ? 'evedoo.exe' : 'evedoo';
const EVEDOO_BINARY_CANDIDATES = [
  path.resolve(__dirname, '..', 'target', 'release', EVEDOO_BINARY_NAME),
  path.resolve(__dirname, '..', 'target', 'debug', EVEDOO_BINARY_NAME),
  path.resolve(__dirname, '..', EVEDOO_BINARY_NAME),
];

// Every /api request must carry this header. A page on another origin cannot
// send a custom header without a CORS preflight, and this server never
// answers one, so cross-site requests (forms, images, no-cors fetches) are
// refused before they reach a handler.
const API_HEADER = 'x-evedoo-studio';

// Why a request to /api must be refused, or null when it may proceed.
//
// The bridge starts scans, returns the host's vulnerability inventory and
// appends to the agent task ledger, so "the socket is loopback" is not enough:
// a web page open in the developer's browser also reaches loopback (CSRF),
// and a DNS-rebinding page does so under its own hostname.
function apiRefusalReason(req: {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  socket: { remoteAddress?: string; localPort?: number };
}): string | null {
  const ra = req.socket.remoteAddress || '';
  if (!(ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1')) {
    return '/api is loopback-only';
  }

  // DNS rebinding: the browser sends the attacker's hostname in Host.
  const port = req.socket.localPort;
  const allowedHosts = [`127.0.0.1:${port}`, `localhost:${port}`];
  const host = typeof req.headers.host === 'string' ? req.headers.host.toLowerCase() : '';
  if (!allowedHosts.includes(host)) {
    return 'unexpected Host header';
  }

  // Cross-site requests: Origin, when sent, must be this server.
  const origin = req.headers.origin;
  if (origin !== undefined) {
    const allowedOrigins = allowedHosts.map((h) => `http://${h}`);
    if (typeof origin !== 'string' || !allowedOrigins.includes(origin.toLowerCase())) {
      return 'cross-origin request';
    }
  }

  if (req.headers[API_HEADER] !== '1') {
    return `missing ${API_HEADER} header`;
  }

  // Anything that changes state or starts work must be a JSON POST.
  const method = req.method || 'GET';
  if (method !== 'GET') {
    const contentType = typeof req.headers['content-type'] === 'string' ? req.headers['content-type'] : '';
    if (method !== 'POST' || !contentType.toLowerCase().startsWith('application/json')) {
      return 'state-changing requests must be POST with Content-Type: application/json';
    }
  }
  return null;
}

// Free text written to the task ledger is read by AI agents as instructions:
// keep it short and free of control characters.
function ledgerText(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 2000);
  return cleaned.length > 0 ? cleaned : fallback;
}

// Task ids already present in the ledger.
function knownTaskIds(jsonlPath: string): Set<string> {
  const ids = new Set<string>();
  if (!fs.existsSync(jsonlPath)) return ids;
  for (const line of fs.readFileSync(jsonlPath, 'utf-8').split('\n')) {
    if (line.trim().length === 0) continue;
    try {
      const record = JSON.parse(line);
      if (typeof record.task === 'string') ids.add(record.task);
    } catch (_) {
      // a malformed ledger line names no task
    }
  }
  return ids;
}

// Helper to find evedoo executable
function findEvedooBinary(): string | null {
  for (const p of EVEDOO_BINARY_CANDIDATES) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// Fold tasks.jsonl into Studio State format
function foldTasksJsonl(repoRoot: string) {
  const jsonlPath = path.resolve(repoRoot, 'docs', 'agent-state', 'tasks.jsonl');
  if (!fs.existsSync(jsonlPath)) {
    return null;
  }

  const lines = fs.readFileSync(jsonlPath, 'utf-8').split('\n').filter((l) => l.trim().length > 0);
  const records = lines.map((l) => JSON.parse(l));
  records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  let activePhaseId = 'P21';
  let activePhaseTitle = 'Enterprise Accuracy & Reachability';
  let activePhaseGoal = 'Runtime reachability, MSRC advisories, CIS compliance, and remediation aggregation.';
  
  const phasesMap = new Map<string, {
    phase_id: string;
    name: string;
    description: string;
    status: 'completed' | 'active' | 'pending';
    task_count: number;
    completed_count: number;
  }>([
    ['P20', { phase_id: 'P20', name: 'Operationalisation Pipeline', description: 'Schema migrations, inventory snapshot, delta tracking, and risk tiers', status: 'completed', task_count: 9, completed_count: 9 }],
    ['P21', { phase_id: 'P21', name: 'Enterprise Accuracy & Reachability', description: 'Runtime reachability, MSRC advisories, CIS compliance, and cross-asset aggregation', status: 'active', task_count: 5, completed_count: 0 }],
    ['P22', { phase_id: 'P22', name: 'Fleet Scale & WinRM Swarm', description: 'Mass parallel WinRM scheduling, zero-trust credential vault, telemetry streaming', status: 'pending', task_count: 6, completed_count: 0 }],
  ]);

  const tasksMap = new Map<string, any>();
  const rulings: any[] = [];
  const handoffs: any[] = [];

  for (const record of records) {
    const { type, timestamp, by } = record;
    if (type === 'phase_opened') {
      activePhaseId = record.phase;
      activePhaseTitle = record.title || activePhaseTitle;
      activePhaseGoal = record.goal || activePhaseGoal;
      if (!phasesMap.has(record.phase)) {
        phasesMap.set(record.phase, {
          phase_id: record.phase,
          name: record.title,
          description: record.goal,
          status: 'active',
          task_count: 0,
          completed_count: 0,
        });
      } else {
        const p = phasesMap.get(record.phase)!;
        p.name = record.title;
        p.description = record.goal;
        p.status = 'active';
      }
    } else if (type === 'task_declared') {
      tasksMap.set(record.task, {
        task_id: record.task,
        phase_id: record.phase,
        title: record.title,
        description: record.description || '',
        status: 'queued',
        assigned_to: by?.runtime || 'unassigned',
        depends_on: record.depends_on || [],
        deliverables: [],
      });
      const p = phasesMap.get(record.phase);
      if (p) p.task_count += 1;
    } else if (type === 'task_started') {
      const t = tasksMap.get(record.task);
      if (t) {
        t.status = 'in_progress';
        t.started_at = timestamp;
        t.assigned_to = by?.runtime || t.assigned_to;
      }
    } else if (type === 'task_finished') {
      const t = tasksMap.get(record.task);
      if (t) {
        t.status = 'done';
        t.completed_at = timestamp;
        t.pr_ref = record.commit;
        const p = phasesMap.get(t.phase_id);
        if (p) p.completed_count += 1;
      }
    } else if (type === 'ruling_recorded') {
      rulings.unshift({
        ruling_id: `RULING-${rulings.length + 1}`,
        title: record.subject,
        decider: by?.runtime || 'Security Architect',
        status: 'approved',
        rationale: `${record.decision} — ${record.rationale}`,
        timestamp,
        affected_phases: ['P20', 'P21'],
      });
    } else if (type === 'handoff_requested' || type === 'handoff_dispatched') {
      handoffs.unshift({
        handoff_id: `HANDOFF-${handoffs.length + 1}`,
        from_agent: by?.runtime || 'Subagent',
        to_agent: record.to || 'Coordinator',
        context_summary: record.reason || record.note || 'State handoff requested',
        timestamp,
        active_task_id: record.task || 'P21-N3',
      });
    }
  }

  // Filter tasks for active phase or all tasks
  const activePhaseTasks = Array.from(tasksMap.values()).filter((t) => t.phase_id === activePhaseId);
  const activeTasksList = activePhaseTasks.length > 0 ? activePhaseTasks : Array.from(tasksMap.values()).slice(-6);

  const nextTask = activeTasksList.find((t) => t.status === 'in_progress') ||
    activeTasksList.find((t) => t.status === 'queued') ||
    activeTasksList[0] || {
      task_id: 'P21-N3',
      phase_id: 'P21',
      title: 'Runtime reachability for loaded modules',
      description: 'Enumerate loaded modules per process on Windows to distinguish active runtime binaries.',
      status: 'queued',
    };

  const activePhaseObj = phasesMap.get(activePhaseId) || {
    phase_id: activePhaseId,
    name: activePhaseTitle,
    description: activePhaseGoal,
    status: 'active' as const,
    task_count: activeTasksList.length,
    completed_count: activeTasksList.filter((t) => t.status === 'done').length,
  };

  return {
    active_phase: activePhaseObj,
    next_task: nextTask,
    active_tasks: activeTasksList,
    rulings: rulings.slice(0, 5),
    handoffs: handoffs.slice(0, 5),
    all_phases: Array.from(phasesMap.values()),
    last_updated: records.length > 0 ? records[records.length - 1].timestamp : new Date().toISOString(),
    store_version: 'v21.4-jsonl',
  };
}

// In-memory scan cache
let cachedLiveScanResult: any = null;

function evedooApiPlugin(): Plugin {
  return {
    name: 'evedoo-api-middleware',
    configureServer(server) {
      const repoRoot = path.resolve(__dirname, '..');
      const dbPath = path.resolve(repoRoot, 'vulndb.sqlite');

      server.middlewares.use(async (req, res, next) => {
        const url = req.url || '';
        if (url.startsWith('/api/')) {
          const refusal = apiRefusalReason(req);
          if (refusal) {
            res.statusCode = 403;
            res.end(`forbidden: ${refusal}`);
            return;
          }
        }

        // Status check
        if (url === '/api/status' && req.method === 'GET') {
          const binary = findEvedooBinary();
          const hasDb = fs.existsSync(dbPath);
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              engine_online: !!binary,
              binary_path: binary,
              db_path: dbPath,
              db_exists: hasDb,
              hostname: os.hostname(),
              platform: os.platform(),
              arch: os.arch(),
            })
          );
          return;
        }

        // Fleet info
        if (url === '/api/fleet' && req.method === 'GET') {
          // Only what is real: this machine, once it has been scanned. There is
          // no fleet store behind this bridge, so no other host is listed.
          const scan = cachedLiveScanResult;
          const findings: any[] = Array.isArray(scan?.findings) ? scan.findings : [];
          const tierCount = (tier: string) => findings.filter((f) => f?.risk?.tier === tier).length;
          const fleetHosts = scan
            ? [
                {
                  id: 'host-localhost',
                  hostname: os.hostname(),
                  ip: '127.0.0.1',
                  os_name: `${os.type()} ${os.release()}`,
                  os_version: os.release(),
                  os_build: '',
                  architecture: os.arch() === 'x64' ? 'x64' : 'x86',
                  agent_status: 'online',
                  last_scan_time: typeof scan.scan_time === 'string' ? scan.scan_time : '',
                  open_p1_count: tierCount('P1'),
                  open_p2_count: tierCount('P2'),
                  total_findings: findings.length,
                  winrm_tls: false,
                  winrm_port: 0,
                  tags: ['Local host'],
                },
              ]
            : [];

          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(fleetHosts));
          return;
        }

        // Real Task State from tasks.jsonl
        if (url === '/api/taskstate' && req.method === 'GET') {
          const state = foldTasksJsonl(repoRoot);
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(state));
          return;
        }

        // Append Task Action
        if (url === '/api/taskstate/action' && req.method === 'POST') {
          let body = '';
          req.on('data', (chunk) => (body += chunk));
          req.on('end', () => {
            try {
              const { action, taskId, toAgent, notes, summary } = JSON.parse(body);
              const jsonlPath = path.resolve(repoRoot, 'docs', 'agent-state', 'tasks.jsonl');
              const now = new Date().toISOString();

              if (action !== 'start' && action !== 'finish' && action !== 'handoff') {
                res.statusCode = 400;
                res.end(JSON.stringify({ error: 'unknown action' }));
                return;
              }
              // A task id must already exist in the ledger; this endpoint never creates one.
              if (taskId !== undefined && (typeof taskId !== 'string' || !knownTaskIds(jsonlPath).has(taskId))) {
                res.statusCode = 400;
                res.end(JSON.stringify({ error: 'unknown task id' }));
                return;
              }

              let record: any = null;
              if (action === 'start' && taskId) {
                record = {
                  timestamp: now,
                  by: { runtime: 'antigravity-studio' },
                  type: 'task_started',
                  task: taskId,
                  note: ledgerText(notes, 'Started via Evedoo Studio'),
                };
              } else if (action === 'finish' && taskId) {
                record = {
                  timestamp: now,
                  by: { runtime: 'antigravity-studio' },
                  type: 'task_finished',
                  task: taskId,
                  outcome: 'done',
                  summary: ledgerText(summary, 'Completed via Evedoo Studio'),
                };
              } else if (action === 'handoff') {
                record = {
                  timestamp: now,
                  by: { runtime: 'antigravity-studio' },
                  type: 'handoff_requested',
                  to: ledgerText(toAgent, 'Coordinator').slice(0, 64),
                  task: taskId,
                  reason: ledgerText(notes, 'Handoff requested via Studio interface'),
                };
              }

              if (record && fs.existsSync(jsonlPath)) {
                fs.appendFileSync(jsonlPath, JSON.stringify(record) + '\n');
              }

              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ success: true, record }));
            } catch (err: any) {
              res.statusCode = 500;
              res.end(JSON.stringify({ error: err.message }));
            }
          });
          return;
        }

        // Latest scan
        if (url === '/api/scan/latest' && req.method === 'GET') {
          if (cachedLiveScanResult) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(cachedLiveScanResult));
            return;
          }
          // If no scan cached yet, fallback to running one
          req.url = '/api/scan/run';
        }

        // Trigger real scan via evedoo.exe
        if (url.startsWith('/api/scan/run')) {
          const binary = findEvedooBinary();
          if (!binary) {
            res.statusCode = 503;
            res.setHeader('Content-Type', 'application/json');
            res.end(
              JSON.stringify({
                error: `Evedoo binary not found. Build it with "cargo build --release -p evedoo". Searched: ${EVEDOO_BINARY_CANDIDATES.join(', ')}`,
              }),
            );
            return;
          }

          const tempOut = path.resolve(os.tmpdir(), `evedoo-scan-${Date.now()}.json`);
          const startTime = Date.now();

          const args = ['scan', '-d', dbPath, '-f', 'json', '--show-excepted', '-o', tempOut];

          const proc = spawn(binary, args, { cwd: repoRoot });
          
          let stdout = '';
          let stderr = '';
          proc.stdout.on('data', (d) => (stdout += d.toString()));
          proc.stderr.on('data', (d) => (stderr += d.toString()));

          proc.on('close', (code) => {
            const durationMs = Date.now() - startTime;
            let rawJson = '';

            if (fs.existsSync(tempOut)) {
              rawJson = fs.readFileSync(tempOut, 'utf-8');
              try { fs.unlinkSync(tempOut); } catch (_) {}
            } else if (stdout.includes('{')) {
              const start = stdout.indexOf('{');
              const end = stdout.lastIndexOf('}');
              if (start >= 0 && end > start) {
                rawJson = stdout.substring(start, end + 1);
              }
            }

            if (!rawJson) {
              res.statusCode = 500;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ error: `Scan exited with code ${code}: ${stderr || stdout}` }));
              return;
            }

            try {
              const parsed = JSON.parse(rawJson);
              parsed.duration_ms = durationMs;
              cachedLiveScanResult = parsed;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify(parsed));
            } catch (parseErr: any) {
              res.statusCode = 500;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ error: `Failed to parse scan JSON: ${parseErr.message}`, raw: rawJson.slice(0, 500) }));
            }
          });
          return;
        }

        next();
      });
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), evedooApiPlugin()],
  server: {
    port: 5173,
    host: '127.0.0.1',
  },
});


// SPDX-License-Identifier: Apache-2.0
import React, { useState } from 'react';
import {
  Bot,
  Play,
  CheckCircle2,
  Clock,
  Share2,
  BookOpen,
  Layers,
  Sparkles,
  Check,
} from 'lucide-react';
import { State } from '../../types/taskstate';

interface AgentStateViewProps {
  taskState: State;
  onDispatchAction: (
    action: 'start' | 'finish' | 'handoff',
    payload: { taskId?: string; toAgent?: string; notes?: string }
  ) => void;
}

export const AgentStateView: React.FC<AgentStateViewProps> = ({
  taskState,
  onDispatchAction,
}) => {
  const [handoffModalOpen, setHandoffModalOpen] = useState(false);
  const [handoffNotes, setHandoffNotes] = useState('');
  const [targetAgent, setTargetAgent] = useState('Codex Core Engine Subagent');

  const { active_phase, next_task, active_tasks, rulings, all_phases } = taskState;

  const handleStartTask = (taskId: string) => {
    onDispatchAction('start', { taskId });
  };

  const handleFinishTask = (taskId: string) => {
    onDispatchAction('finish', { taskId });
  };

  const handleHandoffSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onDispatchAction('handoff', {
      taskId: next_task?.task_id,
      toAgent: targetAgent,
      notes: handoffNotes,
    });
    setHandoffModalOpen(false);
    setHandoffNotes('');
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header Info Banner */}
      <div className="glass-panel p-5 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-p2/10 border border-p2/30 flex items-center justify-center text-p2-light dark:text-p2-dark">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-light-text dark:text-dark-text font-mono">
                Evedoo TaskState Autonomous Agent Control
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-p2/10 text-p2-light dark:text-p2-dark border border-p2/30 font-semibold">
                JSONL Pure Fold {taskState.store_version}
              </span>
            </div>
            <p className="text-xs text-light-muted dark:text-dark-muted mt-0.5">
              Advisory-locked cross-runtime coordination bridge between CLI, Rust engine, and studio (<code className="font-mono text-light-text dark:text-dark-text">docs/agent-state/tasks.jsonl</code>).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs text-light-muted dark:text-dark-muted">
          <span>Last Fold Synced:</span>
          <span className="text-light-text dark:text-dark-text font-bold">
            {new Date(taskState.last_updated).toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* Main Grid: Active Phase & Next Task */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Phase Card */}
        <div className="glass-panel rounded-2xl p-5 border border-p2/40 flex flex-col justify-between relative overflow-hidden shadow-sm">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-p2-light dark:text-p2-dark flex items-center gap-1.5">
                <Layers className="w-4 h-4" />
                Active Phase Roadmap
              </span>
              <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-p2/10 text-p2-light dark:text-p2-dark border border-p2/30 font-bold">
                {active_phase.phase_id} ACTIVE
              </span>
            </div>

            <div>
              <h3 className="text-lg font-bold text-light-text dark:text-dark-text">{active_phase.name}</h3>
              <p className="text-xs text-light-muted dark:text-dark-muted mt-1">{active_phase.description}</p>
            </div>

            {/* Progress Bar */}
            <div className="space-y-1.5 pt-2">
              <div className="flex items-center justify-between text-xs font-mono text-light-muted dark:text-dark-muted">
                <span>Phase Completion</span>
                <span className="text-light-text dark:text-dark-text font-bold">
                  {active_phase.completed_count} / {active_phase.task_count} Tasks (
                  {active_phase.task_count > 0 ? Math.round((active_phase.completed_count / active_phase.task_count) * 100) : 0}%)
                </span>
              </div>
              <div className="w-full bg-light-hover dark:bg-dark-card rounded-full h-2 overflow-hidden border border-light-border dark:border-dark-border">
                <div
                  className="bg-gradient-to-r from-p2 to-p3 h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${active_phase.task_count > 0 ? (active_phase.completed_count / active_phase.task_count) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>
          </div>

          {/* All Phases Mini Roadmap */}
          <div className="mt-5 pt-4 border-t border-light-border/60 dark:border-dark-border/60">
            <div className="text-[11px] font-mono uppercase text-light-muted dark:text-dark-muted mb-2 font-semibold">Phase Index</div>
            <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 text-center font-mono text-xs">
              {all_phases.map((p) => (
                <div
                  key={p.phase_id}
                  className={`p-2 rounded-xl border ${
                    p.status === 'completed'
                      ? 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30'
                      : p.status === 'active'
                      ? 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/50 font-bold shadow-sm'
                      : 'bg-light-surface dark:bg-dark-surface text-light-muted dark:text-dark-muted border-light-border dark:border-dark-border'
                  }`}
                >
                  <div className="text-[11px] font-bold">{p.phase_id}</div>
                  <div className="text-[9px] uppercase mt-0.5">{p.status}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Next Task Card */}
        <div className="glass-panel rounded-2xl p-5 border border-p3/40 flex flex-col justify-between relative overflow-hidden shadow-sm">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-p3 dark:text-p3-dark flex items-center gap-1.5">
                <Sparkles className="w-4 h-4" />
                Target Execution Task
              </span>
              <span
                className={`text-xs font-mono px-2.5 py-0.5 rounded-full border font-bold uppercase ${
                  next_task?.status === 'in_progress'
                    ? 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30 animate-pulse'
                    : 'bg-p3/10 text-p3 dark:text-p3-dark border-p3/30'
                }`}
              >
                {next_task?.status || 'QUEUED'}
              </span>
            </div>

            <div>
              <div className="font-mono text-xs text-p3 dark:text-p3-dark font-bold">{next_task?.task_id}</div>
              <h3 className="text-base font-bold text-light-text dark:text-dark-text mt-0.5">{next_task?.title}</h3>
              <p className="text-xs text-light-muted dark:text-dark-muted mt-1 leading-relaxed">{next_task?.description}</p>
            </div>

            {next_task?.assigned_to && (
              <div className="text-xs font-mono text-light-muted dark:text-dark-muted flex items-center gap-1.5 pt-1">
                <span>Assigned Agent:</span>
                <span className="text-light-text dark:text-dark-text font-semibold">{next_task.assigned_to}</span>
              </div>
            )}

            {next_task?.deliverables && next_task.deliverables.length > 0 && (
              <div className="space-y-1 pt-1">
                <div className="text-[11px] font-mono text-light-muted dark:text-dark-muted">Deliverables:</div>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {next_task.deliverables.map((d, i) => (
                    <span
                      key={i}
                      className="text-[10px] font-mono px-2 py-0.5 rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border text-light-text dark:text-dark-text"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Action Dispatch Buttons */}
          <div className="mt-5 pt-4 border-t border-light-border/60 dark:border-dark-border/60 flex items-center justify-between gap-3">
            <button
              onClick={() => setHandoffModalOpen(true)}
              className="px-3 py-2 rounded-xl bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border hover:border-p3 text-xs font-mono text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <Share2 className="w-3.5 h-3.5 text-p3 dark:text-p3-dark" />
              <span>Dispatch Handoff</span>
            </button>

            <div className="flex items-center gap-2">
              {next_task?.status === 'in_progress' ? (
                <button
                  onClick={() => handleFinishTask(next_task.task_id)}
                  className="px-4 py-2 rounded-xl bg-p4 text-white font-mono font-bold text-xs hover:brightness-110 flex items-center gap-1.5 transition-colors shadow-md"
                >
                  <Check className="w-4 h-4" />
                  <span>Mark Completed</span>
                </button>
              ) : (
                <button
                  onClick={() => next_task && handleStartTask(next_task.task_id)}
                  className="px-4 py-2 rounded-xl bg-p3 text-white font-mono font-bold text-xs hover:brightness-110 flex items-center gap-1.5 transition-colors shadow-md"
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>Start Task</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Task Queue Timeline & Recent Rulings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Tasks Timeline */}
        <div className="glass-panel rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-light-border dark:border-dark-border mb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-light-text dark:text-dark-text flex items-center gap-2 font-mono">
              <Clock className="w-4 h-4 text-p3 dark:text-p3-dark" />
              Phase 21 Task Queue
            </h3>
            <span className="text-[10px] font-mono text-light-muted dark:text-dark-muted">
              {active_tasks.length} Tracked Tasks
            </span>
          </div>

          <div className="space-y-3">
            {active_tasks.map((task) => (
              <div
                key={task.task_id}
                className="p-3.5 rounded-xl bg-light-surface/80 dark:bg-dark-surface/80 border border-light-border dark:border-dark-border flex items-start justify-between gap-3 shadow-sm"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-p3 dark:text-p3-dark">{task.task_id}</span>
                    <span
                      className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border uppercase ${
                        task.status === 'done'
                          ? 'bg-p4/10 text-p4-light dark:text-p4-dark border-p4/30'
                          : task.status === 'in_progress'
                          ? 'bg-p2/10 text-p2-light dark:text-p2-dark border-p2/30'
                          : 'bg-light-hover dark:bg-dark-card text-light-muted dark:text-dark-muted border-light-border dark:border-dark-border'
                      }`}
                    >
                      {task.status}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-light-text dark:text-dark-text">{task.title}</div>
                  <div className="text-[11px] text-light-muted dark:text-dark-muted">{task.description}</div>
                </div>

                <div className="shrink-0 self-center">
                  {task.status === 'queued' && (
                    <button
                      onClick={() => handleStartTask(task.task_id)}
                      className="px-2.5 py-1 rounded-lg bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border hover:border-p3 text-[10px] font-mono text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text transition-colors shadow-sm"
                    >
                      Start
                    </button>
                  )}
                  {task.status === 'done' && <CheckCircle2 className="w-4 h-4 text-p4" />}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Architectural Rulings */}
        <div className="glass-panel rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-light-border dark:border-dark-border mb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-light-text dark:text-dark-text flex items-center gap-2 font-mono">
              <BookOpen className="w-4 h-4 text-p4-light dark:text-p4-dark" />
              Architectural Rulings & Invariants
            </h3>
            <span className="text-[10px] font-mono text-light-muted dark:text-dark-muted">{rulings.length} Active Rulings</span>
          </div>

          <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
            {rulings.map((ruling) => (
              <div
                key={ruling.ruling_id}
                className="p-3.5 rounded-xl bg-light-surface/80 dark:bg-dark-surface/80 border border-light-border dark:border-dark-border space-y-1.5 shadow-sm"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-p4-light dark:text-p4-dark">
                      {ruling.ruling_id}
                    </span>
                    <span className="text-xs font-semibold text-light-text dark:text-dark-text">{ruling.title}</span>
                  </div>
                  <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-p4/10 text-p4-light dark:text-p4-dark border border-p4/30 uppercase font-bold">
                    {ruling.status}
                  </span>
                </div>

                <p className="text-[11px] text-light-muted dark:text-dark-muted leading-relaxed">{ruling.rationale}</p>

                <div className="flex items-center justify-between text-[10px] font-mono text-light-muted dark:text-dark-muted pt-1.5 border-t border-light-border/40 dark:border-dark-border/40">
                  <span>Decider: {ruling.decider}</span>
                  <span>Phases: {ruling.affected_phases.join(', ')}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Handoff Modal */}
      {handoffModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150">
          <div
            className="w-full max-w-md bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-2xl p-5 shadow-2xl space-y-4 font-sans"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-light-border dark:border-dark-border pb-3">
              <div className="flex items-center gap-2">
                <Share2 className="w-4 h-4 text-p3 dark:text-p3-dark" />
                <h3 className="text-sm font-bold text-light-text dark:text-dark-text">Dispatch Subagent Handoff</h3>
              </div>
              <button
                onClick={() => setHandoffModalOpen(false)}
                className="text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleHandoffSubmit} className="space-y-3 text-xs">
              <div className="space-y-1">
                <label className="font-mono text-light-muted dark:text-dark-muted">Target Subagent / Recipient:</label>
                <input
                  type="text"
                  value={targetAgent}
                  onChange={(e) => setTargetAgent(e.target.value)}
                  className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl px-3 py-2 text-light-text dark:text-dark-text font-mono focus:outline-none focus:border-p3 shadow-sm"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="font-mono text-light-muted dark:text-dark-muted">Handoff Notes & Context:</label>
                <textarea
                  rows={3}
                  value={handoffNotes}
                  onChange={(e) => setHandoffNotes(e.target.value)}
                  placeholder="Summarize accomplishments, state deltas, or next steps..."
                  className="w-full bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl p-3 text-light-text dark:text-dark-text focus:outline-none focus:border-p3 shadow-sm leading-relaxed"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setHandoffModalOpen(false)}
                  className="px-3 py-1.5 rounded-xl bg-light-hover dark:bg-dark-hover text-light-muted dark:text-dark-muted hover:text-light-text dark:hover:text-dark-text font-mono transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-p3 text-white font-mono font-bold hover:brightness-110 shadow-md transition-colors"
                >
                  Dispatch
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};



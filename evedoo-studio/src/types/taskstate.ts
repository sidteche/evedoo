// SPDX-License-Identifier: Apache-2.0

export type TaskStatus = 'done' | 'in_progress' | 'queued' | 'blocked';
export type PhaseStatus = 'completed' | 'active' | 'pending';
export type RulingStatus = 'approved' | 'rejected' | 'superseded';

export interface PhaseSummary {
  phase_id: string;
  name: string;
  description: string;
  status: PhaseStatus;
  task_count: number;
  completed_count: number;
}

export interface TaskSummary {
  task_id: string;
  phase_id: string;
  title: string;
  description: string;
  status: TaskStatus;
  assigned_to?: string;
  pr_ref?: string;
  started_at?: string;
  completed_at?: string;
  deliverables?: string[];
}

export interface RulingSummary {
  ruling_id: string;
  title: string;
  decider: string;
  status: RulingStatus;
  rationale: string;
  timestamp: string;
  affected_phases: string[];
}

export interface HandoffSummary {
  handoff_id: string;
  from_agent: string;
  to_agent: string;
  context_summary: string;
  timestamp: string;
  active_task_id: string;
}

export interface State {
  active_phase: PhaseSummary;
  next_task: TaskSummary;
  active_tasks: TaskSummary[];
  rulings: RulingSummary[];
  handoffs: HandoffSummary[];
  all_phases: PhaseSummary[];
  last_updated: string;
  store_version: string;
}


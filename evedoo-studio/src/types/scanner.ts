// SPDX-License-Identifier: Apache-2.0

export type PriorityTier = 'P1' | 'P2' | 'P3' | 'P4';

export type FindingStatus = 'New' | 'Persisting' | 'Resolved' | 'Excepted';

export type Architecture = 'x64' | 'x86' | 'ARM64' | 'AnyCPU';

export interface DetectedSoftware {
  cpe: string;
  vendor: string;
  product: string;
  version: string;
  source: string; // registry://, pe://, appx://, winget://, chocolatey://, scoop://, cargo://
  path?: string;
  architecture?: Architecture;
  install_date?: string;
}

export interface Vulnerability {
  cve_id: string;
  title: string;
  description: string;
  references: string[];
  published_date: string;
  last_modified_date: string;
  patched_in_version?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface RiskAssessment {
  cvss_v3_score: number;
  cvss_v3_vector: string;
  epss_score: number; // 0.0 - 1.0
  epss_percentile: number; // 0.0 - 1.0
  cisa_kev: boolean;
  cisa_due_date?: string;
  ransomware_campaign?: string;
  exploit_maturity: 'High' | 'Functional' | 'PoC' | 'Unproven';
  attack_complexity: 'Low' | 'High';
  privileges_required: 'None' | 'Low' | 'High';
  user_interaction: 'None' | 'Required';
}

export interface ExceptionRef {
  rule_id: string;
  scope_pattern: string; // e.g. "cpe:2.3:a:python:*"
  cve_scope?: string; // e.g. "CVE-2023-24329" or "*"
  host_scope?: string; // "all", "prod", "WIN-PROD-DC01"
  accepted_by: string;
  rationale: string;
  ticket_ref: string;
  expires_at: string; // ISO 8601
  created_at: string;
  specificity_score: number; // 0 - 100%
}

export interface Finding {
  id: string;
  cve_id: string;
  host: string;
  software: DetectedSoftware;
  vulnerability: Vulnerability;
  risk: RiskAssessment;
  priority: PriorityTier;
  status: FindingStatus;
  first_detected: string;
  last_detected: string;
  exception?: ExceptionRef;
}

export interface FleetHost {
  id: string;
  hostname: string;
  ip: string;
  os_name: string;
  os_version: string;
  os_build: string;
  architecture: Architecture;
  agent_status: 'online' | 'offline' | 'scanning' | 'error';
  last_scan_time: string;
  open_p1_count: number;
  open_p2_count: number;
  total_findings: number;
  winrm_tls: boolean;
  winrm_port: number;
  tags: string[];
}

export interface ScanSummary {
  total: number;
  p1: number;
  p2: number;
  p3: number;
  p4: number;
  new: number;
  persisting: number;
  resolved: number;
  excepted: number;
  kev_active: number;
}

export interface ScanResult {
  scan_id: string;
  target: string;
  timestamp: string;
  duration_ms: number;
  host_info: {
    hostname: string;
    os: string;
    ip: string;
  };
  summary: ScanSummary;
  findings: Finding[];
  software_inventory: DetectedSoftware[];
}


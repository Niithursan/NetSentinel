/**
 * NetSentinel - API Client & React Query Hooks
 *
 * Provides typed API calls and caching via @tanstack/react-query.
 */

const API_BASE = 'http://localhost:8000/api';

// ─── Types ─────────────────────────────────────────────────────

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type PortState = 'open' | 'closed' | 'filtered';

export interface PortInfo {
  id: number;
  port_number: number;
  protocol: string;
  state: PortState;
  service_name: string | null;
  service_version: string | null;
  banner: string | null;
}

export interface VulnerabilityInfo {
  id: number;
  title: string;
  description: string | null;
  severity: SeverityLevel;
  port_number: number | null;
  service: string | null;
  remediation: string | null;
  cve_id: string | null;
  detected_at: string;
}

export interface HostInfo {
  id: number;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  os_guess: string | null;
  os_confidence: number | null;
  ttl: number | null;
  is_up: boolean;
  response_time_ms: number | null;
  discovered_at: string;
  ports: PortInfo[];
  vulnerabilities: VulnerabilityInfo[];
}

export interface ScanSummary {
  id: number;
  target: string;
  scan_type: string;
  status: ScanStatus;
  created_at: string;
  completed_at: string | null;
  total_hosts: number;
  total_open_ports: number;
  total_vulnerabilities: number;
}

export interface ScanDetail extends ScanSummary {
  started_at: string | null;
  error_message: string | null;
  hosts: HostInfo[];
}

export interface DashboardStats {
  total_scans: number;
  total_hosts_discovered: number;
  total_open_ports: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  recent_scans: ScanSummary[];
}

export interface RemediationResponse {
  host_ip: string;
  remediation_steps: string;
  severity_summary: Record<string, number>;
  generated_at: string;
}

export interface BaselineInfo {
  id: number;
  name: string;
  description: string | null;
  framework: string | null;
  rules: Record<string, unknown>[];
  created_at: string;
}

// ─── API Functions ─────────────────────────────────────────────

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const error = await res.text();
    throw new Error(`API Error (${res.status}): ${error}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// Dashboard
export const fetchDashboardStats = () => apiFetch<DashboardStats>('/dashboard/stats');

// Scans
export const fetchScans = () => apiFetch<ScanSummary[]>('/scans');
export const fetchScan = (id: number) => apiFetch<ScanDetail>(`/scans/${id}`);
export const createScan = (data: { target: string; scan_type: string; ports?: string; timeout?: number }) =>
  apiFetch<ScanSummary>('/scans', { method: 'POST', body: JSON.stringify(data) });
export const deleteScan = (id: number) =>
  apiFetch<void>(`/scans/${id}`, { method: 'DELETE' });

// Remediation
export const fetchRemediation = (host_ip: string, findings: Record<string, unknown>[]) =>
  apiFetch<RemediationResponse>('/remediation', {
    method: 'POST',
    body: JSON.stringify({ host_ip, findings }),
  });

// Baselines
export const fetchBaselines = () => apiFetch<BaselineInfo[]>('/baselines');
export const createBaseline = (data: {
  name: string;
  description?: string;
  framework?: string;
  rules: Record<string, unknown>[];
}) => apiFetch<BaselineInfo>('/baselines', { method: 'POST', body: JSON.stringify(data) });

// Compliance
export const checkCompliance = (scan_id: number, baseline_id: number) =>
  apiFetch<Record<string, unknown>>(`/compliance/check?scan_id=${scan_id}&baseline_id=${baseline_id}`, {
    method: 'POST',
  });

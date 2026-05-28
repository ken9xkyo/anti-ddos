export type Role = 'admin' | 'operator' | 'viewer';

export interface User {
  id: string;
  username: string;
  role: Role;
}

export interface Session {
  token: string;
  user: User;
  expires_at: string;
}

export interface PrometheusStatus {
  configured: boolean;
  healthy: boolean;
  error?: string;
}

export interface SecurityEventTop {
  key: string;
  count: number;
  packets?: number;
  bytes?: number;
}

export interface SecurityEventSummary {
  window_seconds: number;
  total: number;
  top_sources: SecurityEventTop[];
  top_ports: SecurityEventTop[];
  by_decision: SecurityEventTop[];
}

export interface DashboardOverview {
  generated_at: string;
  prometheus: PrometheusStatus;
  traffic: { pps: number; bps: number; cps: number };
  decision_rates: Record<string, number>;
  security_events: SecurityEventSummary;
  agents: { total: number; stale: number };
  snapshot_version: number;
  latest_apply_status: ApplyStatus[];
}

export interface ApplyStatus {
  agent_id: string;
  hostname: string;
  policy_version: number;
  status: string;
  error_stage?: string;
  error_reason?: string;
  reported_at: string;
}

export interface Service {
  id: string;
  ebpf_id: number;
  name: string;
  backend_cidr: string;
  protocol: string;
  allowed_ports: number[];
  output_interface: string;
  owner: string;
  criticality: string;
  protection_mode: string;
  enabled: boolean;
  sync_status: string;
  neighbor_resolution_status: string;
  counters?: Record<string, number>;
  apply_status?: string;
}

export interface Rule {
  id: string;
  ebpf_id: number;
  service_id?: string;
  name: string;
  action: string;
  mode: string;
  priority: number;
  threshold_pps?: number;
  threshold_bps?: number;
  threshold_cps?: number;
  ttl_seconds?: number;
  expires_at?: string;
  confidence?: number;
  enabled: boolean;
  owner: string;
  ttl_remaining_seconds?: number;
  counters?: Record<string, number>;
}

export interface Agent {
  id: string;
  hostname: string;
  status: string;
  xdp_mode: string;
  devmap_support: boolean;
  active_policy_version: number;
  last_seen_at?: string;
  stale: boolean;
  map_utilization?: Record<string, unknown>;
  latest_apply?: ApplyStatus;
}

export interface SecurityEvent {
  id: string;
  event_time: string;
  agent_id?: string;
  policy_version?: number;
  src_ip: string;
  src_prefix24: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol?: number;
  action?: number;
  reason?: number;
  service_id?: number;
  rule_id?: number;
  pkt_len?: number;
  sample_rate?: number;
}

export interface DashboardData {
  overview: DashboardOverview;
  agents: Agent[];
  services: Service[];
  rules: Rule[];
  events: SecurityEvent[];
}

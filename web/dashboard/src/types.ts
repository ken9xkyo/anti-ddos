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
  dimension?: string;
  ttl_seconds?: number;
  expires_at?: string;
  confidence?: number;
  evidence?: Record<string, unknown>;
  enabled: boolean;
  owner: string;
  ttl_remaining_seconds?: number;
  counters?: Record<string, number>;
}

export interface BaselineProfile {
  id: string;
  service_id: string;
  service_ebpf_id?: number;
  service_name?: string;
  interface: string;
  protocol: string;
  port?: number;
  window: string;
  expected_pps: number;
  expected_bps: number;
  expected_cps: number;
  history_hours: number;
  confidence: number;
  approved: boolean;
  status: string;
}

export interface AnomalyEvaluation {
  id: string;
  service_id?: string;
  service_ebpf_id?: number;
  service_name?: string;
  baseline_id?: string;
  evaluated_at: string;
  window: string;
  pps: number;
  bps: number;
  cps: number;
  drop_ratio: number;
  score: number;
  confidence: number;
  signals?: string[];
  recommendation: string;
  recommended_action: string;
  proposed_ttl_seconds?: number;
  proposed_rule_id?: string;
  auto_enforced: boolean;
  status: string;
  reason?: string;
  source?: string;
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

export interface FeedSource {
  id: string;
  name: string;
  type: string;
  url?: string;
  credential_ref?: string;
  required_for_production: boolean;
  enabled: boolean;
  interval_seconds: number;
  license_note?: string;
  quota_metadata?: Record<string, unknown>;
  status: string;
  last_success_at?: string;
  last_error_at?: string;
  last_error?: string;
  next_run_at?: string;
  active_entries: number;
  conflict_count: number;
  parse_error_count: number;
}

export interface FeedRun {
  id: string;
  source_id: string;
  source_name?: string;
  started_at: string;
  finished_at?: string;
  status: string;
  items_fetched: number;
  items_valid: number;
  parse_errors: number;
  error?: string;
  snapshot_version?: number;
}

export interface FeedConflict {
  id: string;
  source_id: string;
  source_name?: string;
  reputation_id: string;
  whitelist_id: string;
  reputation_cidr: string;
  whitelist_cidr: string;
  status: string;
  detected_at: string;
}

export interface DashboardData {
  overview: DashboardOverview;
  agents: Agent[];
  services: Service[];
  rules: Rule[];
  events: SecurityEvent[];
  baselines: BaselineProfile[];
  anomalies: AnomalyEvaluation[];
  feedSources: FeedSource[];
  feedRuns: FeedRun[];
  feedConflicts: FeedConflict[];
}

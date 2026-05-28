import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DashboardShell, type Tab } from './App';
import type { DashboardData, User } from './types';

const baseUser: User = { id: 'u1', username: 'viewer', role: 'viewer' };
const data: DashboardData = {
  overview: {
    generated_at: new Date().toISOString(),
    prometheus: { configured: false, healthy: false, error: 'prometheus is not configured' },
    traffic: { pps: 1200, bps: 900000, cps: 14 },
    decision_rates: { drop: 20 },
    security_events: {
      window_seconds: 300,
      total: 2,
      top_sources: [{ key: '198.51.100.0/24', count: 2 }],
      top_ports: [{ key: '443', count: 2 }],
      by_decision: [{ key: '1:4', count: 2 }]
    },
    agents: { total: 2, stale: 1 },
    snapshot_version: 7,
    latest_apply_status: []
  },
  agents: [{
    id: 'a1',
    hostname: 'node-a',
    status: 'online',
    xdp_mode: 'native',
    devmap_support: true,
    active_policy_version: 7,
    stale: false,
    latest_apply: { agent_id: 'a1', hostname: 'node-a', policy_version: 7, status: 'applied', reported_at: new Date().toISOString() }
  }],
  services: [{
    id: 's1',
    ebpf_id: 1,
    name: 'api-https',
    backend_cidr: '203.0.113.10/32',
    protocol: 'tcp',
    allowed_ports: [443],
    output_interface: 'backend0',
    owner: 'sre',
    criticality: 'high',
    protection_mode: 'enforce',
    enabled: true,
    sync_status: 'pending',
    neighbor_resolution_status: 'resolved',
    apply_status: 'applied'
  }],
  rules: [{
    id: 'r1',
    ebpf_id: 10,
    name: 'drop-suspect',
    action: 'drop',
    mode: 'enforce',
    priority: 10,
    dimension: 'source_service',
    threshold_pps: 1000,
    threshold_bps: 1000000,
    threshold_cps: 100,
    confidence: 0.95,
    ttl_seconds: 900,
    ttl_remaining_seconds: 540,
    enabled: true,
    owner: 'soc'
  }],
  events: [{
    id: 'e1',
    event_time: new Date().toISOString(),
    src_ip: '198.51.100.10',
    src_prefix24: '198.51.100.0/24',
    dst_ip: '203.0.113.10',
    dst_port: 443,
    protocol: 6,
    action: 1,
    reason: 4,
    sample_rate: 10
  }],
  baselines: [{
    id: 'b1',
    service_id: 's1',
    service_ebpf_id: 1,
    service_name: 'api-https',
    interface: 'wan0',
    protocol: 'tcp',
    port: 443,
    window: '5m',
    expected_pps: 1000,
    expected_bps: 1000000,
    expected_cps: 100,
    history_hours: 24,
    confidence: 0.95,
    approved: true,
    status: 'approved'
  }],
  anomalies: [{
    id: 'a1',
    service_id: 's1',
    service_ebpf_id: 1,
    service_name: 'api-https',
    baseline_id: 'b1',
    evaluated_at: new Date().toISOString(),
    window: '5m',
    pps: 300000,
    bps: 3000000000,
    cps: 30000,
    drop_ratio: 0.1,
    score: 95,
    confidence: 0.95,
    signals: ['pps_spike', 'bps_spike', 'syn_spike'],
    recommendation: 'auto_enforce',
    recommended_action: 'rate_limit',
    proposed_ttl_seconds: 900,
    proposed_rule_id: 'r1',
    auto_enforced: true,
    status: 'auto_enforced',
    source: '198.51.100.10'
  }],
  feedSources: [{
    id: 'f1',
    name: 'spamhaus-drop',
    type: 'spamhaus_drop',
    required_for_production: true,
    enabled: true,
    interval_seconds: 3600,
    status: 'healthy',
    active_entries: 128,
    conflict_count: 1,
    parse_error_count: 0,
    license_note: 'fair use',
    next_run_at: new Date().toISOString()
  }],
  feedRuns: [{
    id: 'fr1',
    source_id: 'f1',
    source_name: 'spamhaus-drop',
    started_at: new Date().toISOString(),
    status: 'success',
    items_fetched: 130,
    items_valid: 128,
    parse_errors: 0,
    snapshot_version: 8
  }],
  feedConflicts: [{
    id: 'fc1',
    source_id: 'f1',
    source_name: 'spamhaus-drop',
    reputation_id: 'rep1',
    whitelist_id: 'w1',
    reputation_cidr: '198.51.100.0/24',
    whitelist_cidr: '198.51.100.10/32',
    status: 'active',
    detected_at: new Date().toISOString()
  }]
};

function renderShell(user: User, activeTab: Tab = 'overview') {
  return render(
    <DashboardShell
      user={user}
      data={data}
      activeTab={activeTab}
      setActiveTab={vi.fn()}
      loading={false}
      error=""
      lastRefresh={new Date().toISOString()}
      onLogout={vi.fn()}
    />
  );
}

describe('DashboardShell', () => {
  it('renders overview freshness and Prometheus unconfigured state', () => {
    renderShell(baseUser);
    expect(screen.getByText('Packets/s')).toBeInTheDocument();
    expect(screen.getByText('unconfigured')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.0/24')).toBeInTheDocument();
  });

  it('keeps viewer read-only', () => {
    renderShell(baseUser, 'services');
    expect(screen.queryByRole('button', { name: /add service/i })).not.toBeInTheDocument();
    expect(screen.getByText('api-https')).toBeInTheDocument();
  });

  it('shows operator mutation entrypoints', () => {
    renderShell({ ...baseUser, role: 'operator', username: 'operator' }, 'rules');
    expect(screen.getByRole('button', { name: /add rule/i })).toBeInTheDocument();
  });

  it('renders anomaly and baseline visibility', () => {
    renderShell(baseUser, 'anomalies');
    expect(screen.getByText('auto_enforced')).toBeInTheDocument();
    expect(screen.getByText('pps_spike')).toBeInTheDocument();
    expect(screen.getByText('approved')).toBeInTheDocument();
  });

  it('renders event investigation table', () => {
    renderShell(baseUser, 'events');
    const table = screen.getByRole('table');
    expect(within(table).getByText('198.51.100.10')).toBeInTheDocument();
    expect(within(table).getByText('203.0.113.10:443')).toBeInTheDocument();
  });

  it('renders feed status and conflicts', () => {
    renderShell(baseUser, 'reputation');
    expect(screen.getAllByText('spamhaus-drop').length).toBeGreaterThan(0);
    expect(screen.getByText('198.51.100.0/24')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.10/32')).toBeInTheDocument();
  });
});

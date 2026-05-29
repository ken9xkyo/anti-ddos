import type { DashboardData, User } from '../types';

export const viewerUser: User = { id: 'u1', username: 'viewer', role: 'viewer' };
export const operatorUser: User = { id: 'u2', username: 'operator', role: 'operator' };

export function dashboardFixture(): DashboardData {
  const now = new Date('2026-05-28T11:00:00Z').toISOString();
  return {
    overview: {
      generated_at: now,
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
      latest_apply: { agent_id: 'a1', hostname: 'node-a', policy_version: 7, status: 'applied', reported_at: now }
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
      resolved_ifindex: 7,
      resolved_next_hop_mac: '02:00:00:00:00:02',
      resolved_src_mac: '02:00:00:00:00:01',
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
      event_time: now,
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
      id: 'an1',
      service_id: 's1',
      service_ebpf_id: 1,
      service_name: 'api-https',
      baseline_id: 'b1',
      evaluated_at: now,
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
      next_run_at: now
    }],
    feedRuns: [{
      id: 'fr1',
      source_id: 'f1',
      source_name: 'spamhaus-drop',
      started_at: now,
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
      detected_at: now
    }],
    telegramConfig: {
      bot_token_ref: 'env://TELEGRAM_TOKEN',
      bot_token_present: true,
      chat_id: '1234',
      enabled: true,
      created_at: now,
      updated_at: now
    },
    alerts: [{
      id: 'al1',
      severity: 'critical',
      type: 'isp_escalation_needed',
      dedupe_key: 'isp:api-https:link_saturation',
      affected_service: 'api-https',
      vector: 'link_saturation',
      evidence: { manual_only: true, peak_bps: 3000000000, peak_pps: 300000 },
      recommended_action: 'manual ISP escalation; no automatic BGP/RTBH/FlowSpec',
      status: 'sent',
      created_at: now,
      deliveries: [{ id: 'd1', alert_id: 'al1', channel: 'telegram', status: 'sent', attempt: 1, created_at: now }]
    }]
  };
}

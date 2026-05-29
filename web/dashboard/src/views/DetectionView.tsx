import { Database, ListChecks, TrendingUp } from 'lucide-react';
import { EmptyTableRow, SignalList, StatusPill, TablePanel } from '../components';
import { durationValue, formatDateTime, numberValue, percentValue } from '../format';
import type { AnomalyEvaluation, BaselineProfile, Rule } from '../types';

export function DetectionView({ anomalies, baselines, rules }: { anomalies: AnomalyEvaluation[]; baselines: BaselineProfile[]; rules: Rule[] }) {
  return (
    <section className="content-stack">
      <TablePanel icon={<TrendingUp size={18} />} title="Anomalies / Auto-Enforce" eyebrow={`${anomalies.length} evaluations`}>
        <thead><tr><th>Service</th><th>Score</th><th>Confidence</th><th>Signals</th><th>Action</th><th>TTL</th><th>Source</th><th>Status</th><th>Evaluated</th></tr></thead>
        <tbody>{anomalies.length === 0 ? (
          <EmptyTableRow colSpan={9} text="No anomaly evaluations available" />
        ) : anomalies.map((item) => (
          <tr key={item.id}>
            <td>{item.service_name || item.service_ebpf_id || 'service'}</td>
            <td>{numberValue(item.score)}</td>
            <td>{percentValue(item.confidence)}</td>
            <td><SignalList signals={item.signals ?? []} /></td>
            <td>{item.recommended_action}</td>
            <td>{durationValue(item.proposed_ttl_seconds)}</td>
            <td>{item.source || 'n/a'}</td>
            <td><StatusPill state={item.auto_enforced || item.status === 'blocked_whitelist' ? 'warn' : item.status === 'observe_only' ? 'off' : 'ok'} text={item.status} /></td>
            <td>{formatDateTime(item.evaluated_at)}</td>
          </tr>
        ))}</tbody>
      </TablePanel>

      <TablePanel icon={<Database size={18} />} title="Baselines" eyebrow={`${baselines.length} profiles`}>
        <thead><tr><th>Service</th><th>Interface</th><th>Protocol</th><th>Window</th><th>PPS</th><th>BPS</th><th>CPS</th><th>History</th><th>Confidence</th><th>Status</th></tr></thead>
        <tbody>{baselines.length === 0 ? (
          <EmptyTableRow colSpan={10} text="No baseline profiles configured" />
        ) : baselines.map((item) => (
          <tr key={item.id}>
            <td>{item.service_name || item.service_ebpf_id || 'service'}</td>
            <td>{item.interface}</td>
            <td>{item.protocol}{item.port ? `/${item.port}` : ''}</td>
            <td>{item.window}</td>
            <td>{numberValue(item.expected_pps)}</td>
            <td>{numberValue(item.expected_bps)}</td>
            <td>{numberValue(item.expected_cps)}</td>
            <td>{item.history_hours}h</td>
            <td>{percentValue(item.confidence)}</td>
            <td><StatusPill state={item.approved && item.history_hours >= 24 ? 'ok' : 'warn'} text={item.approved && item.history_hours >= 24 ? 'approved' : 'low confidence'} /></td>
          </tr>
        ))}</tbody>
      </TablePanel>

      <TablePanel icon={<ListChecks size={18} />} title="Active Rules" eyebrow="read-only in v2">
        <thead><tr><th>Name</th><th>Action</th><th>Mode</th><th>Dimension</th><th>Thresholds</th><th>TTL</th><th>Confidence</th><th>Counters</th><th>State</th></tr></thead>
        <tbody>{rules.length === 0 ? (
          <EmptyTableRow colSpan={9} text="No mitigation rules configured" />
        ) : rules.map((rule) => (
          <tr key={rule.id}>
            <td>{rule.name}</td>
            <td>{rule.action}</td>
            <td>{rule.mode}</td>
            <td>{rule.dimension ?? 'source_service'}</td>
            <td>{rule.threshold_pps ?? 0} pps · {rule.threshold_bps ?? 0} bps · {rule.threshold_cps ?? 0} cps</td>
            <td>{durationValue(rule.ttl_remaining_seconds ?? rule.ttl_seconds)}</td>
            <td>{percentValue(rule.confidence ?? 0)}</td>
            <td>{rule.counters ? Object.keys(rule.counters).length : 0}</td>
            <td><StatusPill state={rule.enabled ? 'ok' : 'off'} text={rule.enabled ? 'enabled' : 'disabled'} /></td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

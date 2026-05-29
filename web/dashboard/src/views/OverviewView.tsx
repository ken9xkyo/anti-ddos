import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  Gauge,
  Router,
  Server,
  ShieldAlert,
  TrendingUp
} from 'lucide-react';
import { BarChart } from '@mui/x-charts/BarChart';
import { MetricPanel, PanelHeader, StatusPill, TablePanel, TopList, EmptyTableRow } from '../components';
import { compactValue, formatDateTime, numberValue, percentValue } from '../format';
import type { DashboardData } from '../types';

export function OverviewView({ data }: { data: DashboardData }) {
  const latestAnomaly = data.anomalies[0];
  const latestAlert = data.alerts[0];
  const failedApplies = data.overview.latest_apply_status.filter((status) => status.status === 'failed');
  const agentHealthy = data.overview.agents.total - data.overview.agents.stale;
  const trafficSeries = [data.overview.traffic.pps, data.overview.traffic.bps / 1000, data.overview.traffic.cps];
  const decisionKeys = Object.keys(data.overview.decision_rates).filter((key) => data.overview.decision_rates[key] !== undefined);
  return (
    <section className="content-stack">
      <div className="metric-grid">
        <MetricPanel icon={<Gauge size={18} />} label="Packets/s" value={compactValue(data.overview.traffic.pps)} detail="terminal actions" />
        <MetricPanel icon={<Activity size={18} />} label="Bits/s" value={compactValue(data.overview.traffic.bps)} detail="ingress estimate" />
        <MetricPanel icon={<Router size={18} />} label="Connections/s" value={numberValue(data.overview.traffic.cps)} detail="TCP SYN approximation" />
        <MetricPanel icon={<Server size={18} />} label="Agents healthy" value={`${agentHealthy}/${data.overview.agents.total}`} tone={data.overview.agents.stale ? 'warn' : 'ok'} detail="fresh heartbeat" />
        <MetricPanel icon={<ShieldAlert size={18} />} label="Drop rate" value={compactValue(data.overview.decision_rates.drop)} detail="packets/s" tone={(data.overview.decision_rates.drop || 0) > 0 ? 'warn' : undefined} />
        <MetricPanel icon={<CheckCircle2 size={18} />} label="Redirect rate" value={compactValue(data.overview.decision_rates.redirect)} detail="packets/s" tone="ok" />
        <MetricPanel icon={<AlertTriangle size={18} />} label="Not allowed" value={compactValue(data.overview.decision_rates.not_allowed_service)} detail="service misses/s" tone={(data.overview.decision_rates.not_allowed_service || 0) > 0 ? 'warn' : undefined} />
        <MetricPanel icon={<TrendingUp size={18} />} label="Anomaly score" value={numberValue(latestAnomaly?.score)} detail={latestAnomaly?.status ?? 'no active signal'} tone={latestAnomaly?.auto_enforced ? 'warn' : undefined} />
      </div>

      <div className="overview-grid">
        <section className="wide-panel chart-panel">
          <PanelHeader icon={<Activity size={18} />} title="Traffic Shape" eyebrow="pps, kbps, cps" />
          <BarChart
            xAxis={[{ data: ['PPS', 'Kbps', 'CPS'], scaleType: 'band' }]}
            series={[{ data: trafficSeries, color: '#5aa7ff' }]}
            height={220}
            skipAnimation
          />
        </section>
        <section className="wide-panel chart-panel">
          <PanelHeader icon={<ShieldAlert size={18} />} title="Decision Rates" eyebrow="packets/s by action" />
          <BarChart
            xAxis={[{ data: decisionKeys.length ? decisionKeys : ['none'], scaleType: 'band' }]}
            series={[{ data: decisionKeys.length ? decisionKeys.map((key) => data.overview.decision_rates[key] || 0) : [0], color: '#66d19e' }]}
            height={220}
            skipAnimation
          />
        </section>
      </div>

      <div className="overview-grid">
        <section className="wide-panel">
          <PanelHeader icon={<Database size={18} />} title="Control Plane Status" eyebrow={`snapshot v${data.overview.snapshot_version}`} />
          <div className="status-row">
            <StatusPill state={data.overview.prometheus.healthy ? 'ok' : data.overview.prometheus.configured ? 'warn' : 'off'} text={data.overview.prometheus.configured ? data.overview.prometheus.healthy ? 'prometheus healthy' : 'prometheus error' : 'prometheus unconfigured'} />
            <span>{data.overview.prometheus.error || 'metrics path ready'}</span>
          </div>
          <div className="status-row">
            <StatusPill state={failedApplies.length > 0 ? 'danger' : 'ok'} text={failedApplies.length > 0 ? `${failedApplies.length} apply failed` : 'fleet apply clean'} />
            <span>generated {formatDateTime(data.overview.generated_at)}</span>
          </div>
        </section>

        <section className="wide-panel">
          <PanelHeader icon={<AlertTriangle size={18} />} title="Current Operational Signal" />
          {latestAlert ? (
            <div className="incident-summary">
              <StatusPill state={latestAlert.severity === 'critical' ? 'danger' : latestAlert.severity === 'warning' ? 'warn' : 'info'} text={latestAlert.severity} />
              <div>
                <strong>{latestAlert.type}</strong>
                <span>{latestAlert.affected_service || latestAlert.service_id || 'control-plane'} · {latestAlert.vector || 'n/a'}</span>
              </div>
            </div>
          ) : (
            <p className="muted">No active alert samples.</p>
          )}
          {latestAnomaly ? (
            <div className="incident-summary">
              <StatusPill state={latestAnomaly.auto_enforced ? 'warn' : 'info'} text={latestAnomaly.status} />
              <div>
                <strong>{latestAnomaly.service_name || latestAnomaly.service_ebpf_id || 'service'}</strong>
                <span>{numberValue(latestAnomaly.score)} score · {percentValue(latestAnomaly.confidence)} confidence · {latestAnomaly.recommended_action}</span>
              </div>
            </div>
          ) : null}
        </section>
      </div>

      <div className="overview-grid">
        <TopList title="Top source /24" items={data.overview.security_events.top_sources} />
        <TopList title="Top ports" items={data.overview.security_events.top_ports} />
        <TopList title="Decision samples" items={data.overview.security_events.by_decision} />
      </div>

      <TablePanel icon={<CheckCircle2 size={18} />} title="Latest Apply Status" eyebrow="per agent">
        <thead><tr><th>Agent</th><th>Policy</th><th>Status</th><th>Stage</th><th>Reported</th></tr></thead>
        <tbody>{data.overview.latest_apply_status.length === 0 ? (
          <EmptyTableRow colSpan={5} text="No apply status has been reported yet" />
        ) : data.overview.latest_apply_status.map((status) => (
          <tr key={`${status.agent_id}-${status.policy_version}`}>
            <td>{status.hostname || status.agent_id}</td>
            <td>v{status.policy_version}</td>
            <td><StatusPill state={status.status === 'applied' ? 'ok' : status.status === 'failed' ? 'danger' : 'off'} text={status.status} /></td>
            <td>{status.error_stage ? `${status.error_stage}: ${status.error_reason || 'failed'}` : 'n/a'}</td>
            <td>{formatDateTime(status.reported_at)}</td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

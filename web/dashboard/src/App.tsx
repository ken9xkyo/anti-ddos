import { FormEvent, ReactNode, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock,
  Database,
  Gauge,
  ListChecks,
  LockKeyhole,
  LogOut,
  RefreshCw,
  Router,
  Search,
  Server,
  Shield,
  TrendingUp
} from 'lucide-react';
import { ApiClient } from './api';
import type { Agent, AnomalyEvaluation, BaselineProfile, DashboardData, Rule, SecurityEvent, Service, User } from './types';
import './styles.css';

const api = new ApiClient();
const tabs = ['overview', 'anomalies', 'rules', 'reputation', 'services', 'agents', 'events'] as const;
export type Tab = (typeof tabs)[number];

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [data, setData] = useState<DashboardData | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<string>('');

  useEffect(() => {
    api.me().then(setUser).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    const load = async () => {
      try {
        setLoading(true);
        const next = await api.dashboard();
        if (!cancelled) {
          setData(next);
          setLastRefresh(new Date().toISOString());
          setError('');
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'load failed');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    const timer = window.setInterval(load, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [user]);

  if (!user) {
    return <LoginView onLogin={setUser} error={error} setError={setError} />;
  }

  return (
    <DashboardShell
      user={user}
      data={data}
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      loading={loading}
      error={error}
      lastRefresh={lastRefresh}
      onLogout={() => {
        api.clearToken();
        setUser(null);
        setData(null);
      }}
    />
  );
}

function LoginView({ onLogin, error, setError }: { onLogin: (user: User) => void; error: string; setError: (value: string) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const session = await api.login(username, password);
      setError('');
      onLogin(session.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'login failed');
    }
  };
  return (
    <main className="login-screen">
      <form className="login-panel" onSubmit={submit}>
        <div className="brand-row">
          <Shield size={24} />
          <div>
            <h1>Anti-DDoS Operations</h1>
            <p>Control Plane Dashboard</p>
          </div>
        </div>
        <label>
          Username
          <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" />
        </label>
        {error ? <div className="error-line">{error}</div> : null}
        <button type="submit" className="primary-action">
          <LockKeyhole size={16} />
          Sign in
        </button>
      </form>
    </main>
  );
}

export function DashboardShell({
  user,
  data,
  activeTab,
  setActiveTab,
  loading,
  error,
  lastRefresh,
  onLogout
}: {
  user: User;
  data: DashboardData | null;
  activeTab: Tab;
  setActiveTab: (tab: Tab) => void;
  loading: boolean;
  error: string;
  lastRefresh: string;
  onLogout: () => void;
}) {
  const canMutate = user.role === 'admin' || user.role === 'operator';
  const stale = useMemo(() => {
    if (!lastRefresh) return true;
    return Date.now() - new Date(lastRefresh).getTime() > 6000;
  }, [lastRefresh]);

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-row">
          <Shield size={24} />
          <div>
            <h1>Anti-DDoS Operations</h1>
            <p>{user.username} · {user.role}</p>
          </div>
        </div>
        <div className="topbar-actions">
          <span className={`freshness ${stale ? 'is-stale' : 'is-fresh'}`}>
            <Clock size={14} />
            {lastRefresh ? formatTime(lastRefresh) : 'pending'}
          </span>
          <button type="button" className="icon-action" aria-label="refresh">
            <RefreshCw size={16} className={loading ? 'spin' : ''} />
          </button>
          <button type="button" className="icon-action" aria-label="logout" onClick={onLogout}>
            <LogOut size={16} />
          </button>
        </div>
      </header>

      <nav className="tabs" aria-label="Dashboard views">
        {tabs.map((tab) => (
          <button key={tab} className={tab === activeTab ? 'active' : ''} onClick={() => setActiveTab(tab)} type="button">
            {tabLabel(tab)}
          </button>
        ))}
      </nav>

      {error ? <div className="banner error"><AlertTriangle size={16} />{error}</div> : null}
      {!data ? <div className="empty-state">Loading dashboard data</div> : null}
      {data && activeTab === 'overview' ? <OverviewView data={data} canMutate={canMutate} /> : null}
      {data && activeTab === 'anomalies' ? <AnomaliesView anomalies={data.anomalies} baselines={data.baselines} /> : null}
      {data && activeTab === 'rules' ? <RulesView rules={data.rules} canMutate={canMutate} /> : null}
      {data && activeTab === 'reputation' ? <ReputationView events={data.events} canMutate={canMutate} /> : null}
      {data && activeTab === 'services' ? <ServicesView services={data.services} canMutate={canMutate} /> : null}
      {data && activeTab === 'agents' ? <AgentsView agents={data.agents} /> : null}
      {data && activeTab === 'events' ? <EventsView events={data.events} /> : null}
    </main>
  );
}

function OverviewView({ data, canMutate }: { data: DashboardData; canMutate: boolean }) {
  return (
    <section className="view-grid">
      <MetricPanel icon={<Gauge size={18} />} label="Packets/s" value={numberValue(data.overview.traffic.pps)} />
      <MetricPanel icon={<Activity size={18} />} label="Bits/s" value={numberValue(data.overview.traffic.bps)} />
      <MetricPanel icon={<Router size={18} />} label="Connections/s" value={numberValue(data.overview.traffic.cps)} />
      <MetricPanel icon={<Server size={18} />} label="Agents" value={`${data.overview.agents.total - data.overview.agents.stale}/${data.overview.agents.total}`} tone={data.overview.agents.stale ? 'warn' : 'ok'} />
      <MetricPanel icon={<TrendingUp size={18} />} label="Anomaly score" value={numberValue(data.anomalies[0]?.score ?? 0)} tone={data.anomalies[0]?.auto_enforced ? 'warn' : undefined} />
      <div className="wide-panel">
        <PanelHeader icon={<Database size={18} />} title="Prometheus" action={canMutate ? 'Open Grafana' : undefined} />
        <div className="status-row">
          <StatusPill state={data.overview.prometheus.healthy ? 'ok' : 'warn'} text={data.overview.prometheus.configured ? data.overview.prometheus.healthy ? 'healthy' : 'error' : 'unconfigured'} />
          <span>{data.overview.prometheus.error ?? 'ready'}</span>
        </div>
      </div>
      <TopList title="Top source /24" items={data.overview.security_events.top_sources} />
      <TopList title="Top ports" items={data.overview.security_events.top_ports} />
      <TopList title="Recent signals" items={(data.anomalies[0]?.signals ?? []).map((signal) => ({ key: signal, count: Math.round(data.anomalies[0]?.score ?? 0) }))} />
    </section>
  );
}

function AnomaliesView({ anomalies, baselines }: { anomalies: AnomalyEvaluation[]; baselines: BaselineProfile[] }) {
  return (
    <section className="stacked-view">
      <TablePanel icon={<TrendingUp size={18} />} title="Anomalies / Auto-Enforce">
        <thead><tr><th>Service</th><th>Score</th><th>Confidence</th><th>Signals</th><th>Action</th><th>TTL</th><th>Source</th><th>Status</th></tr></thead>
        <tbody>{anomalies.map((item) => (
          <tr key={item.id}>
            <td>{item.service_name || item.service_ebpf_id || 'service'}</td>
            <td>{numberValue(item.score)}</td>
            <td>{percentValue(item.confidence)}</td>
            <td><SignalList signals={item.signals ?? []} /></td>
            <td>{item.recommended_action}</td>
            <td>{item.proposed_ttl_seconds ?? 0}s</td>
            <td>{item.source || 'n/a'}</td>
            <td><StatusPill state={item.auto_enforced || item.status === 'blocked_whitelist' ? 'warn' : item.status === 'observe_only' ? 'off' : 'ok'} text={item.status} /></td>
          </tr>
        ))}</tbody>
      </TablePanel>
      <TablePanel icon={<Database size={18} />} title="Baselines">
        <thead><tr><th>Service</th><th>Interface</th><th>Protocol</th><th>Window</th><th>PPS</th><th>BPS</th><th>CPS</th><th>Confidence</th><th>Status</th></tr></thead>
        <tbody>{baselines.map((item) => (
          <tr key={item.id}>
            <td>{item.service_name || item.service_ebpf_id || 'service'}</td>
            <td>{item.interface}</td>
            <td>{item.protocol}{item.port ? `/${item.port}` : ''}</td>
            <td>{item.window}</td>
            <td>{numberValue(item.expected_pps)}</td>
            <td>{numberValue(item.expected_bps)}</td>
            <td>{numberValue(item.expected_cps)}</td>
            <td>{percentValue(item.confidence)}</td>
            <td><StatusPill state={item.approved && item.history_hours >= 24 ? 'ok' : 'warn'} text={item.approved && item.history_hours >= 24 ? 'approved' : 'low confidence'} /></td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

function RulesView({ rules, canMutate }: { rules: Rule[]; canMutate: boolean }) {
  return (
    <TablePanel icon={<ListChecks size={18} />} title="Rules" action={canMutate ? 'Add rule' : undefined}>
      <thead><tr><th>Name</th><th>Action</th><th>Mode</th><th>Dimension</th><th>Thresholds</th><th>TTL</th><th>Confidence</th><th>State</th></tr></thead>
      <tbody>{rules.map((rule) => (
        <tr key={rule.id}>
          <td>{rule.name}</td>
          <td>{rule.action}</td>
          <td>{rule.mode}</td>
          <td>{rule.dimension ?? 'source_service'}</td>
          <td>{rule.threshold_pps ?? 0} pps · {rule.threshold_bps ?? 0} bps · {rule.threshold_cps ?? 0} cps</td>
          <td>{rule.ttl_remaining_seconds ?? rule.ttl_seconds ?? 0}s</td>
          <td>{percentValue(rule.confidence ?? 0)}</td>
          <td><StatusPill state={rule.enabled ? 'ok' : 'off'} text={rule.enabled ? 'enabled' : 'disabled'} /></td>
        </tr>
      ))}</tbody>
    </TablePanel>
  );
}

function ReputationView({ events, canMutate }: { events: SecurityEvent[]; canMutate: boolean }) {
  const sources = [...new Set(events.map((event) => event.src_prefix24))].slice(0, 12);
  return (
    <section className="single-column">
      <PanelHeader icon={<Ban size={18} />} title="Reputation" action={canMutate ? 'Add whitelist' : undefined} />
      <div className="source-grid">
        {sources.map((source) => <span key={source} className="cidr-chip">{source}</span>)}
      </div>
    </section>
  );
}

function ServicesView({ services, canMutate }: { services: Service[]; canMutate: boolean }) {
  return (
    <TablePanel icon={<Router size={18} />} title="Services / Forwarding" action={canMutate ? 'Add service' : undefined}>
      <thead><tr><th>Name</th><th>Backend</th><th>Protocol</th><th>Ports</th><th>Output</th><th>Neighbor</th><th>Apply</th></tr></thead>
      <tbody>{services.map((service) => (
        <tr key={service.id}>
          <td>{service.name}</td>
          <td>{service.backend_cidr}</td>
          <td>{service.protocol}</td>
          <td>{service.allowed_ports.join(', ') || '0'}</td>
          <td>{service.output_interface}</td>
          <td><StatusPill state={service.neighbor_resolution_status === 'resolved' ? 'ok' : 'warn'} text={service.neighbor_resolution_status} /></td>
          <td>{service.apply_status ?? service.sync_status}</td>
        </tr>
      ))}</tbody>
    </TablePanel>
  );
}

function AgentsView({ agents }: { agents: Agent[] }) {
  return (
    <TablePanel icon={<Server size={18} />} title="Agents / Maps">
      <thead><tr><th>Host</th><th>Status</th><th>XDP</th><th>Policy</th><th>DEVMAP</th><th>Apply</th></tr></thead>
      <tbody>{agents.map((agent) => (
        <tr key={agent.id}>
          <td>{agent.hostname}</td>
          <td><StatusPill state={agent.stale ? 'warn' : 'ok'} text={agent.stale ? 'stale' : agent.status} /></td>
          <td>{agent.xdp_mode}</td>
          <td>{agent.active_policy_version}</td>
          <td>{agent.devmap_support ? <CheckCircle2 size={16} /> : <Ban size={16} />}</td>
          <td>{agent.latest_apply?.status ?? 'pending'}</td>
        </tr>
      ))}</tbody>
    </TablePanel>
  );
}

function EventsView({ events }: { events: SecurityEvent[] }) {
  return (
    <TablePanel icon={<Search size={18} />} title="Events / Investigation">
      <thead><tr><th>Time</th><th>Source</th><th>Target</th><th>Proto</th><th>Action</th><th>Reason</th><th>Sample</th></tr></thead>
      <tbody>{events.map((event) => (
        <tr key={event.id}>
          <td>{formatTime(event.event_time)}</td>
          <td>{event.src_ip}</td>
          <td>{event.dst_ip}:{event.dst_port ?? 0}</td>
          <td>{event.protocol}</td>
          <td>{event.action}</td>
          <td>{event.reason}</td>
          <td>{event.sample_rate ?? 1}x</td>
        </tr>
      ))}</tbody>
    </TablePanel>
  );
}

function MetricPanel({ icon, label, value, tone }: { icon: JSX.Element; label: string; value: string; tone?: 'ok' | 'warn' }) {
  return (
    <section className={`metric-panel ${tone ?? ''}`}>
      <div>{icon}<span>{label}</span></div>
      <strong>{value}</strong>
    </section>
  );
}

function PanelHeader({ icon, title, action }: { icon: JSX.Element; title: string; action?: string }) {
  return (
    <div className="panel-header">
      <h2>{icon}{title}</h2>
      {action ? <button type="button" className="secondary-action"><RefreshCw size={15} />{action}</button> : null}
    </div>
  );
}

function TablePanel({ icon, title, action, children }: { icon: JSX.Element; title: string; action?: string; children: ReactNode }) {
  return (
    <section className="table-panel">
      <PanelHeader icon={icon} title={title} action={action} />
      <div className="table-scroll"><table>{children}</table></div>
    </section>
  );
}

function TopList({ title, items }: { title: string; items: { key: string; count: number }[] }) {
  return (
    <section className="list-panel">
      <h2>{title}</h2>
      {items.length === 0 ? <p className="muted">No samples</p> : items.map((item) => (
        <div key={item.key} className="list-row"><span>{item.key}</span><strong>{item.count}</strong></div>
      ))}
    </section>
  );
}

function StatusPill({ state, text }: { state: 'ok' | 'warn' | 'off'; text: string }) {
  return <span className={`status-pill ${state}`}>{text}</span>;
}

function SignalList({ signals }: { signals: string[] }) {
  if (signals.length === 0) {
    return <span className="muted">none</span>;
  }
  return <div className="signal-list">{signals.slice(0, 4).map((signal) => <span key={signal}>{signal}</span>)}</div>;
}

function tabLabel(tab: Tab) {
  return tab.charAt(0).toUpperCase() + tab.slice(1);
}

function numberValue(value: number) {
  return Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value || 0);
}

function percentValue(value: number) {
  return `${Math.round((value || 0) * 100)}%`;
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(value));
}

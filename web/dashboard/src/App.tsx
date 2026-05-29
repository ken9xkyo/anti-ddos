import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock,
  Database,
  Gauge,
  Pencil,
  Plus,
  ListChecks,
  LockKeyhole,
  LogOut,
  RefreshCw,
  Router,
  Save,
  Search,
  Send,
  Server,
  Shield,
  Trash2,
  TrendingUp
} from 'lucide-react';
import { ApiClient } from './api';
import type { Agent, Alert, AnomalyEvaluation, ApplyStatus, BaselineProfile, DashboardData, FeedConflict, FeedRun, FeedSource, Rule, SecurityEvent, Service, ServiceInput, TelegramConfig, TelegramConfigInput, User } from './types';
import './styles.css';

const api = new ApiClient();
const tabs = ['overview', 'alerts', 'anomalies', 'rules', 'reputation', 'services', 'agents', 'events'] as const;
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

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      const next = await api.dashboard();
      setData(next);
      setLastRefresh(new Date().toISOString());
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'load failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    loadDashboard();
    const timer = window.setInterval(loadDashboard, 3000);
    return () => {
      window.clearInterval(timer);
    };
  }, [loadDashboard, user]);

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
      onRefresh={loadDashboard}
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
  onRefresh,
  onLogout
}: {
  user: User;
  data: DashboardData | null;
  activeTab: Tab;
  setActiveTab: (tab: Tab) => void;
  loading: boolean;
  error: string;
  lastRefresh: string;
  onRefresh: () => void | Promise<void>;
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
          <button type="button" className="icon-action" aria-label="refresh" onClick={onRefresh} disabled={loading}>
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
      {data && activeTab === 'alerts' ? <AlertsView alerts={data.alerts} config={data.telegramConfig} user={user} canMutate={canMutate} onRefresh={onRefresh} /> : null}
      {data && activeTab === 'anomalies' ? <AnomaliesView anomalies={data.anomalies} baselines={data.baselines} /> : null}
      {data && activeTab === 'rules' ? <RulesView rules={data.rules} canMutate={canMutate} /> : null}
      {data && activeTab === 'reputation' ? <ReputationView sources={data.feedSources} runs={data.feedRuns} conflicts={data.feedConflicts} canMutate={canMutate} /> : null}
      {data && activeTab === 'services' ? <ServicesView services={data.services} agents={data.agents} applyStatuses={data.overview.latest_apply_status} canMutate={canMutate} onRefresh={onRefresh} /> : null}
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

type TelegramFormState = {
  bot_token_ref: string;
  chat_id: string;
  parse_mode: string;
  enabled: boolean;
  reason: string;
};

function AlertsView({
  alerts,
  config,
  user,
  canMutate,
  onRefresh
}: {
  alerts: Alert[];
  config: TelegramConfig;
  user: User;
  canMutate: boolean;
  onRefresh: () => void | Promise<void>;
}) {
  const [working, setWorking] = useState('');
  const [result, setResult] = useState('');
  const [telegramForm, setTelegramForm] = useState<TelegramFormState>(() => telegramFormFromConfig(config));
  const canConfigureTelegram = user.role === 'admin';

  useEffect(() => {
    setTelegramForm(telegramFormFromConfig(config));
  }, [config]);

  const runAction = async (action: 'test' | 'isp') => {
    if (!canMutate) return;
    try {
      setWorking(action);
      const alert = action === 'test' ? await api.testTelegram() : await api.evaluateIspEscalation();
      setResult(`${alert.type}: ${alert.status}`);
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };
  const saveTelegramConfig = async (event: FormEvent) => {
    event.preventDefault();
    if (!canConfigureTelegram) return;
    try {
      setWorking('telegram');
      const input: TelegramConfigInput = {
        reason: telegramForm.reason,
        bot_token_ref: telegramForm.bot_token_ref,
        chat_id: telegramForm.chat_id,
        parse_mode: telegramForm.parse_mode,
        enabled: telegramForm.enabled
      };
      await api.configureTelegram(input);
      setResult('telegram config saved');
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };
  const latestEscalation = alerts.find((alert) => alert.type === 'isp_escalation_needed');
  return (
    <section className="stacked-view">
      <div className="wide-panel">
        <PanelHeader icon={<Send size={18} />} title="Telegram" />
        <div className="status-row">
          <StatusPill state={config.enabled && config.bot_token_present ? 'ok' : 'warn'} text={config.enabled ? 'enabled' : 'disabled'} />
          <span>{config.chat_id || 'chat not configured'} · {config.bot_token_present ? 'token present' : 'token missing'}</span>
        </div>
        {canConfigureTelegram ? (
          <form className="form-grid" onSubmit={saveTelegramConfig}>
            <label>
              Bot token ref
              <input value={telegramForm.bot_token_ref} onChange={(event) => setTelegramForm({ ...telegramForm, bot_token_ref: event.target.value })} placeholder="env://TELEGRAM_TOKEN" />
            </label>
            <label>
              Chat ID
              <input value={telegramForm.chat_id} onChange={(event) => setTelegramForm({ ...telegramForm, chat_id: event.target.value })} />
            </label>
            <label>
              Parse mode
              <select value={telegramForm.parse_mode} onChange={(event) => setTelegramForm({ ...telegramForm, parse_mode: event.target.value })}>
                <option value="">Plain text</option>
                <option value="HTML">HTML</option>
                <option value="MarkdownV2">MarkdownV2</option>
                <option value="Markdown">Markdown</option>
              </select>
            </label>
            <label>
              Reason
              <input value={telegramForm.reason} onChange={(event) => setTelegramForm({ ...telegramForm, reason: event.target.value })} placeholder="configure alert channel" />
            </label>
            <label className="checkbox-field">
              <input type="checkbox" checked={telegramForm.enabled} onChange={(event) => setTelegramForm({ ...telegramForm, enabled: event.target.checked })} />
              Enabled
            </label>
            <div className="form-actions">
              <button type="submit" className="primary-action" disabled={working !== ''}>
                <Save size={15} />{working === 'telegram' ? 'Saving' : 'Save config'}
              </button>
            </div>
          </form>
        ) : (
          <p className="muted">Telegram configuration changes require admin role.</p>
        )}
        <div className="button-row">
          <button type="button" className="secondary-action" disabled={!canMutate || working !== ''} onClick={() => runAction('test')}>
            <Send size={15} />{working === 'test' ? 'Testing' : 'Test alert'}
          </button>
          <button type="button" className="secondary-action" disabled={!canMutate || working !== ''} onClick={() => runAction('isp')}>
            <AlertTriangle size={15} />{working === 'isp' ? 'Evaluating' : 'ISP runbook'}
          </button>
          {result ? <span className="muted">{result}</span> : null}
        </div>
      </div>
      <TablePanel icon={<AlertTriangle size={18} />} title="Alerts">
        <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Service</th><th>Vector</th><th>Status</th><th>Delivery</th><th>Action</th></tr></thead>
        <tbody>{alerts.map((alert) => {
          const delivery = alert.deliveries?.[alert.deliveries.length - 1];
          return (
            <tr key={alert.id}>
              <td>{formatTime(alert.created_at)}</td>
              <td><StatusPill state={alert.severity === 'critical' ? 'warn' : alert.severity === 'warning' ? 'warn' : 'ok'} text={alert.severity} /></td>
              <td>{alert.type}</td>
              <td>{alert.affected_service || alert.service_id || 'n/a'}</td>
              <td>{alert.vector || 'n/a'}</td>
              <td>{alert.status}</td>
              <td>{delivery ? `${delivery.status} #${delivery.attempt}` : 'pending'}</td>
              <td>{alert.recommended_action || 'investigate'}</td>
            </tr>
          );
        })}</tbody>
      </TablePanel>
      <div className="wide-panel">
        <PanelHeader icon={<ListChecks size={18} />} title="ISP Escalation" />
        <div className="runbook-grid">
          <span>Manual escalation only</span>
          <span>No automatic BGP, RTBH or FlowSpec action</span>
          <span>{latestEscalation?.affected_service || 'Select affected service from incident evidence'}</span>
          <span>{latestEscalation?.vector || 'link_saturation'}</span>
        </div>
        <pre className="payload-box">{JSON.stringify(latestEscalation?.evidence ?? {
          manual_only: true,
          target: 'affected target',
          vector: 'link_saturation',
          required: ['peak_bps', 'peak_pps', 'start_time', 'top_sources']
        }, null, 2)}</pre>
      </div>
    </section>
  );
}

function telegramFormFromConfig(config: TelegramConfig): TelegramFormState {
  return {
    bot_token_ref: config.bot_token_ref,
    chat_id: config.chat_id,
    parse_mode: config.parse_mode ?? '',
    enabled: config.enabled,
    reason: 'update Telegram alert config'
  };
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

function ReputationView({ sources, runs, conflicts, canMutate }: { sources: FeedSource[]; runs: FeedRun[]; conflicts: FeedConflict[]; canMutate: boolean }) {
  return (
    <section className="stacked-view">
      <TablePanel icon={<Ban size={18} />} title="Threat feeds" action={canMutate ? 'Sync feed' : undefined}>
        <thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Active</th><th>Conflicts</th><th>Errors</th><th>Next run</th><th>License</th></tr></thead>
        <tbody>{sources.map((source) => (
          <tr key={source.id}>
            <td>{source.name}</td>
            <td>{source.type}</td>
            <td><StatusPill state={source.enabled ? source.status === 'healthy' ? 'ok' : source.status === 'error' ? 'warn' : 'off' : 'off'} text={source.enabled ? source.status : 'disabled'} /></td>
            <td>{numberValue(source.active_entries)}</td>
            <td>{numberValue(source.conflict_count)}</td>
            <td>{source.last_error || source.parse_error_count ? `${source.parse_error_count} parse` : 'none'}</td>
            <td>{source.next_run_at ? formatTime(source.next_run_at) : 'pending'}</td>
            <td>{source.license_note || 'n/a'}</td>
          </tr>
        ))}</tbody>
      </TablePanel>
      <TablePanel icon={<Clock size={18} />} title="Feed run history">
        <thead><tr><th>Source</th><th>Status</th><th>Fetched</th><th>Valid</th><th>Parse errors</th><th>Snapshot</th><th>Started</th></tr></thead>
        <tbody>{runs.map((run) => (
          <tr key={run.id}>
            <td>{run.source_name || run.source_id}</td>
            <td><StatusPill state={run.status === 'success' ? 'ok' : run.status === 'error' ? 'warn' : 'off'} text={run.status} /></td>
            <td>{numberValue(run.items_fetched)}</td>
            <td>{numberValue(run.items_valid)}</td>
            <td>{numberValue(run.parse_errors)}</td>
            <td>{run.snapshot_version ?? 0}</td>
            <td>{formatTime(run.started_at)}</td>
          </tr>
        ))}</tbody>
      </TablePanel>
      <TablePanel icon={<AlertTriangle size={18} />} title="Whitelist conflicts">
        <thead><tr><th>Source</th><th>Reputation CIDR</th><th>Whitelist CIDR</th><th>Status</th><th>Detected</th></tr></thead>
        <tbody>{conflicts.map((conflict) => (
          <tr key={conflict.id}>
            <td>{conflict.source_name || conflict.source_id}</td>
            <td>{conflict.reputation_cidr}</td>
            <td>{conflict.whitelist_cidr}</td>
            <td><StatusPill state="warn" text={conflict.status} /></td>
            <td>{formatTime(conflict.detected_at)}</td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

type ServiceFormState = {
  reason: string;
  name: string;
  description: string;
  backend_cidr: string;
  protocol: string;
  allowed_ports: string;
  output_interface: string;
  owner: string;
  criticality: string;
  protection_mode: string;
  enabled: boolean;
  priority: string;
  tags: string;
  resolved_ifindex: string;
  resolved_next_hop_mac: string;
  resolved_src_mac: string;
  neighbor_resolution_status: string;
};

type InterfaceOption = {
  name: string;
  label: string;
  ifindex?: number;
  mac?: string;
};

function ServicesView({
  services,
  agents,
  applyStatuses,
  canMutate,
  onRefresh
}: {
  services: Service[];
  agents: Agent[];
  applyStatuses: ApplyStatus[];
  canMutate: boolean;
  onRefresh: () => void | Promise<void>;
}) {
  const [query, setQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [stateFilter, setStateFilter] = useState('all');
  const [formMode, setFormMode] = useState<'create' | 'edit' | ''>('');
  const [editingService, setEditingService] = useState<Service | null>(null);
  const [form, setForm] = useState<ServiceFormState>(() => emptyServiceForm());
  const [deleteTarget, setDeleteTarget] = useState<Service | null>(null);
  const [deleteReason, setDeleteReason] = useState('remove protected service');
  const [working, setWorking] = useState('');
  const [result, setResult] = useState('');

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return services.filter((service) => {
      const matchesText = !needle || [
        service.name,
        service.backend_cidr,
        service.output_interface,
        service.owner,
        service.criticality,
        service.allowed_ports.join(',')
      ].some((value) => value.toLowerCase().includes(needle));
      const matchesProtocol = protocolFilter === 'all' || service.protocol === protocolFilter;
      const matchesState = stateFilter === 'all' || (stateFilter === 'enabled' ? service.enabled : !service.enabled);
      return matchesText && matchesProtocol && matchesState;
    });
  }, [protocolFilter, query, services, stateFilter]);
  const outputInterfaces = useMemo(() => outputInterfaceOptions(agents), [agents]);
  const formOutputInterfaces = useMemo(
    () => withCurrentOutputInterface(outputInterfaces, form.output_interface),
    [form.output_interface, outputInterfaces]
  );
  const failedApplies = applyStatuses.filter((status) => status.status === 'failed');

  const openCreate = () => {
    setFormMode('create');
    setEditingService(null);
    setForm(emptyServiceForm());
    setResult('');
  };
  const openEdit = (service: Service) => {
    setFormMode('edit');
    setEditingService(service);
    setForm(serviceFormFromService(service));
    setResult('');
  };
  const closeForm = () => {
    setFormMode('');
    setEditingService(null);
  };
  const selectOutputInterface = (name: string) => {
    const selected = outputInterfaces.find((item) => item.name === name);
    if (!name) {
      setForm({
        ...form,
        output_interface: '',
        resolved_ifindex: '',
        resolved_src_mac: ''
      });
      return;
    }
    if (!selected) {
      setForm({ ...form, output_interface: name });
      return;
    }
    setForm({
      ...form,
      output_interface: name,
      resolved_ifindex: selected.ifindex ? String(selected.ifindex) : '',
      resolved_src_mac: selected.mac || ''
    });
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!canMutate) return;
    const metadataError = enabledServiceMetadataError(form);
    if (metadataError) {
      setResult(metadataError);
      return;
    }
    try {
      setWorking('service');
      const input = serviceInputFromForm(form);
      if (formMode === 'edit' && editingService) {
        await api.updateService(editingService.id, input);
        setResult(`${input.name} updated`);
      } else {
        await api.createService(input);
        setResult(`${input.name} created`);
      }
      closeForm();
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };
  const confirmDelete = async () => {
    if (!deleteTarget || !canMutate) return;
    try {
      setWorking('delete');
      await api.deleteService(deleteTarget.id, deleteReason);
      setResult(`${deleteTarget.name} deleted`);
      setDeleteTarget(null);
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };

  return (
    <section className="stacked-view">
      <div className="wide-panel">
        <PanelHeader icon={<Router size={18} />} title="Services / Forwarding" />
        <div className="filter-row">
          <label>
            Search
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="name, owner, backend, output" />
          </label>
          <label>
            Protocol
            <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)}>
              <option value="all">All</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </label>
          <label>
            State
            <select value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}>
              <option value="all">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          {canMutate ? (
            <div className="filter-actions">
              <button type="button" className="primary-action" onClick={openCreate}>
                <Plus size={15} />Add service
              </button>
            </div>
          ) : null}
        </div>
        {result ? <div className={result.includes('failed') || result.includes('required') || result.includes('invalid') ? 'error-line inline-message' : 'success-line inline-message'}>{result}</div> : null}
      </div>

      {failedApplies.length > 0 ? (
        <div className="wide-panel apply-failure-panel">
          <PanelHeader icon={<AlertTriangle size={18} />} title="Latest apply failure" />
          {failedApplies.map((status) => (
            <div className="apply-detail" key={`${status.agent_id}-${status.policy_version}`}>
              <StatusPill state="warn" text={status.hostname || status.agent_id} />
              <span>policy v{status.policy_version}</span>
              <span>{status.error_stage || 'apply'}: {status.error_reason || status.status}</span>
            </div>
          ))}
        </div>
      ) : null}

      {formMode ? (
        <form className="wide-panel form-grid service-form" onSubmit={submit}>
          <PanelHeader icon={<Pencil size={18} />} title={formMode === 'edit' ? 'Edit service' : 'Add service'} />
          <label>
            Name
            <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </label>
          <label>
            Backend CIDR
            <input value={form.backend_cidr} onChange={(event) => setForm({ ...form, backend_cidr: event.target.value })} placeholder="203.0.113.10/32" />
          </label>
          <label>
            Protocol
            <select value={form.protocol} onChange={(event) => setForm({ ...form, protocol: event.target.value })}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </label>
          <label>
            Allowed ports
            <input value={form.allowed_ports} onChange={(event) => setForm({ ...form, allowed_ports: event.target.value })} placeholder="443, 8443" disabled={form.protocol === 'icmp'} />
          </label>
          <label>
            Output interface
            {formOutputInterfaces.length > 0 ? (
              <select value={form.output_interface} onChange={(event) => selectOutputInterface(event.target.value)}>
                <option value="">Select interface</option>
                {formOutputInterfaces.map((item) => (
                  <option key={item.name} value={item.name}>{item.label}</option>
                ))}
              </select>
            ) : (
              <input value={form.output_interface} onChange={(event) => setForm({ ...form, output_interface: event.target.value })} placeholder="backend0" />
            )}
          </label>
          <label>
            Owner
            <input value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} />
          </label>
          <label>
            Criticality
            <input value={form.criticality} onChange={(event) => setForm({ ...form, criticality: event.target.value })} placeholder="high" />
          </label>
          <label>
            Protection mode
            <select value={form.protection_mode} onChange={(event) => setForm({ ...form, protection_mode: event.target.value })}>
              <option value="observe">Observe</option>
              <option value="enforce">Enforce</option>
            </select>
          </label>
          <label>
            Priority
            <input value={form.priority} onChange={(event) => setForm({ ...form, priority: event.target.value })} inputMode="numeric" />
          </label>
          <label>
            Neighbor status
            <select value={form.neighbor_resolution_status} onChange={(event) => setForm({ ...form, neighbor_resolution_status: event.target.value })}>
              <option value="unresolved">Unresolved</option>
              <option value="resolved">Resolved</option>
            </select>
          </label>
          <label className="wide-field">
            Description
            <input value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
          </label>
          <label>
            Tags
            <input value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} placeholder="prod, edge" />
          </label>
          <label>
            Resolved ifindex
            <input value={form.resolved_ifindex} onChange={(event) => setForm({ ...form, resolved_ifindex: event.target.value })} inputMode="numeric" />
          </label>
          <label>
            Next-hop MAC
            <input value={form.resolved_next_hop_mac} onChange={(event) => setForm({ ...form, resolved_next_hop_mac: event.target.value })} />
          </label>
          <label>
            Source MAC
            <input value={form.resolved_src_mac} onChange={(event) => setForm({ ...form, resolved_src_mac: event.target.value })} />
          </label>
          <label className="wide-field">
            Reason
            <input value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} />
          </label>
          <label className="checkbox-field">
            <input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />
            Enabled
          </label>
          <div className="form-actions">
            <button type="submit" className="primary-action" disabled={working !== ''}>
              <Save size={15} />{working === 'service' ? 'Saving' : 'Save service'}
            </button>
            <button type="button" className="secondary-action" onClick={closeForm} disabled={working !== ''}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      {deleteTarget ? (
        <div className="wide-panel">
          <PanelHeader icon={<Trash2 size={18} />} title={`Delete ${deleteTarget.name}`} />
          <label>
            Reason
            <input value={deleteReason} onChange={(event) => setDeleteReason(event.target.value)} />
          </label>
          <div className="button-row">
            <button type="button" className="danger-action" disabled={working !== ''} onClick={confirmDelete}>
              <Trash2 size={15} />{working === 'delete' ? 'Deleting' : 'Confirm delete'}
            </button>
            <button type="button" className="secondary-action" onClick={() => setDeleteTarget(null)} disabled={working !== ''}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <TablePanel icon={<Router size={18} />} title={`Protected services (${filtered.length})`}>
        <thead><tr><th>Name</th><th>Backend</th><th>Protocol</th><th>Ports</th><th>Output</th><th>Owner</th><th>Mode</th><th>Neighbor</th><th>Apply</th><th>State</th><th>Actions</th></tr></thead>
        <tbody>{filtered.length === 0 ? (
          <tr>
            <td className="table-empty" colSpan={11}>{services.length === 0 ? 'No protected services configured' : 'No services match the current filters'}</td>
          </tr>
        ) : filtered.map((service) => (
          <tr key={service.id}>
            <td>{service.name}</td>
            <td>{service.backend_cidr}</td>
            <td>{service.protocol}</td>
            <td>{service.allowed_ports.join(', ') || '0'}</td>
            <td>{service.output_interface}</td>
            <td>{service.owner}</td>
            <td>{service.protection_mode}</td>
            <td><StatusPill state={service.neighbor_resolution_status === 'resolved' ? 'ok' : 'warn'} text={service.neighbor_resolution_status} /></td>
            <td>{service.apply_status ?? service.sync_status}</td>
            <td><StatusPill state={service.enabled ? 'ok' : 'off'} text={service.enabled ? 'enabled' : 'disabled'} /></td>
            <td>
              {canMutate ? (
                <div className="row-actions">
                  <button type="button" className="icon-action" aria-label={`edit ${service.name}`} onClick={() => openEdit(service)}>
                    <Pencil size={15} />
                  </button>
                  <button type="button" className="icon-action" aria-label={`delete ${service.name}`} onClick={() => {
                    setDeleteTarget(service);
                    setDeleteReason(`delete ${service.name}`);
                  }}>
                    <Trash2 size={15} />
                  </button>
                </div>
              ) : <span className="muted">read only</span>}
            </td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

function emptyServiceForm(): ServiceFormState {
  return {
    reason: 'update protected service',
    name: '',
    description: '',
    backend_cidr: '',
    protocol: 'tcp',
    allowed_ports: '',
    output_interface: '',
    owner: '',
    criticality: 'high',
    protection_mode: 'enforce',
    enabled: false,
    priority: '',
    tags: '',
    resolved_ifindex: '',
    resolved_next_hop_mac: '',
    resolved_src_mac: '',
    neighbor_resolution_status: 'unresolved'
  };
}

function serviceFormFromService(service: Service): ServiceFormState {
  return {
    reason: `update ${service.name}`,
    name: service.name,
    description: service.description ?? '',
    backend_cidr: service.backend_cidr,
    protocol: service.protocol,
    allowed_ports: service.allowed_ports.join(', '),
    output_interface: service.output_interface,
    owner: service.owner,
    criticality: service.criticality,
    protection_mode: service.protection_mode,
    enabled: service.enabled,
    priority: service.priority ? String(service.priority) : '',
    tags: (service.tags ?? []).join(', '),
    resolved_ifindex: service.resolved_ifindex ? String(service.resolved_ifindex) : '',
    resolved_next_hop_mac: service.resolved_next_hop_mac ?? '',
    resolved_src_mac: service.resolved_src_mac ?? '',
    neighbor_resolution_status: service.neighbor_resolution_status || 'unresolved'
  };
}

function serviceInputFromForm(form: ServiceFormState): ServiceInput {
  const protocol = form.protocol.toLowerCase();
  return {
    reason: form.reason.trim(),
    name: form.name.trim(),
    description: form.description.trim(),
    backend_cidr: form.backend_cidr.trim(),
    protocol,
    allowed_ports: protocol === 'icmp' ? [] : parsePorts(form.allowed_ports),
    output_interface: form.output_interface.trim(),
    owner: form.owner.trim(),
    criticality: form.criticality.trim(),
    protection_mode: form.protection_mode,
    enabled: form.enabled,
    priority: optionalNumber(form.priority),
    tags: splitList(form.tags),
    resolved_ifindex: optionalNumber(form.resolved_ifindex),
    resolved_next_hop_mac: form.resolved_next_hop_mac.trim(),
    resolved_src_mac: form.resolved_src_mac.trim(),
    neighbor_resolution_status: form.neighbor_resolution_status
  };
}

function enabledServiceMetadataError(form: ServiceFormState): string {
  if (!form.enabled) {
    return '';
  }
  if (!form.resolved_ifindex.trim()) {
    return 'resolved ifindex is required before enabling a service';
  }
  if (!form.resolved_next_hop_mac.trim()) {
    return 'resolved next-hop MAC is required before enabling a service';
  }
  if (!form.resolved_src_mac.trim()) {
    return 'source MAC is required before enabling a service';
  }
  return '';
}

function outputInterfaceOptions(agents: Agent[]): InterfaceOption[] {
  const seen = new Set<string>();
  const out: InterfaceOption[] = [];
  for (const agent of agents) {
    for (const iface of agent.interfaces ?? []) {
      const name = iface.name.trim();
      if (!name || seen.has(name)) continue;
      seen.add(name);
      out.push({
        name,
        label: interfaceLabel(iface),
        ifindex: iface.ifindex,
        mac: iface.mac
      });
    }
  }
  return out.sort((left, right) => left.name.localeCompare(right.name));
}

function withCurrentOutputInterface(options: InterfaceOption[], current: string): InterfaceOption[] {
  const name = current.trim();
  if (!name || options.some((item) => item.name === name)) {
    return options;
  }
  return [{ name, label: `${name} (not reported by agent)` }, ...options];
}

function interfaceLabel(iface: { name: string; ifindex?: number; mac?: string; role?: string }): string {
  const details = [
    iface.role,
    iface.ifindex ? `ifindex ${iface.ifindex}` : '',
    iface.mac
  ].filter(Boolean);
  return details.length > 0 ? `${iface.name} (${details.join(', ')})` : iface.name;
}

function parsePorts(value: string): number[] {
  const ports = splitList(value).map((item) => Number(item));
  if (ports.length === 0 || ports.some((port) => !Number.isInteger(port) || port <= 0 || port > 65535)) {
    throw new Error('allowed ports must be comma-separated values from 1 to 65535');
  }
  return ports;
}

function splitList(value: string): string[] {
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function optionalNumber(value: string): number | undefined {
  if (value.trim() === '') return undefined;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) {
    throw new Error('numeric fields must be non-negative integers');
  }
  return next;
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
          <td>
            {agent.latest_apply ? (
              <div className="apply-cell">
                <StatusPill state={agent.latest_apply.status === 'applied' ? 'ok' : agent.latest_apply.status === 'failed' ? 'warn' : 'off'} text={agent.latest_apply.status} />
                <span>v{agent.latest_apply.policy_version}</span>
                {agent.latest_apply.status === 'failed' ? (
                  <span className="apply-error">{agent.latest_apply.error_stage || 'apply'}: {agent.latest_apply.error_reason || 'failed'}</span>
                ) : null}
              </div>
            ) : 'pending'}
          </td>
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

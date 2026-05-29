import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App, { DashboardShell, type Tab } from './App';
import { dashboardFixture, operatorUser, viewerUser } from './test/fixtures';
import type { DashboardData, User } from './types';

const data = dashboardFixture();
const adminUser: User = { id: 'u3', username: 'admin', role: 'admin' };

function renderShell(user: User, activeTab: Tab = 'overview') {
  return renderShellWithData(user, data, activeTab);
}

function renderShellWithData(user: User, dashboardData: DashboardData, activeTab: Tab = 'overview') {
  return render(
    <DashboardShell
      user={user}
      data={dashboardData}
      activeTab={activeTab}
      setActiveTab={vi.fn()}
      loading={false}
      error=""
      lastRefresh={new Date().toISOString()}
      onRefresh={vi.fn()}
      onLogout={vi.fn()}
    />
  );
}

describe('DashboardShell', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('renders overview freshness and Prometheus unconfigured state', () => {
    renderShell(viewerUser);
    expect(screen.getByText('Packets/s')).toBeInTheDocument();
    expect(screen.getByText('unconfigured')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.0/24')).toBeInTheDocument();
  });

  it('keeps viewer read-only', () => {
    renderShell(viewerUser, 'services');
    expect(screen.queryByRole('button', { name: /add service/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /edit api-https/i })).not.toBeInTheDocument();
    expect(screen.getByText('api-https')).toBeInTheDocument();
  });

  it('shows service empty state and apply failure details', () => {
    renderShellWithData(viewerUser, {
      ...data,
      services: [],
      overview: {
        ...data.overview,
        latest_apply_status: [{
          agent_id: 'a1',
          hostname: 'node-a',
          policy_version: 9,
          status: 'failed',
          error_stage: 'validate',
          error_reason: 'policy snapshot object_checksum mismatch',
          reported_at: '2026-05-29T03:00:00Z'
        }]
      },
      agents: [{
        ...data.agents[0],
        latest_apply: {
          agent_id: 'a1',
          hostname: 'node-a',
          policy_version: 9,
          status: 'failed',
          error_stage: 'validate',
          error_reason: 'policy snapshot object_checksum mismatch',
          reported_at: '2026-05-29T03:00:00Z'
        }
      }]
    }, 'services');

    expect(screen.getByText('No protected services configured')).toBeInTheDocument();
    expect(screen.getByText('Latest apply failure')).toBeInTheDocument();
    expect(screen.getByText('validate: policy snapshot object_checksum mismatch')).toBeInTheDocument();
  });

  it('shows agent apply failure details', () => {
    renderShellWithData(viewerUser, {
      ...data,
      agents: [{
        ...data.agents[0],
        latest_apply: {
          agent_id: 'a1',
          hostname: 'node-a',
          policy_version: 9,
          status: 'failed',
          error_stage: 'validate',
          error_reason: 'policy snapshot object_checksum mismatch',
          reported_at: '2026-05-29T03:00:00Z'
        }
      }]
    }, 'agents');

    expect(screen.getByText('v9')).toBeInTheDocument();
    expect(screen.getByText('validate: policy snapshot object_checksum mismatch')).toBeInTheDocument();
  });

  it('shows operator mutation entrypoints', () => {
    renderShell(operatorUser, 'rules');
    expect(screen.getByRole('button', { name: /add rule/i })).toBeInTheDocument();
  });

  it('renders loading and error states without dashboard data', () => {
    render(
      <DashboardShell
        user={viewerUser}
        data={null}
        activeTab="overview"
        setActiveTab={vi.fn()}
        loading={false}
        error="dashboard unavailable"
        lastRefresh=""
        onRefresh={vi.fn()}
        onLogout={vi.fn()}
      />
    );

    expect(screen.getByText('dashboard unavailable')).toBeInTheDocument();
    expect(screen.getByText('Loading dashboard data')).toBeInTheDocument();
  });

  it('renders anomaly and baseline visibility', () => {
    renderShell(viewerUser, 'anomalies');
    expect(screen.getByText('auto_enforced')).toBeInTheDocument();
    expect(screen.getByText('pps_spike')).toBeInTheDocument();
    expect(screen.getByText('approved')).toBeInTheDocument();
  });

  it('renders event investigation table', () => {
    renderShell(viewerUser, 'events');
    const table = screen.getByRole('table');
    expect(within(table).getByText('198.51.100.10')).toBeInTheDocument();
    expect(within(table).getByText('203.0.113.10:443')).toBeInTheDocument();
  });

  it('renders feed status and conflicts', () => {
    renderShell(viewerUser, 'reputation');
    expect(screen.getAllByText('spamhaus-drop').length).toBeGreaterThan(0);
    expect(screen.getByText('198.51.100.0/24')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.10/32')).toBeInTheDocument();
  });

  it('renders alerts and manual ISP runbook', () => {
    renderShell(viewerUser, 'alerts');
    expect(screen.getByText('isp_escalation_needed')).toBeInTheDocument();
    expect(screen.getByText('No automatic BGP, RTBH or FlowSpec action')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /test alert/i })).toBeDisabled();
    expect(screen.queryByRole('button', { name: /save config/i })).not.toBeInTheDocument();
  });

  it('creates a protected service and refreshes after success', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({
        path: input.toString(),
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined
      });
      return jsonResponse(data.services[0]);
    }));
    render(
      <DashboardShell
        user={operatorUser}
        data={data}
        activeTab="services"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onLogout={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /add service/i }));
    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: 'edge-api' } });
    fireEvent.change(screen.getByLabelText(/backend cidr/i), { target: { value: '203.0.113.20/32' } });
    fireEvent.change(screen.getByLabelText(/allowed ports/i), { target: { value: '443, 8443' } });
    fireEvent.change(screen.getByLabelText(/output interface/i), { target: { value: 'backend1' } });
    fireEvent.change(screen.getByLabelText(/^owner$/i), { target: { value: 'platform' } });
    fireEvent.change(screen.getByLabelText(/^reason$/i), { target: { value: 'add edge API service' } });
    fireEvent.click(screen.getByRole('button', { name: /save service/i }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(calls).toEqual([{
      path: '/v1/services',
      method: 'POST',
      body: {
        reason: 'add edge API service',
        name: 'edge-api',
        description: '',
        backend_cidr: '203.0.113.20/32',
        protocol: 'tcp',
        allowed_ports: [443, 8443],
        output_interface: 'backend1',
        owner: 'platform',
        criticality: 'high',
        protection_mode: 'enforce',
        enabled: false,
        tags: [],
        resolved_next_hop_mac: '',
        resolved_src_mac: '',
        neighbor_resolution_status: 'unresolved'
      }
    }]);
  });

  it('selects output interface from reported host interfaces', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
    const dashboardData: DashboardData = {
      ...data,
      agents: [{
        ...data.agents[0],
        interfaces: [{
          name: 'backend0',
          ifindex: 8,
          mac: '02:00:00:00:00:08',
          role: 'backend'
        }]
      }]
    };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({
        path: input.toString(),
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined
      });
      return jsonResponse(data.services[0]);
    }));
    render(
      <DashboardShell
        user={operatorUser}
        data={dashboardData}
        activeTab="services"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onLogout={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /add service/i }));
    expect(screen.getByRole('option', { name: /backend0.*ifindex 8/i })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: 'edge-api' } });
    fireEvent.change(screen.getByLabelText(/backend cidr/i), { target: { value: '203.0.113.20/32' } });
    fireEvent.change(screen.getByLabelText(/allowed ports/i), { target: { value: '443' } });
    fireEvent.change(screen.getByLabelText(/output interface/i), { target: { value: 'backend0' } });
    fireEvent.change(screen.getByLabelText(/^owner$/i), { target: { value: 'platform' } });
    fireEvent.change(screen.getByLabelText(/^reason$/i), { target: { value: 'add edge API service' } });
    fireEvent.click(screen.getByRole('button', { name: /save service/i }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(calls[0].body).toMatchObject({
      output_interface: 'backend0',
      enabled: false,
      resolved_ifindex: 8,
      resolved_src_mac: '02:00:00:00:00:08'
    });
  });

  it('requires resolved next-hop metadata before enabling a service', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const fetchMock = vi.fn();
    const dashboardData: DashboardData = {
      ...data,
      agents: [{
        ...data.agents[0],
        interfaces: [{
          name: 'enp134s0f1',
          ifindex: 7,
          mac: '90:e2:ba:24:9b:b6',
          role: 'backend'
        }]
      }]
    };
    vi.stubGlobal('fetch', fetchMock);
    render(
      <DashboardShell
        user={operatorUser}
        data={dashboardData}
        activeTab="services"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onLogout={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /add service/i }));
    expect(screen.getByLabelText(/enabled/i)).not.toBeChecked();
    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: 'edge-api' } });
    fireEvent.change(screen.getByLabelText(/backend cidr/i), { target: { value: '203.0.113.20/32' } });
    fireEvent.change(screen.getByLabelText(/allowed ports/i), { target: { value: '443' } });
    fireEvent.change(screen.getByLabelText(/output interface/i), { target: { value: 'enp134s0f1' } });
    fireEvent.change(screen.getByLabelText(/^owner$/i), { target: { value: 'platform' } });
    fireEvent.change(screen.getByLabelText(/^reason$/i), { target: { value: 'add edge API service' } });
    fireEvent.click(screen.getByLabelText(/enabled/i));
    fireEvent.click(screen.getByRole('button', { name: /save service/i }));

    expect(await screen.findByText('resolved next-hop MAC is required before enabling a service')).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('updates and deletes a protected service from row actions', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const calls: Array<{ path: string; method?: string; body: unknown; reason: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({
        path: input.toString(),
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        reason: new Headers(init?.headers).get('X-Audit-Reason')
      });
      return jsonResponse(data.services[0]);
    }));
    render(
      <DashboardShell
        user={operatorUser}
        data={data}
        activeTab="services"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onLogout={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /edit api-https/i }));
    fireEvent.change(screen.getByLabelText(/allowed ports/i), { target: { value: '443, 9443' } });
    fireEvent.change(screen.getByLabelText(/^reason$/i), { target: { value: 'open service maintenance port' } });
    fireEvent.click(screen.getByRole('button', { name: /save service/i }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole('button', { name: /delete api-https/i }));
    fireEvent.change(screen.getByLabelText(/^reason$/i), { target: { value: 'retire service' } });
    fireEvent.click(screen.getByRole('button', { name: /confirm delete/i }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(2));

    expect(calls[0]).toMatchObject({
      path: '/v1/services/s1',
      method: 'PUT',
      reason: null
    });
    expect(calls[0].body).toMatchObject({
      reason: 'open service maintenance port',
      name: 'api-https',
      allowed_ports: [443, 9443]
    });
    expect(calls[1]).toEqual({
      path: '/v1/services/s1',
      method: 'DELETE',
      body: undefined,
      reason: 'retire service'
    });
  });

  it('allows only admin to save Telegram config', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const calls: unknown[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ path: input.toString(), method: init?.method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      return jsonResponse({ ...data.telegramConfig, chat_id: '5678' });
    }));

    renderShell(operatorUser, 'alerts');
    expect(screen.queryByRole('button', { name: /save config/i })).not.toBeInTheDocument();

    render(
      <DashboardShell
        user={adminUser}
        data={data}
        activeTab="alerts"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onLogout={vi.fn()}
      />
    );

    fireEvent.change(screen.getByLabelText(/bot token ref/i), { target: { value: 'env://ADMIN_DASHBOARD_TELEGRAM_TOKEN' } });
    fireEvent.change(screen.getByLabelText(/chat id/i), { target: { value: '5678' } });
    fireEvent.change(screen.getByLabelText(/^reason$/i), { target: { value: 'configure alert channel' } });
    fireEvent.click(screen.getByRole('button', { name: /save config/i }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(calls).toEqual([{
      path: '/v1/telegram/config',
      method: 'POST',
      body: {
        reason: 'configure alert channel',
        bot_token_ref: 'env://ADMIN_DASHBOARD_TELEGRAM_TOKEN',
        chat_id: '5678',
        parse_mode: '',
        enabled: true
      }
    }]);
  });

  it('logs in, polls dashboard, runs operator actions, and clears token on logout', async () => {
    let pollDashboard: (() => void) | undefined;
    vi.spyOn(window, 'setInterval').mockImplementation((handler: TimerHandler) => {
      if (typeof handler === 'function') {
        pollDashboard = handler as () => void;
      }
      return 1;
    });
    vi.spyOn(window, 'clearInterval').mockImplementation(() => undefined);
    const seen: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      seen.push(path);
      if (path === '/v1/me') {
        return new Response('unauthenticated', { status: 401 });
      }
      if (path === '/v1/auth/login') {
        expect(JSON.parse(init?.body as string)).toEqual({ username: 'operator', password: 'secret' });
        return jsonResponse({ token: 'operator-token', user: operatorUser, expires_at: '2026-05-28T12:00:00Z' });
      }
      if (path === '/v1/telegram/test') {
        expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer operator-token');
        return jsonResponse({ ...data.alerts[0], type: 'test_alert', status: 'sent' });
      }
      if (path === '/v1/alerts/evaluate-isp-escalation') {
        expect(JSON.parse(init?.body as string)).toEqual({ reason: 'dashboard ISP escalation evaluation', target: 'manual assessment', vector: 'link_saturation' });
        return jsonResponse(data.alerts[0]);
      }
      const dashboardResponse = dashboardResponses(data)[path];
      if (dashboardResponse) {
        expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer operator-token');
        return jsonResponse(dashboardResponse);
      }
      throw new Error(`unexpected request ${path}`);
    }));

    render(<App />);

    fireEvent.change(await screen.findByLabelText(/username/i), { target: { value: 'operator' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByText('Packets/s')).toBeInTheDocument();
    expect(localStorage.getItem('anti_ddos_token')).toBe('operator-token');
    expect(seen.filter((path) => path === '/v1/dashboard/overview')).toHaveLength(1);

    await act(async () => {
      pollDashboard?.();
    });
    await waitFor(() => expect(seen.filter((path) => path === '/v1/dashboard/overview')).toHaveLength(2));

    fireEvent.click(screen.getByRole('button', { name: /alerts/i }));
    fireEvent.click(await screen.findByRole('button', { name: /test alert/i }));
    expect(await screen.findByText('test_alert: sent')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /isp runbook/i }));
    expect(await screen.findByText('isp_escalation_needed: sent')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /logout/i }));
    expect(localStorage.getItem('anti_ddos_token')).toBeNull();
    expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('loads the dashboard after login when backend list endpoints return null', async () => {
    const emptyOverview = {
      ...data.overview,
      security_events: {
        ...data.overview.security_events,
        total: 0,
        top_sources: null,
        top_ports: null,
        by_decision: null
      },
      agents: { total: 0, stale: 0 },
      latest_apply_status: null
    };
    const responses: Record<string, unknown> = {
      ...dashboardResponses(data),
      '/v1/dashboard/overview': emptyOverview,
      '/v1/dashboard/agents': null,
      '/v1/dashboard/services': null,
      '/v1/dashboard/rules': null,
      '/v1/security-events?limit=50': null,
      '/v1/baselines': null,
      '/v1/anomalies?limit=30': null,
      '/v1/feed-sources': null,
      '/v1/feed-runs?limit=20': null,
      '/v1/feed-conflicts': null,
      '/v1/alerts?limit=30': null
    };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      if (path === '/v1/me') {
        return new Response('unauthenticated', { status: 401 });
      }
      if (path === '/v1/auth/login') {
        expect(JSON.parse(init?.body as string)).toEqual({ username: 'operator', password: 'secret' });
        return jsonResponse({ token: 'operator-token', user: operatorUser, expires_at: '2026-05-28T12:00:00Z' });
      }
      if (path in responses) {
        return jsonResponse(responses[path]);
      }
      throw new Error(`unexpected request ${path}`);
    }));

    render(<App />);

    fireEvent.change(await screen.findByLabelText(/username/i), { target: { value: 'operator' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByText('Packets/s')).toBeInTheDocument();
    expect(screen.getAllByText('No samples')).toHaveLength(3);
  });
});

function dashboardResponses(value: DashboardData): Record<string, unknown> {
  return {
    '/v1/dashboard/overview': value.overview,
    '/v1/dashboard/agents': value.agents,
    '/v1/dashboard/services': value.services,
    '/v1/dashboard/rules': value.rules,
    '/v1/security-events?limit=50': value.events,
    '/v1/baselines': value.baselines,
    '/v1/anomalies?limit=30': value.anomalies,
    '/v1/feed-sources': value.feedSources,
    '/v1/feed-runs?limit=20': value.feedRuns,
    '/v1/feed-conflicts': value.feedConflicts,
    '/v1/telegram/config': value.telegramConfig,
    '/v1/alerts?limit=30': value.alerts
  };
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}

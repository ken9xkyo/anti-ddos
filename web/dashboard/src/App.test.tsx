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
    cleanupChartArtifacts();
    localStorage.clear();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    cleanupChartArtifacts();
  });

  it('renders overview freshness and Prometheus unconfigured state', () => {
    renderShell(viewerUser);
    expect(screen.getByText('Packets/s')).toBeInTheDocument();
    expect(screen.getByText('prometheus unconfigured')).toBeInTheDocument();
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
    expect(screen.getByText('Latest Apply Failure')).toBeInTheDocument();
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
    }, 'fleet');

    expect(screen.getByText('v9')).toBeInTheDocument();
    expect(screen.getByText('validate: policy snapshot object_checksum mismatch')).toBeInTheDocument();
  });

  it('shows operator service actions and keeps Detection observe-only', () => {
    renderShell(operatorUser, 'services');
    expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    renderShell(operatorUser, 'detection');
    expect(screen.queryByRole('button', { name: /add rule/i })).not.toBeInTheDocument();
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
    renderShell(viewerUser, 'detection');
    expect(screen.getByText('auto_enforced')).toBeInTheDocument();
    expect(screen.getByText('pps_spike')).toBeInTheDocument();
    expect(screen.getByText('approved')).toBeInTheDocument();
  });

  it('renders event investigation table', () => {
    renderShell(viewerUser, 'investigation');
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
    renderShell(viewerUser, 'incidents');
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
    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: 'edge-api' } });
    fireEvent.change(screen.getByLabelText(/backend cidr/i), { target: { value: '203.0.113.20/32' } });
    fireEvent.change(screen.getByLabelText(/allowed ports/i), { target: { value: '443, 8443' } });
    fireEvent.change(screen.getByLabelText(/output interface/i), { target: { value: 'backend1' } });
    fireEvent.change(screen.getByLabelText(/^owner/i), { target: { value: 'platform' } });
    fireEvent.change(screen.getByLabelText(/^reason/i), { target: { value: 'add edge API service' } });
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
    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: 'edge-api' } });
    fireEvent.change(screen.getByLabelText(/backend cidr/i), { target: { value: '203.0.113.20/32' } });
    fireEvent.change(screen.getByLabelText(/allowed ports/i), { target: { value: '443' } });
    fireEvent.change(screen.getByLabelText(/output interface/i), { target: { value: 'backend0' } });
    fireEvent.change(screen.getByLabelText(/^owner/i), { target: { value: 'platform' } });
    fireEvent.change(screen.getByLabelText(/^reason/i), { target: { value: 'add edge API service' } });
    fireEvent.click(screen.getByRole('button', { name: /save service/i }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(calls[0].body).toMatchObject({
      output_interface: 'backend0',
      enabled: false,
      resolved_ifindex: 8,
      resolved_src_mac: '02:00:00:00:00:08'
    });
  });

  it('allows enabling a service without manual next-hop MAC input', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
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
    expect(screen.getByLabelText(/enabled/i)).not.toBeChecked();
    expect(screen.queryByLabelText(/next-hop mac/i)).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: 'edge-api' } });
    fireEvent.change(screen.getByLabelText(/backend cidr/i), { target: { value: '203.0.113.20/32' } });
    fireEvent.change(screen.getByLabelText(/allowed ports/i), { target: { value: '443' } });
    fireEvent.change(screen.getByLabelText(/output interface/i), { target: { value: 'enp134s0f1' } });
    fireEvent.change(screen.getByLabelText(/^owner/i), { target: { value: 'platform' } });
    fireEvent.change(screen.getByLabelText(/^reason/i), { target: { value: 'add edge API service' } });
    fireEvent.click(screen.getByLabelText(/enabled/i));
    fireEvent.click(screen.getByRole('button', { name: /save service/i }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(calls[0]).toMatchObject({
      path: '/v1/services',
      method: 'POST'
    });
    expect(calls[0].body).toMatchObject({
      output_interface: 'enp134s0f1',
      enabled: true,
      resolved_ifindex: 7,
      resolved_src_mac: '90:e2:ba:24:9b:b6'
    });
    expect(calls[0].body).not.toHaveProperty('resolved_next_hop_mac');
  });

  it('updates and disables a protected service from row actions', async () => {
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
    fireEvent.change(screen.getByLabelText(/^reason/i), { target: { value: 'open service maintenance port' } });
    fireEvent.click(screen.getByRole('button', { name: /save service/i }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole('button', { name: /disable api-https/i }));
    fireEvent.change(screen.getByLabelText(/^reason/i), { target: { value: 'retire service' } });
    fireEvent.click(screen.getByRole('button', { name: /confirm disable/i }));
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

    renderShell(operatorUser, 'incidents');
    expect(screen.queryByRole('button', { name: /save config/i })).not.toBeInTheDocument();

    render(
      <DashboardShell
        user={adminUser}
        data={data}
        activeTab="incidents"
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
    fireEvent.change(screen.getByLabelText(/^reason/i), { target: { value: 'configure alert channel' } });
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

  it('keeps viewer read-only in rule management', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      if (input.toString() === '/v1/rules') {
        return jsonResponse(data.rules);
      }
      throw new Error(`unexpected request ${input.toString()}`);
    }));

    renderShell(viewerUser, 'rules');

    expect(await screen.findByText('drop-suspect')).toBeInTheDocument();
    expect(screen.queryByText(/add rule/i)).not.toBeInTheDocument();
    expect(screen.getByText('read only')).toBeInTheDocument();
  });

  it('runs rule create, edit and soft-disable workflows', async () => {
    const calls: Array<{ path: string; method?: string; body: unknown; reason: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        reason: new Headers(init?.headers).get('X-Audit-Reason')
      });
      if (path === '/v1/rules' && !init?.method) return jsonResponse(data.rules);
      if (path === '/v1/rules' && init?.method === 'POST') return jsonResponse({ ...data.rules[0], id: 'r2', name: 'edge-rate-limit' });
      if (path === '/v1/rules/r1' && init?.method === 'PATCH') return jsonResponse({ ...data.rules[0], threshold_pps: 1500 });
      if (path === '/v1/rules/r1' && init?.method === 'DELETE') return jsonResponse({ ...data.rules[0], enabled: false });
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(operatorUser, 'rules');
    expect(await screen.findByText('drop-suspect')).toBeInTheDocument();

    clickButtonByText(/add rule/i);
    await fillField(/^name/i, 'edge-rate-limit');
    await fillField(/^pps$/i, '1200');
    await fillField(/^owner/i, 'soc');
    await fillField(/^reason/i, 'create edge rate limit');
    clickButtonByText(/save rule/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/rules' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^edit$/i);
    await fillField(/^pps$/i, '1500');
    await fillField(/^reason/i, 'tune rule threshold');
    clickButtonByText(/save rule/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/rules/r1' && call.method === 'PATCH')).toBe(true));

    clickButtonByText(/^disable$/i);
    await fillField(/^reason/i, 'retire rule');
    clickButtonByText(/disable rule/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/rules/r1' && call.method === 'DELETE')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/rules' && call.method === 'POST')?.body).toMatchObject({
      reason: 'create edge rate limit',
      name: 'edge-rate-limit',
      action: 'rate_limit',
      threshold_pps: 1200,
      owner: 'soc',
      enabled: true
    });
    expect(calls.find((call) => call.path === '/v1/rules/r1' && call.method === 'PATCH')?.body).toMatchObject({
      reason: 'tune rule threshold',
      name: 'drop-suspect',
      threshold_pps: 1500
    });
    expect(calls.find((call) => call.path === '/v1/rules/r1' && call.method === 'DELETE')?.reason).toBe('retire rule');
  });

  it('runs whitelist create, edit and soft-disable workflows', async () => {
    const whitelistEntry = whitelistFixture();
    const calls: Array<{ path: string; method?: string; body: unknown; reason: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        reason: new Headers(init?.headers).get('X-Audit-Reason')
      });
      if (path === '/v1/whitelist' && !init?.method) return jsonResponse([whitelistEntry]);
      if (path === '/v1/whitelist' && init?.method === 'POST') return jsonResponse({ ...whitelistEntry, id: 'w2', cidr: '203.0.113.55/32' });
      if (path === '/v1/whitelist/w1' && init?.method === 'PATCH') return jsonResponse({ ...whitelistEntry, label: 'trusted-partner' });
      if (path === '/v1/whitelist/w1' && init?.method === 'DELETE') return jsonResponse({ ...whitelistEntry, enabled: false });
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(operatorUser, 'whitelist');
    expect(await screen.findByText('198.51.100.10/32')).toBeInTheDocument();

    clickButtonByText(/add whitelist/i);
    await fillField(/^cidr/i, '203.0.113.55/32');
    await fillField(/^owner/i, 'noc');
    await fillField(/^reason/i, 'allow partner probe');
    clickButtonByText(/save whitelist/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/whitelist' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^edit$/i);
    await fillField(/^label$/i, 'trusted-partner');
    await fillField(/^reason/i, 'rename whitelist entry');
    clickButtonByText(/save whitelist/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/whitelist/w1' && call.method === 'PATCH')).toBe(true));

    clickButtonByText(/^disable$/i);
    await fillField(/^reason/i, 'partner window closed');
    clickButtonByText(/disable entry/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/whitelist/w1' && call.method === 'DELETE')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/whitelist' && call.method === 'POST')?.body).toMatchObject({
      reason: 'allow partner probe',
      cidr: '203.0.113.55/32',
      scope: 'global',
      owner: 'noc',
      enabled: true
    });
    expect(calls.find((call) => call.path === '/v1/whitelist/w1' && call.method === 'PATCH')?.body).toMatchObject({
      reason: 'rename whitelist entry',
      cidr: '198.51.100.10/32',
      label: 'trusted-partner'
    });
    expect(calls.find((call) => call.path === '/v1/whitelist/w1' && call.method === 'DELETE')?.reason).toBe('partner window closed');
  });

  it('runs feed create, edit, sync and soft-disable workflows with admin credentials', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const calls: Array<{ path: string; method?: string; body: unknown; reason: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        reason: new Headers(init?.headers).get('X-Audit-Reason')
      });
      if (path === '/v1/feed-sources' && !init?.method) return jsonResponse(data.feedSources);
      if (path === '/v1/feed-sources' && init?.method === 'POST') return jsonResponse({ ...data.feedSources[0], id: 'f2', name: 'partner-feed' });
      if (path === '/v1/feed-sources/f1' && init?.method === 'PATCH') return jsonResponse({ ...data.feedSources[0], license_note: 'commercial-ok' });
      if (path === '/v1/feed-sources/f1/sync' && init?.method === 'POST') return jsonResponse({ ...data.feedRuns[0], id: 'fr2' });
      if (path === '/v1/feed-sources/f1' && init?.method === 'DELETE') return jsonResponse({ ...data.feedSources[0], enabled: false });
      throw new Error(`unexpected request ${path}`);
    }));

    render(
      <DashboardShell
        user={adminUser}
        data={data}
        activeTab="reputation"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onLogout={vi.fn()}
      />
    );

    clickButtonByText(/add feed/i);
    await fillField(/^name/i, 'partner-feed');
    await fillField(/^url$/i, 'https://feeds.example.test/drop.json');
    await fillField(/credential ref/i, 'vault://feeds/partner');
    await fillField(/^reason/i, 'add partner feed');
    clickButtonByText(/save feed/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/feed-sources' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^edit$/i);
    await fillField(/license note/i, 'commercial-ok');
    await fillField(/^reason/i, 'update feed license');
    clickButtonByText(/save feed/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/feed-sources/f1' && call.method === 'PATCH')).toBe(true));

    clickButtonByText(/^sync$/i);
    await fillField(/^reason/i, 'manual feed sync');
    clickButtonByText(/sync feed/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/feed-sources/f1/sync' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^disable$/i);
    await fillField(/^reason/i, 'retire feed');
    clickButtonByText(/disable feed/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/feed-sources/f1' && call.method === 'DELETE')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/feed-sources' && call.method === 'POST')?.body).toMatchObject({
      reason: 'add partner feed',
      name: 'partner-feed',
      url: 'https://feeds.example.test/drop.json',
      credential_ref: 'vault://feeds/partner'
    });
    expect(calls.find((call) => call.path === '/v1/feed-sources/f1' && call.method === 'PATCH')?.body).toMatchObject({
      reason: 'update feed license',
      license_note: 'commercial-ok'
    });
    expect(calls.find((call) => call.path === '/v1/feed-sources/f1/sync' && call.method === 'POST')?.body).toEqual({ reason: 'manual feed sync' });
    expect(calls.find((call) => call.path === '/v1/feed-sources/f1' && call.method === 'DELETE')?.reason).toBe('retire feed');
  });

  it('runs user create, reactivate, password reset and session revoke workflows', async () => {
    const managedUser: User = {
      ...operatorUser,
      status: 'revoked',
      force_password_change: true,
      created_at: '2026-05-28T11:00:00Z'
    };
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined
      });
      if (path === '/v1/users' && !init?.method) return jsonResponse([managedUser]);
      if (path === '/v1/users' && init?.method === 'POST') return jsonResponse({ id: 'u4', username: 'analyst', role: 'viewer', status: 'active' });
      if (path === '/v1/users/u2' && init?.method === 'PATCH') return jsonResponse({ ...managedUser, status: 'active' });
      if (path === '/v1/users/u2/password-reset' && init?.method === 'POST') return jsonResponse(managedUser);
      if (path === '/v1/users/u2/sessions/revoke' && init?.method === 'POST') return jsonResponse(managedUser);
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(adminUser, 'access');
    expect((await screen.findAllByText('operator')).length).toBeGreaterThan(0);

    clickButtonByText(/add user/i);
    await fillField(/^username/i, 'analyst');
    await fillField(/temporary password/i, 'TempPass123!');
    await fillField(/^reason/i, 'create analyst user');
    clickButtonByText(/^save$/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/users' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^edit$/i);
    await selectOption(/^status/i, 'Active');
    await fillField(/^reason/i, 'reactivate operator');
    clickButtonByText(/^save$/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/users/u2' && call.method === 'PATCH')).toBe(true));

    clickButtonByText(/^reset$/i);
    await fillField(/temporary password/i, 'NextPass123!');
    await fillField(/^reason/i, 'reset locked account');
    clickButtonByText(/^save$/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/users/u2/password-reset' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^sessions$/i);
    await fillField(/^reason/i, 'clear stale sessions');
    clickButtonByText(/revoke sessions/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/users/u2/sessions/revoke' && call.method === 'POST')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/users' && call.method === 'POST')?.body).toEqual({
      reason: 'create analyst user',
      username: 'analyst',
      password: 'TempPass123!',
      role: 'viewer'
    });
    expect(calls.find((call) => call.path === '/v1/users/u2' && call.method === 'PATCH')?.body).toMatchObject({
      reason: 'reactivate operator',
      status: 'active'
    });
    expect(calls.find((call) => call.path === '/v1/users/u2/password-reset' && call.method === 'POST')?.body).toMatchObject({
      reason: 'reset locked account',
      password: 'NextPass123!',
      force_password_change: true
    });
    expect(calls.find((call) => call.path === '/v1/users/u2/sessions/revoke' && call.method === 'POST')?.body).toEqual({ reason: 'clear stale sessions' });
  });

  it('loads snapshot semantic diff and confirms rollback', async () => {
    const snapshots = snapshotFixtures();
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined
      });
      if (path === '/v1/snapshots?include_snapshot=false') return jsonResponse(snapshots);
      if (path === '/v1/snapshots/diff?from=1&to=2') return jsonResponse(snapshotDiffFixture());
      if (path === '/v1/snapshots/rollback' && init?.method === 'POST') return jsonResponse({ ...snapshots[0], version: 3, rollback_from: 2 });
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(operatorUser, 'snapshots');
    expect(await screen.findByText('Snapshot Versions')).toBeInTheDocument();

    clickButtonByText(/load diff/i);
    expect(await screen.findByText('diff v1 -> v2 loaded')).toBeInTheDocument();
    expect(screen.getByText('changed')).toBeInTheDocument();

    fireEvent.click((await screen.findAllByText(/^rollback$/i))[0].closest('button')!);
    await fillField(/^reason/i, 'rollback bad policy');
    clickButtonByText(/create rollback/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/snapshots/rollback' && call.method === 'POST')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/snapshots/rollback' && call.method === 'POST')?.body).toEqual({
      target_version: 2,
      reason: 'rollback bad policy'
    });
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

    fireEvent.click(screen.getByRole('button', { name: /incidents/i }));
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

function cleanupChartArtifacts() {
  document.querySelectorAll('body > svg[aria-hidden="true"]').forEach((node) => node.remove());
}

function clickButtonByText(text: string | RegExp) {
  const node = screen.getByText(text);
  const button = node.closest('button');
  if (!button) throw new Error(`no button found for ${String(text)}`);
  fireEvent.click(button);
}

async function fillField(label: string | RegExp, value: string) {
  const controls = await screen.findAllByLabelText(label);
  const control = controls.find((item) => (
    item instanceof HTMLInputElement ||
    item instanceof HTMLTextAreaElement ||
    item instanceof HTMLSelectElement
  ));
  if (!control) throw new Error(`no editable control found for ${String(label)}`);
  fireEvent.change(control, { target: { value } });
}

async function selectOption(label: string | RegExp, optionText: string) {
  const controls = await screen.findAllByLabelText(label);
  const combo = controls.find((item) => item.getAttribute('role') === 'combobox');
  if (!combo) throw new Error(`no select control found for ${String(label)}`);
  fireEvent.mouseDown(combo);
  fireEvent.click(await screen.findByText(new RegExp(`^${optionText}$`, 'i')));
}

function whitelistFixture() {
  return {
    id: 'w1',
    ebpf_id: 21,
    cidr: '198.51.100.10/32',
    scope: 'global',
    label: 'trusted-host',
    owner: 'soc',
    priority: 100,
    enabled: true,
    created_at: '2026-05-28T11:00:00Z',
    updated_at: '2026-05-28T11:00:00Z'
  };
}

function snapshotFixtures() {
  return [
    {
      version: 2,
      checksum: 'sha256:22222222222222222222222222222222',
      object_checksum: 'obj222222222222222222222222222222',
      created_by: 'operator',
      created_at: '2026-05-28T11:10:00Z'
    },
    {
      version: 1,
      checksum: 'sha256:11111111111111111111111111111111',
      object_checksum: 'obj111111111111111111111111111111',
      created_by: 'operator',
      created_at: '2026-05-28T11:00:00Z'
    }
  ];
}

function snapshotDiffFixture() {
  const emptyCollection = { added: [], removed: [], changed: [], unchanged: 0 };
  return {
    from_version: 1,
    to_version: 2,
    object_checksum: { from: 'obj111', to: 'obj222', changed: true },
    services: {
      added: [],
      removed: [],
      changed: [{
        key: 'service:api-https',
        before: { name: 'api-https', enabled: true },
        after: { name: 'api-https', enabled: false }
      }],
      unchanged: 0
    },
    whitelist_v4: emptyCollection,
    blacklist_v4: emptyCollection,
    rules: emptyCollection
  };
}

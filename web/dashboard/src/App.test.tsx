import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App, { DashboardShell, type Tab } from './App';
import { dashboardFixture, defaultTenant, operatorUser, viewerUser } from './test/fixtures';
import type { DashboardData, User } from './types';

const data = dashboardFixture();
const adminUser: User = { id: 'u3', username: 'admin', role: 'admin' };
const platformAdminUser: User = {
  ...adminUser,
  platform_role: 'platform_admin',
  active_tenant: defaultTenant,
  tenants: [{ tenant_id: defaultTenant.id, slug: defaultTenant.slug, name: defaultTenant.name, role: 'admin', status: 'active' }]
};

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
      onTenantSwitch={vi.fn()}
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

  it('renders grouped admin navigation labels', () => {
    renderShell(viewerUser);
    for (const group of ['Operation', 'Configuration', 'Threat Intelligence', 'Setting']) {
      expect(screen.getByText(group)).toBeInTheDocument();
    }
    for (const label of ['Dashboard', 'Incidents', 'Detections', 'Events', 'Services', 'Rules', 'Whitelist', 'Blacklist', 'UDP Ports', 'Reputation', 'Snapshots', 'Accounts', 'Nodes']) {
      expect(screen.getByRole('button', { name: label })).toBeInTheDocument();
    }
    expect(screen.queryByRole('button', { name: 'Tenants' })).not.toBeInTheDocument();
  });

  it('shows tenant management navigation to platform admins', () => {
    renderShell(platformAdminUser);
    expect(screen.getByRole('button', { name: 'Tenants' })).toBeInTheDocument();
  });

  it('hides tenant switcher when operator has one tenant', () => {
    renderShell(operatorUser);
    expect(screen.queryByLabelText('tenant')).not.toBeInTheDocument();
  });

  it('switches active tenant from the topbar', async () => {
    const onTenantSwitch = vi.fn();
    render(
      <DashboardShell
        user={{
          ...platformAdminUser,
          active_tenant: defaultTenant,
          tenants: [
            { tenant_id: defaultTenant.id, slug: defaultTenant.slug, name: defaultTenant.name, role: 'admin', status: 'active' },
            { tenant_id: 'tenant-b', slug: 'tenant-b', name: 'Tenant B', role: 'admin', status: 'active' }
          ]
        }}
        data={data}
        activeTab="overview"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={vi.fn()}
        onTenantSwitch={onTenantSwitch}
        onLogout={vi.fn()}
      />
    );

    fireEvent.change(screen.getByLabelText('tenant'), { target: { value: 'tenant-b' } });

    await waitFor(() => expect(onTenantSwitch).toHaveBeenCalledWith('tenant-b'));
  });

  it('runs platform tenant create, edit and accounts jump workflows', async () => {
    const onTenantSwitch = vi.fn(async () => undefined);
    const setActiveTab = vi.fn();
    const tenantRows = [
      { tenant_id: defaultTenant.id, slug: defaultTenant.slug, name: defaultTenant.name, role: 'admin', status: 'active' },
      { tenant_id: 'tenant-b', slug: 'tenant-b', name: 'Tenant B', role: 'admin', status: 'active' }
    ];
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined
      });
      if (path === '/v1/tenants?include_revoked=true' && !init?.method) return jsonResponse(tenantRows);
      if (path === '/v1/tenants' && init?.method === 'POST') return jsonResponse({ id: 'tenant-c', slug: 'tenant-c', name: 'Tenant C', status: 'active' });
      if (path === `/v1/tenants/${defaultTenant.id}` && init?.method === 'PATCH') return jsonResponse({ ...defaultTenant, name: 'Default Tenant Updated' });
      throw new Error(`unexpected request ${path}`);
    }));

    render(
      <DashboardShell
        user={platformAdminUser}
        data={data}
        activeTab="tenants"
        setActiveTab={setActiveTab}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={vi.fn()}
        onTenantSwitch={onTenantSwitch}
        onLogout={vi.fn()}
      />
    );

    expect(await screen.findByText('Tenant B')).toBeInTheDocument();
    clickButtonByText(/add tenant/i);
    await fillField(/^slug/i, 'tenant-c');
    await fillField(/^name/i, 'Tenant C');
    clickButtonByText(/^save$/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/tenants' && call.method === 'POST')).toBe(true));

    fireEvent.click(screen.getAllByText(/^edit$/i)[0].closest('button')!);
    await fillField(/^name/i, 'Default Tenant Updated');
    clickButtonByText(/^save$/i);
    await waitFor(() => expect(calls.some((call) => call.path === `/v1/tenants/${defaultTenant.id}` && call.method === 'PATCH')).toBe(true));

    const accountButtons = screen.getAllByText(/^accounts$/i);
    fireEvent.click(accountButtons[accountButtons.length - 1].closest('button')!);
    await waitFor(() => expect(onTenantSwitch).toHaveBeenCalledWith('tenant-b'));
    expect(setActiveTab).toHaveBeenCalledWith('access');
    expect(calls.find((call) => call.path === '/v1/tenants' && call.method === 'POST')?.body).toMatchObject({ slug: 'tenant-c', name: 'Tenant C', status: 'active' });
    expect(calls.find((call) => call.path === `/v1/tenants/${defaultTenant.id}` && call.method === 'PATCH')?.body).toMatchObject({ name: 'Default Tenant Updated', status: 'active' });
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
        onTenantSwitch={vi.fn()}
        onLogout={vi.fn()}
      />
    );

    expect(screen.getByText('dashboard unavailable')).toBeInTheDocument();
    expect(screen.getByText('Loading dashboard data')).toBeInTheDocument();
  });

  it('renders anomaly and baseline visibility', () => {
    renderShell(viewerUser, 'detection');
    expect(screen.getByText('alert_only')).toBeInTheDocument();
    expect(screen.getByText('pps_spike')).toBeInTheDocument();
    expect(screen.getByText('approved')).toBeInTheDocument();
  });

  it('limits Detection tables to 10 rows and paginates independently', () => {
    renderShellWithData(viewerUser, detectionPaginationFixture(), 'detection');
    const [anomalyTable, baselineTable, ruleTable] = screen.getAllByRole('table');

    expect(within(anomalyTable).getAllByRole('row')).toHaveLength(11);
    expect(within(baselineTable).getAllByRole('row')).toHaveLength(11);
    expect(within(ruleTable).getAllByRole('row')).toHaveLength(11);
    expect(within(anomalyTable).getByText('anomaly-service-01')).toBeInTheDocument();
    expect(within(anomalyTable).queryByText('anomaly-service-11')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /previous anomaly evaluations page/i })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: /next anomaly evaluations page/i }));
    expect(within(anomalyTable).getByText('anomaly-service-11')).toBeInTheDocument();
    expect(within(anomalyTable).queryByText('anomaly-service-01')).not.toBeInTheDocument();
    expect(within(baselineTable).getByText('baseline-service-01')).toBeInTheDocument();
    expect(within(ruleTable).getByText('rule-01')).toBeInTheDocument();
  });

  it('filters Detection tables independently and shows filtered empty states', async () => {
    renderShellWithData(viewerUser, detectionPaginationFixture(), 'detection');
    const [anomalyTable, baselineTable, ruleTable] = screen.getAllByRole('table');

    await fillField(/^search anomalies/i, 'source-12');
    expect(within(anomalyTable).getByText('anomaly-service-12')).toBeInTheDocument();
    expect(within(anomalyTable).queryByText('anomaly-service-01')).not.toBeInTheDocument();
    expect(within(baselineTable).getByText('baseline-service-01')).toBeInTheDocument();
    expect(within(ruleTable).getByText('rule-01')).toBeInTheDocument();

    await fillField(/^search baselines/i, 'no baseline match');
    expect(within(baselineTable).getByText('No baseline profiles match the current search')).toBeInTheDocument();
    expect(within(ruleTable).getByText('rule-01')).toBeInTheDocument();

    await fillField(/^search rules/i, 'no rule match');
    expect(within(ruleTable).getByText('No active rules match the current search')).toBeInTheDocument();
    expect(within(anomalyTable).getByText('anomaly-service-12')).toBeInTheDocument();
  });

  it('resets Detection pagination when the table search changes', async () => {
    renderShellWithData(operatorUser, detectionPaginationFixture(), 'detection');
    const [anomalyTable] = screen.getAllByRole('table');

    fireEvent.click(screen.getByRole('button', { name: /next anomaly evaluations page/i }));
    expect(within(anomalyTable).getByText('anomaly-service-11')).toBeInTheDocument();

    await fillField(/^search anomalies/i, 'anomaly-service');
    expect(within(anomalyTable).getByText('anomaly-service-01')).toBeInTheDocument();
    expect(within(anomalyTable).queryByText('anomaly-service-11')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /previous anomaly evaluations page/i })).toBeDisabled();
    expect(screen.queryByRole('button', { name: /add rule/i })).not.toBeInTheDocument();
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
        onTenantSwitch={vi.fn()}
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
        onTenantSwitch={vi.fn()}
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
        onTenantSwitch={vi.fn()}
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
        onTenantSwitch={vi.fn()}
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

  it('allows operator to save Telegram config', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const calls: unknown[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ path: input.toString(), method: init?.method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      return jsonResponse({ ...data.telegramConfig, chat_id: '5678' });
    }));

    render(
      <DashboardShell
        user={operatorUser}
        data={data}
        activeTab="incidents"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onTenantSwitch={vi.fn()}
        onLogout={vi.fn()}
      />
    );

    const tokenInput = screen.getByLabelText(/bot token/i);
    expect(tokenInput).toHaveAttribute('type', 'password');
    expect(tokenInput).toHaveValue('*****');
    fireEvent.change(tokenInput, { target: { value: '123456:abcdefghijklmnopqrstuvwxyzABCDEF' } });
    fireEvent.change(screen.getByLabelText(/chat id/i), { target: { value: '5678' } });
    fireEvent.change(screen.getByLabelText(/^reason/i), { target: { value: 'configure alert channel' } });
    fireEvent.click(screen.getByRole('button', { name: /save config/i }));

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(calls).toEqual([{
      path: '/v1/telegram/config',
      method: 'POST',
      body: {
        reason: 'configure alert channel',
        bot_token_ref: '123456:abcdefghijklmnopqrstuvwxyzABCDEF',
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

  it('filters whitelist entries through API query params', async () => {
    const globalEntry = whitelistFixture();
    const scopedEntry = { ...globalEntry, id: 'w2', cidr: '198.51.100.20/32', scope: 'service', service_id: 's1', label: 'api-customer' };
    const disabledEntry = { ...globalEntry, id: 'w3', cidr: '203.0.113.50/32', label: 'legacy-partner', enabled: false };
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push(path);
      if (init?.method) throw new Error(`unexpected mutation ${path}`);
      if (path === '/v1/whitelist') return jsonResponse([globalEntry, scopedEntry, disabledEntry]);
      if (path.includes('state=disabled')) return jsonResponse([disabledEntry]);
      if (path.includes('q=api')) return jsonResponse([scopedEntry]);
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(operatorUser, 'whitelist');
    expect(await screen.findByText('198.51.100.10/32')).toBeInTheDocument();

    await fillField(/^search/i, 'api');
    await waitFor(() => expect(calls).toContain('/v1/whitelist?q=api'));
    await waitFor(() => expect(screen.getByText('198.51.100.20/32')).toBeInTheDocument());

    await fillField(/^scope/i, 'service');
    await waitFor(() => expect(calls).toContain('/v1/whitelist?q=api&scope=service'));

    await fillField(/^service/i, 's1');
    await waitFor(() => expect(calls).toContain('/v1/whitelist?q=api&scope=service&service_id=s1'));

    await fillField(/^state/i, 'disabled');
    await waitFor(() => expect(calls).toContain('/v1/whitelist?q=api&scope=service&service_id=s1&state=disabled'));
    await waitFor(() => expect(screen.getByText('203.0.113.50/32')).toBeInTheDocument());
  });

  it('runs blacklist create, edit and soft-disable workflows', async () => {
    const entry = blacklistFixture();
    const feedEntry = blacklistFeedFixture();
    const calls: Array<{ path: string; method?: string; body: unknown; reason: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        reason: new Headers(init?.headers).get('X-Audit-Reason')
      });
      if (path.startsWith('/v1/blacklist/entries') && !init?.method) return jsonResponse(blacklistPage([entry, feedEntry]));
      if (path === '/v1/blacklist' && init?.method === 'POST') return jsonResponse({ ...entry, id: 'b2', cidr: '203.0.113.44/32', score: 90 });
      if (path === '/v1/blacklist/b1' && init?.method === 'PATCH') return jsonResponse({ ...entry, score: 95 });
      if (path === '/v1/blacklist/b1' && init?.method === 'DELETE') return jsonResponse({ ...entry, enabled: false });
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(operatorUser, 'blacklist');
    expect(await screen.findByText('198.51.100.200/32')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.8/32')).toBeInTheDocument();
    expect(screen.getByText('feed read only')).toBeInTheDocument();

    clickButtonByText(/add blacklist/i);
    await fillField(/^cidr/i, '203.0.113.44/32');
    await fillField(/^score/i, '90');
    await fillField(/^reason/i, 'block scanner');
    clickButtonByText(/save blacklist/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/blacklist' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^edit$/i);
    await fillField(/^score/i, '95');
    await fillField(/^reason/i, 'raise blacklist score');
    clickButtonByText(/save blacklist/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/blacklist/b1' && call.method === 'PATCH')).toBe(true));

    clickButtonByText(/^disable$/i);
    await fillField(/^reason/i, 'attack stopped');
    clickButtonByText(/disable entry/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/blacklist/b1' && call.method === 'DELETE')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/blacklist' && call.method === 'POST')?.body).toMatchObject({
      reason: 'block scanner',
      cidr: '203.0.113.44/32',
      source: 'manual',
      action: 'drop',
      score: 90,
      enabled: true
    });
    expect(calls.find((call) => call.path === '/v1/blacklist/b1' && call.method === 'PATCH')?.body).toMatchObject({
      reason: 'raise blacklist score',
      cidr: '198.51.100.200/32',
      source: 'manual',
      action: 'drop',
      score: 95
    });
    expect(calls.find((call) => call.path === '/v1/blacklist/b1' && call.method === 'DELETE')?.reason).toBe('attack stopped');
  });

  it('filters blacklist entries and keeps viewers read-only', async () => {
    const entry = blacklistFixture();
    const disabledEntry = { ...entry, id: 'b2', cidr: '203.0.113.50/32', reason: 'old scanner', enabled: false, status: 'disabled' };
    const feedEntry = blacklistFeedFixture();
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push(path);
      if (init?.method) throw new Error(`unexpected mutation ${path}`);
      if (path.startsWith('/v1/blacklist/entries') && path.includes('state=disabled')) return jsonResponse(blacklistPage([disabledEntry]));
      if (path.startsWith('/v1/blacklist/entries') && path.includes('q=scanner')) return jsonResponse(blacklistPage([disabledEntry]));
      if (path.startsWith('/v1/blacklist/entries')) return jsonResponse(blacklistPage([entry, disabledEntry, feedEntry]));
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(viewerUser, 'blacklist');
    expect(await screen.findByText('198.51.100.200/32')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.8/32')).toBeInTheDocument();
    expect(screen.queryByText(/add blacklist/i)).not.toBeInTheDocument();
    expect(screen.getAllByText('read only').length).toBeGreaterThan(0);
    expect(screen.getByText('feed read only')).toBeInTheDocument();

    await fillField(/^search/i, 'scanner');
    await waitFor(() => expect(calls).toContain('/v1/blacklist/entries?q=scanner&page=0&page_size=25'));
    await waitFor(() => expect(screen.getByText('203.0.113.50/32')).toBeInTheDocument());

    await fillField(/^source/i, 'manual');
    await waitFor(() => expect(calls).toContain('/v1/blacklist/entries?q=scanner&source=manual&page=0&page_size=25'));

    await fillField(/^state/i, 'disabled');
    await waitFor(() => expect(calls).toContain('/v1/blacklist/entries?q=scanner&source=manual&state=disabled&page=0&page_size=25'));
  });

  it('runs UDP source port create, edit and soft-disable workflows', async () => {
    const entry = udpPortFixture();
    const calls: Array<{ path: string; method?: string; body: unknown; reason: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        reason: new Headers(init?.headers).get('X-Audit-Reason')
      });
      if (path.startsWith('/v1/udp-source-port-blocks') && !init?.method) return jsonResponse([entry]);
      if (path === '/v1/udp-source-port-blocks' && init?.method === 'POST') return jsonResponse({ ...entry, id: 'u2', port: 11211, label: 'Memcached' });
      if (path === '/v1/udp-source-port-blocks/u1' && init?.method === 'PATCH') return jsonResponse({ ...entry, label: 'NTP reflection' });
      if (path === '/v1/udp-source-port-blocks/u1' && init?.method === 'DELETE') return jsonResponse({ ...entry, enabled: false });
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(operatorUser, 'udpPorts');
    expect(await screen.findByText('NTP')).toBeInTheDocument();

    clickButtonByText(/add port/i);
    await fillField(/^port/i, '11211');
    await fillField(/^label/i, 'Memcached');
    await fillField(/^owner/i, 'soc');
    await fillField(/^reason/i, 'block memcached reflection');
    clickButtonByText(/save port/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/udp-source-port-blocks' && call.method === 'POST')).toBe(true));

    clickButtonByText(/^edit$/i);
    await fillField(/^label/i, 'NTP reflection');
    await fillField(/^reason/i, 'rename ntp reflection');
    clickButtonByText(/save port/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/udp-source-port-blocks/u1' && call.method === 'PATCH')).toBe(true));

    clickButtonByText(/^disable$/i);
    await fillField(/^reason/i, 'attack stopped');
    clickButtonByText(/disable port/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/udp-source-port-blocks/u1' && call.method === 'DELETE')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/udp-source-port-blocks' && call.method === 'POST')?.body).toMatchObject({
      reason: 'block memcached reflection',
      port: 11211,
      label: 'Memcached',
      owner: 'soc',
      enabled: true
    });
    expect(calls.find((call) => call.path === '/v1/udp-source-port-blocks/u1' && call.method === 'PATCH')?.body).toMatchObject({
      reason: 'rename ntp reflection',
      port: 123,
      label: 'NTP reflection',
      owner: 'soc',
      enabled: true
    });
    expect(calls.find((call) => call.path === '/v1/udp-source-port-blocks/u1' && call.method === 'DELETE')?.reason).toBe('attack stopped');
  });

  it('filters UDP source ports and keeps viewers read-only', async () => {
    const entry = udpPortFixture();
    const disabledEntry = { ...entry, id: 'u2', port: 1900, label: 'SSDP', enabled: false };
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push(path);
      if (init?.method) throw new Error(`unexpected mutation ${path}`);
      if (path.startsWith('/v1/udp-source-port-blocks') && path.includes('state=disabled')) return jsonResponse([disabledEntry]);
      if (path.startsWith('/v1/udp-source-port-blocks') && path.includes('q=ssdp')) return jsonResponse([disabledEntry]);
      if (path.startsWith('/v1/udp-source-port-blocks')) return jsonResponse([entry, disabledEntry]);
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(viewerUser, 'udpPorts');
    expect(await screen.findByText('NTP')).toBeInTheDocument();
    expect(screen.queryByText(/add port/i)).not.toBeInTheDocument();
    expect(screen.getAllByText('read only').length).toBeGreaterThan(0);

    await fillField(/^search/i, 'ssdp');
    await waitFor(() => expect(calls).toContain('/v1/udp-source-port-blocks?q=ssdp'));
    await waitFor(() => expect(screen.getByText('SSDP')).toBeInTheDocument());

    await fillField(/^state/i, 'disabled');
    await waitFor(() => expect(calls).toContain('/v1/udp-source-port-blocks?q=ssdp&state=disabled'));
  });

  it('runs feed create, edit, sync and soft-disable workflows with admin credentials', async () => {
    const onRefresh = vi.fn(async () => undefined);
    const rawKey = 'raw-abuseipdb-key';
    const feedData = {
      ...data,
      feedSources: data.feedSources.map((source) => source.id === 'f1' ? { ...source, credential_ref: '***' } : source)
    };
    const calls: Array<{ path: string; method?: string; body: unknown; reason: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        reason: new Headers(init?.headers).get('X-Audit-Reason')
      });
      if (path === '/v1/feed-sources' && !init?.method) return jsonResponse(feedData.feedSources);
      if (path === '/v1/feed-sources' && init?.method === 'POST') return jsonResponse({ ...feedData.feedSources[0], id: 'f2', name: 'partner-feed', credential_ref: '***' });
      if (path === '/v1/feed-sources/f1' && init?.method === 'PATCH') return jsonResponse({ ...feedData.feedSources[0], license_note: 'commercial-ok', credential_ref: '***' });
      if (path === '/v1/feed-sources/f1/sync' && init?.method === 'POST') return jsonResponse({ ...data.feedRuns[0], id: 'fr2' });
      if (path === '/v1/feed-sources/f1' && init?.method === 'DELETE') return jsonResponse({ ...feedData.feedSources[0], enabled: false });
      throw new Error(`unexpected request ${path}`);
    }));

    render(
      <DashboardShell
        user={adminUser}
        data={feedData}
        activeTab="reputation"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={onRefresh}
        onTenantSwitch={vi.fn()}
        onLogout={vi.fn()}
      />
    );

    clickButtonByText(/add feed/i);
    await fillField(/^name/i, 'partner-feed');
    await fillField(/^url$/i, 'https://feeds.example.test/drop.json');
    await fillField(/credential ref/i, rawKey);
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
      credential_ref: rawKey
    });
    expect(calls.find((call) => call.path === '/v1/feed-sources/f1' && call.method === 'PATCH')?.body).toMatchObject({
      reason: 'update feed license',
      credential_ref: '***',
      license_note: 'commercial-ok'
    });
    expect(calls.find((call) => call.path === '/v1/feed-sources/f1/sync' && call.method === 'POST')?.body).toEqual({ reason: 'manual feed sync' });
    expect(calls.find((call) => call.path === '/v1/feed-sources/f1' && call.method === 'DELETE')?.reason).toBe('retire feed');
  });

  it('hides feed credential controls from operators', async () => {
    const feedData = {
      ...data,
      feedSources: data.feedSources.map((source) => source.id === 'f1' ? { ...source, credential_ref: undefined } : source)
    };
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined
      });
      if (path === '/v1/feed-sources' && !init?.method) return jsonResponse(feedData.feedSources);
      if (path === '/v1/feed-sources/f1' && init?.method === 'PATCH') return jsonResponse({ ...feedData.feedSources[0], license_note: 'operator-ok' });
      throw new Error(`unexpected request ${path}`);
    }));

    renderShellWithData(operatorUser, feedData, 'reputation');
    expect((await screen.findAllByText('spamhaus-drop')).length).toBeGreaterThan(0);
    clickButtonByText(/^edit$/i);
    expect(screen.queryByLabelText(/credential ref/i)).not.toBeInTheDocument();
    await fillField(/license note/i, 'operator-ok');
    await fillField(/^reason/i, 'operator updates feed metadata');
    clickButtonByText(/save feed/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/feed-sources/f1' && call.method === 'PATCH')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/feed-sources/f1' && call.method === 'PATCH')?.body).not.toHaveProperty('credential_ref');
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

  it('lets operator manage viewer accounts only', async () => {
    const managedViewer: User = { id: 'u4', username: 'analyst', role: 'viewer', status: 'active', force_password_change: true };
    const managedOperator: User = { id: 'u5', username: 'peer-operator', role: 'operator', status: 'active', force_password_change: false };
    const calls: Array<{ path: string; method?: string; body: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        method: init?.method,
        body: init?.body ? JSON.parse(init.body as string) : undefined
      });
      if (path === '/v1/users' && !init?.method) return jsonResponse([managedViewer, managedOperator]);
      if (path === '/v1/users' && init?.method === 'POST') return jsonResponse({ id: 'u6', username: 'new-viewer', role: 'viewer', status: 'active' });
      if (path === '/v1/users/u4' && init?.method === 'PATCH') return jsonResponse({ ...managedViewer, status: 'revoked' });
      throw new Error(`unexpected request ${path}`);
    }));

    renderShell(operatorUser, 'access');
    expect(await screen.findByText('analyst')).toBeInTheDocument();
    expect(screen.getByText(/add viewer/i).closest('button')).toBeTruthy();
    expect(screen.getByText('read only')).toBeInTheDocument();

    clickButtonByText(/add viewer/i);
    await fillField(/^username/i, 'new-viewer');
    await fillField(/temporary password/i, 'TempPass123!');
    await fillField(/^reason/i, 'create tenant viewer');
    clickButtonByText(/^save$/i);
    await waitFor(() => expect(calls.some((call) => call.path === '/v1/users' && call.method === 'POST')).toBe(true));

    expect(calls.find((call) => call.path === '/v1/users' && call.method === 'POST')?.body).toEqual({
      reason: 'create tenant viewer',
      username: 'new-viewer',
      password: 'TempPass123!',
      role: 'viewer'
    });
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

function detectionPaginationFixture(): DashboardData {
  const base = dashboardFixture();
  return {
    ...base,
    anomalies: Array.from({ length: 12 }, (_, index) => {
      const id = String(index + 1).padStart(2, '0');
      return {
        ...base.anomalies[0],
        id: `an-${id}`,
        service_id: `anomaly-service-id-${id}`,
        service_ebpf_id: index + 1,
        service_name: `anomaly-service-${id}`,
        baseline_id: `baseline-${id}`,
        evaluated_at: `2026-05-28T11:${id}:00Z`,
        score: 80 + index,
        confidence: 0.5 + index / 100,
        signals: [`signal-${id}`, 'pps_spike'],
        source: `source-${id}`,
        status: index % 2 === 0 ? 'alert_only' : 'observe_only'
      };
    }),
    baselines: Array.from({ length: 12 }, (_, index) => {
      const id = String(index + 1).padStart(2, '0');
      return {
        ...base.baselines[0],
        id: `baseline-${id}`,
        service_id: `baseline-service-id-${id}`,
        service_ebpf_id: index + 1,
        service_name: `baseline-service-${id}`,
        interface: `wan${index + 1}`,
        port: 4000 + index,
        expected_pps: 1000 + index,
        expected_bps: 1000000 + index,
        expected_cps: 100 + index,
        history_hours: index % 2 === 0 ? 24 : 12,
        confidence: 0.7 + index / 100,
        approved: index % 2 === 0,
        status: index % 2 === 0 ? 'approved' : 'learning'
      };
    }),
    rules: Array.from({ length: 12 }, (_, index) => {
      const id = String(index + 1).padStart(2, '0');
      return {
        ...base.rules[0],
        id: `rule-${id}`,
        ebpf_id: 100 + index,
        name: `rule-${id}`,
        action: index % 2 === 0 ? 'drop' : 'rate_limit',
        mode: index % 2 === 0 ? 'enforce' : 'observe',
        threshold_pps: 1000 + index,
        threshold_bps: 1000000 + index,
        threshold_cps: 100 + index,
        owner: `owner-${id}`,
        enabled: index % 2 === 0,
        counters: { packets: index + 1 }
      };
    })
  };
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

function blacklistFixture() {
  return {
    id: 'b1',
    ebpf_id: 31,
    cidr: '198.51.100.200/32',
    score: 80,
    action: 'drop',
    source: 'manual',
    rule_id: '',
    reason: 'manual attack source',
    enabled: true,
    status: 'enabled',
    origin: 'manual',
    editable: true,
    created_at: '2026-05-28T11:00:00Z',
    updated_at: '2026-05-28T11:00:00Z'
  };
}

function blacklistFeedFixture() {
  return {
    id: 'rep1',
    ebpf_id: 41,
    cidr: '203.0.113.8/32',
    score: 100,
    action: 'drop',
    source: 'abuseipdb',
    source_name: 'abuseipdb-fixture',
    rule_id: '',
    reason: 'abuseipdb confidence feed',
    enabled: true,
    status: 'active',
    origin: 'feed',
    editable: false,
    created_at: '2026-05-28T11:00:00Z',
    updated_at: '2026-05-28T11:00:00Z'
  };
}

function blacklistPage(items: ReturnType<typeof blacklistFixture>[]) {
  return {
    items,
    total: items.length,
    page: 0,
    page_size: 25
  };
}

function udpPortFixture() {
  return {
    id: 'u1',
    ebpf_id: 51,
    port: 123,
    label: 'NTP',
    reason: 'block reflection traffic',
    owner: 'soc',
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
    udp_source_port_blocks: emptyCollection,
    rules: emptyCollection
  };
}

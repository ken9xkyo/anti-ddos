import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App, { DashboardShell, type Tab } from './App';
import { dashboardFixture, operatorUser, viewerUser } from './test/fixtures';
import type { DashboardData, User } from './types';

const data = dashboardFixture();

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
    expect(screen.getByText('api-https')).toBeInTheDocument();
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

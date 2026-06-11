import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App, { DashboardShell, type Tab } from './App';
import { api } from './client';
import { adminUser, dashboardFixture, normalUser } from './test/fixtures';
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
      onRefresh={vi.fn()}
      onViewUserConfig={vi.fn()}
      onLogout={vi.fn()}
    />
  );
}

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init
  });
}

describe('DashboardShell RBAC', () => {
  beforeEach(() => {
    localStorage.clear();
    api.clearToken();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('renders the user dashboard without tenant or reputation navigation', () => {
    renderShell(normalUser);

    for (const group of ['Operation', 'Configuration', 'Setting']) {
      expect(screen.getByText(group)).toBeInTheDocument();
    }
    for (const label of ['Dashboard', 'Incidents', 'Detections', 'Events', 'Services', 'Rules', 'Whitelist', 'Blacklist', 'UDP Ports', 'Snapshots', 'Nodes']) {
      expect(screen.getByRole('button', { name: label })).toBeInTheDocument();
    }

    expect(screen.queryByRole('button', { name: 'Accounts' })).not.toBeInTheDocument();
    expect(screen.queryByText('Threat Intelligence')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Reputation' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Tenants' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('tenant')).not.toBeInTheDocument();
  });

  it('shows Reputation navigation only for normal admins', () => {
    const { unmount } = renderShell(adminUser);
    expect(screen.getByRole('button', { name: 'Reputation' })).toBeInTheDocument();

    unmount();
    renderShell({ ...adminUser, viewing_user: { id: normalUser.id, username: normalUser.username }, read_only: true });
    expect(screen.queryByRole('button', { name: 'Reputation' })).not.toBeInTheDocument();
  });

  it('allows users to mutate config and keeps admin view-user sessions read-only', () => {
    const viewingUser: User = {
      ...adminUser,
      viewing_user: { id: normalUser.id, username: normalUser.username },
      read_only: true
    };

    const { unmount } = renderShell(normalUser, 'services');
    expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();

    unmount();
    renderShell(viewingUser, 'services');
    expect(screen.getByText(/viewing user/i)).toBeInTheDocument();
    expect(screen.getAllByText(/read only/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: /add service/i })).not.toBeInTheDocument();
  });

  it('lets admins open a user config context from Accounts', async () => {
    const onViewUserConfig = vi.fn();
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      if (input.toString() === '/v1/users') {
        return jsonResponse([
          { id: 'u2', username: 'alice', role: 'user', status: 'active', force_password_change: false },
          { id: 'u0', username: 'admin', role: 'admin', status: 'active', force_password_change: false }
        ]);
      }
      throw new Error(`unexpected request ${input.toString()}`);
    }));

    render(
      <DashboardShell
        user={adminUser}
        data={data}
        activeTab="access"
        setActiveTab={vi.fn()}
        loading={false}
        error=""
        lastRefresh={new Date().toISOString()}
        onRefresh={vi.fn()}
        onViewUserConfig={onViewUserConfig}
        onLogout={vi.fn()}
      />
    );

    expect(await screen.findByText('alice')).toBeInTheDocument();
    fireEvent.click(screen.getAllByText(/view config/i)[0].closest('button')!);

    expect(onViewUserConfig).toHaveBeenCalledWith('u2');
  });
});

describe('App bootstrap', () => {
  beforeEach(() => {
    localStorage.clear();
    api.clearToken();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('logs in and loads dashboard data without tenant or feed endpoints', async () => {
    const responses = dashboardResponses(data);
    const seen: string[] = [];

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      seen.push(path);

      if (path === '/v1/me') {
        return new Response('', { status: 401 });
      }
      if (path === '/v1/auth/login') {
        expect(JSON.parse(init?.body as string)).toEqual({ username: 'user', password: 'secret' });
        return jsonResponse({ token: 'user-token', user: normalUser, expires_at: '2026-05-28T12:00:00Z' });
      }
      if (path in responses) {
        expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer user-token');
        return jsonResponse(responses[path]);
      }
      throw new Error(`unexpected request ${path}`);
    }));

    render(<App />);

    fireEvent.change(await screen.findByLabelText(/username/i), { target: { value: 'user' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByText('Packets/s')).toBeInTheDocument();
    await waitFor(() => expect(seen).toContain('/v1/dashboard/overview'));

    expect(localStorage.getItem('anti_ddos_token')).toBe('user-token');
    expect(seen.some((path) => path.includes('/v1/tenants'))).toBe(false);
    expect(seen.some((path) => path.includes('/v1/feed-'))).toBe(false);
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
    '/v1/telegram/config': value.telegramConfig,
    '/v1/alerts?limit=30': value.alerts
  };
}

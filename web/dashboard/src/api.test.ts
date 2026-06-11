import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiClient } from './api';
import { adminUser, dashboardFixture, normalUser } from './test/fixtures';
import type { DashboardData } from './types';

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init
  });
}

describe('ApiClient', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('stores login token and sends it on authenticated requests', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      if (path === '/v1/auth/login') {
        expect(JSON.parse(init?.body as string)).toEqual({ username: 'user', password: 'secret' });
        expect(new Headers(init?.headers).has('Authorization')).toBe(false);
        return jsonResponse({ token: 'token-user', user: normalUser, expires_at: '2026-05-28T12:00:00Z' });
      }
      if (path === '/v1/me') {
        expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token-user');
        return jsonResponse(normalUser);
      }
      throw new Error(`unexpected request ${path}`);
    }));

    const client = new ApiClient();
    const session = await client.login('user', 'secret');
    const me = await client.me();

    expect(session.user.role).toBe('user');
    expect(me.username).toBe('user');
    expect(localStorage.getItem('anti_ddos_token')).toBe('token-user');
  });

  it('opens admin read-only user config context', async () => {
    const viewed = { ...adminUser, viewing_user: { id: 'u2', username: 'user' }, read_only: true };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(input.toString()).toBe('/v1/admin/view-user');
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer admin-token');
      expect(JSON.parse(init?.body as string)).toEqual({ user_id: 'u2' });
      return jsonResponse({ token: 'view-token', user: viewed, expires_at: '2026-05-28T12:00:00Z' });
    }));

    const client = new ApiClient();
    client.setToken('admin-token');
    const session = await client.viewUserConfig('u2');

    expect(session.user.read_only).toBe(true);
    expect(session.user.viewing_user?.username).toBe('user');
    expect(localStorage.getItem('anti_ddos_token')).toBe('view-token');
  });

  it('loads user dashboard data without tenant or threat-feed endpoints', async () => {
    const data = dashboardFixture();
    const responses = dashboardResponses(data);
    const seen: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = input.toString();
      seen.push(path);
      if (!(path in responses)) {
        throw new Error(`unexpected request ${path}`);
      }
      return jsonResponse(responses[path]);
    }));

    const client = new ApiClient();
    client.setToken('token-user');
    const loaded = await client.dashboard(normalUser);

    expect(loaded.overview.traffic.pps).toBe(1200);
    expect(loaded.alerts[0].type).toBe('isp_escalation_needed');
    expect(seen.sort()).toEqual(Object.keys(responses).sort());
    expect(seen.some((path) => path.includes('/v1/tenants'))).toBe(false);
    expect(seen.some((path) => path.includes('/v1/feed-'))).toBe(false);
  });

  it('loads feed dashboard data for normal admin sessions only', async () => {
    const data = dashboardFixture();
    data.feedSources = [{ id: 'f1', name: 'global-feed', type: 'internal_json', required_for_production: false, enabled: true, interval_seconds: 3600, status: 'healthy', active_entries: 1, conflict_count: 0, parse_error_count: 0 }];
    data.feedRuns = [{ id: 'run1', source_id: 'f1', source_name: 'global-feed', started_at: '2026-05-28T11:00:00Z', status: 'success', items_fetched: 1, items_valid: 1, parse_errors: 0 }];
    data.feedConflicts = [];
    const responses = dashboardResponses(data, true);
    const seen: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = input.toString();
      seen.push(path);
      if (!(path in responses)) {
        throw new Error(`unexpected request ${path}`);
      }
      return jsonResponse(responses[path]);
    }));

    const client = new ApiClient();
    client.setToken('admin-token');
    const loaded = await client.dashboard(adminUser);

    expect(loaded.feedSources[0].name).toBe('global-feed');
    expect(seen).toContain('/v1/feed-sources');
    expect(seen).toContain('/v1/feed-runs?limit=50');
    expect(seen).toContain('/v1/feed-conflicts');
  });

  it('normalizes null dashboard lists to empty arrays', async () => {
    const data = dashboardFixture();
    const responses = dashboardResponses(data);
    responses['/v1/dashboard/overview'] = {
      ...data.overview,
      security_events: {
        ...data.overview.security_events,
        top_sources: null,
        top_ports: null,
        by_decision: null
      },
      latest_apply_status: null
    };
    for (const path of [
      '/v1/dashboard/agents',
      '/v1/dashboard/services',
      '/v1/dashboard/rules',
      '/v1/security-events?limit=50',
      '/v1/baselines',
      '/v1/anomalies?limit=30',
      '/v1/alerts?limit=30'
    ]) {
      responses[path] = null;
    }
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => jsonResponse(responses[input.toString()])));

    const client = new ApiClient();
    client.setToken('token-user');
    const loaded = await client.dashboard(normalUser);

    expect(loaded.overview.security_events.top_sources).toEqual([]);
    expect(loaded.overview.latest_apply_status).toEqual([]);
    expect(loaded.agents).toEqual([]);
    expect(loaded.events).toEqual([]);
    expect(loaded.anomalies).toEqual([]);
    expect(loaded.alerts).toEqual([]);
  });
});

function dashboardResponses(value: DashboardData, includeFeed = false): Record<string, unknown> {
  const responses: Record<string, unknown> = {
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
  if (includeFeed) {
    responses['/v1/feed-sources'] = value.feedSources;
    responses['/v1/feed-runs?limit=50'] = value.feedRuns;
    responses['/v1/feed-conflicts'] = value.feedConflicts;
  }
  return responses;
}

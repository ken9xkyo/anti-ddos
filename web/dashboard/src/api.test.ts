import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiClient } from './api';
import { dashboardFixture, operatorUser } from './test/fixtures';
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
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      if (path === '/v1/auth/login') {
        expect(init?.method).toBe('POST');
        expect(JSON.parse(init?.body as string)).toEqual({ username: 'operator', password: 'secret' });
        expect(new Headers(init?.headers).has('Authorization')).toBe(false);
        return jsonResponse({ token: 'token-operator', user: operatorUser, expires_at: '2026-05-28T12:00:00Z' });
      }
      if (path === '/v1/me') {
        expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token-operator');
        return jsonResponse(operatorUser);
      }
      throw new Error(`unexpected request ${path}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const client = new ApiClient();
    const session = await client.login('operator', 'secret');
    const me = await client.me();

    expect(session.user.username).toBe('operator');
    expect(me.role).toBe('operator');
    expect(localStorage.getItem('anti_ddos_token')).toBe('token-operator');
  });

  it('loads dashboard data from every dashboard dependency endpoint', async () => {
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
    client.setToken('token-admin');
    const loaded = await client.dashboard();

    expect(loaded.overview.traffic.pps).toBe(1200);
    expect(loaded.alerts[0].type).toBe('isp_escalation_needed');
    expect(seen.sort()).toEqual(Object.keys(responses).sort());
  });

  it('surfaces backend error bodies', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('session expired', { status: 401 })));
    const client = new ApiClient();

    await expect(client.me()).rejects.toThrow('session expired');
  });

  it('posts Telegram and ISP dashboard actions with reasons', async () => {
    const calls: Array<{ path: string; body: unknown; auth: string | null }> = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = input.toString();
      calls.push({
        path,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
        auth: new Headers(init?.headers).get('Authorization')
      });
      return jsonResponse({ ...dashboardFixture().alerts[0], type: path.includes('telegram') ? 'test_alert' : 'isp_escalation_needed' });
    }));

    const client = new ApiClient();
    client.setToken('operator-token');
    await client.testTelegram();
    await client.evaluateIspEscalation();

    expect(calls).toEqual([
      {
        path: '/v1/telegram/test',
        body: { reason: 'dashboard test alert' },
        auth: 'Bearer operator-token'
      },
      {
        path: '/v1/alerts/evaluate-isp-escalation',
        body: { reason: 'dashboard ISP escalation evaluation', target: 'manual assessment', vector: 'link_saturation' },
        auth: 'Bearer operator-token'
      }
    ]);
  });
});

function dashboardResponses(data: DashboardData): Record<string, unknown> {
  return {
    '/v1/dashboard/overview': data.overview,
    '/v1/dashboard/agents': data.agents,
    '/v1/dashboard/services': data.services,
    '/v1/dashboard/rules': data.rules,
    '/v1/security-events?limit=50': data.events,
    '/v1/baselines': data.baselines,
    '/v1/anomalies?limit=30': data.anomalies,
    '/v1/feed-sources': data.feedSources,
    '/v1/feed-runs?limit=20': data.feedRuns,
    '/v1/feed-conflicts': data.feedConflicts,
    '/v1/telegram/config': data.telegramConfig,
    '/v1/alerts?limit=30': data.alerts
  };
}

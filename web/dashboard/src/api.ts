import type { Agent, Alert, AnomalyEvaluation, BaselineProfile, DashboardData, DashboardOverview, FeedConflict, FeedRun, FeedSource, Rule, SecurityEvent, Service, ServiceInput, Session, TelegramConfig, TelegramConfigInput, User } from './types';

export class ApiClient {
  private token = localStorage.getItem('anti_ddos_token') ?? '';

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('anti_ddos_token', token);
  }

  clearToken() {
    this.token = '';
    localStorage.removeItem('anti_ddos_token');
  }

  async login(username: string, password: string): Promise<Session> {
    const session = await this.request<Session>('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    }, false);
    this.setToken(session.token);
    return session;
  }

  async me(): Promise<User> {
    return this.request<User>('/v1/me');
  }

  async dashboard(): Promise<DashboardData> {
    const [overview, agents, services, rules, events, baselines, anomalies, feedSources, feedRuns, feedConflicts, telegramConfig, alerts] = await Promise.all([
      this.request<DashboardOverview>('/v1/dashboard/overview'),
      this.request<Agent[] | null>('/v1/dashboard/agents'),
      this.request<Service[] | null>('/v1/dashboard/services'),
      this.request<Rule[] | null>('/v1/dashboard/rules'),
      this.request<SecurityEvent[] | null>('/v1/security-events?limit=50'),
      this.request<BaselineProfile[] | null>('/v1/baselines'),
      this.request<AnomalyEvaluation[] | null>('/v1/anomalies?limit=30'),
      this.request<FeedSource[] | null>('/v1/feed-sources'),
      this.request<FeedRun[] | null>('/v1/feed-runs?limit=20'),
      this.request<FeedConflict[] | null>('/v1/feed-conflicts'),
      this.request<TelegramConfig>('/v1/telegram/config'),
      this.request<Alert[] | null>('/v1/alerts?limit=30')
    ]);
    return {
      overview: normalizeOverview(overview),
      agents: asArray(agents),
      services: asArray(services),
      rules: asArray(rules),
      events: asArray(events),
      baselines: asArray(baselines),
      anomalies: asArray(anomalies),
      feedSources: asArray(feedSources),
      feedRuns: asArray(feedRuns),
      feedConflicts: asArray(feedConflicts),
      telegramConfig,
      alerts: asArray(alerts)
    };
  }

  async investigate(target: string): Promise<{ target: string; events: SecurityEvent[] }> {
    return this.request(`/v1/security-events/investigate?target=${encodeURIComponent(target)}&limit=50`);
  }

  async createService(input: ServiceInput): Promise<Service> {
    return this.request<Service>('/v1/services', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async updateService(id: string, input: ServiceInput): Promise<Service> {
    return this.request<Service>(`/v1/services/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(input)
    });
  }

  async deleteService(id: string, reason: string): Promise<Service> {
    return this.request<Service>(`/v1/services/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { 'X-Audit-Reason': reason }
    });
  }

  async configureTelegram(input: TelegramConfigInput): Promise<TelegramConfig> {
    return this.request<TelegramConfig>('/v1/telegram/config', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async testTelegram(): Promise<Alert> {
    return this.request<Alert>('/v1/telegram/test', {
      method: 'POST',
      body: JSON.stringify({ reason: 'dashboard test alert' })
    });
  }

  async evaluateIspEscalation(): Promise<Alert> {
    return this.request<Alert>('/v1/alerts/evaluate-isp-escalation', {
      method: 'POST',
      body: JSON.stringify({ reason: 'dashboard ISP escalation evaluation', target: 'manual assessment', vector: 'link_saturation' })
    });
  }

  private async request<T>(path: string, init: RequestInit = {}, authenticated = true): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    if (authenticated && this.token) {
      headers.set('Authorization', `Bearer ${this.token}`);
    }
    const response = await fetch(path, { ...init, headers });
    if (!response.ok) {
      const body = await response.text();
      throw new Error(body || `request failed: ${response.status}`);
    }
    return response.json() as Promise<T>;
  }
}

function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function normalizeOverview(overview: DashboardOverview): DashboardOverview {
  return {
    ...overview,
    latest_apply_status: asArray(overview.latest_apply_status),
    security_events: {
      ...overview.security_events,
      top_sources: asArray(overview.security_events.top_sources),
      top_ports: asArray(overview.security_events.top_ports),
      by_decision: asArray(overview.security_events.by_decision)
    }
  };
}

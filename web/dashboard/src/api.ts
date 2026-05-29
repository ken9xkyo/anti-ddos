import type {
  Agent,
  Alert,
  AnomalyEvaluation,
  AuditEvent,
  BaselineProfile,
  DashboardData,
  DashboardOverview,
  FeedConflict,
  FeedRun,
  FeedSource,
  FeedSourceInput,
  OwnPasswordInput,
  PasswordResetInput,
  Rule,
  RuleInput,
  SecurityEvent,
  Service,
  ServiceInput,
  Session,
  SnapshotDiff,
  SnapshotMetadata,
  TelegramConfig,
  TelegramConfigInput,
  User,
  UserUpdateInput,
  WhitelistEntry,
  WhitelistInput
} from './types';

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

  async changeOwnPassword(input: OwnPasswordInput): Promise<User> {
    return this.request<User>('/v1/me/password', {
      method: 'POST',
      body: JSON.stringify(input)
    });
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

  async users(): Promise<User[]> {
    return asArray(await this.request<User[] | null>('/v1/users'));
  }

  async createUser(input: { reason: string; username: string; password: string; role: string }): Promise<User> {
    return this.request<User>('/v1/users', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async updateUser(id: string, input: UserUpdateInput): Promise<User> {
    return this.request<User>(`/v1/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input)
    });
  }

  async resetUserPassword(id: string, input: PasswordResetInput): Promise<User> {
    return this.request<User>(`/v1/users/${encodeURIComponent(id)}/password-reset`, {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async revokeUserSessions(id: string, reason: string): Promise<User> {
    return this.request<User>(`/v1/users/${encodeURIComponent(id)}/sessions/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason })
    });
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

  async rules(): Promise<Rule[]> {
    return asArray(await this.request<Rule[] | null>('/v1/rules'));
  }

  async createRule(input: RuleInput): Promise<Rule> {
    return this.request<Rule>('/v1/rules', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async updateRule(id: string, input: RuleInput): Promise<Rule> {
    return this.request<Rule>(`/v1/rules/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input)
    });
  }

  async disableRule(id: string, reason: string): Promise<Rule> {
    return this.request<Rule>(`/v1/rules/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { 'X-Audit-Reason': reason }
    });
  }

  async whitelist(): Promise<WhitelistEntry[]> {
    return asArray(await this.request<WhitelistEntry[] | null>('/v1/whitelist'));
  }

  async createWhitelist(input: WhitelistInput): Promise<WhitelistEntry> {
    return this.request<WhitelistEntry>('/v1/whitelist', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async updateWhitelist(id: string, input: WhitelistInput): Promise<WhitelistEntry> {
    return this.request<WhitelistEntry>(`/v1/whitelist/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input)
    });
  }

  async disableWhitelist(id: string, reason: string): Promise<WhitelistEntry> {
    return this.request<WhitelistEntry>(`/v1/whitelist/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { 'X-Audit-Reason': reason }
    });
  }

  async feedSources(): Promise<FeedSource[]> {
    return asArray(await this.request<FeedSource[] | null>('/v1/feed-sources'));
  }

  async createFeedSource(input: FeedSourceInput): Promise<FeedSource> {
    return this.request<FeedSource>('/v1/feed-sources', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async updateFeedSource(id: string, input: FeedSourceInput): Promise<FeedSource> {
    return this.request<FeedSource>(`/v1/feed-sources/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input)
    });
  }

  async disableFeedSource(id: string, reason: string): Promise<FeedSource> {
    return this.request<FeedSource>(`/v1/feed-sources/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { 'X-Audit-Reason': reason }
    });
  }

  async syncFeedSource(id: string, reason: string): Promise<FeedRun> {
    return this.request<FeedRun>(`/v1/feed-sources/${encodeURIComponent(id)}/sync`, {
      method: 'POST',
      body: JSON.stringify({ reason })
    });
  }

  async snapshots(includeSnapshot = false): Promise<SnapshotMetadata[]> {
    return asArray(await this.request<SnapshotMetadata[] | null>(`/v1/snapshots?include_snapshot=${includeSnapshot ? 'true' : 'false'}`));
  }

  async snapshot(version: number): Promise<SnapshotMetadata> {
    return this.request<SnapshotMetadata>(`/v1/snapshots/${encodeURIComponent(String(version))}`);
  }

  async snapshotDiff(from: number, to: number): Promise<SnapshotDiff> {
    return this.request<SnapshotDiff>(`/v1/snapshots/diff?from=${encodeURIComponent(String(from))}&to=${encodeURIComponent(String(to))}`);
  }

  async rollbackSnapshot(targetVersion: number, reason: string): Promise<SnapshotMetadata> {
    return this.request<SnapshotMetadata>('/v1/snapshots/rollback', {
      method: 'POST',
      body: JSON.stringify({ target_version: targetVersion, reason })
    });
  }

  async audit(limit = 100): Promise<AuditEvent[]> {
    return asArray(await this.request<AuditEvent[] | null>(`/v1/audit?limit=${limit}`));
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

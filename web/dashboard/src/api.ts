import type {
  Agent,
  Alert,
  AuditEvent,
  BlacklistEntriesPage,
  BlacklistEntry,
  BlacklistEntryRow,
  BlacklistFilters,
  BlacklistInput,
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
  UDPSourcePortBlock,
  UDPSourcePortBlockFilters,
  UDPSourcePortBlockInput,
  User,
  UserUpdateInput,
  WhitelistEntry,
  WhitelistFilters,
  WhitelistInput,
  AllocatedCIDR,
  AllocatedCIDRInput
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
    const body = { username, password };
    const session = await this.request<Session>('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(body)
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

  async dashboard(user?: User): Promise<DashboardData> {
    const isAdmin = user?.role === 'admin';
    const canLoadFeed = isAdmin && !user.read_only && !user.viewing_user;
    const canLoadAdminOnly = isAdmin;
    const canLoadTelegram = isAdmin && !user.viewing_user;
    const baseRequests = Promise.all([
      isAdmin
        ? this.request<DashboardOverview>('/v1/dashboard/overview')
        : Promise.resolve<DashboardOverview>({
            generated_at: new Date().toISOString(),
            prometheus: { configured: false, healthy: false },
            traffic: { pps: 0, bps: 0, cps: 0 },
            decision_rates: {},
            security_events: {
              window_seconds: 0,
              total: 0,
              top_sources: [],
              top_ports: [],
              by_decision: []
            },
            agents: { total: 0, stale: 0 },
            snapshot_version: 0,
            latest_apply_status: []
          }),
      this.request<Agent[] | null>('/v1/dashboard/agents'),
      this.request<Service[] | null>('/v1/dashboard/services'),
      this.request<Rule[] | null>('/v1/dashboard/rules'),
      isAdmin
        ? this.request<SecurityEvent[] | null>('/v1/security-events?limit=50')
        : Promise.resolve<SecurityEvent[]>([]),
      canLoadTelegram
        ? this.request<TelegramConfig>('/v1/telegram/config')
        : Promise.resolve<TelegramConfig>({
            bot_token_ref: '',
            chat_id: '',
            parse_mode: '',
            enabled: false,
            bot_token_present: false,
            created_at: '',
            updated_at: ''
          }),
      canLoadAdminOnly
        ? this.request<Alert[] | null>('/v1/alerts?limit=30')
        : Promise.resolve<Alert[]>([]),
    ]);
    const feedRequests = canLoadFeed
      ? Promise.all([this.feedSources(), this.feedRuns(), this.feedConflicts()])
      : Promise.resolve<[FeedSource[], FeedRun[], FeedConflict[]]>([[], [], []]);
    const [[overview, agents, services, rules, events, telegramConfig, alerts], [feedSources, feedRuns, feedConflicts]] = await Promise.all([
      baseRequests,
      feedRequests
    ]);
    return {
      overview: normalizeOverview(overview),
      agents: asArray(agents),
      services: asArray(services),
      rules: asArray(rules),
      events: asArray(events),
      telegramConfig,
      alerts: asArray(alerts),
      feedSources,
      feedRuns,
      feedConflicts
    };
  }

  async investigate(target: string): Promise<{ target: string; events: SecurityEvent[] }> {
    return this.request(`/v1/security-events/investigate?target=${encodeURIComponent(target)}&limit=50`);
  }

  async users(): Promise<User[]> {
    return asArray(await this.request<User[] | null>('/v1/users'));
  }

  async viewUserConfig(userID: string): Promise<Session> {
    const session = await this.request<Session>('/v1/admin/view-user', {
      method: 'POST',
      body: JSON.stringify({ user_id: userID })
    });
    this.setToken(session.token);
    return session;
  }

  async createUser(input: { reason: string; username: string; password: string; role: string; default_output_interface?: string }): Promise<User> {
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

  async meAllocatedCIDRs(): Promise<AllocatedCIDR[]> {
    return asArray(await this.request<AllocatedCIDR[] | null>('/v1/me/allocated-cidrs'));
  }

  async userAllocatedCIDRs(userID: string): Promise<AllocatedCIDR[]> {
    return asArray(await this.request<AllocatedCIDR[] | null>(`/v1/users/${encodeURIComponent(userID)}/allocated-cidrs`));
  }

  async createAllocatedCIDR(userID: string, input: AllocatedCIDRInput): Promise<AllocatedCIDR> {
    return this.request<AllocatedCIDR>(`/v1/users/${encodeURIComponent(userID)}/allocated-cidrs`, {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async deleteAllocatedCIDR(userID: string, id: string, reason: string): Promise<void> {
    await this.request<any>(`/v1/users/${encodeURIComponent(userID)}/allocated-cidrs/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { 'X-Audit-Reason': reason }
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

  async whitelist(filters: WhitelistFilters = {}): Promise<WhitelistEntry[]> {
    return asArray(await this.request<WhitelistEntry[] | null>(`/v1/whitelist${whitelistFilterQuery(filters)}`));
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

  async blacklist(filters: BlacklistFilters = {}): Promise<BlacklistEntry[]> {
    return asArray(await this.request<BlacklistEntry[] | null>(`/v1/blacklist${blacklistFilterQuery(filters)}`));
  }

  async blacklistEntries(filters: BlacklistFilters = {}, page = 0, pageSize = 25): Promise<BlacklistEntriesPage> {
    return normalizeBlacklistEntriesPage(await this.request<BlacklistEntriesPage | null>(`/v1/blacklist/entries${blacklistEntriesQuery(filters, page, pageSize)}`), page, pageSize);
  }

  async createBlacklist(input: BlacklistInput): Promise<BlacklistEntry> {
    return this.request<BlacklistEntry>('/v1/blacklist', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async updateBlacklist(id: string, input: BlacklistInput): Promise<BlacklistEntry> {
    return this.request<BlacklistEntry>(`/v1/blacklist/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input)
    });
  }

  async disableBlacklist(id: string, reason: string): Promise<BlacklistEntry> {
    return this.request<BlacklistEntry>(`/v1/blacklist/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { 'X-Audit-Reason': reason }
    });
  }

  async udpSourcePortBlocks(filters: UDPSourcePortBlockFilters = {}): Promise<UDPSourcePortBlock[]> {
    return asArray(await this.request<UDPSourcePortBlock[] | null>(`/v1/udp-source-port-blocks${udpSourcePortBlockQuery(filters)}`));
  }

  async createUDPSourcePortBlock(input: UDPSourcePortBlockInput): Promise<UDPSourcePortBlock> {
    return this.request<UDPSourcePortBlock>('/v1/udp-source-port-blocks', {
      method: 'POST',
      body: JSON.stringify(input)
    });
  }

  async updateUDPSourcePortBlock(id: string, input: UDPSourcePortBlockInput): Promise<UDPSourcePortBlock> {
    return this.request<UDPSourcePortBlock>(`/v1/udp-source-port-blocks/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input)
    });
  }

  async disableUDPSourcePortBlock(id: string, reason: string): Promise<UDPSourcePortBlock> {
    return this.request<UDPSourcePortBlock>(`/v1/udp-source-port-blocks/${encodeURIComponent(id)}`, {
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

  async feedRuns(limit = 50): Promise<FeedRun[]> {
    return asArray(await this.request<FeedRun[] | null>(`/v1/feed-runs?limit=${encodeURIComponent(String(limit))}`));
  }

  async feedConflicts(): Promise<FeedConflict[]> {
    return asArray(await this.request<FeedConflict[] | null>('/v1/feed-conflicts'));
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

function whitelistFilterQuery(filters: WhitelistFilters): string {
  const params = new URLSearchParams();
  const q = filters.q?.trim();
  if (q) params.set('q', q);
  if (filters.scope_type && filters.scope_type !== 'all') params.set('scope_type', filters.scope_type);
  if (filters.scope && filters.scope !== 'all') params.set('scope', filters.scope);
  const serviceID = filters.service_id?.trim();
  if (serviceID) params.set('service_id', serviceID);
  if (filters.state && filters.state !== 'all') params.set('state', filters.state);
  if (filters.expiry && filters.expiry !== 'all') params.set('expiry', filters.expiry);
  const encoded = params.toString();
  return encoded ? `?${encoded}` : '';
}

function blacklistFilterQuery(filters: BlacklistFilters): string {
  const params = new URLSearchParams();
  const q = filters.q?.trim();
  if (q) params.set('q', q);
  const source = filters.source?.trim();
  if (source) params.set('source', source);
  if (filters.scope_type && filters.scope_type !== 'all') params.set('scope_type', filters.scope_type);
  const serviceID = filters.service_id?.trim();
  if (serviceID) params.set('service_id', serviceID);
  if (filters.origin && filters.origin !== 'all') params.set('origin', filters.origin);
  if (filters.state && filters.state !== 'all') params.set('state', filters.state);
  if (filters.expiry && filters.expiry !== 'all') params.set('expiry', filters.expiry);
  const encoded = params.toString();
  return encoded ? `?${encoded}` : '';
}

function blacklistEntriesQuery(filters: BlacklistFilters, page: number, pageSize: number): string {
  const params = new URLSearchParams();
  const q = filters.q?.trim();
  if (q) params.set('q', q);
  const source = filters.source?.trim();
  if (source) params.set('source', source);
  if (filters.scope_type && filters.scope_type !== 'all') params.set('scope_type', filters.scope_type);
  const serviceID = filters.service_id?.trim();
  if (serviceID) params.set('service_id', serviceID);
  if (filters.origin && filters.origin !== 'all') params.set('origin', filters.origin);
  if (filters.state && filters.state !== 'all') params.set('state', filters.state);
  if (filters.expiry && filters.expiry !== 'all') params.set('expiry', filters.expiry);
  params.set('page', String(page));
  params.set('page_size', String(pageSize));
  const encoded = params.toString();
  return encoded ? `?${encoded}` : '';
}

function udpSourcePortBlockQuery(filters: UDPSourcePortBlockFilters): string {
  const params = new URLSearchParams();
  const q = filters.q?.trim();
  if (q) params.set('q', q);
  if (filters.scope_type && filters.scope_type !== 'all') params.set('scope_type', filters.scope_type);
  const serviceID = filters.service_id?.trim();
  if (serviceID) params.set('service_id', serviceID);
  if (filters.state && filters.state !== 'all') params.set('state', filters.state);
  if (filters.expiry && filters.expiry !== 'all') params.set('expiry', filters.expiry);
  const encoded = params.toString();
  return encoded ? `?${encoded}` : '';
}

function normalizeBlacklistEntriesPage(value: BlacklistEntriesPage | null | undefined, page: number, pageSize: number): BlacklistEntriesPage {
  return {
    items: asArray<BlacklistEntryRow>(value?.items),
    total: value?.total ?? 0,
    page: value?.page ?? page,
    page_size: value?.page_size ?? pageSize
  };
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

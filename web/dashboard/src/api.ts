import type { Agent, DashboardData, DashboardOverview, Rule, SecurityEvent, Service, Session, User } from './types';

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
    const [overview, agents, services, rules, events] = await Promise.all([
      this.request<DashboardOverview>('/v1/dashboard/overview'),
      this.request<Agent[]>('/v1/dashboard/agents'),
      this.request<Service[]>('/v1/dashboard/services'),
      this.request<Rule[]>('/v1/dashboard/rules'),
      this.request<SecurityEvent[]>('/v1/security-events?limit=50')
    ]);
    return { overview, agents, services, rules, events };
  }

  async investigate(target: string): Promise<{ target: string; events: SecurityEvent[] }> {
    return this.request(`/v1/security-events/investigate?target=${encodeURIComponent(target)}&limit=50`);
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

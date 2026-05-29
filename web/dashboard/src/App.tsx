import { FormEvent, useCallback, useEffect, useState } from 'react';
import { LockKeyhole, Shield } from 'lucide-react';
import { api } from './client';
import { DashboardShell } from './DashboardShell';
import type { Tab } from './navigation';
import type { DashboardData, User } from './types';
import './styles.css';

export { DashboardShell };
export type { Tab };

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [data, setData] = useState<DashboardData | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<string>('');

  useEffect(() => {
    api.me().then(setUser).catch(() => undefined);
  }, []);

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      const next = await api.dashboard();
      setData(next);
      setLastRefresh(new Date().toISOString());
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'load failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    loadDashboard();
    const timer = window.setInterval(loadDashboard, 3000);
    return () => {
      window.clearInterval(timer);
    };
  }, [loadDashboard, user]);

  if (!user) {
    return <LoginView onLogin={setUser} error={error} setError={setError} />;
  }

  return (
    <DashboardShell
      user={user}
      data={data}
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      loading={loading}
      error={error}
      lastRefresh={lastRefresh}
      onRefresh={loadDashboard}
      onLogout={() => {
        api.clearToken();
        setUser(null);
        setData(null);
      }}
    />
  );
}

function LoginView({ onLogin, error, setError }: { onLogin: (user: User) => void; error: string; setError: (value: string) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const session = await api.login(username, password);
      setError('');
      onLogin(session.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'login failed');
    }
  };

  return (
    <main className="login-screen">
      <form className="login-panel" onSubmit={submit}>
        <div className="brand-row">
          <Shield size={24} />
          <div>
            <h1>Anti-DDoS Operations</h1>
            <p>Control Plane Dashboard</p>
          </div>
        </div>
        <label>
          Username
          <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" />
        </label>
        {error ? <div className="error-line">{error}</div> : null}
        <button type="submit" className="primary-action">
          <LockKeyhole size={16} />
          Sign in
        </button>
      </form>
    </main>
  );
}

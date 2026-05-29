import { useMemo } from 'react';
import {
  Clock,
  LogOut,
  RefreshCw,
  Shield
} from 'lucide-react';
import { Banner, FreshnessPill } from './components';
import { formatTime } from './format';
import { tabs, type Tab } from './navigation';
import { OverviewView } from './views/OverviewView';
import { IncidentsView } from './views/IncidentsView';
import { ServicesView } from './views/ServicesView';
import { DetectionView } from './views/DetectionView';
import { ReputationView } from './views/ReputationView';
import { FleetView } from './views/FleetView';
import { InvestigationView } from './views/InvestigationView';
import { RulesAdminView } from './views/RulesAdminView';
import { WhitelistAdminView } from './views/WhitelistAdminView';
import { SnapshotsView } from './views/SnapshotsView';
import { AccessView } from './views/AccessView';
import type { DashboardData, User } from './types';

export function DashboardShell({
  user,
  data,
  activeTab,
  setActiveTab,
  loading,
  error,
  lastRefresh,
  onRefresh,
  onLogout
}: {
  user: User;
  data: DashboardData | null;
  activeTab: Tab;
  setActiveTab: (tab: Tab) => void;
  loading: boolean;
  error: string;
  lastRefresh: string;
  onRefresh: () => void | Promise<void>;
  onLogout: () => void;
}) {
  const canMutate = user.role === 'admin' || user.role === 'operator';
  const stale = useMemo(() => {
    if (!lastRefresh) return true;
    return Date.now() - new Date(lastRefresh).getTime() > 6000;
  }, [lastRefresh]);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <Shield size={25} />
          <div>
            <h1>Anti-DDoS</h1>
            <p>Admin Dashboard v2</p>
          </div>
        </div>
        <nav className="side-nav" aria-label="Dashboard views">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button key={tab.id} className={tab.id === activeTab ? 'active' : ''} onClick={() => setActiveTab(tab.id)} type="button">
                <Icon size={16} />
                <span>{tab.label}</span>
                <small>{tab.section}</small>
              </button>
            );
          })}
        </nav>
      </aside>

      <section className="main-column">
        <header className="topbar">
          <div>
            <p className="eyebrow">Operations console</p>
            <h1>{tabs.find((tab) => tab.id === activeTab)?.label ?? activeTab}</h1>
          </div>
          <div className="topbar-actions">
            <span className="user-chip">{user.username} · {user.role}</span>
            <FreshnessPill stale={stale} text={lastRefresh ? formatTime(lastRefresh) : 'pending'} />
            <button type="button" className="icon-action" aria-label="refresh" onClick={onRefresh} disabled={loading}>
              <RefreshCw size={16} className={loading ? 'spin' : ''} />
            </button>
            <button type="button" className="icon-action" aria-label="logout" onClick={onLogout}>
              <LogOut size={16} />
            </button>
          </div>
        </header>

        {error ? <Banner tone="error">{error}</Banner> : null}
        {!data ? (
          <div className="loading-panel">
            <Clock size={18} className={loading ? 'spin' : ''} />
            Loading dashboard data
          </div>
        ) : null}

        {data && activeTab === 'overview' ? <OverviewView data={data} /> : null}
        {data && activeTab === 'incidents' ? <IncidentsView alerts={data.alerts} config={data.telegramConfig} user={user} canMutate={canMutate} onRefresh={onRefresh} /> : null}
        {data && activeTab === 'services' ? <ServicesView services={data.services} agents={data.agents} applyStatuses={data.overview.latest_apply_status} canMutate={canMutate} onRefresh={onRefresh} /> : null}
        {data && activeTab === 'rules' ? <RulesAdminView services={data.services} canMutate={canMutate} /> : null}
        {data && activeTab === 'whitelist' ? <WhitelistAdminView services={data.services} canMutate={canMutate} /> : null}
        {data && activeTab === 'detection' ? <DetectionView anomalies={data.anomalies} baselines={data.baselines} rules={data.rules} /> : null}
        {data && activeTab === 'reputation' ? <ReputationView sources={data.feedSources} runs={data.feedRuns} conflicts={data.feedConflicts} user={user} canMutate={canMutate} onRefresh={onRefresh} /> : null}
        {data && activeTab === 'snapshots' ? <SnapshotsView canMutate={canMutate} /> : null}
        {data && activeTab === 'access' ? <AccessView currentUser={user} /> : null}
        {data && activeTab === 'fleet' ? <FleetView agents={data.agents} /> : null}
        {data && activeTab === 'investigation' ? <InvestigationView events={data.events} /> : null}
      </section>
    </main>
  );
}

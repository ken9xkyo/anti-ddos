import { useMemo } from 'react';
import {
  Clock,
  LogOut,
  RefreshCw,
  Shield
} from 'lucide-react';
import { Banner, FreshnessPill } from './components';
import { formatTime } from './format';
import { navGroups, tabLabel, type Tab } from './navigation';
import { OverviewView } from './views/OverviewView';
import { IncidentsView } from './views/IncidentsView';
import { ServicesView } from './views/ServicesView';
import { FleetView } from './views/FleetView';
import { InvestigationView } from './views/InvestigationView';
import { RulesAdminView } from './views/RulesAdminView';
import { WhitelistAdminView } from './views/WhitelistAdminView';
import { BlacklistAdminView } from './views/BlacklistAdminView';
import { ReputationView } from './views/ReputationView';
import { UDPPortsAdminView } from './views/UDPPortsAdminView';
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
  onViewUserConfig,
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
  onViewUserConfig?: (userID: string) => void | Promise<void>;
  onLogout: () => void;
}) {
  const isAdmin = user.role === 'admin';
  const canMutateUserConfig = user.role === 'user' && !user.read_only;
  const canMutatePolicy = !user.read_only && (user.role === 'user' || (isAdmin && !user.viewing_user));
  const canManageReputation = isAdmin && !user.read_only && !user.viewing_user;
  const policyScopeOptions = isAdmin && !user.viewing_user ? ['admin_global' as const] : ['user_global' as const, 'service' as const];
  const visibleNavGroups = useMemo(() => navGroups.map((group) => ({
    ...group,
    items: group.items.filter((item) => {
      if (item.id === 'access') return isAdmin;
      if (item.id === 'reputation') return canManageReputation;
      if (item.id === 'incidents') return isAdmin;
      if (item.id === 'snapshots') return isAdmin;
      if (item.id === 'fleet') return isAdmin;
      return true;
    })
  })).filter((group) => group.items.length > 0), [canManageReputation, isAdmin]);
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
            <p>Admin Dashboard</p>
          </div>
        </div>
        <nav className="side-nav" aria-label="Dashboard views">
          {visibleNavGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-group-label">{group.label}</div>
              <div className="nav-group-items">
                {group.items.map((tab) => {
                  const Icon = tab.icon;
                  return (
                    <button
                      key={tab.id}
                      className={tab.id === activeTab ? 'active' : ''}
                      onClick={() => setActiveTab(tab.id)}
                      type="button"
                      aria-current={tab.id === activeTab ? 'page' : undefined}
                    >
                      <Icon size={16} />
                      <span>{tab.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
      </aside>

      <section className="main-column">
        <header className="topbar">
          <div>
            <p className="eyebrow">Operations console</p>
            <h1>{tabLabel(activeTab)}</h1>
          </div>
          <div className="topbar-actions">
            <span className="user-chip">{user.username} · {user.role}{user.viewing_user ? ` · viewing ${user.viewing_user.username}` : ''}{user.read_only ? ' · read only' : ''}</span>
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
        {data && activeTab === 'incidents' ? <IncidentsView alerts={data.alerts} config={data.telegramConfig} user={user} canMutate={isAdmin && !user.read_only && !user.viewing_user} onRefresh={onRefresh} /> : null}
        {data && activeTab === 'services' ? <ServicesView services={data.services} agents={data.agents} applyStatuses={data.overview.latest_apply_status} canMutate={canMutateUserConfig} user={user} onRefresh={onRefresh} /> : null}
        {data && activeTab === 'rules' ? <RulesAdminView services={data.services} canMutate={canMutatePolicy} scopeOptions={policyScopeOptions} /> : null}
        {data && activeTab === 'whitelist' ? <WhitelistAdminView services={data.services} canMutate={canMutatePolicy} scopeOptions={policyScopeOptions} /> : null}
        {data && activeTab === 'blacklist' ? <BlacklistAdminView services={data.services} canMutate={canMutatePolicy} scopeOptions={policyScopeOptions} /> : null}
        {data && activeTab === 'reputation' && canManageReputation ? (
          <ReputationView
            sources={data.feedSources}
            runs={data.feedRuns}
            conflicts={data.feedConflicts}
            canMutate={canManageReputation}
            onRefresh={onRefresh}
          />
        ) : null}
        {data && activeTab === 'udpPorts' ? <UDPPortsAdminView services={data.services} canMutate={canMutatePolicy} scopeOptions={policyScopeOptions} /> : null}
        {data && activeTab === 'snapshots' ? <SnapshotsView canMutate={canMutateUserConfig} /> : null}
        {data && activeTab === 'access' && isAdmin ? <AccessView currentUser={user} onViewUserConfig={onViewUserConfig} /> : null}
        {data && activeTab === 'fleet' ? <FleetView agents={data.agents} /> : null}
        {data && activeTab === 'investigation' ? <InvestigationView events={data.events} /> : null}
      </section>
    </main>
  );
}

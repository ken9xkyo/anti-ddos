import {
  Activity,
  AlertTriangle,
  Ban,
  DatabaseBackup,
  Gauge,
  ListChecks,
  Router,
  Search,
  Server,
  ShieldCheck,
  Users
} from 'lucide-react';

export const tabs = [
  { id: 'overview', label: 'Overview', section: 'Operations', icon: Gauge },
  { id: 'incidents', label: 'Incidents', section: 'Operations', icon: AlertTriangle },
  { id: 'services', label: 'Services', section: 'Policy', icon: Router },
  { id: 'rules', label: 'Rules', section: 'Policy', icon: ListChecks },
  { id: 'whitelist', label: 'Whitelist', section: 'Policy', icon: ShieldCheck },
  { id: 'detection', label: 'Detection', section: 'Policy', icon: Activity },
  { id: 'reputation', label: 'Reputation', section: 'Intelligence', icon: Ban },
  { id: 'snapshots', label: 'Snapshots', section: 'Control', icon: DatabaseBackup },
  { id: 'access', label: 'Access', section: 'Control', icon: Users },
  { id: 'fleet', label: 'Fleet', section: 'Infrastructure', icon: Server },
  { id: 'investigation', label: 'Investigation', section: 'Infrastructure', icon: Search }
] as const;

export type Tab = (typeof tabs)[number]['id'];

export function tabLabel(tab: Tab): string {
  return tabs.find((item) => item.id === tab)?.label ?? tab;
}

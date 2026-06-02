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

export const navGroups = [
  {
    label: 'Operation',
    items: [
      { id: 'overview', label: 'Dashboard', icon: Gauge },
      { id: 'incidents', label: 'Incidents', icon: AlertTriangle },
      { id: 'detection', label: 'Detections', icon: Activity },
      { id: 'investigation', label: 'Events', icon: Search }
    ]
  },
  {
    label: 'Configuration',
    items: [
      { id: 'services', label: 'Services', icon: Router },
      { id: 'rules', label: 'Rules', icon: ListChecks },
      { id: 'whitelist', label: 'Whitelist', icon: ShieldCheck },
      { id: 'blacklist', label: 'Blacklist', icon: Ban }
    ]
  },
  {
    label: 'Threat Intelligence',
    items: [
      { id: 'reputation', label: 'Reputation', icon: Ban }
    ]
  },
  {
    label: 'Setting',
    items: [
      { id: 'snapshots', label: 'Snapshots', icon: DatabaseBackup },
      { id: 'access', label: 'Accounts', icon: Users },
      { id: 'fleet', label: 'Nodes', icon: Server }
    ]
  }
] as const;

export type Tab = (typeof navGroups)[number]['items'][number]['id'];

export const tabs = navGroups.flatMap((group) => (
  group.items.map((item) => ({ ...item, section: group.label }))
));

export function tabLabel(tab: Tab): string {
  return tabs.find((item) => item.id === tab)?.label ?? tab;
}

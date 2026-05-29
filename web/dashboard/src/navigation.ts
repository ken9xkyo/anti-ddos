import {
  Activity,
  AlertTriangle,
  Ban,
  Gauge,
  Router,
  Search,
  Server
} from 'lucide-react';

export const tabs = [
  { id: 'overview', label: 'Overview', section: 'Operations', icon: Gauge },
  { id: 'incidents', label: 'Incidents', section: 'Operations', icon: AlertTriangle },
  { id: 'services', label: 'Services', section: 'Policy', icon: Router },
  { id: 'detection', label: 'Detection', section: 'Policy', icon: Activity },
  { id: 'reputation', label: 'Reputation', section: 'Intelligence', icon: Ban },
  { id: 'fleet', label: 'Fleet', section: 'Infrastructure', icon: Server },
  { id: 'investigation', label: 'Investigation', section: 'Infrastructure', icon: Search }
] as const;

export type Tab = (typeof tabs)[number]['id'];

export function tabLabel(tab: Tab): string {
  return tabs.find((item) => item.id === tab)?.label ?? tab;
}

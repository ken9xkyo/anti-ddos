import { AlertTriangle, Ban, Clock } from 'lucide-react';
import { EmptyTableRow, StatusPill, TablePanel } from '../components';
import { formatDateTime, numberValue } from '../format';
import type { FeedConflict, FeedRun, FeedSource } from '../types';

export function ReputationView({ sources, runs, conflicts }: { sources: FeedSource[]; runs: FeedRun[]; conflicts: FeedConflict[] }) {
  return (
    <section className="content-stack">
      <TablePanel icon={<Ban size={18} />} title="Threat Feeds" eyebrow={`${sources.length} sources`}>
        <thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Active</th><th>Conflicts</th><th>Errors</th><th>Next run</th><th>License</th></tr></thead>
        <tbody>{sources.length === 0 ? (
          <EmptyTableRow colSpan={8} text="No threat feed sources configured" />
        ) : sources.map((source) => (
          <tr key={source.id}>
            <td>{source.name}</td>
            <td>{source.type}</td>
            <td><StatusPill state={source.enabled ? source.status === 'healthy' ? 'ok' : source.status === 'error' ? 'warn' : 'off' : 'off'} text={source.enabled ? source.status : 'disabled'} /></td>
            <td>{numberValue(source.active_entries)}</td>
            <td>{numberValue(source.conflict_count)}</td>
            <td>{source.last_error || source.parse_error_count ? `${source.parse_error_count} parse` : 'none'}</td>
            <td>{formatDateTime(source.next_run_at)}</td>
            <td>{source.license_note || 'n/a'}</td>
          </tr>
        ))}</tbody>
      </TablePanel>

      <TablePanel icon={<Clock size={18} />} title="Feed Run History" eyebrow={`${runs.length} recent`}>
        <thead><tr><th>Source</th><th>Status</th><th>Fetched</th><th>Valid</th><th>Parse errors</th><th>Snapshot</th><th>Started</th><th>Finished</th></tr></thead>
        <tbody>{runs.length === 0 ? (
          <EmptyTableRow colSpan={8} text="No feed runs recorded" />
        ) : runs.map((run) => (
          <tr key={run.id}>
            <td>{run.source_name || run.source_id}</td>
            <td><StatusPill state={run.status === 'success' ? 'ok' : run.status === 'error' ? 'warn' : 'off'} text={run.status} /></td>
            <td>{numberValue(run.items_fetched)}</td>
            <td>{numberValue(run.items_valid)}</td>
            <td>{numberValue(run.parse_errors)}</td>
            <td>{run.snapshot_version ?? 0}</td>
            <td>{formatDateTime(run.started_at)}</td>
            <td>{formatDateTime(run.finished_at)}</td>
          </tr>
        ))}</tbody>
      </TablePanel>

      <TablePanel icon={<AlertTriangle size={18} />} title="Whitelist Conflicts" eyebrow={`${conflicts.length} active/recent`}>
        <thead><tr><th>Source</th><th>Reputation CIDR</th><th>Whitelist CIDR</th><th>Status</th><th>Detected</th></tr></thead>
        <tbody>{conflicts.length === 0 ? (
          <EmptyTableRow colSpan={5} text="No whitelist conflicts detected" />
        ) : conflicts.map((conflict) => (
          <tr key={conflict.id}>
            <td>{conflict.source_name || conflict.source_id}</td>
            <td>{conflict.reputation_cidr}</td>
            <td>{conflict.whitelist_cidr}</td>
            <td><StatusPill state="warn" text={conflict.status} /></td>
            <td>{formatDateTime(conflict.detected_at)}</td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

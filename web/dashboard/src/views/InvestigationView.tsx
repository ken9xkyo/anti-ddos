import { FormEvent, useState } from 'react';
import { Search } from 'lucide-react';
import { api } from '../client';
import { EmptyTableRow, PanelHeader, StatusPill, TablePanel } from '../components';
import { formatDateTime } from '../format';
import type { SecurityEvent } from '../types';

export function InvestigationView({ events }: { events: SecurityEvent[] }) {
  const [target, setTarget] = useState('');
  const [resultTarget, setResultTarget] = useState('');
  const [results, setResults] = useState<SecurityEvent[]>([]);
  const [error, setError] = useState('');
  const [working, setWorking] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = target.trim();
    if (!trimmed) return;
    try {
      setWorking(true);
      const next = await api.investigate(trimmed);
      setResultTarget(next.target);
      setResults(next.events ?? []);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'investigation failed');
    } finally {
      setWorking(false);
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader icon={<Search size={18} />} title="Investigate Source / Prefix / Service" />
        <form className="investigation-form" onSubmit={submit}>
          <label>
            Target
            <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="198.51.100.10 or 198.51.100.0/24" />
          </label>
          <button type="submit" className="primary-action" disabled={working || !target.trim()}>
            <Search size={15} />{working ? 'Searching' : 'Investigate'}
          </button>
          {error ? <span className="error-line inline-message">{error}</span> : null}
        </form>
      </section>

      {resultTarget ? (
        <SecurityEventTable title={`Investigation results for ${resultTarget}`} events={results} emptyText="No sampled events matched the investigation target" />
      ) : null}

      <SecurityEventTable title="Recent Sampled Events" events={events} emptyText="No sampled security events recorded" />
    </section>
  );
}

function SecurityEventTable({ title, events, emptyText }: { title: string; events: SecurityEvent[]; emptyText: string }) {
  return (
    <TablePanel icon={<Search size={18} />} title={title} eyebrow={`${events.length} samples`}>
      <thead><tr><th>Time</th><th>Source</th><th>Target</th><th>Proto</th><th>Action</th><th>Reason</th><th>Service</th><th>Rule</th><th>Sample</th></tr></thead>
      <tbody>{events.length === 0 ? (
        <EmptyTableRow colSpan={9} text={emptyText} />
      ) : events.map((event) => (
        <tr key={event.id}>
          <td>{formatDateTime(event.event_time)}</td>
          <td>{event.src_ip}</td>
          <td>{event.dst_ip}:{event.dst_port ?? 0}</td>
          <td>{event.protocol}</td>
          <td><StatusPill state={event.action === 1 || event.action === 2 ? 'warn' : event.action === 6 ? 'ok' : 'info'} text={String(event.action ?? 'n/a')} /></td>
          <td>{event.reason ?? 'n/a'}</td>
          <td>{event.service_id ?? 'n/a'}</td>
          <td>{event.rule_id ?? 'n/a'}</td>
          <td>{event.sample_rate ?? 1}x</td>
        </tr>
      ))}</tbody>
    </TablePanel>
  );
}

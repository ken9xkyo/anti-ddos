import { ReactNode } from 'react';
import { AlertTriangle, CircleDashed, Database, Search } from 'lucide-react';

export type StatusState = 'ok' | 'warn' | 'off' | 'danger' | 'info';

export function StatusPill({ state, text }: { state: StatusState; text: string }) {
  return <span className={`status-pill ${state}`}>{text}</span>;
}

export function FreshnessPill({ stale, text }: { stale: boolean; text: string }) {
  return <span className={`freshness ${stale ? 'is-stale' : 'is-fresh'}`}>{text}</span>;
}

export function MetricPanel({
  icon,
  label,
  value,
  detail,
  tone
}: {
  icon: JSX.Element;
  label: string;
  value: string;
  detail?: string;
  tone?: 'ok' | 'warn' | 'danger' | 'info';
}) {
  return (
    <section className={`metric-panel ${tone ?? ''}`}>
      <div className="metric-label">{icon}<span>{label}</span></div>
      <strong>{value}</strong>
      {detail ? <span className="metric-detail">{detail}</span> : null}
    </section>
  );
}

export function PanelHeader({
  icon,
  title,
  eyebrow,
  actions
}: {
  icon: JSX.Element;
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="panel-header">
      <div className="panel-title">
        <h2>{icon}{title}</h2>
        {eyebrow ? <span>{eyebrow}</span> : null}
      </div>
      {actions ? <div className="panel-actions">{actions}</div> : null}
    </div>
  );
}

export function TablePanel({
  icon,
  title,
  eyebrow,
  actions,
  children
}: {
  icon: JSX.Element;
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="table-panel">
      <PanelHeader icon={icon} title={title} eyebrow={eyebrow} actions={actions} />
      <div className="table-scroll"><table>{children}</table></div>
    </section>
  );
}

export function EmptyTableRow({ colSpan, text }: { colSpan: number; text: string }) {
  return (
    <tr>
      <td className="table-empty" colSpan={colSpan}>{text}</td>
    </tr>
  );
}

export function EmptyState({ text }: { text: string }) {
  return (
    <div className="empty-state">
      <CircleDashed size={16} />
      {text}
    </div>
  );
}

export function Banner({ tone, children }: { tone: 'error' | 'warn' | 'info'; children: ReactNode }) {
  const icon = tone === 'info' ? <Database size={16} /> : <AlertTriangle size={16} />;
  return <div className={`banner ${tone}`}>{icon}{children}</div>;
}

export function DataToolbar({ children }: { children: ReactNode }) {
  return <div className="data-toolbar">{children}</div>;
}

export function SearchField({
  label,
  value,
  placeholder,
  onChange
}: {
  label: string;
  value: string;
  placeholder?: string;
  onChange: (value: string) => void;
}) {
  return (
    <label>
      {label}
      <div className="input-with-icon">
        <Search size={15} />
        <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />
      </div>
    </label>
  );
}

export function TopList({ title, items }: { title: string; items: { key: string; count: number }[] }) {
  return (
    <section className="list-panel">
      <h2>{title}</h2>
      {items.length === 0 ? <p className="muted">No samples</p> : items.map((item) => (
        <div key={item.key} className="list-row"><span>{item.key}</span><strong>{item.count}</strong></div>
      ))}
    </section>
  );
}

export function SignalList({ signals }: { signals: string[] }) {
  if (signals.length === 0) {
    return <span className="muted">none</span>;
  }
  return <div className="signal-list">{signals.slice(0, 4).map((signal) => <span key={signal}>{signal}</span>)}</div>;
}

export function JsonBlock({ value }: { value: string }) {
  return <pre className="payload-box">{value}</pre>;
}

export function KeyValueGrid({ children }: { children: ReactNode }) {
  return <div className="kv-grid">{children}</div>;
}

export function KeyValue({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="kv-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

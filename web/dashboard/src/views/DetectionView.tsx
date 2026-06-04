import { useEffect, useMemo, useState } from 'react';
import { Database, ListChecks, TrendingUp } from 'lucide-react';
import { EmptyTableRow, SearchField, SignalList, StatusPill, TablePanel } from '../components';
import { durationValue, formatDateTime, numberValue, percentValue } from '../format';
import type { AnomalyEvaluation, BaselineProfile, Rule } from '../types';

const PAGE_SIZE = 10;

export function DetectionView({ anomalies, baselines, rules }: { anomalies: AnomalyEvaluation[]; baselines: BaselineProfile[]; rules: Rule[] }) {
  const anomalyPage = usePagedSearch(anomalies, anomalySearchFields);
  const baselinePage = usePagedSearch(baselines, baselineSearchFields);
  const rulePage = usePagedSearch(rules, ruleSearchFields);

  return (
    <section className="content-stack">
      <TablePanel
        icon={<TrendingUp size={18} />}
        title="Anomalies / Alerts"
        eyebrow={`${anomalies.length} evaluations`}
        actions={<TableSearch label="Search anomalies" value={anomalyPage.query} onChange={anomalyPage.setQuery} placeholder="service, signal, source, status" />}
        footer={<TablePaginationFooter label="anomaly evaluations" page={anomalyPage.page} filtered={anomalyPage.filtered.length} total={anomalies.length} onPageChange={anomalyPage.setPage} />}
      >
        <thead><tr><th>Service</th><th>Score</th><th>Confidence</th><th>Signals</th><th>Guidance</th><th>Source</th><th>Status</th><th>Evaluated</th></tr></thead>
        <tbody>{anomalies.length === 0 ? (
          <EmptyTableRow colSpan={8} text="No anomaly evaluations available" />
        ) : anomalyPage.filtered.length === 0 ? (
          <EmptyTableRow colSpan={8} text="No anomaly evaluations match the current search" />
        ) : anomalyPage.visible.map((item) => (
          <tr key={item.id}>
            <td>{item.service_name || item.service_ebpf_id || 'service'}</td>
            <td>{numberValue(item.score)}</td>
            <td>{percentValue(item.confidence)}</td>
            <td><SignalList signals={item.signals ?? []} /></td>
            <td>{item.recommended_action}</td>
            <td>{item.source || 'n/a'}</td>
            <td><StatusPill state={item.status === 'alert_only' ? 'warn' : item.status === 'observe_only' ? 'off' : 'info'} text={item.status} /></td>
            <td>{formatDateTime(item.evaluated_at)}</td>
          </tr>
        ))}</tbody>
      </TablePanel>

      <TablePanel
        icon={<Database size={18} />}
        title="Baselines"
        eyebrow={`${baselines.length} profiles`}
        actions={<TableSearch label="Search baselines" value={baselinePage.query} onChange={baselinePage.setQuery} placeholder="service, interface, protocol, status" />}
        footer={<TablePaginationFooter label="baseline profiles" page={baselinePage.page} filtered={baselinePage.filtered.length} total={baselines.length} onPageChange={baselinePage.setPage} />}
      >
        <thead><tr><th>Service</th><th>Interface</th><th>Protocol</th><th>Window</th><th>PPS</th><th>BPS</th><th>CPS</th><th>History</th><th>Confidence</th><th>Status</th></tr></thead>
        <tbody>{baselines.length === 0 ? (
          <EmptyTableRow colSpan={10} text="No baseline profiles configured" />
        ) : baselinePage.filtered.length === 0 ? (
          <EmptyTableRow colSpan={10} text="No baseline profiles match the current search" />
        ) : baselinePage.visible.map((item) => (
          <tr key={item.id}>
            <td>{item.service_name || item.service_ebpf_id || 'service'}</td>
            <td>{item.interface}</td>
            <td>{item.protocol}{item.port ? `/${item.port}` : ''}</td>
            <td>{item.window}</td>
            <td>{numberValue(item.expected_pps)}</td>
            <td>{numberValue(item.expected_bps)}</td>
            <td>{numberValue(item.expected_cps)}</td>
            <td>{item.history_hours}h</td>
            <td>{percentValue(item.confidence)}</td>
            <td><StatusPill state={item.approved && item.history_hours >= 24 ? 'ok' : 'warn'} text={item.approved && item.history_hours >= 24 ? 'approved' : 'low confidence'} /></td>
          </tr>
        ))}</tbody>
      </TablePanel>

      <TablePanel
        icon={<ListChecks size={18} />}
        title="Active Rules"
        eyebrow="read-only in v2"
        actions={<TableSearch label="Search rules" value={rulePage.query} onChange={rulePage.setQuery} placeholder="name, action, owner, state" />}
        footer={<TablePaginationFooter label="active rules" page={rulePage.page} filtered={rulePage.filtered.length} total={rules.length} onPageChange={rulePage.setPage} />}
      >
        <thead><tr><th>Name</th><th>Action</th><th>Mode</th><th>Dimension</th><th>Thresholds</th><th>TTL</th><th>Confidence</th><th>Counters</th><th>State</th></tr></thead>
        <tbody>{rules.length === 0 ? (
          <EmptyTableRow colSpan={9} text="No mitigation rules configured" />
        ) : rulePage.filtered.length === 0 ? (
          <EmptyTableRow colSpan={9} text="No active rules match the current search" />
        ) : rulePage.visible.map((rule) => (
          <tr key={rule.id}>
            <td>{rule.name}</td>
            <td>{rule.action}</td>
            <td>{rule.mode}</td>
            <td>{rule.dimension ?? 'source_service'}</td>
            <td>{rule.threshold_pps ?? 0} pps · {rule.threshold_bps ?? 0} bps · {rule.threshold_cps ?? 0} cps</td>
            <td>{durationValue(rule.ttl_remaining_seconds ?? rule.ttl_seconds)}</td>
            <td>{percentValue(rule.confidence ?? 0)}</td>
            <td>{rule.counters ? Object.keys(rule.counters).length : 0}</td>
            <td><StatusPill state={rule.enabled ? 'ok' : 'off'} text={rule.enabled ? 'enabled' : 'disabled'} /></td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

function TableSearch({
  label,
  value,
  placeholder,
  onChange
}: {
  label: string;
  value: string;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="table-search-action">
      <SearchField label={label} value={value} onChange={onChange} placeholder={placeholder} />
    </div>
  );
}

function TablePaginationFooter({
  label,
  page,
  filtered,
  total,
  onPageChange
}: {
  label: string;
  page: number;
  filtered: number;
  total: number;
  onPageChange: (page: number) => void;
}) {
  if (total === 0) return null;
  const first = filtered === 0 ? 0 : page * PAGE_SIZE + 1;
  const last = Math.min(filtered, (page + 1) * PAGE_SIZE);
  const pageCount = filtered === 0 ? 0 : Math.ceil(filtered / PAGE_SIZE);
  return (
    <div className="table-pagination" aria-label={`${label} pagination`}>
      <span>Showing {first}-{last} of {filtered} matches ({total} total)</span>
      <div className="pagination-actions">
        <button type="button" className="secondary-action" aria-label={`previous ${label} page`} onClick={() => onPageChange(page - 1)} disabled={page <= 0}>
          Previous
        </button>
        <span>Page {pageCount === 0 ? 0 : page + 1} / {pageCount}</span>
        <button type="button" className="secondary-action" aria-label={`next ${label} page`} onClick={() => onPageChange(page + 1)} disabled={filtered === 0 || page >= pageCount - 1}>
          Next
        </button>
      </div>
    </div>
  );
}

type SearchValue = string | number | boolean | null | undefined;

function usePagedSearch<T>(items: T[], fieldsForItem: (item: T) => SearchValue[]) {
  const [query, setQueryValue] = useState('');
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    const needle = normalizeSearchValue(query);
    if (!needle) return items;
    return items.filter((item) => fieldsForItem(item).some((field) => normalizeSearchValue(field).includes(needle)));
  }, [fieldsForItem, items, query]);
  const lastPage = Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1);
  const currentPage = Math.min(page, lastPage);

  useEffect(() => {
    setPage((current) => Math.min(current, lastPage));
  }, [lastPage]);

  const visible = useMemo(() => {
    const start = currentPage * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [currentPage, filtered]);

  const setQuery = (value: string) => {
    setQueryValue(value);
    setPage(0);
  };

  return { query, setQuery, page: currentPage, setPage, filtered, visible };
}

function normalizeSearchValue(value: SearchValue): string {
  return String(value ?? '').trim().toLowerCase();
}

function anomalySearchFields(item: AnomalyEvaluation): SearchValue[] {
  return [
    item.id,
    item.service_id,
    item.service_ebpf_id,
    item.service_name,
    item.baseline_id,
    item.window,
    item.score,
    numberValue(item.score),
    item.confidence,
    percentValue(item.confidence),
    item.signals?.join(' '),
    item.recommendation,
    item.recommended_action,
    item.source,
    item.status,
    item.reason,
    item.evaluated_at,
    formatDateTime(item.evaluated_at)
  ];
}

function baselineSearchFields(item: BaselineProfile): SearchValue[] {
  const displayStatus = item.approved && item.history_hours >= 24 ? 'approved' : 'low confidence';
  return [
    item.id,
    item.service_id,
    item.service_ebpf_id,
    item.service_name,
    item.interface,
    item.protocol,
    item.port,
    item.port ? `${item.protocol}/${item.port}` : item.protocol,
    item.window,
    item.expected_pps,
    numberValue(item.expected_pps),
    item.expected_bps,
    numberValue(item.expected_bps),
    item.expected_cps,
    numberValue(item.expected_cps),
    `${item.history_hours}h`,
    item.confidence,
    percentValue(item.confidence),
    item.approved,
    item.status,
    displayStatus
  ];
}

function ruleSearchFields(rule: Rule): SearchValue[] {
  const countersCount = rule.counters ? Object.keys(rule.counters).length : 0;
  return [
    rule.id,
    rule.ebpf_id,
    rule.service_id,
    rule.name,
    rule.action,
    rule.mode,
    rule.dimension ?? 'source_service',
    rule.threshold_pps ?? 0,
    rule.threshold_bps ?? 0,
    rule.threshold_cps ?? 0,
    `${rule.threshold_pps ?? 0} pps`,
    `${rule.threshold_bps ?? 0} bps`,
    `${rule.threshold_cps ?? 0} cps`,
    durationValue(rule.ttl_remaining_seconds ?? rule.ttl_seconds),
    rule.confidence ?? 0,
    percentValue(rule.confidence ?? 0),
    rule.owner,
    countersCount,
    rule.counters ? Object.keys(rule.counters).join(' ') : undefined,
    rule.counters ? Object.values(rule.counters).join(' ') : undefined,
    rule.enabled,
    rule.enabled ? 'enabled' : 'disabled'
  ];
}

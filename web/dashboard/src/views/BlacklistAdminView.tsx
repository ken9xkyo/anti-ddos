import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef, GridPaginationModel } from '@mui/x-data-grid';
import { Ban, Plus, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { DataToolbar, PanelHeader, SearchField, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { BlacklistEntriesPage, BlacklistEntryRow, BlacklistFilters, BlacklistInput, ScopeType, Service } from '../types';

type BlacklistForm = {
  reason: string;
  scope_type: ScopeType;
  service_id: string;
  cidr: string;
  source: string;
  score: string;
  rule_id: string;
  expires_at: string;
  enabled: boolean;
};

const emptyForm: BlacklistForm = {
  reason: 'update blacklist entry',
  scope_type: 'user_global',
  service_id: '',
  cidr: '',
  source: 'manual',
  score: '80',
  rule_id: '',
  expires_at: '',
  enabled: true
};

export function BlacklistAdminView({
  services,
  canMutate,
  scopeOptions
}: {
  services: Service[];
  canMutate: boolean;
  scopeOptions: ScopeType[];
}) {
  const [pageData, setPageData] = useState<BlacklistEntriesPage>({ items: [], total: 0, page: 0, page_size: 25 });
  const [paginationModel, setPaginationModel] = useState<GridPaginationModel>({ page: 0, pageSize: 25 });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [filters, setFilters] = useState<BlacklistFilters>({ origin: 'all', state: 'all', expiry: 'all' });
  const [mode, setMode] = useState<'create' | 'edit' | ''>('');
  const [target, setTarget] = useState<BlacklistEntryRow | null>(null);
  const [form, setForm] = useState<BlacklistForm>(emptyForm);
  const [disableTarget, setDisableTarget] = useState<BlacklistEntryRow | null>(null);
  const [reason, setReason] = useState('disable blacklist entry');
  const firstLoad = useRef(true);

  const entries = pageData.items;
  const defaultScopeType = scopeOptions[0] ?? 'user_global';
  const serviceName = (id?: string) => services.find((service) => service.id === id)?.name || 'all services';

  const load = async (nextFilters: BlacklistFilters, nextPagination: GridPaginationModel) => {
    try {
      setLoading(true);
      setPageData(await api.blacklistEntries(nextFilters, nextPagination.page, nextPagination.pageSize));
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load blacklist failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const delay = firstLoad.current ? 0 : 250;
    firstLoad.current = false;
    const timer = window.setTimeout(() => {
      void load(filters, paginationModel);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [filters, paginationModel]);

  const updateFilters = (patch: Partial<BlacklistFilters>) => {
    setFilters((current) => ({ ...current, ...patch }));
    setPaginationModel((current) => ({ ...current, page: 0 }));
  };

  const hasActiveFilters = Boolean(
    filters.q?.trim() ||
    filters.source?.trim() ||
    (filters.scope_type && filters.scope_type !== 'all') ||
    filters.service_id?.trim() ||
    (filters.origin && filters.origin !== 'all') ||
    (filters.state && filters.state !== 'all') ||
    (filters.expiry && filters.expiry !== 'all')
  );

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'cidr', headerName: 'CIDR', flex: 1, minWidth: 155 },
    { field: 'scope_type', headerName: 'Scope', width: 135, valueGetter: (_, row) => scopeTypeLabel(row.scope_type) },
    { field: 'service_id', headerName: 'Service', width: 130, valueGetter: (_, row) => row.scope_type === 'service' ? serviceName(row.service_id) : 'all services' },
    {
      field: 'origin',
      headerName: 'Origin',
      width: 115,
      renderCell: (params) => {
        const row = params.row as BlacklistEntryRow;
        return <StatusPill state={row.origin === 'feed' ? 'info' : 'ok'} text={row.origin} />;
      }
    },
    {
      field: 'source',
      headerName: 'Source',
      width: 160,
      valueGetter: (_, row) => row.source_name ? `${row.source_name} (${row.source})` : row.source
    },
    { field: 'owner', headerName: 'Owner', width: 115, valueGetter: (_, row) => row.owner || 'system' },
    { field: 'score', headerName: 'Score', width: 90 },
    { field: 'rule_id', headerName: 'Rule ID', width: 155, valueGetter: (_, row) => row.rule_id || 'none' },
    { field: 'expires_at', headerName: 'Expires', width: 150, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    {
      field: 'enabled',
      headerName: 'State',
      width: 120,
      renderCell: (params) => {
        const row = params.row as BlacklistEntryRow;
        return <StatusPill state={row.enabled ? 'warn' : 'off'} text={row.enabled ? 'enabled' : 'disabled'} />;
      }
    },
    { field: 'reason', headerName: 'Reason', flex: 1, minWidth: 170 },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as BlacklistEntryRow;
        if (!canMutate) return <span className="muted">read only</span>;
        if (!row.editable) return <span className="muted">{row.origin === 'feed' ? 'feed read only' : 'read only'}</span>;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" color="warning" onClick={() => {
              setDisableTarget(row);
              setReason(`disable ${row.cidr}`);
            }}>Disable</Button>
          </Stack>
        );
      }
    }
  ], [canMutate, services]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyForm, scope_type: defaultScopeType, reason: 'create blacklist entry' });
    setMode('create');
  };

  const openEdit = (entry: BlacklistEntryRow) => {
    if (!entry.editable) return;
    setTarget(entry);
    setForm({
      reason: `update ${entry.cidr}`,
      scope_type: entry.scope_type ?? defaultScopeType,
      service_id: entry.service_id ?? '',
      cidr: entry.cidr,
      source: entry.source,
      score: String(entry.score ?? 0),
      rule_id: entry.rule_id ?? '',
      expires_at: entry.expires_at ?? '',
      enabled: entry.enabled
    });
    setMode('edit');
  };

  const submit = async () => {
    try {
      const input = blacklistInputFromForm(form);
      if (mode === 'edit' && target) {
        await api.updateBlacklist(target.id, input);
        setResult(`${input.cidr} updated`);
      } else {
        await api.createBlacklist(input);
        setResult(`${input.cidr} created`);
      }
      setMode('');
      await load(filters, paginationModel);
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'blacklist mutation failed');
    }
  };

  const disable = async () => {
    if (!disableTarget) return;
    if (!disableTarget.editable) {
      setResult('feed-origin rows are read only');
      setDisableTarget(null);
      return;
    }
    try {
      await api.disableBlacklist(disableTarget.id, reason);
      setResult(`${disableTarget.cidr} disabled`);
      setDisableTarget(null);
      await load(filters, paginationModel);
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'disable blacklist failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<Ban size={18} />}
          title="Blacklist CRUD"
          eyebrow={hasActiveFilters ? `${pageData.total} matching block entries` : `${pageData.total} block entries`}
          actions={canMutate ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add blacklist</button> : null}
        />
        <DataToolbar>
          <SearchField label="Search" value={filters.q ?? ''} onChange={(value) => updateFilters({ q: value })} placeholder="cidr, source, reason, rule" />
          <SearchField label="Source" value={filters.source ?? ''} onChange={(value) => updateFilters({ source: value })} placeholder="manual, feed source" />
          <label>
            Scope
            <select value={filters.scope_type ?? 'all'} onChange={(event) => updateFilters({ scope_type: event.target.value as BlacklistFilters['scope_type'] })}>
              <option value="all">All</option>
              <option value="admin_global">Admin global</option>
              <option value="user_global">User global</option>
              <option value="service">Service</option>
            </select>
          </label>
          <label>
            Service
            <select value={filters.service_id ?? ''} onChange={(event) => updateFilters({ service_id: event.target.value })}>
              <option value="">All services</option>
              {services.map((service) => <option key={service.id} value={service.id}>{service.name}</option>)}
            </select>
          </label>
          <label>
            Origin
            <select value={filters.origin ?? 'all'} onChange={(event) => updateFilters({ origin: event.target.value as BlacklistFilters['origin'] })}>
              <option value="all">All</option>
              <option value="manual">Manual</option>
              <option value="feed">Feed</option>
            </select>
          </label>
          <label>
            State
            <select value={filters.state ?? 'all'} onChange={(event) => updateFilters({ state: event.target.value as BlacklistFilters['state'] })}>
              <option value="all">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          <label>
            Expiry
            <select value={filters.expiry ?? 'all'} onChange={(event) => updateFilters({ expiry: event.target.value as BlacklistFilters['expiry'] })}>
              <option value="all">All</option>
              <option value="valid">Valid</option>
              <option value="expired">Expired</option>
              <option value="none">No expiry</option>
            </select>
          </label>
        </DataToolbar>
        <InlineResult result={result} />
      </section>

      <AdminGrid
        rows={entries}
        columns={columns}
        loading={loading}
        emptyText={hasActiveFilters ? 'No blacklist entries match the current filters' : 'No blacklist entries configured'}
        height={540}
        rowCount={pageData.total}
        paginationMode="server"
        paginationModel={paginationModel}
        onPaginationModelChange={setPaginationModel}
        getRowId={(row) => row.id}
      />

      <AdminDrawer
        open={mode !== ''}
        title={mode === 'edit' ? `Edit ${target?.cidr ?? 'Blacklist'}` : 'Add Blacklist Entry'}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={<Save size={16} />}>Save blacklist</Button>
        </>}
      >
        <TextField label="CIDR" value={form.cidr} onChange={(event) => setForm({ ...form, cidr: event.target.value })} fullWidth required />
        <Stack direction="row" spacing={1}>
          <TextField select label="Scope" value={form.scope_type} onChange={(event) => setForm({ ...form, scope_type: event.target.value as ScopeType, service_id: '' })} fullWidth>
            {scopeOptions.map((scope) => <MenuItem key={scope} value={scope}>{scopeTypeLabel(scope)}</MenuItem>)}
          </TextField>
          <TextField select label="Service" value={form.service_id} onChange={(event) => setForm({ ...form, service_id: event.target.value })} fullWidth disabled={form.scope_type !== 'service'}>
            <MenuItem value="">Select service</MenuItem>
            {services.map((service) => <MenuItem key={service.id} value={service.id}>{service.name}</MenuItem>)}
          </TextField>
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField label="Source" value={form.source} onChange={(event) => setForm({ ...form, source: event.target.value })} fullWidth required />
          <TextField label="Score" value={form.score} onChange={(event) => setForm({ ...form, score: event.target.value })} inputMode="numeric" fullWidth />
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField label="Rule ID" value={form.rule_id} onChange={(event) => setForm({ ...form, rule_id: event.target.value })} fullWidth />
          <TextField label="Expires at" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} placeholder="2026-06-01T00:00:00Z" fullWidth />
        </Stack>
        <FormControlLabel control={<Checkbox checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />} label="Enabled" />
        <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />
      </AdminDrawer>

      <ConfirmDialog open={Boolean(disableTarget)} title={`Disable ${disableTarget?.cidr ?? 'blacklist entry'}`} confirmText="Disable entry" onCancel={() => setDisableTarget(null)} onConfirm={disable}>
        <ReasonField value={reason} onChange={setReason} />
        <div className="muted"><Trash2 size={14} /> Entry remains visible and is removed from the next active snapshot.</div>
      </ConfirmDialog>
    </section>
  );
}

function blacklistInputFromForm(form: BlacklistForm): BlacklistInput {
  return {
    reason: form.reason.trim(),
    cidr: form.cidr.trim(),
    scope_type: form.scope_type,
    service_id: form.scope_type === 'service' ? form.service_id.trim() : undefined,
    score: optionalNumber(form.score),
    action: 'drop',
    source: form.source.trim(),
    rule_id: form.rule_id.trim() || undefined,
    expires_at: form.expires_at.trim() || undefined,
    enabled: form.enabled
  };
}

function scopeTypeLabel(value?: ScopeType): string {
  if (value === 'admin_global') return 'Admin global';
  if (value === 'service') return 'Service';
  return 'User global';
}

function optionalNumber(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) throw new Error('numeric fields must be non-negative integers');
  return next;
}

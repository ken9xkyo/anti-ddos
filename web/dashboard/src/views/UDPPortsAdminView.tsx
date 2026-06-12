import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { Ban, Plus, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { DataToolbar, PanelHeader, SearchField, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { ScopeType, Service, UDPSourcePortBlock, UDPSourcePortBlockFilters, UDPSourcePortBlockInput } from '../types';

type UDPPortForm = {
  reason: string;
  scope_type: ScopeType;
  service_id: string;
  port: string;
  label: string;
  owner: string;
  expires_at: string;
  enabled: boolean;
};

const emptyForm: UDPPortForm = {
  reason: 'update UDP source port block',
  scope_type: 'user_global',
  service_id: '',
  port: '',
  label: '',
  owner: '',
  expires_at: '',
  enabled: true
};

export function UDPPortsAdminView({
  services,
  canMutate,
  scopeOptions
}: {
  services: Service[];
  canMutate: boolean;
  scopeOptions: ScopeType[];
}) {
  const [entries, setEntries] = useState<UDPSourcePortBlock[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [filters, setFilters] = useState<UDPSourcePortBlockFilters>({ state: 'all', expiry: 'all' });
  const [mode, setMode] = useState<'create' | 'edit' | ''>('');
  const [target, setTarget] = useState<UDPSourcePortBlock | null>(null);
  const [form, setForm] = useState<UDPPortForm>(emptyForm);
  const [disableTarget, setDisableTarget] = useState<UDPSourcePortBlock | null>(null);
  const [reason, setReason] = useState('disable UDP source port block');
  const firstLoad = useRef(true);
  const defaultScopeType = scopeOptions[0] ?? 'user_global';
  const serviceName = (id?: string) => services.find((service) => service.id === id)?.name || 'all services';

  const load = async (nextFilters: UDPSourcePortBlockFilters) => {
    try {
      setLoading(true);
      setEntries(await api.udpSourcePortBlocks(nextFilters));
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load UDP source port blocks failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const delay = firstLoad.current ? 0 : 250;
    firstLoad.current = false;
    const timer = window.setTimeout(() => {
      void load(filters);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [filters]);

  const hasActiveFilters = Boolean(
    filters.q?.trim() ||
    (filters.scope_type && filters.scope_type !== 'all') ||
    filters.service_id?.trim() ||
    (filters.state && filters.state !== 'all') ||
    (filters.expiry && filters.expiry !== 'all')
  );

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'port', headerName: 'Port', width: 95 },
    { field: 'scope_type', headerName: 'Scope', width: 135, valueGetter: (_, row) => scopeTypeLabel(row.scope_type) },
    { field: 'service_id', headerName: 'Service', width: 130, valueGetter: (_, row) => row.scope_type === 'service' ? serviceName(row.service_id) : 'all services' },
    { field: 'label', headerName: 'Label', flex: 1, minWidth: 155 },
    { field: 'owner', headerName: 'Owner', width: 115 },
    { field: 'expires_at', headerName: 'Expires', width: 150, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'enabled', headerName: 'State', width: 105, renderCell: (params) => <StatusPill state={params.value ? 'warn' : 'off'} text={params.value ? 'enabled' : 'disabled'} /> },
    { field: 'reason', headerName: 'Reason', flex: 1, minWidth: 180 },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as UDPSourcePortBlock;
        if (!canMutate) return <span className="muted">read only</span>;
        if (row.editable === false) return <span className="muted">read only</span>;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" color="warning" onClick={() => {
              setDisableTarget(row);
              setReason(`disable UDP source port ${row.port}`);
            }}>Disable</Button>
          </Stack>
        );
      }
    }
  ], [canMutate, services]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyForm, scope_type: defaultScopeType, reason: 'create UDP source port block' });
    setMode('create');
  };

  const openEdit = (entry: UDPSourcePortBlock) => {
    setTarget(entry);
    setForm({
      reason: `update UDP source port ${entry.port}`,
      scope_type: entry.scope_type ?? defaultScopeType,
      service_id: entry.service_id ?? '',
      port: String(entry.port),
      label: entry.label ?? '',
      owner: entry.owner,
      expires_at: entry.expires_at ?? '',
      enabled: entry.enabled
    });
    setMode('edit');
  };

  const submit = async () => {
    try {
      const input = udpPortInputFromForm(form);
      if (mode === 'edit' && target) {
        await api.updateUDPSourcePortBlock(target.id, input);
        setResult(`UDP source port ${input.port} updated`);
      } else {
        await api.createUDPSourcePortBlock(input);
        setResult(`UDP source port ${input.port} created`);
      }
      setMode('');
      await load(filters);
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'UDP source port mutation failed');
    }
  };

  const disable = async () => {
    if (!disableTarget) return;
    try {
      await api.disableUDPSourcePortBlock(disableTarget.id, reason);
      setResult(`UDP source port ${disableTarget.port} disabled`);
      setDisableTarget(null);
      await load(filters);
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'disable UDP source port failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<Ban size={18} />}
          title="UDP Source Ports"
          eyebrow={hasActiveFilters ? `${entries.length} matching ports` : `${entries.length} configured ports`}
          actions={canMutate ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add port</button> : null}
        />
        <DataToolbar className="whitelist-toolbar">
          <SearchField label="Search" value={filters.q ?? ''} onChange={(value) => setFilters({ ...filters, q: value })} placeholder="port, label, owner, reason" />
          <label>
            Scope
            <select value={filters.scope_type ?? 'all'} onChange={(event) => setFilters({ ...filters, scope_type: event.target.value as UDPSourcePortBlockFilters['scope_type'] })}>
              <option value="all">All</option>
              <option value="admin_global">Admin global</option>
              <option value="user_global">User global</option>
              <option value="service">Service</option>
            </select>
          </label>
          <label>
            Service
            <select value={filters.service_id ?? ''} onChange={(event) => setFilters({ ...filters, service_id: event.target.value })}>
              <option value="">All services</option>
              {services.map((service) => <option key={service.id} value={service.id}>{service.name}</option>)}
            </select>
          </label>
          <label>
            State
            <select value={filters.state ?? 'all'} onChange={(event) => setFilters({ ...filters, state: event.target.value as UDPSourcePortBlockFilters['state'] })}>
              <option value="all">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          <label>
            Expiry
            <select value={filters.expiry ?? 'all'} onChange={(event) => setFilters({ ...filters, expiry: event.target.value as UDPSourcePortBlockFilters['expiry'] })}>
              <option value="all">All</option>
              <option value="valid">Valid</option>
              <option value="expired">Expired</option>
              <option value="none">No expiry</option>
            </select>
          </label>
        </DataToolbar>
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={entries} columns={columns} loading={loading} emptyText={hasActiveFilters ? 'No UDP source ports match the current filters' : 'No UDP source ports configured'} height={540} />

      <AdminDrawer
        open={mode !== ''}
        title={mode === 'edit' ? `Edit UDP Port ${target?.port ?? ''}` : 'Add UDP Source Port'}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={<Save size={16} />}>Save port</Button>
        </>}
      >
        <Stack direction="row" spacing={1}>
          <TextField label="Port" value={form.port} onChange={(event) => setForm({ ...form, port: event.target.value })} inputMode="numeric" fullWidth required />
          <TextField label="Label" value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} fullWidth />
        </Stack>
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
          {mode === 'edit' ? <TextField label="Owner" value={form.owner} fullWidth disabled /> : null}
          <TextField label="Expires at" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} placeholder="2026-06-03T00:00:00Z" fullWidth />
        </Stack>
        <FormControlLabel control={<Checkbox checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />} label="Enabled" />
        <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />
      </AdminDrawer>

      <ConfirmDialog open={Boolean(disableTarget)} title={`Disable UDP source port ${disableTarget?.port ?? ''}`} confirmText="Disable port" onCancel={() => setDisableTarget(null)} onConfirm={disable}>
        <ReasonField value={reason} onChange={setReason} />
        <div className="muted"><Trash2 size={14} /> Port remains visible and is removed from the next active snapshot.</div>
      </ConfirmDialog>
    </section>
  );
}

function udpPortInputFromForm(form: UDPPortForm): UDPSourcePortBlockInput {
  return {
    reason: form.reason.trim(),
    port: parsePort(form.port),
    scope_type: form.scope_type,
    service_id: form.scope_type === 'service' ? form.service_id.trim() : undefined,
    label: form.label.trim(),
    expires_at: form.expires_at.trim() || undefined,
    enabled: form.enabled
  };
}

function scopeTypeLabel(value?: ScopeType): string {
  if (value === 'admin_global') return 'Admin global';
  if (value === 'service') return 'Service';
  return 'User global';
}

function parsePort(value: string): number {
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0 || next > 65535) throw new Error('port must be an integer from 0 to 65535');
  return next;
}

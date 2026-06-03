import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Checkbox, FormControlLabel, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { Ban, Plus, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { DataToolbar, PanelHeader, SearchField, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { UDPSourcePortBlock, UDPSourcePortBlockFilters, UDPSourcePortBlockInput } from '../types';

type UDPPortForm = {
  reason: string;
  port: string;
  label: string;
  owner: string;
  expires_at: string;
  enabled: boolean;
};

const emptyForm: UDPPortForm = {
  reason: 'update UDP source port block',
  port: '',
  label: '',
  owner: '',
  expires_at: '',
  enabled: true
};

export function UDPPortsAdminView({ canMutate }: { canMutate: boolean }) {
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
    (filters.state && filters.state !== 'all') ||
    (filters.expiry && filters.expiry !== 'all')
  );

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'port', headerName: 'Port', width: 95 },
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
  ], [canMutate]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyForm, reason: 'create UDP source port block' });
    setMode('create');
  };

  const openEdit = (entry: UDPSourcePortBlock) => {
    setTarget(entry);
    setForm({
      reason: `update UDP source port ${entry.port}`,
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
          <TextField label="Owner" value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} fullWidth required />
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
    label: form.label.trim(),
    owner: form.owner.trim(),
    expires_at: form.expires_at.trim() || undefined,
    enabled: form.enabled
  };
}

function parsePort(value: string): number {
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0 || next > 65535) throw new Error('port must be an integer from 0 to 65535');
  return next;
}

import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Checkbox, FormControlLabel, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { Ban, Plus, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { DataToolbar, PanelHeader, SearchField, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { BlacklistEntry, BlacklistFilters, BlacklistInput } from '../types';

type BlacklistForm = {
  reason: string;
  cidr: string;
  source: string;
  score: string;
  rule_id: string;
  expires_at: string;
  enabled: boolean;
};

const emptyForm: BlacklistForm = {
  reason: 'update blacklist entry',
  cidr: '',
  source: 'manual',
  score: '80',
  rule_id: '',
  expires_at: '',
  enabled: true
};

export function BlacklistAdminView({ canMutate }: { canMutate: boolean }) {
  const [entries, setEntries] = useState<BlacklistEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [filters, setFilters] = useState<BlacklistFilters>({ state: 'all', expiry: 'all' });
  const [mode, setMode] = useState<'create' | 'edit' | ''>('');
  const [target, setTarget] = useState<BlacklistEntry | null>(null);
  const [form, setForm] = useState<BlacklistForm>(emptyForm);
  const [disableTarget, setDisableTarget] = useState<BlacklistEntry | null>(null);
  const [reason, setReason] = useState('disable blacklist entry');
  const firstLoad = useRef(true);

  const load = async (nextFilters: BlacklistFilters) => {
    try {
      setLoading(true);
      setEntries(await api.blacklist(nextFilters));
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
      void load(filters);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [filters]);

  const hasActiveFilters = Boolean(
    filters.q?.trim() ||
    filters.source?.trim() ||
    (filters.state && filters.state !== 'all') ||
    (filters.expiry && filters.expiry !== 'all')
  );

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'cidr', headerName: 'CIDR', flex: 1, minWidth: 155 },
    { field: 'source', headerName: 'Source', width: 120 },
    { field: 'score', headerName: 'Score', width: 90 },
    { field: 'rule_id', headerName: 'Rule ID', width: 155, valueGetter: (_, row) => row.rule_id || 'none' },
    { field: 'expires_at', headerName: 'Expires', width: 150, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'enabled', headerName: 'State', width: 105, renderCell: (params) => <StatusPill state={params.value ? 'warn' : 'off'} text={params.value ? 'enabled' : 'disabled'} /> },
    { field: 'reason', headerName: 'Reason', flex: 1, minWidth: 170 },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as BlacklistEntry;
        if (!canMutate) return <span className="muted">read only</span>;
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
  ], [canMutate]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyForm, reason: 'create blacklist entry' });
    setMode('create');
  };

  const openEdit = (entry: BlacklistEntry) => {
    setTarget(entry);
    setForm({
      reason: `update ${entry.cidr}`,
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
      await load(filters);
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'blacklist mutation failed');
    }
  };

  const disable = async () => {
    if (!disableTarget) return;
    try {
      await api.disableBlacklist(disableTarget.id, reason);
      setResult(`${disableTarget.cidr} disabled`);
      setDisableTarget(null);
      await load(filters);
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
          eyebrow={hasActiveFilters ? `${entries.length} matching block entries` : `${entries.length} block entries`}
          actions={canMutate ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add blacklist</button> : null}
        />
        <DataToolbar className="whitelist-toolbar">
          <SearchField label="Search" value={filters.q ?? ''} onChange={(value) => setFilters({ ...filters, q: value })} placeholder="cidr, source, reason, rule" />
          <SearchField label="Source" value={filters.source ?? ''} onChange={(value) => setFilters({ ...filters, source: value })} placeholder="manual" />
          <label>
            State
            <select value={filters.state ?? 'all'} onChange={(event) => setFilters({ ...filters, state: event.target.value as BlacklistFilters['state'] })}>
              <option value="all">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          <label>
            Expiry
            <select value={filters.expiry ?? 'all'} onChange={(event) => setFilters({ ...filters, expiry: event.target.value as BlacklistFilters['expiry'] })}>
              <option value="all">All</option>
              <option value="valid">Valid</option>
              <option value="expired">Expired</option>
              <option value="none">No expiry</option>
            </select>
          </label>
        </DataToolbar>
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={entries} columns={columns} loading={loading} emptyText={hasActiveFilters ? 'No blacklist entries match the current filters' : 'No blacklist entries configured'} height={540} />

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
    score: optionalNumber(form.score),
    action: 'drop',
    source: form.source.trim(),
    rule_id: form.rule_id.trim() || undefined,
    expires_at: form.expires_at.trim() || undefined,
    enabled: form.enabled
  };
}

function optionalNumber(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) throw new Error('numeric fields must be non-negative integers');
  return next;
}

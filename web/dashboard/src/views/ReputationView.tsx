import { useEffect, useMemo, useState } from 'react';
import { Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { AlertTriangle, Ban, Clock, Plus, RefreshCw, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, JsonTextField, parseJsonObject, ReasonField } from '../adminUi';
import { EmptyTableRow, PanelHeader, StatusPill, TablePanel } from '../components';
import { formatDateTime, numberValue } from '../format';
import type { FeedConflict, FeedRun, FeedSource, FeedSourceInput, User } from '../types';

type FeedForm = {
  reason: string;
  name: string;
  type: string;
  url: string;
  credential_ref: string;
  required_for_production: boolean;
  enabled: boolean;
  interval_seconds: string;
  license_note: string;
  quota_metadata: string;
  status: string;
};

const emptyFeedForm: FeedForm = {
  reason: 'update feed source',
  name: '',
  type: 'internal_json',
  url: '',
  credential_ref: '',
  required_for_production: false,
  enabled: false,
  interval_seconds: '3600',
  license_note: '',
  quota_metadata: '',
  status: 'placeholder'
};

export function ReputationView({
  sources,
  runs,
  conflicts,
  user,
  canMutate,
  onRefresh
}: {
  sources: FeedSource[];
  runs: FeedRun[];
  conflicts: FeedConflict[];
  user: User;
  canMutate: boolean;
  onRefresh: () => void | Promise<void>;
}) {
  const [localSources, setLocalSources] = useState<FeedSource[]>(sources);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [mode, setMode] = useState<'create' | 'edit' | ''>('');
  const [target, setTarget] = useState<FeedSource | null>(null);
  const [form, setForm] = useState<FeedForm>(emptyFeedForm);
  const [confirm, setConfirm] = useState<{ type: 'disable' | 'sync'; source: FeedSource } | null>(null);
  const [reason, setReason] = useState('update feed source');
  const canConfigureCredential = user.role === 'admin';

  useEffect(() => {
    setLocalSources(sources);
  }, [sources]);

  const loadSources = async () => {
    try {
      setLoading(true);
      setLocalSources(await api.feedSources());
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load feed sources failed');
    } finally {
      setLoading(false);
    }
  };

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'name', headerName: 'Name', flex: 1, minWidth: 180 },
    { field: 'type', headerName: 'Type', width: 145 },
    {
      field: 'status',
      headerName: 'Status',
      width: 145,
      renderCell: (params) => {
        const row = params.row as FeedSource;
        return <StatusPill state={row.enabled ? row.status === 'healthy' ? 'ok' : row.status === 'error' ? 'warn' : 'info' : 'off'} text={row.enabled ? row.status : 'disabled'} />;
      }
    },
    { field: 'active_entries', headerName: 'Active', width: 100 },
    { field: 'conflict_count', headerName: 'Conflicts', width: 110 },
    { field: 'parse_error_count', headerName: 'Parse errors', width: 120 },
    { field: 'next_run_at', headerName: 'Next run', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'license_note', headerName: 'License', width: 170 },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 245,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as FeedSource;
        if (!canMutate) return <span className="muted">read only</span>;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" onClick={() => {
              setConfirm({ type: 'sync', source: row });
              setReason(`sync ${row.name}`);
            }}>Sync</Button>
            <Button size="small" variant="outlined" color="warning" onClick={() => {
              setConfirm({ type: 'disable', source: row });
              setReason(`disable ${row.name}`);
            }}>Disable</Button>
          </Stack>
        );
      }
    }
  ], [canMutate]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyFeedForm, reason: 'create feed source' });
    setMode('create');
  };

  const openEdit = (source: FeedSource) => {
    setTarget(source);
    setForm({
      reason: `update ${source.name}`,
      name: source.name,
      type: source.type,
      url: source.url ?? '',
      credential_ref: '',
      required_for_production: source.required_for_production,
      enabled: source.enabled,
      interval_seconds: String(source.interval_seconds ?? 3600),
      license_note: source.license_note ?? '',
      quota_metadata: source.quota_metadata && Object.keys(source.quota_metadata).length > 0 ? JSON.stringify(source.quota_metadata, null, 2) : '',
      status: source.status
    });
    setMode('edit');
  };

  const submit = async () => {
    try {
      const input = feedInputFromForm(form, canConfigureCredential);
      if (mode === 'edit' && target) {
        await api.updateFeedSource(target.id, input);
        setResult(`${input.name} updated`);
      } else {
        await api.createFeedSource(input);
        setResult(`${input.name} created`);
      }
      setMode('');
      await loadSources();
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'feed mutation failed');
    }
  };

  const confirmAction = async () => {
    if (!confirm) return;
    try {
      if (confirm.type === 'sync') {
        await api.syncFeedSource(confirm.source.id, reason);
        setResult(`${confirm.source.name} sync started`);
      } else {
        await api.disableFeedSource(confirm.source.id, reason);
        setResult(`${confirm.source.name} disabled`);
      }
      setConfirm(null);
      await loadSources();
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'feed action failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<Ban size={18} />}
          title="Threat Feed Management"
          eyebrow={`${localSources.length} sources`}
          actions={canMutate ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add feed</button> : null}
        />
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={localSources} columns={columns} loading={loading} emptyText="No threat feed sources configured" height={500} />

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

      <AdminDrawer
        open={mode !== ''}
        title={mode === 'edit' ? `Edit ${target?.name ?? 'Feed'}` : 'Add Feed Source'}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={<Save size={16} />}>Save feed</Button>
        </>}
      >
        <TextField label="Name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} fullWidth required />
        <Stack direction="row" spacing={1}>
          <TextField select label="Type" value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value })} fullWidth>
            <MenuItem value="internal_json">Internal JSON</MenuItem>
            <MenuItem value="spamhaus_drop">Spamhaus DROP</MenuItem>
            <MenuItem value="team_cymru">Team Cymru</MenuItem>
            <MenuItem value="abuseipdb">AbuseIPDB</MenuItem>
          </TextField>
          <TextField label="Interval seconds" value={form.interval_seconds} onChange={(event) => setForm({ ...form, interval_seconds: event.target.value })} inputMode="numeric" fullWidth />
        </Stack>
        <TextField label="URL" value={form.url} onChange={(event) => setForm({ ...form, url: event.target.value })} fullWidth />
        <TextField label="Credential ref" value={form.credential_ref} onChange={(event) => setForm({ ...form, credential_ref: event.target.value })} fullWidth disabled={!canConfigureCredential} />
        <Stack direction="row" spacing={1}>
          <TextField label="Status" value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })} fullWidth />
          <TextField label="License note" value={form.license_note} onChange={(event) => setForm({ ...form, license_note: event.target.value })} fullWidth />
        </Stack>
        <Stack direction="row" spacing={2}>
          <FormControlLabel control={<Checkbox checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />} label="Enabled" />
          <FormControlLabel control={<Checkbox checked={form.required_for_production} onChange={(event) => setForm({ ...form, required_for_production: event.target.checked })} />} label="Required" />
        </Stack>
        <JsonTextField label="Quota metadata" value={form.quota_metadata} onChange={(value) => setForm({ ...form, quota_metadata: value })} />
        <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />
      </AdminDrawer>

      <ConfirmDialog
        open={Boolean(confirm)}
        title={confirm?.type === 'sync' ? `Sync ${confirm.source.name}` : `Disable ${confirm?.source.name ?? 'feed'}`}
        confirmText={confirm?.type === 'sync' ? 'Sync feed' : 'Disable feed'}
        onCancel={() => setConfirm(null)}
        onConfirm={confirmAction}
      >
        <Stack spacing={1.5}>
          <ReasonField value={reason} onChange={setReason} />
          <div className="muted">{confirm?.type === 'sync' ? <RefreshCw size={14} /> : <Trash2 size={14} />} {confirm?.source.type ?? 'feed'}</div>
        </Stack>
      </ConfirmDialog>
    </section>
  );
}

function feedInputFromForm(form: FeedForm, includeCredential: boolean): FeedSourceInput {
  return {
    reason: form.reason.trim(),
    name: form.name.trim(),
    type: form.type,
    url: form.url.trim(),
    credential_ref: includeCredential ? form.credential_ref.trim() : undefined,
    required_for_production: form.required_for_production,
    enabled: form.enabled,
    interval_seconds: optionalNumber(form.interval_seconds),
    license_note: form.license_note.trim(),
    quota_metadata: parseJsonObject(form.quota_metadata),
    status: form.status.trim()
  };
}

function optionalNumber(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) throw new Error('numeric fields must be non-negative integers');
  return next;
}

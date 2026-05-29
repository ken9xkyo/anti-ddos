import { useEffect, useMemo, useState } from 'react';
import { Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { ShieldCheck, Plus, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { PanelHeader, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { Service, WhitelistEntry, WhitelistInput } from '../types';

type WhitelistForm = {
  reason: string;
  cidr: string;
  scope: string;
  service_id: string;
  label: string;
  owner: string;
  priority: string;
  expires_at: string;
  enabled: boolean;
};

const emptyForm: WhitelistForm = {
  reason: 'update whitelist entry',
  cidr: '',
  scope: 'global',
  service_id: '',
  label: '',
  owner: '',
  priority: '100',
  expires_at: '',
  enabled: true
};

export function WhitelistAdminView({ services, canMutate }: { services: Service[]; canMutate: boolean }) {
  const [entries, setEntries] = useState<WhitelistEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [mode, setMode] = useState<'create' | 'edit' | ''>('');
  const [target, setTarget] = useState<WhitelistEntry | null>(null);
  const [form, setForm] = useState<WhitelistForm>(emptyForm);
  const [disableTarget, setDisableTarget] = useState<WhitelistEntry | null>(null);
  const [reason, setReason] = useState('disable whitelist entry');

  const load = async () => {
    try {
      setLoading(true);
      setEntries(await api.whitelist());
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load whitelist failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const serviceName = (id?: string) => services.find((service) => service.id === id)?.name || 'all services';
  const columns = useMemo<GridColDef[]>(() => [
    { field: 'cidr', headerName: 'CIDR', flex: 1, minWidth: 170 },
    { field: 'scope', headerName: 'Scope', width: 110 },
    { field: 'service_id', headerName: 'Service', width: 150, valueGetter: (_, row) => row.scope === 'service' ? serviceName(row.service_id) : 'global' },
    { field: 'label', headerName: 'Label', width: 150 },
    { field: 'owner', headerName: 'Owner', width: 120 },
    { field: 'priority', headerName: 'Priority', width: 100 },
    { field: 'expires_at', headerName: 'Expires', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'enabled', headerName: 'State', width: 115, renderCell: (params) => <StatusPill state={params.value ? 'ok' : 'off'} text={params.value ? 'enabled' : 'disabled'} /> },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 170,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as WhitelistEntry;
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
  ], [canMutate, services]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyForm, reason: 'create whitelist entry' });
    setMode('create');
  };

  const openEdit = (entry: WhitelistEntry) => {
    setTarget(entry);
    setForm({
      reason: `update ${entry.cidr}`,
      cidr: entry.cidr,
      scope: entry.scope,
      service_id: entry.service_id ?? '',
      label: entry.label ?? '',
      owner: entry.owner,
      priority: String(entry.priority ?? 100),
      expires_at: entry.expires_at ?? '',
      enabled: entry.enabled
    });
    setMode('edit');
  };

  const submit = async () => {
    try {
      const input = whitelistInputFromForm(form);
      if (mode === 'edit' && target) {
        await api.updateWhitelist(target.id, input);
        setResult(`${input.cidr} updated`);
      } else {
        await api.createWhitelist(input);
        setResult(`${input.cidr} created`);
      }
      setMode('');
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'whitelist mutation failed');
    }
  };

  const disable = async () => {
    if (!disableTarget) return;
    try {
      await api.disableWhitelist(disableTarget.id, reason);
      setResult(`${disableTarget.cidr} disabled`);
      setDisableTarget(null);
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'disable whitelist failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<ShieldCheck size={18} />}
          title="Whitelist CRUD"
          eyebrow={`${entries.length} allow entries`}
          actions={canMutate ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add whitelist</button> : null}
        />
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={entries} columns={columns} loading={loading} emptyText="No whitelist entries configured" height={540} />

      <AdminDrawer
        open={mode !== ''}
        title={mode === 'edit' ? `Edit ${target?.cidr ?? 'Whitelist'}` : 'Add Whitelist Entry'}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={<Save size={16} />}>Save whitelist</Button>
        </>}
      >
        <TextField label="CIDR" value={form.cidr} onChange={(event) => setForm({ ...form, cidr: event.target.value })} fullWidth required />
        <Stack direction="row" spacing={1}>
          <TextField select label="Scope" value={form.scope} onChange={(event) => setForm({ ...form, scope: event.target.value })} fullWidth>
            <MenuItem value="global">Global</MenuItem>
            <MenuItem value="service">Service</MenuItem>
          </TextField>
          <TextField select label="Service" value={form.service_id} onChange={(event) => setForm({ ...form, service_id: event.target.value })} fullWidth disabled={form.scope !== 'service'}>
            <MenuItem value="">Select service</MenuItem>
            {services.map((service) => <MenuItem key={service.id} value={service.id}>{service.name}</MenuItem>)}
          </TextField>
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField label="Label" value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} fullWidth />
          <TextField label="Owner" value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} fullWidth required />
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField label="Priority" value={form.priority} onChange={(event) => setForm({ ...form, priority: event.target.value })} inputMode="numeric" fullWidth />
          <TextField label="Expires at" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} placeholder="2026-05-29T12:00:00Z" fullWidth />
        </Stack>
        <FormControlLabel control={<Checkbox checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />} label="Enabled" />
        <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />
      </AdminDrawer>

      <ConfirmDialog open={Boolean(disableTarget)} title={`Disable ${disableTarget?.cidr ?? 'whitelist entry'}`} confirmText="Disable entry" onCancel={() => setDisableTarget(null)} onConfirm={disable}>
        <ReasonField value={reason} onChange={setReason} />
        <div className="muted"><Trash2 size={14} /> Entry remains visible and is removed from the next active snapshot.</div>
      </ConfirmDialog>
    </section>
  );
}

function whitelistInputFromForm(form: WhitelistForm): WhitelistInput {
  return {
    reason: form.reason.trim(),
    cidr: form.cidr.trim(),
    scope: form.scope,
    service_id: form.scope === 'service' ? form.service_id.trim() : undefined,
    label: form.label.trim(),
    owner: form.owner.trim(),
    priority: optionalNumber(form.priority),
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

import { useEffect, useMemo, useState } from 'react';
import { Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { ListChecks, Plus, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, JsonTextField, parseJsonObject, ReasonField } from '../adminUi';
import { PanelHeader, StatusPill } from '../components';
import { durationValue, formatDateTime, percentValue } from '../format';
import type { Rule, RuleInput, Service } from '../types';

type RuleForm = {
  reason: string;
  service_id: string;
  name: string;
  priority: string;
  action: string;
  mode: string;
  dimension: string;
  threshold_pps: string;
  threshold_bps: string;
  threshold_cps: string;
  burst_packets: string;
  burst_bytes: string;
  sample_denom: string;
  ttl_seconds: string;
  expires_at: string;
  confidence: string;
  owner: string;
  enabled: boolean;
  match_expr: string;
  evidence: string;
};

const emptyRuleForm: RuleForm = {
  reason: 'update mitigation rule',
  service_id: '',
  name: '',
  priority: '100',
  action: 'rate_limit',
  mode: 'observe',
  dimension: 'source_service',
  threshold_pps: '',
  threshold_bps: '',
  threshold_cps: '',
  burst_packets: '',
  burst_bytes: '',
  sample_denom: '',
  ttl_seconds: '',
  expires_at: '',
  confidence: '',
  owner: '',
  enabled: true,
  match_expr: '',
  evidence: ''
};

export function RulesAdminView({ services, canMutate }: { services: Service[]; canMutate: boolean }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [mode, setMode] = useState<'create' | 'edit' | ''>('');
  const [target, setTarget] = useState<Rule | null>(null);
  const [form, setForm] = useState<RuleForm>(emptyRuleForm);
  const [disableTarget, setDisableTarget] = useState<Rule | null>(null);
  const [reason, setReason] = useState('disable mitigation rule');

  const load = async () => {
    try {
      setLoading(true);
      setRules(await api.rules());
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load rules failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const serviceName = (id?: string) => services.find((service) => service.id === id)?.name || 'global';
  const columns = useMemo<GridColDef[]>(() => [
    { field: 'name', headerName: 'Name', flex: 1, minWidth: 180 },
    { field: 'service_id', headerName: 'Scope', width: 150, valueGetter: (_, row) => serviceName(row.service_id) },
    { field: 'action', headerName: 'Action', width: 115 },
    { field: 'mode', headerName: 'Mode', width: 110 },
    { field: 'dimension', headerName: 'Dimension', width: 145 },
    { field: 'thresholds', headerName: 'Thresholds', width: 240, valueGetter: (_, row) => `${row.threshold_pps ?? 0} pps / ${row.threshold_bps ?? 0} bps / ${row.threshold_cps ?? 0} cps` },
    { field: 'ttl_seconds', headerName: 'TTL', width: 110, valueFormatter: (value) => durationValue(Number(value) || undefined) },
    { field: 'confidence', headerName: 'Confidence', width: 120, valueFormatter: (value) => percentValue(Number(value) || 0) },
    { field: 'expires_at', headerName: 'Expires', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'enabled', headerName: 'State', width: 115, renderCell: (params) => <StatusPill state={params.value ? 'ok' : 'off'} text={params.value ? 'enabled' : 'disabled'} /> },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 170,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as Rule;
        if (!canMutate) return <span className="muted">read only</span>;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" color="warning" onClick={() => {
              setDisableTarget(row);
              setReason(`disable ${row.name}`);
            }}>Disable</Button>
          </Stack>
        );
      }
    }
  ], [canMutate, services]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyRuleForm, reason: 'create mitigation rule' });
    setMode('create');
  };

  const openEdit = (rule: Rule) => {
    setTarget(rule);
    setForm({
      reason: `update ${rule.name}`,
      service_id: rule.service_id ?? '',
      name: rule.name,
      priority: String(rule.priority ?? 100),
      action: rule.action,
      mode: rule.mode,
      dimension: rule.dimension ?? 'source_service',
      threshold_pps: optionalString(rule.threshold_pps),
      threshold_bps: optionalString(rule.threshold_bps),
      threshold_cps: optionalString(rule.threshold_cps),
      burst_packets: optionalString(rule.burst_packets),
      burst_bytes: optionalString(rule.burst_bytes),
      sample_denom: optionalString(rule.sample_denom),
      ttl_seconds: optionalString(rule.ttl_seconds),
      expires_at: rule.expires_at ?? '',
      confidence: optionalString(rule.confidence),
      owner: rule.owner,
      enabled: rule.enabled,
      match_expr: jsonString(rule.match_expr),
      evidence: jsonString(rule.evidence)
    });
    setMode('edit');
  };

  const submit = async () => {
    try {
      const input = ruleInputFromForm(form);
      if (mode === 'edit' && target) {
        await api.updateRule(target.id, input);
        setResult(`${input.name} updated`);
      } else {
        await api.createRule(input);
        setResult(`${input.name} created`);
      }
      setMode('');
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'rule mutation failed');
    }
  };

  const disable = async () => {
    if (!disableTarget) return;
    try {
      await api.disableRule(disableTarget.id, reason);
      setResult(`${disableTarget.name} disabled`);
      setDisableTarget(null);
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'disable rule failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<ListChecks size={18} />}
          title="Rule CRUD"
          eyebrow={`${rules.length} mitigation rules`}
          actions={canMutate ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add rule</button> : null}
        />
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={rules} columns={columns} loading={loading} emptyText="No mitigation rules configured" height={560} />

      <AdminDrawer
        open={mode !== ''}
        title={mode === 'edit' ? `Edit ${target?.name ?? 'Rule'}` : 'Add Rule'}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={<Save size={16} />}>Save rule</Button>
        </>}
      >
        <TextField label="Name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} fullWidth required />
        <TextField select label="Service scope" value={form.service_id} onChange={(event) => setForm({ ...form, service_id: event.target.value })} fullWidth>
          <MenuItem value="">Global</MenuItem>
          {services.map((service) => <MenuItem key={service.id} value={service.id}>{service.name}</MenuItem>)}
        </TextField>
        <Stack direction="row" spacing={1}>
          <TextField select label="Action" value={form.action} onChange={(event) => setForm({ ...form, action: event.target.value })} fullWidth>
            <MenuItem value="observe">Observe</MenuItem>
            <MenuItem value="drop">Drop</MenuItem>
            <MenuItem value="rate_limit">Rate limit</MenuItem>
            <MenuItem value="sample">Sample</MenuItem>
          </TextField>
          <TextField select label="Mode" value={form.mode} onChange={(event) => setForm({ ...form, mode: event.target.value })} fullWidth>
            <MenuItem value="observe">Observe</MenuItem>
            <MenuItem value="enforce">Enforce</MenuItem>
          </TextField>
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField select label="Dimension" value={form.dimension} onChange={(event) => setForm({ ...form, dimension: event.target.value })} fullWidth>
            <MenuItem value="source">Source</MenuItem>
            <MenuItem value="service">Service</MenuItem>
            <MenuItem value="source_service">Source + service</MenuItem>
          </TextField>
          <TextField label="Priority" value={form.priority} onChange={(event) => setForm({ ...form, priority: event.target.value })} inputMode="numeric" fullWidth />
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField label="PPS" value={form.threshold_pps} onChange={(event) => setForm({ ...form, threshold_pps: event.target.value })} inputMode="numeric" fullWidth />
          <TextField label="BPS" value={form.threshold_bps} onChange={(event) => setForm({ ...form, threshold_bps: event.target.value })} inputMode="numeric" fullWidth />
          <TextField label="CPS" value={form.threshold_cps} onChange={(event) => setForm({ ...form, threshold_cps: event.target.value })} inputMode="numeric" fullWidth />
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField label="Burst packets" value={form.burst_packets} onChange={(event) => setForm({ ...form, burst_packets: event.target.value })} inputMode="numeric" fullWidth />
          <TextField label="Burst bytes" value={form.burst_bytes} onChange={(event) => setForm({ ...form, burst_bytes: event.target.value })} inputMode="numeric" fullWidth />
          <TextField label="Sample denom" value={form.sample_denom} onChange={(event) => setForm({ ...form, sample_denom: event.target.value })} inputMode="numeric" fullWidth />
        </Stack>
        <Stack direction="row" spacing={1}>
          <TextField label="TTL seconds" value={form.ttl_seconds} onChange={(event) => setForm({ ...form, ttl_seconds: event.target.value })} inputMode="numeric" fullWidth />
          <TextField label="Confidence" value={form.confidence} onChange={(event) => setForm({ ...form, confidence: event.target.value })} inputMode="decimal" fullWidth />
        </Stack>
        <TextField label="Expires at" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} placeholder="2026-05-29T12:00:00Z" fullWidth />
        <TextField label="Owner" value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} fullWidth required />
        <FormControlLabel control={<Checkbox checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />} label="Enabled" />
        <JsonTextField label="Match expression" value={form.match_expr} onChange={(value) => setForm({ ...form, match_expr: value })} />
        <JsonTextField label="Evidence" value={form.evidence} onChange={(value) => setForm({ ...form, evidence: value })} />
        <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />
      </AdminDrawer>

      <ConfirmDialog open={Boolean(disableTarget)} title={`Disable ${disableTarget?.name ?? 'rule'}`} confirmText="Disable rule" onCancel={() => setDisableTarget(null)} onConfirm={disable}>
        <ReasonField value={reason} onChange={setReason} />
        <div className="muted"><Trash2 size={14} /> Rule remains visible and is removed from the next active snapshot.</div>
      </ConfirmDialog>
    </section>
  );
}

function ruleInputFromForm(form: RuleForm): RuleInput {
  return {
    reason: form.reason.trim(),
    service_id: form.service_id.trim() || undefined,
    name: form.name.trim(),
    priority: optionalNumber(form.priority),
    action: form.action,
    mode: form.mode,
    dimension: form.dimension,
    threshold_pps: optionalNumber(form.threshold_pps),
    threshold_bps: optionalNumber(form.threshold_bps),
    threshold_cps: optionalNumber(form.threshold_cps),
    burst_packets: optionalNumber(form.burst_packets),
    burst_bytes: optionalNumber(form.burst_bytes),
    sample_denom: optionalNumber(form.sample_denom),
    ttl_seconds: optionalNumber(form.ttl_seconds),
    expires_at: form.expires_at.trim() || undefined,
    confidence: optionalFloat(form.confidence),
    enabled: form.enabled,
    owner: form.owner.trim(),
    match_expr: parseJsonObject(form.match_expr),
    evidence: parseJsonObject(form.evidence)
  };
}

function optionalNumber(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) throw new Error('numeric fields must be non-negative integers');
  return next;
}

function optionalFloat(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const next = Number(value);
  if (!Number.isFinite(next) || next < 0) throw new Error('confidence must be a non-negative number');
  return next;
}

function optionalString(value: number | undefined): string {
  return value === undefined || value === null ? '' : String(value);
}

function jsonString(value: Record<string, unknown> | undefined): string {
  return value && Object.keys(value).length > 0 ? JSON.stringify(value, null, 2) : '';
}

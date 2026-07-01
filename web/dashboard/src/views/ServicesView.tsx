import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { AlertTriangle, Plus, Router, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { DataToolbar, PanelHeader, SearchField, StatusPill } from '../components';
import { formatDateTime, numberValue } from '../format';
import type { Agent, ApplyStatus, Service, ServiceInput, User } from '../types';

type ServiceFormState = {
  reason: string;
  name: string;
  description: string;
  backend_cidr: string;
  protocol: string;
  allowed_ports: string;
  output_interface: string;
  owner: string;
  criticality: string;
  protection_mode: string;
  enabled: boolean;
  priority: string;
  tags: string;
  resolved_ifindex: string;
  resolved_src_mac: string;
  neighbor_resolution_status: string;
};

type InterfaceOption = {
  name: string;
  label: string;
  ifindex?: number;
  mac?: string;
};

export function ServicesView({
  services,
  agents,
  applyStatuses,
  canMutate,
  user,
  onRefresh
}: {
  services: Service[];
  agents: Agent[];
  applyStatuses: ApplyStatus[];
  canMutate: boolean;
  user?: User;
  onRefresh: () => void | Promise<void>;
}) {
  const [query, setQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [stateFilter, setStateFilter] = useState('all');
  const [formMode, setFormMode] = useState<'create' | 'edit' | ''>('');
  const [editingService, setEditingService] = useState<Service | null>(null);
  const [form, setForm] = useState<ServiceFormState>(() => emptyServiceForm(user));
  const [disableTarget, setDisableTarget] = useState<Service | null>(null);
  const [disableReason, setDisableReason] = useState('disable protected service');
  const [working, setWorking] = useState('');
  const [result, setResult] = useState('');
  const [allocatedCidrs, setAllocatedCidrs] = useState<string[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    if (canMutate) {
      api.meAllocatedCIDRs()
        .then((list) => setAllocatedCidrs(list.map((c) => c.cidr)))
        .catch((err) => console.error('failed to load allocated CIDRs', err));
    }
  }, [canMutate]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return services.filter((service) => {
      const matchesText = !needle || [
        service.name,
        service.backend_cidr,
        service.output_interface,
        service.owner,
        service.criticality,
        service.allowed_ports.join(',')
      ].some((value) => value.toLowerCase().includes(needle));
      const matchesProtocol = protocolFilter === 'all' || service.protocol === protocolFilter;
      const matchesState = stateFilter === 'all' || (stateFilter === 'enabled' ? service.enabled : !service.enabled);
      return matchesText && matchesProtocol && matchesState;
    });
  }, [protocolFilter, query, services, stateFilter]);
  const outputInterfaces = useMemo(() => outputInterfaceOptions(agents), [agents]);
  const formOutputInterfaces = useMemo(
    () => withCurrentOutputInterface(outputInterfaces, form.output_interface),
    [form.output_interface, outputInterfaces]
  );
  const failedApplies = applyStatuses.filter((status) => status.status === 'failed');

  const openCreate = () => {
    setFormMode('create');
    setEditingService(null);
    setShowAdvanced(false);
    const initialForm = emptyServiceForm(user);
    if (outputInterfaces.length > 0) {
      const defaultIface = outputInterfaces[0];
      initialForm.output_interface = defaultIface.name;
      initialForm.resolved_ifindex = defaultIface.ifindex ? String(defaultIface.ifindex) : '';
      initialForm.resolved_src_mac = defaultIface.mac || '';
    }
    setForm(initialForm);
    setResult('');
  };

  const openEdit = (service: Service) => {
    setFormMode('edit');
    setEditingService(service);
    setShowAdvanced(false);
    setForm(serviceFormFromService(service));
    setResult('');
  };

  const closeForm = () => {
    setFormMode('');
    setEditingService(null);
  };

  const selectOutputInterface = (name: string) => {
    const selected = outputInterfaces.find((item) => item.name === name);
    if (!name) {
      setForm({
        ...form,
        output_interface: '',
        resolved_ifindex: '',
        resolved_src_mac: ''
      });
      return;
    }
    if (!selected) {
      setForm({ ...form, output_interface: name });
      return;
    }
    setForm({
      ...form,
      output_interface: name,
      resolved_ifindex: selected.ifindex ? String(selected.ifindex) : '',
      resolved_src_mac: selected.mac || ''
    });
  };

  const submit = async (event?: FormEvent) => {
    if (event) event.preventDefault();
    if (!canMutate) return;
    const metadataError = enabledServiceMetadataError(form);
    if (metadataError) {
      setResult(metadataError);
      return;
    }
    try {
      setWorking('service');
      const input = serviceInputFromForm(form);
      if (formMode === 'edit' && editingService) {
        await api.updateService(editingService.id, input);
        setResult(`${input.name} updated`);
      } else {
        await api.createService(input);
        setResult(`${input.name} created`);
      }
      closeForm();
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };

  const confirmDisable = async () => {
    if (!disableTarget || !canMutate) return;
    try {
      setWorking('disable');
      await api.deleteService(disableTarget.id, disableReason);
      setResult(`${disableTarget.name} disabled`);
      setDisableTarget(null);
      await onRefresh();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'request failed');
    } finally {
      setWorking('');
    }
  };

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'name', headerName: 'Name', flex: 1, minWidth: 120 },
    { field: 'backend_cidr', headerName: 'Backend', width: 140 },
    { field: 'protocol', headerName: 'Protocol', width: 90, valueFormatter: (value) => String(value).toUpperCase() },
    { field: 'allowed_ports', headerName: 'Ports', width: 120, valueGetter: (_, row) => row.allowed_ports.join(', ') || '0' },
    { field: 'output_interface', headerName: 'Output', width: 110 },
    { field: 'owner', headerName: 'Owner', width: 110 },
    { field: 'protection_mode', headerName: 'Mode', width: 90 },
    { field: 'neighbor_resolution_status', headerName: 'Neighbor', width: 110, renderCell: (params) => <StatusPill state={params.value === 'resolved' ? 'ok' : 'warn'} text={String(params.value)} /> },
    { field: 'counters', headerName: 'Counters', width: 100, valueGetter: (_, row) => row.counters ? Object.values(row.counters).reduce((sum: number, val: any) => sum + (Number(val) || 0), 0) : 0, valueFormatter: (value) => numberValue(Number(value) || 0) },
    { field: 'apply_status', headerName: 'Apply', width: 110, valueGetter: (_, row) => row.apply_status ?? row.sync_status },
    { field: 'enabled', headerName: 'State', width: 105, renderCell: (params) => <StatusPill state={params.value ? 'ok' : 'off'} text={params.value ? 'enabled' : 'disabled'} /> },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 150,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as Service;
        if (!canMutate) return <span className="muted">read only</span>;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" color="warning" onClick={() => {
              setDisableTarget(row);
              setDisableReason(`disable ${row.name}`);
            }}>Disable</Button>
          </Stack>
        );
      }
    }
  ], [canMutate]);

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<Router size={18} />}
          title="Protected Services"
          eyebrow="allowlist and DEVMAP forwarding registry"
          actions={canMutate ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add service</button> : null}
        />
        <DataToolbar>
          <SearchField label="Search" value={query} onChange={setQuery} placeholder="name, owner, backend, output" />
          <label>
            Protocol
            <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)}>
              <option value="all">All</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </label>
          <label>
            State
            <select value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}>
              <option value="all">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
        </DataToolbar>
        <InlineResult result={result} />
      </section>

      {failedApplies.length > 0 ? (
        <section className="wide-panel apply-failure-panel">
          <PanelHeader icon={<AlertTriangle size={18} />} title="Latest Apply Failure" />
          {failedApplies.map((status) => (
            <div className="apply-detail" key={`${status.agent_id}-${status.policy_version}`}>
              <StatusPill state="danger" text={status.hostname || status.agent_id} />
              <span>policy v{status.policy_version}</span>
              <span>{status.error_stage || 'apply'}: {status.error_reason || status.status}</span>
              <span>{formatDateTime(status.reported_at)}</span>
            </div>
          ))}
        </section>
      ) : null}

      <AdminDrawer
        open={formMode !== ''}
        title={formMode === 'edit' ? `Edit ${editingService?.name ?? 'Service'}` : 'Add Service'}
        onClose={closeForm}
        actions={<>
          <Button onClick={closeForm}>Cancel</Button>
          <Button variant="contained" onClick={() => submit()} startIcon={<Save size={16} />} disabled={working !== ''}>
            {working === 'service' ? 'Saving' : 'Save service'}
          </Button>
        </>}
      >
        <form className="service-form" onSubmit={submit} style={{ display: 'contents' }}>
          <TextField
            label="Name"
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            fullWidth
            required
          />
          <TextField
            label="Backend CIDR"
            value={form.backend_cidr}
            onChange={(event) => setForm({ ...form, backend_cidr: event.target.value })}
            placeholder="203.0.113.10/32"
            fullWidth
            required
            helperText={
              allocatedCidrs.length > 0
                ? `Allocated bounds: ${allocatedCidrs.join(', ')}`
                : "No active CIDR allocations found."
            }
            slotProps={{
              formHelperText: {
                style: { color: allocatedCidrs.length > 0 ? 'rgba(148, 163, 184, 0.7)' : 'rgba(239, 68, 68, 0.8)' }
              }
            }}
          />
          <TextField
            select
            label="Protocol"
            value={form.protocol}
            onChange={(event) => setForm({ ...form, protocol: event.target.value })}
            fullWidth
          >
            <MenuItem value="tcp">TCP</MenuItem>
            <MenuItem value="udp">UDP</MenuItem>
            <MenuItem value="icmp">ICMP</MenuItem>
          </TextField>
          <TextField
            label="Allowed ports"
            value={form.allowed_ports}
            onChange={(event) => setForm({ ...form, allowed_ports: event.target.value })}
            placeholder="443, 8443"
            fullWidth
            disabled={form.protocol === 'icmp'}
          />

          {formOutputInterfaces.length > 0 ? (
            <TextField
              select
              label="Output interface"
              value={form.output_interface}
              onChange={(event) => selectOutputInterface(event.target.value)}
              fullWidth
            >
              <MenuItem value="">Select interface</MenuItem>
              {formOutputInterfaces.map((item) => (
                <MenuItem key={item.name} value={item.name}>{item.label}</MenuItem>
              ))}
            </TextField>
          ) : (
            <TextField
              label="Output interface"
              value={form.output_interface}
              onChange={(event) => setForm({ ...form, output_interface: event.target.value })}
              placeholder="backend0"
              fullWidth
            />
          )}

          <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />

          {formMode === 'edit' && (
            <button
              type="button"
              className="secondary-action toggle-advanced-btn"
              style={{
                alignSelf: 'flex-start',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                margin: '8px 0',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                background: 'rgba(255, 255, 255, 0.05)',
                padding: '6px 12px',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.875rem'
              }}
              onClick={() => setShowAdvanced(!showAdvanced)}
            >
              <span>{showAdvanced ? '▼ Hide Advanced Settings' : '▶ Show Advanced Settings'}</span>
            </button>
          )}

          {formMode === 'edit' && showAdvanced && (
            <Stack spacing={1.5}>
              <TextField
                label="Owner"
                value={form.owner}
                fullWidth
                disabled
              />
              <TextField
                label="Criticality"
                value={form.criticality}
                onChange={(event) => setForm({ ...form, criticality: event.target.value })}
                placeholder="high"
                fullWidth
              />
              <TextField
                select
                label="Protection mode"
                value={form.protection_mode}
                onChange={(event) => setForm({ ...form, protection_mode: event.target.value })}
                fullWidth
              >
                <MenuItem value="observe">Observe</MenuItem>
                <MenuItem value="enforce">Enforce</MenuItem>
              </TextField>
              <TextField
                label="Priority"
                value={form.priority}
                onChange={(event) => setForm({ ...form, priority: event.target.value })}
                inputMode="numeric"
                fullWidth
              />
              <TextField
                select
                label="Neighbor status"
                value={form.neighbor_resolution_status}
                onChange={(event) => setForm({ ...form, neighbor_resolution_status: event.target.value })}
                fullWidth
              >
                <MenuItem value="unresolved">Unresolved</MenuItem>
                <MenuItem value="resolved">Resolved</MenuItem>
              </TextField>
              <TextField
                label="Description"
                value={form.description}
                onChange={(event) => setForm({ ...form, description: event.target.value })}
                fullWidth
              />
              <TextField
                label="Tags"
                value={form.tags}
                onChange={(event) => setForm({ ...form, tags: event.target.value })}
                placeholder="prod, edge"
                fullWidth
              />
              <TextField
                label="Resolved ifindex"
                value={form.resolved_ifindex}
                onChange={(event) => setForm({ ...form, resolved_ifindex: event.target.value })}
                inputMode="numeric"
                fullWidth
              />
              <TextField
                label="Source MAC"
                value={form.resolved_src_mac}
                onChange={(event) => setForm({ ...form, resolved_src_mac: event.target.value })}
                fullWidth
              />
              <FormControlLabel
                control={<Checkbox checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />}
                label="Enabled"
              />
            </Stack>
          )}
        </form>
      </AdminDrawer>

      <ConfirmDialog
        open={Boolean(disableTarget)}
        title={`Disable ${disableTarget?.name ?? 'service'}`}
        confirmText="Disable service"
        onCancel={() => setDisableTarget(null)}
        onConfirm={confirmDisable}
        busy={working === 'disable'}
      >
        <ReasonField value={disableReason} onChange={setDisableReason} />
        <div className="muted">
          <Trash2 size={14} /> Service remains visible and is removed from the next active snapshot.
        </div>
      </ConfirmDialog>

      <AdminGrid
        rows={filtered}
        columns={columns}
        emptyText={services.length === 0 ? 'No protected services configured' : 'No services match the current filters'}
        height={560}
      />
    </section>
  );
}

function emptyServiceForm(user?: User): ServiceFormState {
  return {
    reason: 'create protected service',
    name: '',
    description: '',
    backend_cidr: '',
    protocol: 'tcp',
    allowed_ports: '',
    output_interface: '',
    owner: user?.username || '',
    criticality: 'high',
    protection_mode: 'enforce',
    enabled: true,
    priority: '',
    tags: '',
    resolved_ifindex: '',
    resolved_src_mac: '',
    neighbor_resolution_status: 'unresolved'
  };
}

function serviceFormFromService(service: Service): ServiceFormState {
  return {
    reason: `update ${service.name}`,
    name: service.name,
    description: service.description ?? '',
    backend_cidr: service.backend_cidr,
    protocol: service.protocol,
    allowed_ports: service.allowed_ports.join(', '),
    output_interface: service.output_interface,
    owner: service.owner,
    criticality: service.criticality,
    protection_mode: service.protection_mode,
    enabled: service.enabled,
    priority: service.priority ? String(service.priority) : '',
    tags: (service.tags ?? []).join(', '),
    resolved_ifindex: service.resolved_ifindex ? String(service.resolved_ifindex) : '',
    resolved_src_mac: service.resolved_src_mac ?? '',
    neighbor_resolution_status: service.neighbor_resolution_status || 'unresolved'
  };
}

function serviceInputFromForm(form: ServiceFormState): ServiceInput {
  const protocol = form.protocol.toLowerCase();
  return {
    reason: form.reason.trim(),
    name: form.name.trim(),
    description: form.description.trim(),
    backend_cidr: form.backend_cidr.trim(),
    protocol,
    allowed_ports: protocol === 'icmp' ? [] : parsePorts(form.allowed_ports),
    output_interface: form.output_interface.trim(),
    owner: form.owner.trim(),
    criticality: form.criticality.trim(),
    protection_mode: form.protection_mode,
    enabled: form.enabled,
    priority: optionalNumber(form.priority),
    tags: splitList(form.tags),
    resolved_ifindex: optionalNumber(form.resolved_ifindex),
    resolved_src_mac: form.resolved_src_mac.trim(),
    neighbor_resolution_status: form.neighbor_resolution_status
  };
}

function enabledServiceMetadataError(form: ServiceFormState): string {
  return '';
}

function outputInterfaceOptions(agents: Agent[]): InterfaceOption[] {
  const seen = new Set<string>();
  const out: InterfaceOption[] = [];
  for (const agent of agents) {
    for (const iface of agent.interfaces ?? []) {
      const name = iface.name.trim();
      if (!name || seen.has(name)) continue;
      seen.add(name);
      out.push({
        name,
        label: interfaceLabel(iface),
        ifindex: iface.ifindex,
        mac: iface.mac
      });
    }
  }
  return out.sort((left, right) => left.name.localeCompare(right.name));
}

function withCurrentOutputInterface(options: InterfaceOption[], current: string): InterfaceOption[] {
  const name = current.trim();
  if (!name || options.some((item) => item.name === name)) {
    return options;
  }
  return [{ name, label: `${name} (not reported by agent)` }, ...options];
}

function interfaceLabel(iface: { name: string; ifindex?: number; mac?: string; role?: string }): string {
  const details = [
    iface.role,
    iface.ifindex ? `ifindex ${iface.ifindex}` : '',
    iface.mac
  ].filter(Boolean);
  return details.length > 0 ? `${iface.name} (${details.join(', ')})` : iface.name;
}

function parsePorts(value: string): number[] {
  const ports = splitList(value).map((item) => Number(item));
  if (ports.length === 0 || ports.some((port) => !Number.isInteger(port) || port <= 0 || port > 65535)) {
    throw new Error('allowed ports must be comma-separated values from 1 to 65535');
  }
  return ports;
}

function splitList(value: string): string[] {
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function optionalNumber(value: string): number | undefined {
  if (value.trim() === '') return undefined;
  const next = Number(value);
  if (!Number.isInteger(next) || next < 0) {
    throw new Error('numeric fields must be non-negative integers');
  }
  return next;
}

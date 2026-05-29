import { FormEvent, useMemo, useState } from 'react';
import { AlertTriangle, Pencil, Plus, Router, Save, Trash2 } from 'lucide-react';
import { api } from '../client';
import { DataToolbar, EmptyTableRow, PanelHeader, SearchField, StatusPill, TablePanel } from '../components';
import { formatDateTime, numberValue } from '../format';
import type { Agent, ApplyStatus, Service, ServiceInput } from '../types';

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
  onRefresh
}: {
  services: Service[];
  agents: Agent[];
  applyStatuses: ApplyStatus[];
  canMutate: boolean;
  onRefresh: () => void | Promise<void>;
}) {
  const [query, setQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [stateFilter, setStateFilter] = useState('all');
  const [formMode, setFormMode] = useState<'create' | 'edit' | ''>('');
  const [editingService, setEditingService] = useState<Service | null>(null);
  const [form, setForm] = useState<ServiceFormState>(() => emptyServiceForm());
  const [disableTarget, setDisableTarget] = useState<Service | null>(null);
  const [disableReason, setDisableReason] = useState('disable protected service');
  const [working, setWorking] = useState('');
  const [result, setResult] = useState('');

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
    setForm(emptyServiceForm());
    setResult('');
  };

  const openEdit = (service: Service) => {
    setFormMode('edit');
    setEditingService(service);
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

  const submit = async (event: FormEvent) => {
    event.preventDefault();
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

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader icon={<Router size={18} />} title="Protected Services" eyebrow="allowlist and DEVMAP forwarding registry" />
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
          {canMutate ? (
            <div className="toolbar-actions">
              <button type="button" className="primary-action" onClick={openCreate}>
                <Plus size={15} />Add service
              </button>
            </div>
          ) : null}
        </DataToolbar>
        {result ? <div className={result.includes('failed') || result.includes('required') || result.includes('invalid') || result.includes('must') ? 'error-line inline-message' : 'success-line inline-message'}>{result}</div> : null}
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

      {formMode ? (
        <form className="wide-panel form-grid service-form" onSubmit={submit}>
        <PanelHeader icon={<Pencil size={18} />} title={formMode === 'edit' ? 'Edit Service' : 'Add Service'} eyebrow={form.enabled ? 'requires Agent-reported interface metadata' : 'new services default disabled'} />
          <label>
            Name
            <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </label>
          <label>
            Backend CIDR
            <input value={form.backend_cidr} onChange={(event) => setForm({ ...form, backend_cidr: event.target.value })} placeholder="203.0.113.10/32" />
          </label>
          <label>
            Protocol
            <select value={form.protocol} onChange={(event) => setForm({ ...form, protocol: event.target.value })}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </label>
          <label>
            Allowed ports
            <input value={form.allowed_ports} onChange={(event) => setForm({ ...form, allowed_ports: event.target.value })} placeholder="443, 8443" disabled={form.protocol === 'icmp'} />
          </label>
          <label>
            Output interface
            {formOutputInterfaces.length > 0 ? (
              <select value={form.output_interface} onChange={(event) => selectOutputInterface(event.target.value)}>
                <option value="">Select interface</option>
                {formOutputInterfaces.map((item) => (
                  <option key={item.name} value={item.name}>{item.label}</option>
                ))}
              </select>
            ) : (
              <input value={form.output_interface} onChange={(event) => setForm({ ...form, output_interface: event.target.value })} placeholder="backend0" />
            )}
          </label>
          <label>
            Owner
            <input value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} />
          </label>
          <label>
            Criticality
            <input value={form.criticality} onChange={(event) => setForm({ ...form, criticality: event.target.value })} placeholder="high" />
          </label>
          <label>
            Protection mode
            <select value={form.protection_mode} onChange={(event) => setForm({ ...form, protection_mode: event.target.value })}>
              <option value="observe">Observe</option>
              <option value="enforce">Enforce</option>
            </select>
          </label>
          <label>
            Priority
            <input value={form.priority} onChange={(event) => setForm({ ...form, priority: event.target.value })} inputMode="numeric" />
          </label>
          <label>
            Neighbor status
            <select value={form.neighbor_resolution_status} onChange={(event) => setForm({ ...form, neighbor_resolution_status: event.target.value })}>
              <option value="unresolved">Unresolved</option>
              <option value="resolved">Resolved</option>
            </select>
          </label>
          <label className="wide-field">
            Description
            <input value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
          </label>
          <label>
            Tags
            <input value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} placeholder="prod, edge" />
          </label>
          <label>
            Resolved ifindex
            <input value={form.resolved_ifindex} onChange={(event) => setForm({ ...form, resolved_ifindex: event.target.value })} inputMode="numeric" />
          </label>
          <label>
            Source MAC
            <input value={form.resolved_src_mac} onChange={(event) => setForm({ ...form, resolved_src_mac: event.target.value })} />
          </label>
          <label className="wide-field">
            Reason
            <input value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} />
          </label>
          <label className="checkbox-field">
            <input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />
            Enabled
          </label>
          <div className="form-actions">
            <button type="submit" className="primary-action" disabled={working !== ''}>
              <Save size={15} />{working === 'service' ? 'Saving' : 'Save service'}
            </button>
            <button type="button" className="secondary-action" onClick={closeForm} disabled={working !== ''}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      {disableTarget ? (
        <section className="wide-panel">
          <PanelHeader icon={<Trash2 size={18} />} title={`Disable ${disableTarget.name}`} />
          <label>
            Reason
            <input value={disableReason} onChange={(event) => setDisableReason(event.target.value)} />
          </label>
          <div className="button-row">
            <button type="button" className="danger-action" disabled={working !== ''} onClick={confirmDisable}>
              <Trash2 size={15} />{working === 'disable' ? 'Disabling' : 'Confirm disable'}
            </button>
            <button type="button" className="secondary-action" onClick={() => setDisableTarget(null)} disabled={working !== ''}>
              Cancel
            </button>
          </div>
        </section>
      ) : null}

      <TablePanel icon={<Router size={18} />} title={`Service Registry (${filtered.length})`} eyebrow="searchable read model">
        <thead><tr><th>Name</th><th>Backend</th><th>Protocol</th><th>Ports</th><th>Output</th><th>Owner</th><th>Mode</th><th>Neighbor</th><th>Counters</th><th>Apply</th><th>State</th><th>Actions</th></tr></thead>
        <tbody>{filtered.length === 0 ? (
          <EmptyTableRow colSpan={12} text={services.length === 0 ? 'No protected services configured' : 'No services match the current filters'} />
        ) : filtered.map((service) => (
          <tr key={service.id}>
            <td>{service.name}</td>
            <td>{service.backend_cidr}</td>
            <td>{service.protocol}</td>
            <td>{service.allowed_ports.join(', ') || '0'}</td>
            <td>{service.output_interface}</td>
            <td>{service.owner}</td>
            <td>{service.protection_mode}</td>
            <td><StatusPill state={service.neighbor_resolution_status === 'resolved' ? 'ok' : 'warn'} text={service.neighbor_resolution_status} /></td>
            <td>{service.counters ? numberValue(Object.values(service.counters).reduce((sum, value) => sum + value, 0)) : '0'}</td>
            <td>{service.apply_status ?? service.sync_status}</td>
            <td><StatusPill state={service.enabled ? 'ok' : 'off'} text={service.enabled ? 'enabled' : 'disabled'} /></td>
            <td>
              {canMutate ? (
                <div className="row-actions">
                  <button type="button" className="icon-action" aria-label={`edit ${service.name}`} onClick={() => openEdit(service)}>
                    <Pencil size={15} />
                  </button>
                  <button type="button" className="icon-action" aria-label={`disable ${service.name}`} onClick={() => {
                    setDisableTarget(service);
                    setDisableReason(`disable ${service.name}`);
                  }}>
                    <Trash2 size={15} />
                  </button>
                </div>
              ) : <span className="muted">read only</span>}
            </td>
          </tr>
        ))}</tbody>
      </TablePanel>
    </section>
  );
}

function emptyServiceForm(): ServiceFormState {
  return {
    reason: 'update protected service',
    name: '',
    description: '',
    backend_cidr: '',
    protocol: 'tcp',
    allowed_ports: '',
    output_interface: '',
    owner: '',
    criticality: 'high',
    protection_mode: 'enforce',
    enabled: false,
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
  if (!form.enabled) {
    return '';
  }
  if (!form.resolved_ifindex.trim()) {
    return 'resolved ifindex is required before enabling a service';
  }
  if (!form.resolved_src_mac.trim()) {
    return 'source MAC is required before enabling a service';
  }
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

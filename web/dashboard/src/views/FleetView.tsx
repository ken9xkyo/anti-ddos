import { Ban, CheckCircle2, Network, Server } from 'lucide-react';
import { EmptyTableRow, JsonBlock, PanelHeader, StatusPill, TablePanel } from '../components';
import { formatDateTime, jsonPreview, numberValue } from '../format';
import type { Agent } from '../types';

export function FleetView({ agents }: { agents: Agent[] }) {
  return (
    <section className="content-stack">
      <TablePanel icon={<Server size={18} />} title="Agents / XDP" eyebrow={`${agents.length} registered`}>
        <thead><tr><th>Host</th><th>Status</th><th>XDP</th><th>Policy</th><th>DEVMAP</th><th>Last seen</th><th>Apply</th></tr></thead>
        <tbody>{agents.length === 0 ? (
          <EmptyTableRow colSpan={7} text="No agents registered" />
        ) : agents.map((agent) => (
          <tr key={agent.id}>
            <td>{agent.hostname}</td>
            <td><StatusPill state={agent.stale ? 'warn' : 'ok'} text={agent.stale ? 'stale' : agent.status} /></td>
            <td>{agent.xdp_mode}</td>
            <td>v{agent.active_policy_version}</td>
            <td>{agent.devmap_support ? <CheckCircle2 size={16} /> : <Ban size={16} />}</td>
            <td>{formatDateTime(agent.last_seen_at)}</td>
            <td>
              {agent.latest_apply ? (
                <div className="apply-cell">
                  <StatusPill state={agent.latest_apply.status === 'applied' ? 'ok' : agent.latest_apply.status === 'failed' ? 'danger' : 'off'} text={agent.latest_apply.status} />
                  <span>v{agent.latest_apply.policy_version}</span>
                  {agent.latest_apply.status === 'failed' ? (
                    <span className="apply-error">{agent.latest_apply.error_stage || 'apply'}: {agent.latest_apply.error_reason || 'failed'}</span>
                  ) : null}
                </div>
              ) : 'pending'}
            </td>
          </tr>
        ))}</tbody>
      </TablePanel>

      <div className="two-column-grid">
        <TablePanel icon={<Network size={18} />} title="Reported Interfaces">
          <thead><tr><th>Agent</th><th>Name</th><th>Role</th><th>Ifindex</th><th>MAC</th><th>Speed</th></tr></thead>
          <tbody>{interfaceRows(agents).length === 0 ? (
            <EmptyTableRow colSpan={6} text="No interface metadata reported" />
          ) : interfaceRows(agents).map((row) => (
            <tr key={`${row.agentID}-${row.name}`}>
              <td>{row.hostname}</td>
              <td>{row.name}</td>
              <td>{row.role || 'n/a'}</td>
              <td>{row.ifindex || 'n/a'}</td>
              <td>{row.mac || 'n/a'}</td>
              <td>{row.link_speed_bps ? `${numberValue(row.link_speed_bps / 1000000000)} Gbps` : 'n/a'}</td>
            </tr>
          ))}</tbody>
        </TablePanel>

        <section className="wide-panel">
          <PanelHeader icon={<Server size={18} />} title="Map Utilization" />
          <div className="map-grid">
            {agents.length === 0 ? <p className="muted">No agent map utilization available.</p> : agents.map((agent) => (
              <div className="map-panel" key={agent.id}>
                <strong>{agent.hostname}</strong>
                <JsonBlock value={jsonPreview(agent.map_utilization ?? {})} />
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}

function interfaceRows(agents: Agent[]) {
  return agents.flatMap((agent) => (agent.interfaces ?? []).map((iface) => ({
    agentID: agent.id,
    hostname: agent.hostname,
    ...iface
  })));
}

package control

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (s *Store) RegisterAgent(ctx context.Context, req AgentRegisterRequest) (AgentRegisterResponse, error) {
	if strings.TrimSpace(req.Hostname) == "" {
		return AgentRegisterResponse{}, errors.New("hostname is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AgentRegisterResponse{}, err
	}
	defer tx.Rollback(ctx)

	var id string
	err = tx.QueryRow(ctx, `SELECT id::text FROM agents WHERE hostname=$1`, req.Hostname).Scan(&id)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return AgentRegisterResponse{}, err
		}
		id, err = newUUID()
		if err != nil {
			return AgentRegisterResponse{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agents(id, hostname, kernel_version, ubuntu_version, xdp_mode, devmap_support, agent_version, status, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,'registered',now())`,
			id, req.Hostname, req.KernelVersion, req.UbuntuVersion, req.XDPMode, req.DevmapSupport, req.AgentVersion); err != nil {
			return AgentRegisterResponse{}, err
		}
	} else {
		if _, err := tx.Exec(ctx, `UPDATE agents SET kernel_version=$2, ubuntu_version=$3, xdp_mode=$4, devmap_support=$5,
    agent_version=$6, status='online', last_seen_at=now(), updated_at=now()
WHERE id=$1`, id, req.KernelVersion, req.UbuntuVersion, req.XDPMode, req.DevmapSupport, req.AgentVersion); err != nil {
			return AgentRegisterResponse{}, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_interfaces WHERE agent_id=$1`, id); err != nil {
			return AgentRegisterResponse{}, err
		}
	}
	for _, iface := range req.Interfaces {
		if strings.TrimSpace(iface.Name) == "" {
			continue
		}
		ifaceID, err := newUUID()
		if err != nil {
			return AgentRegisterResponse{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_interfaces(id, agent_id, name, ifindex, mac, role, link_speed_bps)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			ifaceID, id, iface.Name, iface.Ifindex, iface.MAC, iface.Role, iface.LinkSpeedBPS); err != nil {
			return AgentRegisterResponse{}, err
		}
	}
	version, err := latestPolicyVersion(ctx, tx)
	if err != nil {
		return AgentRegisterResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AgentRegisterResponse{}, err
	}
	return AgentRegisterResponse{AgentID: id, DesiredPolicyVersion: version}, nil
}

func (s *Store) HeartbeatAgent(ctx context.Context, id string, req AgentHeartbeatRequest) (AgentHeartbeatResponse, error) {
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "online"
	}
	if _, err := s.pool.Exec(ctx, `UPDATE agents SET status=$2, active_policy_version=$3, xdp_mode=COALESCE(NULLIF($4,''), xdp_mode),
    last_seen_at=now(), updated_at=now(), metadata=jsonb_set(metadata, '{map_utilization}', COALESCE(NULLIF($5,'')::jsonb, '{}'::jsonb), true)
WHERE id=$1`, id, status, req.ActivePolicyVersion, req.XDPMode, string(defaultJSON(req.MapUtilization))); err != nil {
		return AgentHeartbeatResponse{}, err
	}
	version, err := s.LatestPolicyVersion(ctx)
	if err != nil {
		return AgentHeartbeatResponse{}, err
	}
	return AgentHeartbeatResponse{DesiredPolicyVersion: version}, nil
}

func (s *Store) RecordAgentApply(ctx context.Context, agentID string, req AgentApplyRequest) error {
	if strings.TrimSpace(agentID) == "" {
		return errors.New("agent id is required")
	}
	if req.PolicyVersion == 0 {
		return errors.New("policy_version is required")
	}
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "failed"
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	mapStats := defaultJSON(req.MapStats)
	devmapStats := defaultJSON(req.DevmapStats)
	_, err = s.pool.Exec(ctx, `INSERT INTO policy_apply_status(id, agent_id, policy_version, status, error_stage, error_reason, map_stats, devmap_stats, reported_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
ON CONFLICT (agent_id, policy_version) DO UPDATE SET
    status=EXCLUDED.status,
    error_stage=EXCLUDED.error_stage,
    error_reason=EXCLUDED.error_reason,
    map_stats=EXCLUDED.map_stats,
    devmap_stats=EXCLUDED.devmap_stats,
    reported_at=now()`,
		id, agentID, req.PolicyVersion, status, req.ErrorStage, req.ErrorReason, mapStats, devmapStats,
	)
	return err
}

func latestPolicyVersion(ctx context.Context, q dbQuerier) (uint32, error) {
	var version uint32
	err := q.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&version)
	return version, err
}

package control

import (
	"context"
	"encoding/json"
	"time"
)

func (s *Store) BuildDashboardOverview(ctx context.Context, prom *PrometheusClient, staleAfter time.Duration) (DashboardOverview, error) {
	now := time.Now().UTC()
	summary, err := s.SecurityEventSummary(ctx, SecurityEventQuery{Since: now.Add(-5 * time.Minute), Until: now})
	if err != nil {
		return DashboardOverview{}, err
	}
	version, err := s.LatestPolicyVersion(ctx)
	if err != nil {
		return DashboardOverview{}, err
	}
	agents, err := s.ListDashboardAgents(ctx, staleAfter)
	if err != nil {
		return DashboardOverview{}, err
	}
	apply, err := s.LatestApplyStatuses(ctx)
	if err != nil {
		return DashboardOverview{}, err
	}

	overview := DashboardOverview{
		GeneratedAt:       now,
		SecurityEvents:    summary,
		SnapshotVersion:   version,
		LatestApplyStatus: apply,
		DecisionRates:     map[string]float64{},
	}
	overview.AgentSummary.Total = len(agents)
	for _, agent := range agents {
		if agent.Stale {
			overview.AgentSummary.Stale++
		}
	}

	status := PrometheusStatus{Configured: false, Healthy: false, Error: "prometheus is not configured"}
	if prom != nil && prom.Configured() {
		overview.Traffic.PPS, status = prom.QueryScalar(ctx, `sum(rate(anti_ddos_xdp_packets_total{action=~"0|1|6"}[1m]))`)
		overview.Traffic.BPS, status = prom.QueryScalar(ctx, `sum(rate(anti_ddos_xdp_bytes_total{action=~"0|1|6"}[1m])) * 8`)
		overview.Traffic.CPS, status = prom.QueryScalar(ctx, `sum(rate(anti_ddos_xdp_packets_total{proto="6",tcp_syn="1",action=~"0|1|6"}[1m]))`)
		overview.DecisionRates["drop"], status = prom.QueryScalar(ctx, `sum(rate(anti_ddos_xdp_packets_total{action="1"}[1m]))`)
		overview.DecisionRates["redirect"], status = prom.QueryScalar(ctx, `sum(rate(anti_ddos_redirected_packets_total[1m]))`)
		overview.DecisionRates["not_allowed_service"], status = prom.QueryScalar(ctx, `sum(rate(anti_ddos_not_allowed_service_total[1m]))`)
	}
	overview.Prometheus = status
	return overview, nil
}

func (s *Store) LatestApplyStatuses(ctx context.Context) ([]DashboardApplyStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (pas.agent_id)
       pas.agent_id::text, a.hostname, pas.policy_version, pas.status, pas.error_stage, pas.error_reason, pas.reported_at
FROM policy_apply_status pas
JOIN agents a ON a.id = pas.agent_id
ORDER BY pas.agent_id, pas.reported_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]DashboardApplyStatus, 0)
	for rows.Next() {
		var item DashboardApplyStatus
		if err := rows.Scan(&item.AgentID, &item.Hostname, &item.PolicyVersion, &item.Status, &item.ErrorStage, &item.ErrorReason, &item.ReportedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListDashboardAgents(ctx context.Context, staleAfter time.Duration) ([]DashboardAgent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, hostname, status, COALESCE(NULLIF(xdp_mode, ''), 'unknown'), devmap_support,
       active_policy_version, last_seen_at, COALESCE(metadata->'map_utilization', '{}'::jsonb)
FROM agents ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	agents := make([]DashboardAgent, 0)
	for rows.Next() {
		var agent DashboardAgent
		var mapUtil json.RawMessage
		if err := rows.Scan(
			&agent.ID,
			&agent.Hostname,
			&agent.Status,
			&agent.XDPMode,
			&agent.DevmapSupport,
			&agent.ActivePolicyVersion,
			&agent.LastSeenAt,
			&mapUtil,
		); err != nil {
			return nil, err
		}
		agent.MapUtilization = mapUtil
		agent.Stale = agent.LastSeenAt == nil || now.Sub(*agent.LastSeenAt) > staleAfter
		if agent.Stale {
			dedupe := "agent_stale:" + agent.ID
			if !s.RecentAlertExists(ctx, dedupe, 10*time.Minute) {
				_, alertErr := s.CreateSystemAlert(ctx, AlertInput{
					Severity:          "warning",
					Type:              "agent_stale",
					DedupeKey:         dedupe,
					AffectedService:   agent.Hostname,
					Vector:            "control_plane_heartbeat",
					Evidence:          mustJSON(map[string]any{"agent_id": agent.ID, "hostname": agent.Hostname, "last_seen_at": agent.LastSeenAt}),
					RecommendedAction: "check agent process, control-plane connectivity and last-valid policy state",
				})
				if alertErr != nil {
					s.logger.Warn("agent stale alert creation failed", "agent_id", agent.ID, "error", agentRedactedError(alertErr))
				}
			}
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	apply, err := s.LatestApplyStatuses(ctx)
	if err != nil {
		return nil, err
	}
	applyByAgent := map[string]DashboardApplyStatus{}
	for _, item := range apply {
		applyByAgent[item.AgentID] = item
	}
	for i := range agents {
		if latest, ok := applyByAgent[agents[i].ID]; ok {
			value := latest
			agents[i].LatestApply = &value
		}
		ifaces, err := s.agentInterfaces(ctx, agents[i].ID)
		if err != nil {
			return nil, err
		}
		agents[i].Interfaces = ifaces
	}
	return agents, nil
}

func (s *Store) ListDashboardServices(ctx context.Context) ([]DashboardService, error) {
	services, err := s.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	counters, err := s.recentCountersByService(ctx)
	if err != nil {
		return nil, err
	}
	latestVersion, _ := s.LatestPolicyVersion(ctx)
	apply, _ := s.LatestApplyStatuses(ctx)
	status := latestFleetApplyStatus(apply, latestVersion)
	out := make([]DashboardService, 0, len(services))
	for _, service := range services {
		out = append(out, DashboardService{
			Service:     service,
			Counters:    counters[service.EBPFID],
			ApplyStatus: status,
		})
	}
	return out, nil
}

func (s *Store) ListDashboardRules(ctx context.Context) ([]DashboardRule, error) {
	rules, err := s.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	counters, err := s.recentCountersByRule(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]DashboardRule, 0, len(rules))
	for _, rule := range rules {
		item := DashboardRule{Rule: rule, Counters: counters[rule.EBPFID]}
		if rule.ExpiresAt != nil {
			item.TTLRemainingSeconds = int64(rule.ExpiresAt.Sub(now).Seconds())
			if item.TTLRemainingSeconds < 0 {
				item.TTLRemainingSeconds = 0
			}
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Store) agentInterfaces(ctx context.Context, agentID string) ([]AgentInterface, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, ifindex, mac, role, link_speed_bps FROM agent_interfaces WHERE agent_id=$1 ORDER BY name`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AgentInterface, 0)
	for rows.Next() {
		var iface AgentInterface
		if err := rows.Scan(&iface.Name, &iface.Ifindex, &iface.MAC, &iface.Role, &iface.LinkSpeedBPS); err != nil {
			return nil, err
		}
		out = append(out, iface)
	}
	return out, rows.Err()
}

func (s *Store) recentCountersByService(ctx context.Context) (map[uint32]map[string]float64, error) {
	rows, err := s.pool.Query(ctx, `SELECT service_id, action, reason, COALESCE(sum(sample_rate), 0)::float8
FROM security_events
WHERE event_time > now() - interval '5 minutes' AND service_id > 0
GROUP BY service_id, action, reason`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint32]map[string]float64{}
	for rows.Next() {
		var serviceID uint32
		var action, reason int
		var count float64
		if err := rows.Scan(&serviceID, &action, &reason, &count); err != nil {
			return nil, err
		}
		if out[serviceID] == nil {
			out[serviceID] = map[string]float64{}
		}
		out[serviceID][decisionKey(action, reason)] = count
	}
	return out, rows.Err()
}

func (s *Store) recentCountersByRule(ctx context.Context) (map[uint32]map[string]float64, error) {
	rows, err := s.pool.Query(ctx, `SELECT rule_id, action, reason, COALESCE(sum(sample_rate), 0)::float8
FROM security_events
WHERE event_time > now() - interval '5 minutes' AND rule_id > 0
GROUP BY rule_id, action, reason`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint32]map[string]float64{}
	for rows.Next() {
		var ruleID uint32
		var action, reason int
		var count float64
		if err := rows.Scan(&ruleID, &action, &reason, &count); err != nil {
			return nil, err
		}
		if out[ruleID] == nil {
			out[ruleID] = map[string]float64{}
		}
		out[ruleID][decisionKey(action, reason)] = count
	}
	return out, rows.Err()
}

func latestFleetApplyStatus(statuses []DashboardApplyStatus, version uint32) string {
	if len(statuses) == 0 || version == 0 {
		return "pending"
	}
	var sawPending bool
	for _, status := range statuses {
		if status.Status == "failed" {
			return "failed"
		}
		if status.PolicyVersion < version || status.Status != "applied" {
			sawPending = true
		}
	}
	if sawPending {
		return "pending"
	}
	return "applied"
}

func decisionKey(action, reason int) string {
	return "action_" + intString(action) + "_reason_" + intString(reason)
}

func intString(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	v := value
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

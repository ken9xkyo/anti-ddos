package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	alertMinConfidence = 0.90
	alertMinScore      = 85.0
	alertMinSignals    = 2

	legacyAutoEnforceOwner = "system:auto-enforce"

	defaultBaselinePPS   = 100000.0
	defaultBaselineBPS   = 1000000000.0
	defaultBaselineCPS   = 10000.0
	defaultLowConfidence = 0.25
)

func (s *Store) CreateBaselineProfile(ctx context.Context, actor *Actor, input BaselineProfileInput, reason string) (BaselineProfile, error) {
	if err := requireConfigMutation(actor); err != nil {
		return BaselineProfile{}, err
	}
	if err := validateBaselineProfileInput(input); err != nil {
		return BaselineProfile{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return BaselineProfile{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return BaselineProfile{}, err
	}
	evidence := defaultJSON(input.Evidence)
	if ownerUserID := actorOwnerUserID(actor); ownerUserID != "" {
		ctx = contextWithOwner(ctx, ownerUserID)
	}
	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return BaselineProfile{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := s.getService(ctx, tx, input.ServiceID); err != nil {
		return BaselineProfile{}, err
	}

	var profile BaselineProfile
	err = scanBaselineProfile(tx.QueryRow(ctx, `INSERT INTO baseline_profiles(
    id, owner_user_id, service_id, interface_name, protocol, port, time_window, expected_pps, expected_bps, expected_cps,
    history_hours, confidence, evidence
) VALUES ($1, NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid, $2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING id::text, service_id::text, 0, '', interface_name, protocol, port, time_window, expected_pps,
          expected_bps, expected_cps, history_hours, confidence::float8, approved, status, evidence,
          created_at, updated_at, approved_at`,
		id,
		input.ServiceID,
		strings.TrimSpace(input.Interface),
		normalizeBaselineProtocol(input.Protocol),
		input.Port,
		defaultString(input.Window, "5m"),
		input.ExpectedPPS,
		input.ExpectedBPS,
		input.ExpectedCPS,
		input.HistoryHours,
		input.Confidence,
		evidence,
	), &profile)
	if err != nil {
		return BaselineProfile{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_baseline", "baseline_profile", profile.ID, nil, profile, reason, ""); err != nil {
		return BaselineProfile{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return BaselineProfile{}, err
	}
	return profile, nil
}

func (s *Store) ListBaselineProfiles(ctx context.Context) ([]BaselineProfile, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT bp.id::text, bp.service_id::text, bs.ebpf_id, bs.name, bp.interface_name,
       bp.protocol, bp.port, bp.time_window, bp.expected_pps, bp.expected_bps, bp.expected_cps,
       bp.history_hours, bp.confidence::float8, bp.approved, bp.status, bp.evidence,
       bp.created_at, bp.updated_at, bp.approved_at
FROM baseline_profiles bp
JOIN backend_services bs ON bs.id = bp.service_id
WHERE bp.owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
  AND bs.owner_user_id = bp.owner_user_id
ORDER BY bs.name, bp.time_window, bp.protocol, bp.port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]BaselineProfile, 0)
	for rows.Next() {
		var profile BaselineProfile
		if err := scanBaselineProfile(rows, &profile); err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) ApproveBaselineProfile(ctx context.Context, actor *Actor, id, reason string) (BaselineProfile, error) {
	if err := requireConfigMutation(actor); err != nil {
		return BaselineProfile{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return BaselineProfile{}, errors.New("reason is required")
	}
	if ownerUserID := actorOwnerUserID(actor); ownerUserID != "" {
		ctx = contextWithOwner(ctx, ownerUserID)
	}
	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return BaselineProfile{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.getBaselineProfile(ctx, tx, id)
	if err != nil {
		return BaselineProfile{}, err
	}
	var after BaselineProfile
	err = scanBaselineProfile(tx.QueryRow(ctx, `UPDATE baseline_profiles
SET approved=true, status='approved', approved_by=$2, approved_at=now(), updated_at=now()
WHERE id=$1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
RETURNING id::text, service_id::text, 0, '', interface_name, protocol, port, time_window, expected_pps,
          expected_bps, expected_cps, history_hours, confidence::float8, approved, status, evidence,
          created_at, updated_at, approved_at`, id, actor.ID), &after)
	if err != nil {
		return BaselineProfile{}, err
	}
	if err := insertAudit(ctx, tx, actor, "approve_baseline", "baseline_profile", id, before, after, reason, ""); err != nil {
		return BaselineProfile{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) RecalibrateBaselineProfile(ctx context.Context, actor *Actor, id string, input BaselineProfileInput, reason string) (BaselineProfile, error) {
	if err := requireConfigMutation(actor); err != nil {
		return BaselineProfile{}, err
	}
	if err := validateBaselineProfileInput(input); err != nil {
		return BaselineProfile{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return BaselineProfile{}, errors.New("reason is required")
	}
	if ownerUserID := actorOwnerUserID(actor); ownerUserID != "" {
		ctx = contextWithOwner(ctx, ownerUserID)
	}
	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return BaselineProfile{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.getBaselineProfile(ctx, tx, id)
	if err != nil {
		return BaselineProfile{}, err
	}
	var after BaselineProfile
	err = scanBaselineProfile(tx.QueryRow(ctx, `UPDATE baseline_profiles SET
    interface_name=$2, protocol=$3, port=$4, time_window=$5, expected_pps=$6, expected_bps=$7, expected_cps=$8,
    history_hours=$9, confidence=$10, approved=false, status='draft', evidence=$11, approved_by=NULL,
    approved_at=NULL, updated_at=now()
WHERE id=$1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
RETURNING id::text, service_id::text, 0, '', interface_name, protocol, port, time_window, expected_pps,
          expected_bps, expected_cps, history_hours, confidence::float8, approved, status, evidence,
          created_at, updated_at, approved_at`,
		id,
		strings.TrimSpace(input.Interface),
		normalizeBaselineProtocol(input.Protocol),
		input.Port,
		defaultString(input.Window, "5m"),
		input.ExpectedPPS,
		input.ExpectedBPS,
		input.ExpectedCPS,
		input.HistoryHours,
		input.Confidence,
		defaultJSON(input.Evidence),
	), &after)
	if err != nil {
		return BaselineProfile{}, err
	}
	if err := insertAudit(ctx, tx, actor, "recalibrate_baseline", "baseline_profile", id, before, after, reason, ""); err != nil {
		return BaselineProfile{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) EvaluateAnomalies(ctx context.Context, prom *PrometheusClient, reason string) ([]AnomalyEvaluation, error) {
	if prom == nil || !prom.Configured() {
		return nil, nil
	}
	if ownerUserIDFromContext(ctx) == "" {
		ownerUserIDs, err := s.activeOwnerUserIDs(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]AnomalyEvaluation, 0)
		var joined error
		for _, ownerUserID := range ownerUserIDs {
			evaluations, err := s.EvaluateAnomalies(contextWithOwner(ctx, ownerUserID), prom, reason)
			if err != nil {
				joined = errors.Join(joined, err)
				continue
			}
			out = append(out, evaluations...)
		}
		return out, joined
	}
	services, err := s.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AnomalyEvaluation, 0)
	for _, service := range services {
		if !service.Enabled {
			continue
		}
		eval, err := s.evaluateServiceAnomaly(ctx, prom, service, reason)
		if err != nil {
			return out, err
		}
		if eval.ID != "" {
			out = append(out, eval)
		}
	}
	return out, nil
}

func queryRequiredScalar(ctx context.Context, prom *PrometheusClient, promQL string) (float64, error) {
	value, status := prom.QueryScalar(ctx, promQL)
	if !status.Configured {
		return 0, errors.New("prometheus is not configured")
	}
	if !status.Healthy {
		if status.Error == "" {
			status.Error = "prometheus query failed"
		}
		return 0, fmt.Errorf("prometheus query failed: %s", status.Error)
	}
	return value, nil
}

func (s *Store) ListAnomalies(ctx context.Context, limit int) ([]AnomalyEvaluation, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT ae.id::text, COALESCE(ae.service_id::text, ''), COALESCE(bs.ebpf_id, 0), COALESCE(bs.name, ''),
       COALESCE(ae.baseline_id::text, ''), ae.evaluated_at, ae.time_window, ae.pps, ae.bps, ae.cps, ae.drop_ratio,
       ae.score::float8, ae.confidence::float8, ae.signals, ae.recommendation, ae.recommended_action,
       ae.proposed_ttl_seconds, COALESCE(ae.proposed_rule_id::text, ''), ae.auto_enforced, ae.status, ae.reason,
       ae.source, ae.evidence
FROM anomaly_evaluations ae
LEFT JOIN backend_services bs ON bs.id = ae.service_id
WHERE ae.owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
ORDER BY ae.evaluated_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AnomalyEvaluation, 0)
	for rows.Next() {
		eval, err := scanAnomalyEvaluation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, eval)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) ExpireTTLRules(ctx context.Context) (int, error) {
	if ownerUserIDFromContext(ctx) == "" {
		ownerUserIDs, err := s.activeOwnerUserIDs(ctx)
		if err != nil {
			return 0, err
		}
		total := 0
		var joined error
		for _, ownerUserID := range ownerUserIDs {
			count, err := s.ExpireTTLRules(contextWithOwner(ctx, ownerUserID))
			total += count
			if err != nil {
				joined = errors.Join(joined, err)
			}
		}
		return total, joined
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, COALESCE(service_id::text, ''), name, priority, match_expr, action, mode,
       threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
       ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, created_at, updated_at
FROM rules
WHERE enabled AND expires_at IS NOT NULL AND expires_at <= now()
  AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
ORDER BY expires_at`)
	if err != nil {
		return 0, err
	}
	var expired []Rule
	for rows.Next() {
		var rule Rule
		if err := scanRule(rows, &rule); err != nil {
			rows.Close()
			return 0, err
		}
		expired = append(expired, rule)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	if len(expired) == 0 {
		return 0, tx.Commit(ctx)
	}

	for _, before := range expired {
		var after Rule
		err := scanRule(tx.QueryRow(ctx, `UPDATE rules SET enabled=false, updated_at=now()
WHERE id=$1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), name, priority, match_expr, action, mode,
          threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
          ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, created_at, updated_at`, before.ID), &after)
		if err != nil {
			return 0, err
		}
		if err := insertAudit(ctx, tx, nil, "expire_rule", "rule", before.ID, before, after, "ttl expired", ""); err != nil {
			return 0, err
		}
	}
	if _, err := s.rebuildSnapshotInTx(ctx, tx, nil, nil, "ttl expired"); err != nil {
		return 0, err
	}
	return len(expired), tx.Commit(ctx)
}

func (s *Store) evaluateServiceAnomaly(ctx context.Context, prom *PrometheusClient, service Service, reason string) (AnomalyEvaluation, error) {
	baseline, err := s.approvedBaselineForService(ctx, service.ID)
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	timeWindow := "5m"
	if baseline != nil && baseline.Window != "" {
		timeWindow = baseline.Window
	}
	pps, err := queryRequiredScalar(ctx, prom, fmt.Sprintf(`sum(rate(anti_ddos_xdp_packets_total{service_id="%d",action=~"0|1|6"}[1m]))`, service.EBPFID))
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	bps, err := queryRequiredScalar(ctx, prom, fmt.Sprintf(`sum(rate(anti_ddos_xdp_bytes_total{service_id="%d",action=~"0|1|6"}[1m])) * 8`, service.EBPFID))
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	cps, err := queryRequiredScalar(ctx, prom, fmt.Sprintf(`sum(rate(anti_ddos_xdp_packets_total{service_id="%d",proto="6",tcp_syn="1",action=~"0|1|6"}[1m]))`, service.EBPFID))
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	drops, err := queryRequiredScalar(ctx, prom, fmt.Sprintf(`sum(rate(anti_ddos_xdp_packets_total{service_id="%d",action="1"}[1m]))`, service.EBPFID))
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	dropRatio := 0.0
	if pps > 0 {
		dropRatio = drops / pps
	}

	confidence := defaultLowConfidence
	expectedPPS := defaultBaselinePPS
	expectedBPS := defaultBaselineBPS
	expectedCPS := defaultBaselineCPS
	lowConfidence := true
	var baselineID string
	if baseline != nil {
		baselineID = baseline.ID
		expectedPPS = nonzeroFloat(baseline.ExpectedPPS, defaultBaselinePPS)
		expectedBPS = nonzeroFloat(baseline.ExpectedBPS, defaultBaselineBPS)
		expectedCPS = nonzeroFloat(baseline.ExpectedCPS, defaultBaselineCPS)
		confidence = baseline.Confidence
		lowConfidence = !baseline.Approved || baseline.HistoryHours < 24 || baseline.Confidence < alertMinConfidence
	}

	var signals []string
	score := 0.0
	if pps > math.Max(defaultBaselinePPS, expectedPPS*2) {
		signals = append(signals, "pps_spike")
		score += 35
	}
	if bps > math.Max(defaultBaselineBPS, expectedBPS*2) {
		signals = append(signals, "bps_spike")
		score += 35
	}
	if cps > math.Max(defaultBaselineCPS, expectedCPS*2) {
		signals = append(signals, "syn_spike")
		score += 30
	}
	if dropRatio > 0.25 {
		signals = append(signals, "drop_ratio_spike")
		score += 10
	}
	if len(signals) == 0 {
		return AnomalyEvaluation{}, nil
	}
	if score > 100 {
		score = 100
	}

	source, _ := s.topEventSourceForService(ctx, service.EBPFID)
	whitelistConflict := false
	if source != "" {
		whitelistConflict, err = s.sourceWhitelistConflict(ctx, source, service.ID)
		if err != nil {
			return AnomalyEvaluation{}, err
		}
	}
	status := "observe_only"
	recommendation := "observe"
	recommendedAction := "investigate"
	evalReason := strings.TrimSpace(reason)
	if evalReason == "" {
		evalReason = "alert-only anomaly evaluation"
	}
	if score >= alertMinScore && len(signals) >= alertMinSignals {
		status = "alert_only"
		recommendation = "manual_mitigation"
		recommendedAction = "rate_limit"
	} else if evalReason == "alert-only anomaly evaluation" {
		evalReason = "score or evidence below alert threshold"
	}

	evidence := mustJSON(map[string]any{
		"signals":            signals,
		"source":             source,
		"whitelist_conflict": whitelistConflict,
		"metrics":            map[string]float64{"pps": pps, "bps": bps, "cps": cps, "drop_ratio": dropRatio},
		"baseline":           map[string]any{"id": baselineID, "expected_pps": expectedPPS, "expected_bps": expectedBPS, "expected_cps": expectedCPS, "low_confidence": lowConfidence},
	})
	eval, err := s.insertAnomalyEvaluation(ctx, AnomalyEvaluation{
		ServiceID:         service.ID,
		ServiceEBPFID:     service.EBPFID,
		ServiceName:       service.Name,
		BaselineID:        baselineID,
		Window:            timeWindow,
		PPS:               pps,
		BPS:               bps,
		CPS:               cps,
		DropRatio:         dropRatio,
		Score:             score,
		Confidence:        confidence,
		Signals:           signals,
		Recommendation:    recommendation,
		RecommendedAction: recommendedAction,
		AutoEnforced:      false,
		Status:            status,
		Reason:            evalReason,
		Source:            source,
		Evidence:          evidence,
	})
	if err == nil && eval.Status == "alert_only" {
		_, alertErr := s.CreateSystemAlert(ctx, AlertInput{
			Severity:          "critical",
			Type:              "anomaly",
			DedupeKey:         fmt.Sprintf("anomaly:%s:%s", service.ID, strings.Join(signals, ",")),
			ServiceID:         service.ID,
			AffectedService:   service.Name,
			Vector:            strings.Join(signals, ","),
			Evidence:          evidence,
			RecommendedAction: recommendedAction,
		})
		if alertErr != nil {
			s.logger.Warn("anomaly alert creation failed", "service_id", service.ID, "error", agentRedactedError(alertErr))
		}
	}
	return eval, err
}

func (s *Store) CreateSystemRule(ctx context.Context, input RuleInput, reason string) (Rule, error) {
	if err := validateRuleInput(input); err != nil {
		return Rule{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return Rule{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return Rule{}, err
	}
	enabled := boolDefault(input.Enabled, true)
	if input.TTLSeconds > 0 && input.ExpiresAt.IsZero() {
		input.ExpiresAt = time.Now().UTC().Add(time.Duration(input.TTLSeconds) * time.Second)
	}
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
	}
	var expires any
	if !input.ExpiresAt.IsZero() {
		expires = input.ExpiresAt
	}
	ctx, err = s.ownerContextForService(ctx, strings.TrimSpace(input.ServiceID))
	if err != nil {
		return Rule{}, err
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return Rule{}, err
	}
	defer tx.Rollback(ctx)
	var rule Rule
	err = scanRule(tx.QueryRow(ctx, `INSERT INTO rules(
    id, owner_user_id, service_id, name, priority, match_expr, action, mode, threshold_pps, threshold_bps, threshold_cps,
    dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence, confidence, enabled, owner
) VALUES ($1, NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid, $2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), name, priority, match_expr, action, mode, threshold_pps,
          threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence,
          confidence::float8, enabled, owner, created_at, updated_at`,
		id, serviceID, input.Name, defaultPriority(input.Priority), defaultJSON(input.MatchExpr),
		normalizeRuleAction(input.Action), normalizeMode(input.Mode), input.ThresholdPPS, input.ThresholdBPS,
		input.ThresholdCPS, normalizeRuleDimension(input.Dimension), input.BurstPackets, input.BurstBytes,
		input.SampleDenom, input.TTLSeconds, expires, defaultJSON(input.Evidence), input.Confidence, enabled, input.Owner,
	), &rule)
	if err != nil {
		return Rule{}, err
	}
	if err := insertAudit(ctx, tx, nil, "create_rule", "rule", rule.ID, nil, rule, reason, ""); err != nil {
		return Rule{}, err
	}
	if _, err := s.rebuildSnapshotInTx(ctx, tx, nil, nil, reason); err != nil {
		return Rule{}, err
	}
	return rule, tx.Commit(ctx)
}

func (s *Store) approvedBaselineForService(ctx context.Context, serviceID string) (*BaselineProfile, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `SELECT bp.id::text, bp.service_id::text, bs.ebpf_id, bs.name, bp.interface_name,
       bp.protocol, bp.port, bp.time_window, bp.expected_pps, bp.expected_bps, bp.expected_cps,
       bp.history_hours, bp.confidence::float8, bp.approved, bp.status, bp.evidence,
       bp.created_at, bp.updated_at, bp.approved_at
FROM baseline_profiles bp
JOIN backend_services bs ON bs.id = bp.service_id
WHERE bp.service_id=$1 AND bp.approved
  AND bp.owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
  AND bs.owner_user_id = bp.owner_user_id
ORDER BY bp.updated_at DESC
LIMIT 1`, serviceID)
	var profile BaselineProfile
	if err := scanBaselineProfile(row, &profile); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (s *Store) getBaselineProfile(ctx context.Context, q dbQuerier, id string) (BaselineProfile, error) {
	var profile BaselineProfile
	err := scanBaselineProfile(q.QueryRow(ctx, `SELECT bp.id::text, bp.service_id::text, COALESCE(bs.ebpf_id, 0), COALESCE(bs.name, ''),
       bp.interface_name, bp.protocol, bp.port, bp.time_window, bp.expected_pps, bp.expected_bps, bp.expected_cps,
       bp.history_hours, bp.confidence::float8, bp.approved, bp.status, bp.evidence,
       bp.created_at, bp.updated_at, bp.approved_at
FROM baseline_profiles bp
LEFT JOIN backend_services bs ON bs.id = bp.service_id
WHERE bp.id=$1 AND bp.owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid`, id), &profile)
	return profile, err
}

func scanBaselineProfile(row rowScanner, profile *BaselineProfile) error {
	var serviceEBPFID uint32
	var serviceName string
	var approvedAt *time.Time
	if err := row.Scan(
		&profile.ID,
		&profile.ServiceID,
		&serviceEBPFID,
		&serviceName,
		&profile.Interface,
		&profile.Protocol,
		&profile.Port,
		&profile.Window,
		&profile.ExpectedPPS,
		&profile.ExpectedBPS,
		&profile.ExpectedCPS,
		&profile.HistoryHours,
		&profile.Confidence,
		&profile.Approved,
		&profile.Status,
		&profile.Evidence,
		&profile.CreatedAt,
		&profile.UpdatedAt,
		&approvedAt,
	); err != nil {
		return err
	}
	profile.ServiceEBPFID = serviceEBPFID
	profile.ServiceName = serviceName
	profile.ApprovedAt = approvedAt
	return nil
}

func (s *Store) insertAnomalyEvaluation(ctx context.Context, input AnomalyEvaluation) (AnomalyEvaluation, error) {
	id, err := newUUID()
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	var baselineID any
	if strings.TrimSpace(input.BaselineID) != "" {
		baselineID = input.BaselineID
	}
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = input.ServiceID
	}
	var ruleID any
	if strings.TrimSpace(input.ProposedRuleID) != "" {
		ruleID = input.ProposedRuleID
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `INSERT INTO anomaly_evaluations(
    id, owner_user_id, service_id, baseline_id, time_window, pps, bps, cps, drop_ratio, score, confidence, signals,
    recommendation, recommended_action, proposed_ttl_seconds, proposed_rule_id, auto_enforced,
    status, reason, source, evidence
) VALUES ($1, NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid, $2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
RETURNING id::text, COALESCE(service_id::text, ''), $21::bigint, $22::text, COALESCE(baseline_id::text, ''),
          evaluated_at, time_window, pps, bps, cps, drop_ratio, score::float8, confidence::float8, signals,
          recommendation, recommended_action, proposed_ttl_seconds, COALESCE(proposed_rule_id::text, ''),
          auto_enforced, status, reason, source, evidence`,
		id, serviceID, baselineID, input.Window, input.PPS, input.BPS, input.CPS, input.DropRatio,
		input.Score, input.Confidence, pgtype.FlatArray[string](input.Signals), input.Recommendation,
		input.RecommendedAction, input.ProposedTTLSeconds, ruleID, input.AutoEnforced, input.Status,
		input.Reason, input.Source, defaultJSON(input.Evidence), input.ServiceEBPFID, input.ServiceName,
	)
	eval, err := scanAnomalyEvaluation(row)
	if err != nil {
		return AnomalyEvaluation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AnomalyEvaluation{}, err
	}
	return eval, nil
}

func scanAnomalyEvaluation(row rowScanner) (AnomalyEvaluation, error) {
	var eval AnomalyEvaluation
	var signals pgtype.FlatArray[string]
	if err := row.Scan(
		&eval.ID,
		&eval.ServiceID,
		&eval.ServiceEBPFID,
		&eval.ServiceName,
		&eval.BaselineID,
		&eval.EvaluatedAt,
		&eval.Window,
		&eval.PPS,
		&eval.BPS,
		&eval.CPS,
		&eval.DropRatio,
		&eval.Score,
		&eval.Confidence,
		&signals,
		&eval.Recommendation,
		&eval.RecommendedAction,
		&eval.ProposedTTLSeconds,
		&eval.ProposedRuleID,
		&eval.AutoEnforced,
		&eval.Status,
		&eval.Reason,
		&eval.Source,
		&eval.Evidence,
	); err != nil {
		return AnomalyEvaluation{}, err
	}
	eval.Signals = []string(signals)
	return eval, nil
}

func (s *Store) topEventSourceForService(ctx context.Context, serviceEBPFID uint32) (string, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var source string
	err = tx.QueryRow(ctx, `SELECT src_ip::text
FROM security_events
WHERE service_id=$1 AND event_time > now() - interval '5 minutes'
  AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
GROUP BY src_ip
ORDER BY COALESCE(sum(sample_rate), 0) DESC
LIMIT 1`, serviceEBPFID).Scan(&source)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return source, nil
}

func (s *Store) sourceWhitelistConflict(ctx context.Context, source, serviceID string) (bool, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT ip_or_cidr::text, scope, COALESCE(service_id::text, '')
FROM whitelist_entries
WHERE enabled AND (expires_at IS NULL OR expires_at > now())
  AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
  AND (scope = 'global' OR service_id = $1)`, serviceID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cidr, scope, entryServiceID string
		if err := rows.Scan(&cidr, &scope, &entryServiceID); err != nil {
			return false, err
		}
		if scope == "service" && entryServiceID != serviceID {
			continue
		}
		if cidrMatches(source, cidr) {
			rows.Close()
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, tx.Commit(ctx)
}

func validateBaselineProfileInput(input BaselineProfileInput) error {
	var errs []error
	if strings.TrimSpace(input.ServiceID) == "" {
		errs = append(errs, errors.New("service_id is required"))
	}
	if strings.TrimSpace(input.Interface) == "" {
		errs = append(errs, errors.New("interface is required"))
	}
	switch normalizeBaselineProtocol(input.Protocol) {
	case "tcp", "udp":
		if input.Port == 0 {
			errs = append(errs, errors.New("tcp/udp baseline requires port"))
		}
	case "icmp", "all":
	default:
		errs = append(errs, errors.New("protocol must be tcp, udp, icmp or all"))
	}
	if input.ExpectedPPS < 0 || input.ExpectedBPS < 0 || input.ExpectedCPS < 0 {
		errs = append(errs, errors.New("expected rates must be non-negative"))
	}
	if input.Confidence < 0 || input.Confidence > 1 {
		errs = append(errs, errors.New("confidence must be between 0 and 1"))
	}
	if len(input.Evidence) > 0 && !json.Valid(input.Evidence) {
		errs = append(errs, errors.New("evidence must be valid JSON"))
	}
	return errors.Join(errs...)
}

func normalizeBaselineProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "all"
	}
	return value
}

func nonzeroFloat(value, fallback float64) float64 {
	if value > 0 {
		return value
	}
	return fallback
}

func mustJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

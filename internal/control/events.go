package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type SecurityEventQuery struct {
	Since     time.Time
	Until     time.Time
	ServiceID uint32
	RuleID    uint32
	Src       string
	Action    uint8
	Reason    uint8
	Limit     int
}

func (s *Store) IngestSecurityEvents(ctx context.Context, agentID string, batch SecurityEventBatch, metrics *ControlMetrics) (SecurityEventIngestResult, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		if metrics != nil {
			metrics.IncSecurityEventReject("agent_id")
		}
		return SecurityEventIngestResult{}, errors.New("agent id is required")
	}
	if len(batch.Events) == 0 {
		return SecurityEventIngestResult{}, nil
	}
	if len(batch.Events) > 1000 {
		if metrics != nil {
			metrics.IncSecurityEventReject("batch_too_large")
		}
		return SecurityEventIngestResult{}, errors.New("event batch exceeds max 1000")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SecurityEventIngestResult{}, err
	}
	defer tx.Rollback(ctx)

	var accepted int
	for _, event := range batch.Events {
		normalized, err := normalizeSecurityEvent(event, s.cfg.EventSampleDenom)
		if err != nil {
			if metrics != nil {
				metrics.IncSecurityEventReject("validation")
			}
			return SecurityEventIngestResult{}, err
		}
		id, err := newUUID()
		if err != nil {
			return SecurityEventIngestResult{}, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO security_events(
    id, event_time, agent_id, mono_ts_ns, policy_version, src_ip, src_prefix24, dst_ip, src_port, dst_port,
    protocol, tcp_flags, action, reason, service_id, rule_id, pkt_len, sample_rate, metadata
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			id,
			normalized.EventTime,
			agentID,
			int64(normalized.MonoTSNS),
			normalized.PolicyVersion,
			normalized.SrcIP,
			normalized.SrcPrefix24,
			normalized.DstIP,
			normalized.SrcPort,
			normalized.DstPort,
			normalized.Protocol,
			normalized.TCPFlags,
			normalized.Action,
			normalized.Reason,
			normalized.ServiceID,
			normalized.RuleID,
			normalized.PktLen,
			normalized.SampleRate,
			normalized.Metadata,
		)
		if err != nil {
			return SecurityEventIngestResult{}, err
		}
		accepted++
		if metrics != nil {
			metrics.IncSecurityEvent(event)
		}
	}
	return SecurityEventIngestResult{Accepted: accepted}, tx.Commit(ctx)
}

func (s *Store) ListSecurityEvents(ctx context.Context, query SecurityEventQuery) ([]SecurityEvent, error) {
	where, args, err := securityEventWhere(query)
	if err != nil {
		return nil, err
	}
	limit := query.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	sql := `SELECT id::text, received_at, event_time, COALESCE(agent_id::text, ''), policy_version,
       src_ip::text, src_prefix24::text, dst_ip::text, src_port, dst_port, protocol, tcp_flags, action, reason,
       service_id, rule_id, pkt_len, sample_rate, metadata
FROM security_events ` + where + fmt.Sprintf(` ORDER BY event_time DESC LIMIT $%d`, len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SecurityEvent, 0)
	for rows.Next() {
		event, err := scanSecurityEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *Store) SecurityEventSummary(ctx context.Context, query SecurityEventQuery) (SecurityEventSummary, error) {
	if query.Since.IsZero() {
		query.Since = time.Now().Add(-5 * time.Minute)
	}
	if query.Until.IsZero() {
		query.Until = time.Now()
	}
	where, args, err := securityEventWhere(query)
	if err != nil {
		return SecurityEventSummary{}, err
	}
	summary := SecurityEventSummary{WindowSeconds: int(query.Until.Sub(query.Since).Seconds())}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_events `+where, args...).Scan(&summary.Total); err != nil {
		return SecurityEventSummary{}, err
	}
	summary.TopSources, err = s.securityEventTop(ctx, `src_prefix24::text`, where, args)
	if err != nil {
		return SecurityEventSummary{}, err
	}
	summary.TopPorts, err = s.securityEventTop(ctx, `dst_port::text`, where, args)
	if err != nil {
		return SecurityEventSummary{}, err
	}
	summary.ByDecision, err = s.securityEventTop(ctx, `(action::text || ':' || reason::text)`, where, args)
	if err != nil {
		return SecurityEventSummary{}, err
	}
	return summary, nil
}

func (s *Store) InvestigateSecurityEvents(ctx context.Context, target string, limit int) (map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target is required")
	}
	query := SecurityEventQuery{Src: target, Limit: limit}
	events, err := s.ListSecurityEvents(ctx, query)
	if err != nil {
		return nil, err
	}
	whitelist, err := s.ListWhitelistEntries(ctx)
	if err != nil {
		return nil, err
	}
	blacklist, err := s.ListBlacklistEntries(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"target":    target,
		"events":    events,
		"whitelist": matchingCIDRs(target, whitelist),
		"blacklist": matchingBlacklistCIDRs(target, blacklist),
	}, nil
}

func normalizeSecurityEvent(input SecurityEventInput, defaultSampleRate uint32) (SecurityEvent, error) {
	src, err := netip.ParseAddr(strings.TrimSpace(input.SrcIP))
	if err != nil || !src.Is4() {
		return SecurityEvent{}, errors.New("src_ip must be an IPv4 address")
	}
	dst, err := netip.ParseAddr(strings.TrimSpace(input.DstIP))
	if err != nil || !dst.Is4() {
		return SecurityEvent{}, errors.New("dst_ip must be an IPv4 address")
	}
	eventTime := input.EventTime
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	sampleRate := input.SampleRate
	if sampleRate == 0 {
		sampleRate = defaultSampleRate
	}
	if sampleRate == 0 {
		sampleRate = 1
	}
	metadata := defaultJSON(input.Metadata)
	return SecurityEvent{
		EventTime:     eventTime.UTC(),
		MonoTSNS:      input.MonoTSNS,
		PolicyVersion: input.PolicyVersion,
		SrcIP:         src.String(),
		SrcPrefix24:   netip.PrefixFrom(src, 24).Masked().String(),
		DstIP:         dst.String(),
		SrcPort:       input.SrcPort,
		DstPort:       input.DstPort,
		Protocol:      input.Protocol,
		TCPFlags:      input.TCPFlags,
		Action:        input.Action,
		Reason:        input.Reason,
		ServiceID:     input.ServiceID,
		RuleID:        input.RuleID,
		PktLen:        input.PktLen,
		SampleRate:    sampleRate,
		Metadata:      metadata,
	}, nil
}

func securityEventWhere(query SecurityEventQuery) (string, []any, error) {
	var clauses []string
	var args []any
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if !query.Since.IsZero() {
		add("event_time >= $%d", query.Since)
	}
	if !query.Until.IsZero() {
		add("event_time <= $%d", query.Until)
	}
	if query.ServiceID != 0 {
		add("service_id = $%d", query.ServiceID)
	}
	if query.RuleID != 0 {
		add("rule_id = $%d", query.RuleID)
	}
	if query.Action != 0 {
		add("action = $%d", query.Action)
	}
	if query.Reason != 0 {
		add("reason = $%d", query.Reason)
	}
	if strings.TrimSpace(query.Src) != "" {
		src := strings.TrimSpace(query.Src)
		if strings.Contains(src, "/") {
			if prefix, err := netip.ParsePrefix(src); err != nil || !prefix.Addr().Is4() {
				return "", nil, errors.New("src must be an IPv4 address or CIDR")
			}
			add("src_ip <<= $%d::cidr", src)
		} else {
			if addr, err := netip.ParseAddr(src); err != nil || !addr.Is4() {
				return "", nil, errors.New("src must be an IPv4 address or CIDR")
			}
			add("src_ip = $%d::inet", src)
		}
	}
	if len(clauses) == 0 {
		return "", args, nil
	}
	return "WHERE " + strings.Join(clauses, " AND "), args, nil
}

func (s *Store) securityEventTop(ctx context.Context, keyExpr, where string, args []any) ([]SecurityEventTop, error) {
	queryArgs := append([]any{}, args...)
	queryArgs = append(queryArgs, 10)
	sql := fmt.Sprintf(`SELECT %s AS key, count(*)::bigint, COALESCE(sum(sample_rate), 0)::bigint, COALESCE(sum(pkt_len * sample_rate), 0)::bigint
FROM security_events %s
GROUP BY key
ORDER BY count(*) DESC
LIMIT $%d`, keyExpr, where, len(queryArgs))
	rows, err := s.pool.Query(ctx, sql, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SecurityEventTop, 0)
	for rows.Next() {
		var item SecurityEventTop
		if err := rows.Scan(&item.Key, &item.Count, &item.Packets, &item.Bytes); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanSecurityEvent(row rowScanner) (SecurityEvent, error) {
	var event SecurityEvent
	var policyVersion, serviceID, ruleID int64
	var srcPort, dstPort, protocol, tcpFlags, action, reason, pktLen, sampleRate int64
	if err := row.Scan(
		&event.ID,
		&event.ReceivedAt,
		&event.EventTime,
		&event.AgentID,
		&policyVersion,
		&event.SrcIP,
		&event.SrcPrefix24,
		&event.DstIP,
		&srcPort,
		&dstPort,
		&protocol,
		&tcpFlags,
		&action,
		&reason,
		&serviceID,
		&ruleID,
		&pktLen,
		&sampleRate,
		&event.Metadata,
	); err != nil {
		return SecurityEvent{}, err
	}
	event.PolicyVersion = uint32(policyVersion)
	event.SrcPort = uint16(srcPort)
	event.DstPort = uint16(dstPort)
	event.Protocol = uint8(protocol)
	event.TCPFlags = uint8(tcpFlags)
	event.Action = uint8(action)
	event.Reason = uint8(reason)
	event.ServiceID = uint32(serviceID)
	event.RuleID = uint32(ruleID)
	event.PktLen = uint32(pktLen)
	event.SampleRate = uint32(sampleRate)
	return event, nil
}

func matchingCIDRs(target string, entries []WhitelistEntry) []WhitelistEntry {
	out := make([]WhitelistEntry, 0)
	for _, entry := range entries {
		if cidrMatches(target, entry.CIDR) {
			out = append(out, entry)
		}
	}
	return out
}

func matchingBlacklistCIDRs(target string, entries []BlacklistEntry) []BlacklistEntry {
	out := make([]BlacklistEntry, 0)
	for _, entry := range entries {
		if cidrMatches(target, entry.CIDR) {
			out = append(out, entry)
		}
	}
	return out
}

func cidrMatches(target, cidr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(strings.TrimSpace(target))
		if prefixErr != nil {
			return false
		}
		addr = prefix.Addr()
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		parsed, addrErr := netip.ParseAddr(strings.TrimSpace(cidr))
		if addrErr != nil {
			return false
		}
		prefix = netip.PrefixFrom(parsed, 32)
	}
	return prefix.Contains(addr)
}

func parseSecurityEventQuery(values map[string][]string) (SecurityEventQuery, error) {
	var query SecurityEventQuery
	var err error
	if raw := first(values, "since"); raw != "" {
		query.Since, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return query, fmt.Errorf("since must be RFC3339: %w", err)
		}
	}
	if raw := first(values, "until"); raw != "" {
		query.Until, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return query, fmt.Errorf("until must be RFC3339: %w", err)
		}
	}
	query.ServiceID = parseUint32Query(values, "service_id")
	query.RuleID = parseUint32Query(values, "rule_id")
	query.Action = uint8(parseUint32Query(values, "action"))
	query.Reason = uint8(parseUint32Query(values, "reason"))
	query.Src = first(values, "src")
	query.Limit = int(parseUint32Query(values, "limit"))
	return query, nil
}

func parseUint32Query(values map[string][]string, key string) uint32 {
	raw := first(values, key)
	if raw == "" {
		return 0
	}
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(parsed)
}

func first(values map[string][]string, key string) string {
	if len(values[key]) == 0 {
		return ""
	}
	return strings.TrimSpace(values[key][0])
}

func compactJSON(value any) json.RawMessage {
	raw, _ := json.Marshal(value)
	return raw
}

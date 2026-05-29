package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

func (s *Store) RebuildSnapshot(ctx context.Context, actor *Actor, reason string) (*SnapshotMetadata, error) {
	if err := requireOperator(actor); err != nil {
		return nil, err
	}
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("reason is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	meta, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, reason)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return meta, nil
}

func (s *Store) rebuildSnapshotInTx(ctx context.Context, tx pgx.Tx, actor *Actor, rollbackFrom *uint32, reason string) (*SnapshotMetadata, error) {
	latest, latestRaw, err := latestSnapshot(ctx, tx)
	if err != nil {
		return nil, err
	}
	nextVersion := uint32(1)
	if latest != nil {
		nextVersion = latest.Version + 1
	}

	snapshot, err := s.buildEffectiveSnapshot(ctx, tx, nextVersion)
	if err != nil {
		return nil, err
	}
	signed, err := agent.SignPolicySnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	if _, err := agent.VerifyPolicySnapshot(signed, agent.PolicySnapshotVerifyOptions{Now: time.Now().UTC()}); err != nil {
		return nil, err
	}
	if rollbackFrom == nil && latestRaw != nil {
		var previous agent.PolicySnapshot
		if err := json.Unmarshal(latestRaw, &previous); err == nil {
			prevFingerprint, prevErr := policyContentFingerprint(previous)
			nextFingerprint, nextErr := policyContentFingerprint(signed)
			if prevErr == nil && nextErr == nil && prevFingerprint == nextFingerprint {
				return nil, nil
			}
		}
	}

	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	var actorID any
	if actor != nil {
		actorID = actor.ID
	}
	var rollbackValue any
	if rollbackFrom != nil {
		rollbackValue = *rollbackFrom
	}
	if _, err := tx.Exec(ctx, `INSERT INTO policy_snapshots(version, checksum, object_checksum, snapshot, rollback_from, created_by)
VALUES ($1, $2, $3, $4, $5, $6)`,
		signed.Version,
		signed.Checksum,
		signed.ObjectChecksum,
		raw,
		rollbackValue,
		actorID,
	); err != nil {
		return nil, err
	}
	action := "create_snapshot"
	if rollbackFrom != nil {
		action = "rollback_snapshot"
	}
	meta := SnapshotMetadata{
		Version:        signed.Version,
		Checksum:       signed.Checksum,
		ObjectChecksum: signed.ObjectChecksum,
		RollbackFrom:   rollbackFrom,
		Snapshot:       raw,
	}
	if err := insertAudit(ctx, tx, actor, action, "policy_snapshot", fmt.Sprint(signed.Version), nil, meta, reason, ""); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (s *Store) RollbackSnapshot(ctx context.Context, actor *Actor, targetVersion uint32, reason string) (SnapshotMetadata, error) {
	if err := requireOperator(actor); err != nil {
		return SnapshotMetadata{}, err
	}
	if targetVersion == 0 {
		return SnapshotMetadata{}, errors.New("target_version is required")
	}
	if strings.TrimSpace(reason) == "" {
		return SnapshotMetadata{}, errors.New("reason is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SnapshotMetadata{}, err
	}
	defer tx.Rollback(ctx)

	latest, _, err := latestSnapshot(ctx, tx)
	if err != nil {
		return SnapshotMetadata{}, err
	}
	if latest == nil {
		return SnapshotMetadata{}, errors.New("no snapshots available")
	}
	targetRaw, err := snapshotRaw(ctx, tx, targetVersion)
	if err != nil {
		return SnapshotMetadata{}, err
	}
	var target agent.PolicySnapshot
	if err := json.Unmarshal(targetRaw, &target); err != nil {
		return SnapshotMetadata{}, err
	}
	nextVersion := latest.Version + 1
	target.Version = nextVersion
	target.Checksum = ""
	signed, err := agent.SignPolicySnapshot(target)
	if err != nil {
		return SnapshotMetadata{}, err
	}
	if _, err := agent.VerifyPolicySnapshot(signed, agent.PolicySnapshotVerifyOptions{Now: time.Now().UTC()}); err != nil {
		return SnapshotMetadata{}, err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return SnapshotMetadata{}, err
	}
	var actorID any
	if actor != nil {
		actorID = actor.ID
	}
	rollbackFrom := latest.Version
	if _, err := tx.Exec(ctx, `INSERT INTO policy_snapshots(version, checksum, object_checksum, snapshot, rollback_from, created_by)
VALUES ($1, $2, $3, $4, $5, $6)`, signed.Version, signed.Checksum, signed.ObjectChecksum, raw, rollbackFrom, actorID); err != nil {
		return SnapshotMetadata{}, err
	}
	meta := SnapshotMetadata{
		Version:        signed.Version,
		Checksum:       signed.Checksum,
		ObjectChecksum: signed.ObjectChecksum,
		RollbackFrom:   &rollbackFrom,
		Snapshot:       raw,
	}
	if err := insertAudit(ctx, tx, actor, "rollback_snapshot", "policy_snapshot", fmt.Sprint(signed.Version), targetVersion, meta, reason, ""); err != nil {
		return SnapshotMetadata{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SnapshotMetadata{}, err
	}
	return meta, nil
}

func (s *Store) ListSnapshots(ctx context.Context, includeSnapshot bool) ([]SnapshotMetadata, error) {
	rows, err := s.pool.Query(ctx, `SELECT version, checksum, object_checksum, snapshot, rollback_from, COALESCE(created_by::text, ''), created_at
FROM policy_snapshots ORDER BY version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SnapshotMetadata, 0)
	for rows.Next() {
		meta, err := scanSnapshot(rows, includeSnapshot)
		if err != nil {
			return nil, err
		}
		out = append(out, meta)
	}
	return out, rows.Err()
}

func (s *Store) LatestPolicyVersion(ctx context.Context) (uint32, error) {
	var version uint32
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&version)
	return version, err
}

func (s *Store) FetchSnapshot(ctx context.Context, activeVersion uint32) (*agent.PolicySnapshot, error) {
	var raw []byte
	var version uint32
	err := s.pool.QueryRow(ctx, `SELECT version, snapshot FROM policy_snapshots ORDER BY version DESC LIMIT 1`).Scan(&version, &raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if activeVersion >= version {
		return nil, nil
	}
	var snapshot agent.PolicySnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func latestSnapshot(ctx context.Context, q dbQuerier) (*SnapshotMetadata, []byte, error) {
	rows, err := q.Query(ctx, `SELECT version, checksum, object_checksum, snapshot, rollback_from, COALESCE(created_by::text, ''), created_at
FROM policy_snapshots ORDER BY version DESC LIMIT 1`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil, rows.Err()
	}
	meta, err := scanSnapshot(rows, true)
	if err != nil {
		return nil, nil, err
	}
	return &meta, meta.Snapshot, rows.Err()
}

func snapshotRaw(ctx context.Context, q dbQuerier, version uint32) ([]byte, error) {
	var raw []byte
	if err := q.QueryRow(ctx, `SELECT snapshot FROM policy_snapshots WHERE version = $1`, version).Scan(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func scanSnapshot(row rowScanner, includeSnapshot bool) (SnapshotMetadata, error) {
	var meta SnapshotMetadata
	var rollback *uint32
	var raw []byte
	if err := row.Scan(&meta.Version, &meta.Checksum, &meta.ObjectChecksum, &raw, &rollback, &meta.CreatedBy, &meta.CreatedAt); err != nil {
		return SnapshotMetadata{}, err
	}
	meta.RollbackFrom = rollback
	if includeSnapshot {
		meta.Snapshot = raw
	}
	return meta, nil
}

func (s *Store) buildEffectiveSnapshot(ctx context.Context, q dbQuerier, version uint32) (agent.PolicySnapshot, error) {
	objectChecksum, err := agent.FileSHA256(s.cfg.XDPObject)
	if err != nil {
		objectChecksum = "control-object-unavailable"
	}
	snapshot := agent.PolicySnapshot{
		SchemaVersion:  1,
		Version:        version,
		ObjectChecksum: objectChecksum,
		FeatureFlags:   []string{"policy_snapshot_v1", "ipv4", "ab_policy_maps", "tx_devmap"},
		Runtime: agent.PolicyRuntimeConfig{
			MalformedPolicy: ActionDrop,
			SampleDenom:     0,
		},
	}

	rules, err := snapshotRules(ctx, q)
	if err != nil {
		return agent.PolicySnapshot{}, err
	}
	services, err := s.snapshotServices(ctx, q, rules)
	if err != nil {
		return agent.PolicySnapshot{}, err
	}
	whitelist, err := snapshotWhitelist(ctx, q)
	if err != nil {
		return agent.PolicySnapshot{}, err
	}
	blacklist, err := snapshotBlacklist(ctx, q)
	if err != nil {
		return agent.PolicySnapshot{}, err
	}
	snapshot.Services = services
	snapshot.WhitelistV4 = whitelist
	snapshot.BlacklistV4 = blacklist
	snapshot.Rules = rules
	return snapshot, nil
}

func (s *Store) snapshotServices(ctx context.Context, q dbQuerier, rules []agent.PolicyRule) ([]agent.PolicyService, error) {
	fromPolicies, err := s.snapshotServicesFromForwardingPolicies(ctx, q)
	if err != nil {
		return nil, err
	}
	fallback, err := s.snapshotServicesFromBackendServices(ctx, q)
	if err != nil {
		return nil, err
	}
	out := append(fromPolicies, fallback...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].DstV4 != out[j].DstV4 {
			return out[i].DstV4 < out[j].DstV4
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].DstPort < out[j].DstPort
	})
	assignDefaultRules(out, rules)
	return out, nil
}

func (s *Store) snapshotServicesFromForwardingPolicies(ctx context.Context, q dbQuerier) ([]agent.PolicyService, error) {
	rows, err := q.Query(ctx, `SELECT fp.ebpf_id, fp.service_id::text, bs.ebpf_id, fp.match_protocol, fp.match_dst_port,
       fp.backend_target::text, fp.output_interface, fp.resolved_ifindex, fp.resolved_dst_mac, fp.resolved_src_mac,
       fp.devmap_key, fp.priority
FROM forwarding_policies fp
JOIN backend_services bs ON bs.id = fp.service_id
WHERE fp.enabled AND bs.enabled AND bs.deleted_at IS NULL
ORDER BY fp.priority, fp.ebpf_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]agent.PolicyService, 0)
	for rows.Next() {
		var policyID, serviceID, port, ifindex, devmapKey, priority uint32
		var serviceUUID, proto, target, outputInterface, dstMAC, srcMAC string
		if err := rows.Scan(&policyID, &serviceUUID, &serviceID, &proto, &port, &target, &outputInterface, &ifindex, &dstMAC, &srcMAC, &devmapKey, &priority); err != nil {
			return nil, err
		}
		host, err := hostV4(target)
		if err != nil {
			return nil, fmt.Errorf("forwarding policy %d target: %w", policyID, err)
		}
		service, err := s.makePolicyService(agent.ServiceResolveRequest{
			ServiceID:          serviceID,
			ForwardingPolicyID: policyID,
			DstV4:              host,
			DstPort:            uint16(port),
			Proto:              mustProto(proto),
			Priority:           priority,
			OutputInterface:    outputInterface,
			DevmapKey:          devmapKeyOrDefault(devmapKey, policyID),
		}, ifindex, dstMAC, srcMAC)
		if err != nil {
			return nil, fmt.Errorf("forwarding policy %d service %s: %w", policyID, serviceUUID, err)
		}
		out = append(out, service)
	}
	return out, rows.Err()
}

func (s *Store) snapshotServicesFromBackendServices(ctx context.Context, q dbQuerier) ([]agent.PolicyService, error) {
	rows, err := q.Query(ctx, `SELECT bs.id::text, bs.ebpf_id, bs.backend_cidr::text, bs.protocol, bs.allowed_ports, bs.output_interface,
       bs.resolved_ifindex, bs.resolved_next_hop_mac, bs.resolved_src_mac, bs.priority
FROM backend_services bs
WHERE bs.enabled AND bs.deleted_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM forwarding_policies fp WHERE fp.service_id = bs.id AND fp.enabled)
ORDER BY bs.priority, bs.ebpf_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]agent.PolicyService, 0)
	for rows.Next() {
		var uuid, cidr, proto, outputInterface, dstMAC, srcMAC string
		var serviceID, ifindex, priority uint32
		var ports pgtype.FlatArray[int32]
		if err := rows.Scan(&uuid, &serviceID, &cidr, &proto, &ports, &outputInterface, &ifindex, &dstMAC, &srcMAC, &priority); err != nil {
			return nil, err
		}
		host, err := hostV4(cidr)
		if err != nil {
			return nil, fmt.Errorf("backend service %s target: %w", uuid, err)
		}
		if proto == "icmp" && len(ports) == 0 {
			ports = pgtype.FlatArray[int32]{0}
		}
		for _, port := range ports {
			request := agent.ServiceResolveRequest{
				ServiceID:          serviceID,
				ForwardingPolicyID: serviceID,
				DstV4:              host,
				DstPort:            uint16(port),
				Proto:              mustProto(proto),
				Priority:           priority,
				OutputInterface:    outputInterface,
				DevmapKey:          devmapKeyOrDefault(0, serviceID),
			}
			service, err := s.makePolicyService(request, ifindex, dstMAC, srcMAC)
			if err != nil {
				return nil, fmt.Errorf("backend service %s: %w", uuid, err)
			}
			out = append(out, service)
		}
	}
	return out, rows.Err()
}

func (s *Store) makePolicyService(req agent.ServiceResolveRequest, ifindex uint32, dstMAC, srcMAC string) (agent.PolicyService, error) {
	dstMAC = strings.TrimSpace(dstMAC)
	srcMAC = strings.TrimSpace(srcMAC)
	if ifindex != 0 || dstMAC != "" || srcMAC != "" {
		if ifindex == 0 {
			return agent.PolicyService{}, errors.New("resolved_ifindex is required when using resolved forwarding metadata")
		}
		if dstMAC == "" {
			return agent.PolicyService{}, errors.New("resolved_next_hop_mac is required when using resolved forwarding metadata")
		}
		if srcMAC == "" {
			return agent.PolicyService{}, errors.New("resolved_src_mac is required when using resolved forwarding metadata")
		}
		return agent.PolicyService{
			ServiceID:          req.ServiceID,
			ForwardingPolicyID: req.ForwardingPolicyID,
			DstV4:              req.DstV4,
			DstPort:            req.DstPort,
			Proto:              req.Proto,
			Action:             ActionRedirect,
			Priority:           req.Priority,
			OutputIfindex:      ifindex,
			DevmapKey:          req.DevmapKey,
			NeighborStatus:     NeighborResolved,
			DstMAC:             dstMAC,
			SrcMAC:             srcMAC,
		}, nil
	}
	if s.resolver == nil {
		return agent.PolicyService{}, errors.New("resolved ifindex and MAC metadata are required")
	}
	resolved, err := s.resolver.ResolveService(req)
	if err != nil {
		return agent.PolicyService{}, err
	}
	return resolved.Service, nil
}

func snapshotWhitelist(ctx context.Context, q dbQuerier) ([]agent.PolicyCIDREntry, error) {
	rows, err := q.Query(ctx, `SELECT w.ebpf_id, w.ip_or_cidr::text, w.priority, w.scope, COALESCE(bs.ebpf_id, 0), w.expires_at
FROM whitelist_entries w
LEFT JOIN backend_services bs ON bs.id = w.service_id
WHERE w.enabled AND (w.expires_at IS NULL OR w.expires_at > now())
ORDER BY w.priority, w.ebpf_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]agent.PolicyCIDREntry, 0)
	for rows.Next() {
		var entry agent.PolicyCIDREntry
		var scope string
		var serviceID uint32
		var expires *time.Time
		if err := rows.Scan(&entry.EntryID, &entry.CIDR, &entry.Priority, &scope, &serviceID, &expires); err != nil {
			return nil, err
		}
		entry.Action = ActionPass
		entry.SourceType = 1
		entry.Scope = PolicyScopeGlobal
		if scope == "service" {
			entry.Scope = PolicyScopeService
			entry.ServiceID = serviceID
		}
		if expires != nil {
			entry.ExpiresAtUnixNS = uint64(expires.UnixNano())
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func snapshotBlacklist(ctx context.Context, q dbQuerier) ([]agent.PolicyCIDREntry, error) {
	rows, err := q.Query(ctx, `SELECT b.ebpf_id, b.ip_or_cidr::text, b.score, COALESCE(r.ebpf_id, 0), b.expires_at
FROM manual_blacklist_entries b
LEFT JOIN rules r ON r.id = b.rule_id
WHERE b.enabled AND (b.expires_at IS NULL OR b.expires_at > now())
UNION ALL
SELECT r.ebpf_id, r.ip_or_cidr::text, r.score, 0, r.expires_at
FROM reputation_entries r
JOIN feed_sources fs ON fs.id = r.source_id
WHERE fs.enabled
  AND r.status = 'active'
  AND r.action = 'drop'
  AND (r.expires_at IS NULL OR r.expires_at > now())
ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]agent.PolicyCIDREntry, 0)
	for rows.Next() {
		var entry agent.PolicyCIDREntry
		var expires *time.Time
		if err := rows.Scan(&entry.EntryID, &entry.CIDR, &entry.Score, &entry.RuleID, &expires); err != nil {
			return nil, err
		}
		entry.Action = ActionDrop
		entry.SourceType = 1
		entry.Scope = PolicyScopeGlobal
		if expires != nil {
			entry.ExpiresAtUnixNS = uint64(expires.UnixNano())
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func snapshotRules(ctx context.Context, q dbQuerier) ([]agent.PolicyRule, error) {
	rows, err := q.Query(ctx, `SELECT r.ebpf_id, COALESCE(bs.ebpf_id, 0), r.priority, r.action, r.mode, r.dimension, r.threshold_pps,
       r.threshold_bps, r.threshold_cps, r.burst_packets, r.burst_bytes, r.sample_denom, r.expires_at
FROM rules r
LEFT JOIN backend_services bs ON bs.id = r.service_id
WHERE r.enabled AND (r.expires_at IS NULL OR r.expires_at > now())
ORDER BY r.priority, r.ebpf_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]agent.PolicyRule, 0)
	for rows.Next() {
		var rule agent.PolicyRule
		var action, mode, dimension string
		var expires *time.Time
		if err := rows.Scan(&rule.RuleID, &rule.ServiceID, &rule.Priority, &action, &mode, &dimension, &rule.ThresholdPPS,
			&rule.ThresholdBPS, &rule.ThresholdCPS, &rule.BurstPackets, &rule.BurstBytes, &rule.SampleDenom, &expires); err != nil {
			return nil, err
		}
		rule.Action = ruleActionNumber(action)
		rule.Mode = ruleModeNumber(mode)
		rule.Dimension = ruleDimensionNumber(dimension)
		if expires != nil {
			rule.ExpiresAtUnixNS = uint64(expires.UnixNano())
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

func assignDefaultRules(services []agent.PolicyService, rules []agent.PolicyRule) {
	var global *agent.PolicyRule
	serviceRules := map[uint32]agent.PolicyRule{}
	for _, rule := range rules {
		if rule.RuleID == 0 {
			continue
		}
		if rule.ServiceID == 0 {
			if global == nil || rule.Priority < global.Priority ||
				(rule.Priority == global.Priority && rule.RuleID < global.RuleID) {
				candidate := rule
				global = &candidate
			}
			continue
		}
		current, ok := serviceRules[rule.ServiceID]
		if !ok || rule.Priority < current.Priority ||
			(rule.Priority == current.Priority && rule.RuleID < current.RuleID) {
			serviceRules[rule.ServiceID] = rule
		}
	}
	for i := range services {
		if rule, ok := serviceRules[services[i].ServiceID]; ok {
			services[i].DefaultRuleID = rule.RuleID
		} else if global != nil {
			services[i].DefaultRuleID = global.RuleID
		}
	}
}

func policyContentFingerprint(snapshot agent.PolicySnapshot) (string, error) {
	snapshot.Version = 0
	snapshot.Checksum = ""
	return agent.CanonicalPolicyChecksum(snapshot)
}

func hostV4(value string) (string, error) {
	prefix, err := parseCIDR(value)
	if err != nil {
		return "", err
	}
	if prefix.Bits() != 32 {
		return "", fmt.Errorf("active service snapshot requires IPv4 host /32, got %s", value)
	}
	return prefix.Addr().String(), nil
}

func mustProto(proto string) uint8 {
	value, err := policyProtoNumber(proto)
	if err != nil {
		return 0
	}
	return value
}

func devmapKeyOrDefault(value, seed uint32) uint32 {
	if value != 0 {
		return value
	}
	key := seed % 128
	if key == 0 {
		key = 1
	}
	return key
}

func validateHostCIDR(value string) error {
	prefix, err := parseCIDR(value)
	if err != nil {
		return err
	}
	if prefix.Bits() != 32 {
		return fmt.Errorf("active service snapshot requires IPv4 host /32, got %s", value)
	}
	return nil
}

func parseHost(value string) (netip.Addr, error) {
	prefix, err := parseCIDR(value)
	if err != nil {
		return netip.Addr{}, err
	}
	if prefix.Bits() != 32 {
		return netip.Addr{}, fmt.Errorf("expected IPv4 host /32, got %s", value)
	}
	return prefix.Addr(), nil
}

var _ = parseHost

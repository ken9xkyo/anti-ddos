package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func (s *Store) CreateService(ctx context.Context, actor *Actor, input ServiceInput, reason string) (Service, error) {
	if err := requireConfigMutation(actor); err != nil {
		return Service{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return Service{}, errors.New("reason is required")
	}

	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return Service{}, err
	}
	defer tx.Rollback(ctx)

	if actor.Role == RoleUser {
		ownerID := actorOwnerUserID(actor)
		user, err := s.getUser(ctx, tx, ownerID)
		if err != nil {
			return Service{}, fmt.Errorf("fetch owner user: %w", err)
		}
		if strings.TrimSpace(user.DefaultOutputInterface) != "" {
			input.OutputInterface = user.DefaultOutputInterface
		} else if strings.TrimSpace(input.OutputInterface) == "" {
			return Service{}, errors.New("default output interface not assigned by administrator")
		}
	}

	if input.OutputInterface != "" && (input.ResolvedIfindex == 0 || input.ResolvedSourceMAC == "") {
		var ifaceIfindex int
		var ifaceMAC string
		err := tx.QueryRow(ctx, `SELECT ifindex, mac FROM agent_interfaces WHERE name = $1 AND owner_user_id = $2 LIMIT 1`,
			input.OutputInterface, actorOwnerUserID(actor)).Scan(&ifaceIfindex, &ifaceMAC)
		if err == nil {
			if input.ResolvedIfindex == 0 {
				input.ResolvedIfindex = uint32(ifaceIfindex)
			}
			if input.ResolvedSourceMAC == "" {
				input.ResolvedSourceMAC = ifaceMAC
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return Service{}, fmt.Errorf("lookup agent interface: %w", err)
		}
	}

	if err := validateServiceInput(input); err != nil {
		return Service{}, err
	}

	id, err := newUUID()
	if err != nil {
		return Service{}, err
	}
	enabled := boolDefault(input.Enabled, true)
	ports := int32Ports(input.AllowedPorts)
	tags := textArray(input.Tags)

	if err := s.ValidateServiceCIDR(ctx, tx, actorOwnerUserID(actor), input.BackendCIDR); err != nil {
		return Service{}, err
	}

	var service Service
	err = scanService(tx.QueryRow(ctx, `INSERT INTO backend_services(
    id, owner_user_id, name, description, backend_cidr, protocol, allowed_ports, output_interface, owner, criticality,
    protection_mode, enabled, priority, tags, resolved_ifindex, resolved_next_hop_mac, resolved_src_mac, neighbor_resolution_status
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
RETURNING id::text, ebpf_id, name, description, backend_cidr::text, protocol, allowed_ports, output_interface, owner,
          criticality, protection_mode, enabled, priority, tags, sync_status, resolved_ifindex, resolved_next_hop_mac,
          resolved_src_mac, neighbor_resolution_status, created_at, updated_at`,
		id,
		actorOwnerUserID(actor),
		input.Name,
		input.Description,
		input.BackendCIDR,
		normalizeProtocol(input.Protocol),
		pgtype.FlatArray[int32](ports),
		input.OutputInterface,
		actor.Username,
		input.Criticality,
		strings.ToLower(strings.TrimSpace(input.ProtectionMode)),
		enabled,
		defaultPriority(input.Priority),
		tags,
		input.ResolvedIfindex,
		strings.TrimSpace(input.ResolvedNextHopMAC),
		strings.TrimSpace(input.ResolvedSourceMAC),
		neighborStatus(input.NeighborResolutionStatus),
	), &service)
	if err != nil {
		return Service{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_service", "backend_service", service.ID, nil, service, reason, ""); err != nil {
		return Service{}, err
	}
	if _, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, reason); err != nil {
		return Service{}, err
	}
	return service, tx.Commit(ctx)
}

func (s *Store) UpdateService(ctx context.Context, actor *Actor, id string, input ServiceInput, reason string) (Service, error) {
	if err := requireConfigMutation(actor); err != nil {
		return Service{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return Service{}, errors.New("reason is required")
	}
	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return Service{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.getService(ctx, tx, id)
	if err != nil {
		return Service{}, err
	}

	if actor.Role == RoleUser {
		input.OutputInterface = before.OutputInterface
	}

	if err := validateServiceInput(input); err != nil {
		return Service{}, err
	}

	if err := s.ValidateServiceCIDR(ctx, tx, actorOwnerUserID(actor), input.BackendCIDR); err != nil {
		return Service{}, err
	}

	enabled := boolDefault(input.Enabled, before.Enabled)
	ports := int32Ports(input.AllowedPorts)
	var after Service
	err = scanService(tx.QueryRow(ctx, `UPDATE backend_services SET
    name=$2, description=$3, backend_cidr=$4, protocol=$5, allowed_ports=$6, output_interface=$7, owner=$8,
    criticality=$9, protection_mode=$10, enabled=$11, priority=$12, tags=$13, resolved_ifindex=$14,
    resolved_next_hop_mac=$15, resolved_src_mac=$16, neighbor_resolution_status=$17, sync_status='pending', updated_at=now()
WHERE id=$1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
RETURNING id::text, ebpf_id, name, description, backend_cidr::text, protocol, allowed_ports, output_interface, owner,
          criticality, protection_mode, enabled, priority, tags, sync_status, resolved_ifindex, resolved_next_hop_mac,
          resolved_src_mac, neighbor_resolution_status, created_at, updated_at`,
		id,
		input.Name,
		input.Description,
		input.BackendCIDR,
		normalizeProtocol(input.Protocol),
		pgtype.FlatArray[int32](ports),
		input.OutputInterface,
		before.Owner,
		input.Criticality,
		strings.ToLower(strings.TrimSpace(input.ProtectionMode)),
		enabled,
		defaultPriority(input.Priority),
		textArray(input.Tags),
		input.ResolvedIfindex,
		strings.TrimSpace(input.ResolvedNextHopMAC),
		strings.TrimSpace(input.ResolvedSourceMAC),
		neighborStatus(input.NeighborResolutionStatus),
	), &after)
	if err != nil {
		return Service{}, err
	}
	if err := insertAudit(ctx, tx, actor, "update_service", "backend_service", id, before, after, reason, ""); err != nil {
		return Service{}, err
	}
	if _, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, reason); err != nil {
		return Service{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) DeleteService(ctx context.Context, actor *Actor, id, reason string) (Service, error) {
	if err := requireConfigMutation(actor); err != nil {
		return Service{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return Service{}, errors.New("reason is required")
	}
	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return Service{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.getService(ctx, tx, id)
	if err != nil {
		return Service{}, err
	}
	var after Service
	err = scanService(tx.QueryRow(ctx, `UPDATE backend_services SET enabled=false, deleted_at=now(), sync_status='pending', updated_at=now()
WHERE id=$1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
RETURNING id::text, ebpf_id, name, description, backend_cidr::text, protocol, allowed_ports, output_interface, owner,
          criticality, protection_mode, enabled, priority, tags, sync_status, resolved_ifindex, resolved_next_hop_mac,
          resolved_src_mac, neighbor_resolution_status, created_at, updated_at`, id), &after)
	if err != nil {
		return Service{}, err
	}
	if err := insertAudit(ctx, tx, actor, "disable_service", "backend_service", id, before, after, reason, ""); err != nil {
		return Service{}, err
	}
	if _, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, reason); err != nil {
		return Service{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) ListServices(ctx context.Context) ([]Service, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, name, description, backend_cidr::text, protocol, allowed_ports, output_interface, owner,
          criticality, protection_mode, enabled, priority, tags, sync_status, resolved_ifindex, resolved_next_hop_mac,
          resolved_src_mac, neighbor_resolution_status, created_at, updated_at
FROM backend_services
WHERE deleted_at IS NULL
  AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Service, 0)
	for rows.Next() {
		var service Service
		if err := scanService(rows, &service); err != nil {
			return nil, err
		}
		out = append(out, service)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) getService(ctx context.Context, q dbQuerier, id string) (Service, error) {
	var service Service
	err := scanService(q.QueryRow(ctx, `SELECT id::text, ebpf_id, name, description, backend_cidr::text, protocol, allowed_ports, output_interface, owner,
          criticality, protection_mode, enabled, priority, tags, sync_status, resolved_ifindex, resolved_next_hop_mac,
          resolved_src_mac, neighbor_resolution_status, created_at, updated_at
FROM backend_services
WHERE id=$1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid`, id), &service)
	return service, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanService(row rowScanner, service *Service) error {
	var ports pgtype.FlatArray[int32]
	var tags pgtype.FlatArray[string]
	if err := row.Scan(
		&service.ID,
		&service.EBPFID,
		&service.Name,
		&service.Description,
		&service.BackendCIDR,
		&service.Protocol,
		&ports,
		&service.OutputInterface,
		&service.Owner,
		&service.Criticality,
		&service.ProtectionMode,
		&service.Enabled,
		&service.Priority,
		&tags,
		&service.SyncStatus,
		&service.ResolvedIfindex,
		&service.ResolvedNextHopMAC,
		&service.ResolvedSourceMAC,
		&service.NeighborResolutionStatus,
		&service.CreatedAt,
		&service.UpdatedAt,
	); err != nil {
		return err
	}
	service.AllowedPorts = uint16Ports([]int32(ports))
	service.Tags = []string(tags)
	return nil
}

func (s *Store) CreateForwardingPolicy(ctx context.Context, actor *Actor, input ForwardingPolicyInput, reason string) (ForwardingPolicy, error) {
	if err := requireConfigMutation(actor); err != nil {
		return ForwardingPolicy{}, err
	}
	if err := validateForwardingPolicyInput(input); err != nil {
		return ForwardingPolicy{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return ForwardingPolicy{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return ForwardingPolicy{}, err
	}
	enabled := boolDefault(input.Enabled, true)
	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return ForwardingPolicy{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := s.getService(ctx, tx, input.ServiceID); err != nil {
		return ForwardingPolicy{}, err
	}
	var policy ForwardingPolicy
	err = scanForwardingPolicy(tx.QueryRow(ctx, `INSERT INTO forwarding_policies(
    id, owner_user_id, service_id, match_protocol, match_dst_port, backend_target, output_interface, resolved_ifindex,
    resolved_dst_mac, resolved_src_mac, devmap_key, action, priority, enabled, owner
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
RETURNING id::text, ebpf_id, service_id::text, match_protocol, match_dst_port, backend_target::text, output_interface,
          resolved_ifindex, resolved_dst_mac, resolved_src_mac, devmap_key, action, priority, enabled, owner, created_at, updated_at`,
		id,
		actorOwnerUserID(actor),
		input.ServiceID,
		normalizeProtocol(input.MatchProtocol),
		input.MatchDstPort,
		input.BackendTarget,
		input.OutputInterface,
		input.ResolvedIfindex,
		strings.TrimSpace(input.ResolvedDstMAC),
		strings.TrimSpace(input.ResolvedSrcMAC),
		input.DevmapKey,
		normalizeForwardingAction(input.Action),
		defaultPriority(input.Priority),
		enabled,
		input.Owner,
	), &policy)
	if err != nil {
		return ForwardingPolicy{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_forwarding_policy", "forwarding_policy", policy.ID, nil, policy, reason, ""); err != nil {
		return ForwardingPolicy{}, err
	}
	if _, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, reason); err != nil {
		return ForwardingPolicy{}, err
	}
	return policy, tx.Commit(ctx)
}

func (s *Store) ListForwardingPolicies(ctx context.Context) ([]ForwardingPolicy, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, service_id::text, match_protocol, match_dst_port, backend_target::text, output_interface,
          resolved_ifindex, resolved_dst_mac, resolved_src_mac, devmap_key, action, priority, enabled, owner, created_at, updated_at
FROM forwarding_policies
WHERE owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ForwardingPolicy, 0)
	for rows.Next() {
		var policy ForwardingPolicy
		if err := scanForwardingPolicy(rows, &policy); err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func scanForwardingPolicy(row rowScanner, policy *ForwardingPolicy) error {
	return row.Scan(
		&policy.ID,
		&policy.EBPFID,
		&policy.ServiceID,
		&policy.MatchProtocol,
		&policy.MatchDstPort,
		&policy.BackendTarget,
		&policy.OutputInterface,
		&policy.ResolvedIfindex,
		&policy.ResolvedDstMAC,
		&policy.ResolvedSrcMAC,
		&policy.DevmapKey,
		&policy.Action,
		&policy.Priority,
		&policy.Enabled,
		&policy.Owner,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
}

func (s *Store) CreateWhitelistEntry(ctx context.Context, actor *Actor, input WhitelistInput, reason string) (WhitelistEntry, error) {
	scope, err := requirePolicyMutation(actor, input.ScopeType, input.Scope, input.ServiceID)
	if err != nil {
		return WhitelistEntry{}, err
	}
	input.ScopeType = scope.ScopeType
	input.Scope = legacyScopeForScopeType(scope.ScopeType)
	if scope.ScopeType != ScopeTypeService {
		input.ServiceID = ""
	}
	if err := validateWhitelistInput(input); err != nil {
		return WhitelistEntry{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return WhitelistEntry{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return WhitelistEntry{}, err
	}
	enabled := boolDefault(input.Enabled, true)
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return WhitelistEntry{}, err
	}
	defer tx.Rollback(ctx)
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
		if _, err := s.getService(ctx, tx, strings.TrimSpace(input.ServiceID)); err != nil {
			return WhitelistEntry{}, err
		}
	}
	var expires any
	if !input.ExpiresAt.IsZero() {
		expires = input.ExpiresAt
	}
	var entry WhitelistEntry
	err = scanWhitelistEntry(tx.QueryRow(ctx, `INSERT INTO whitelist_entries(id, owner_user_id, ip_or_cidr, scope, scope_type, service_id, label, reason, owner, priority, expires_at, enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING id::text, ebpf_id, ip_or_cidr::text, scope, scope_type, COALESCE(service_id::text, ''), label, reason, owner, priority,
          expires_at, enabled, true, created_at, updated_at`,
		id,
		scope.OwnerUserID,
		input.CIDR,
		normalizeScope(input.Scope),
		scope.ScopeType,
		serviceID,
		input.Label,
		reason,
		scope.Owner,
		defaultPriority(input.Priority),
		expires,
		enabled,
	), &entry)
	if err != nil {
		return WhitelistEntry{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_whitelist", "whitelist_entry", entry.ID, nil, entry, reason, ""); err != nil {
		return WhitelistEntry{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return WhitelistEntry{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) ListWhitelistEntries(ctx context.Context, actor *Actor, query WhitelistEntryQuery) ([]WhitelistEntry, error) {
	where, args := whitelistEntryWhere(actor, query)
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT w.id::text, w.ebpf_id, w.ip_or_cidr::text, w.scope, w.scope_type, COALESCE(w.service_id::text, ''), w.label, w.reason, w.owner, w.priority,
          w.expires_at, w.enabled, `+policyEditableSQL("w", actor)+`, w.created_at, w.updated_at
FROM whitelist_entries w
LEFT JOIN backend_services bs ON bs.id = w.service_id
`+where+` ORDER BY w.priority, w.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]WhitelistEntry, 0)
	for rows.Next() {
		var entry WhitelistEntry
		if err := scanWhitelistEntry(rows, &entry); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func parseWhitelistEntryQuery(values map[string][]string) (WhitelistEntryQuery, error) {
	query := WhitelistEntryQuery{
		Search:    first(values, "q"),
		Scope:     whitelistQueryValue(first(values, "scope"), "all"),
		ScopeType: whitelistQueryValue(first(values, "scope_type"), "all"),
		ServiceID: first(values, "service_id"),
		State:     whitelistQueryValue(first(values, "state"), "all"),
		Expiry:    whitelistQueryValue(first(values, "expiry"), "all"),
	}
	switch query.Scope {
	case "all", "global", "service":
	default:
		return query, fmt.Errorf("scope must be all, global, or service")
	}
	switch query.ScopeType {
	case "all", ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
	default:
		return query, fmt.Errorf("scope_type must be all, admin_global, user_global, or service")
	}
	switch query.State {
	case "all", "enabled", "disabled":
	default:
		return query, fmt.Errorf("state must be all, enabled, or disabled")
	}
	switch query.Expiry {
	case "all", "valid", "expired", "none":
	default:
		return query, fmt.Errorf("expiry must be all, valid, expired, or none")
	}
	return query, nil
}

func whitelistQueryValue(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func whitelistEntryWhere(actor *Actor, query WhitelistEntryQuery) (string, []any) {
	clauses := []string{policyListWhere("w", actor)}
	args := make([]any, 0)
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}

	if search := strings.TrimSpace(query.Search); search != "" {
		args = append(args, "%"+search+"%")
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf(`(w.ip_or_cidr::text ILIKE $%d OR w.label ILIKE $%d OR w.owner ILIKE $%d OR w.reason ILIKE $%d OR COALESCE(bs.name, '') ILIKE $%d)`, idx, idx, idx, idx, idx))
	}
	switch whitelistQueryValue(query.Scope, "all") {
	case "global":
		add("w.scope = $%d", "global")
	case "service":
		add("w.scope = $%d", "service")
	}
	switch whitelistQueryValue(query.ScopeType, "all") {
	case ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
		add("w.scope_type = $%d", query.ScopeType)
	}
	switch whitelistQueryValue(query.State, "all") {
	case "enabled":
		clauses = append(clauses, "w.enabled")
	case "disabled":
		clauses = append(clauses, "NOT w.enabled")
	}
	switch whitelistQueryValue(query.Expiry, "all") {
	case "valid":
		clauses = append(clauses, "(w.expires_at IS NULL OR w.expires_at > now())")
	case "expired":
		clauses = append(clauses, "w.expires_at IS NOT NULL AND w.expires_at <= now()")
	case "none":
		clauses = append(clauses, "w.expires_at IS NULL")
	}
	if serviceID := strings.TrimSpace(query.ServiceID); serviceID != "" {
		if whitelistQueryValue(query.Scope, "all") == "service" {
			add("w.service_id = $%d", serviceID)
		} else {
			add("(w.scope = 'global' OR w.service_id = $%d)", serviceID)
		}
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

func scanWhitelistEntry(row rowScanner, entry *WhitelistEntry) error {
	var expires *time.Time
	if err := row.Scan(
		&entry.ID,
		&entry.EBPFID,
		&entry.CIDR,
		&entry.Scope,
		&entry.ScopeType,
		&entry.ServiceID,
		&entry.Label,
		&entry.Reason,
		&entry.Owner,
		&entry.Priority,
		&expires,
		&entry.Enabled,
		&entry.Editable,
		&entry.CreatedAt,
		&entry.UpdatedAt,
	); err != nil {
		return err
	}
	entry.ExpiresAt = expires
	return nil
}

func (s *Store) CreateRule(ctx context.Context, actor *Actor, input RuleInput, reason string) (Rule, error) {
	scope, err := requirePolicyMutation(actor, input.ScopeType, "", input.ServiceID)
	if err != nil {
		return Rule{}, err
	}
	input.ScopeType = scope.ScopeType
	if scope.ScopeType != ScopeTypeService {
		input.ServiceID = ""
	}
	if err := validateRuleInput(input); err != nil {
		return Rule{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return Rule{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return Rule{}, err
	}
	enabled := boolDefault(input.Enabled, true)
	matchExpr := defaultJSON(input.MatchExpr)
	evidence := defaultJSON(input.Evidence)
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
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return Rule{}, err
	}
	defer tx.Rollback(ctx)
	if strings.TrimSpace(input.ServiceID) != "" {
		if _, err := s.getService(ctx, tx, strings.TrimSpace(input.ServiceID)); err != nil {
			return Rule{}, err
		}
	}
	var rule Rule
	err = scanRule(tx.QueryRow(ctx, `INSERT INTO rules(
    id, owner_user_id, scope_type, service_id, name, priority, match_expr, action, mode, threshold_pps, threshold_bps, threshold_cps,
    dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence, confidence, enabled, owner
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode, threshold_pps,
          threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence,
          confidence::float8, enabled, owner, true, created_at, updated_at`,
		id,
		scope.OwnerUserID,
		scope.ScopeType,
		serviceID,
		input.Name,
		defaultPriority(input.Priority),
		matchExpr,
		normalizeRuleAction(input.Action),
		normalizeMode(input.Mode),
		input.ThresholdPPS,
		input.ThresholdBPS,
		input.ThresholdCPS,
		normalizeRuleDimension(input.Dimension),
		input.BurstPackets,
		input.BurstBytes,
		input.SampleDenom,
		input.TTLSeconds,
		expires,
		evidence,
		input.Confidence,
		enabled,
		scope.Owner,
	), &rule)
	if err != nil {
		return Rule{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_rule", "rule", rule.ID, nil, rule, reason, ""); err != nil {
		return Rule{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return Rule{}, err
	}
	return rule, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) ListRules(ctx context.Context, actor *Actor) ([]Rule, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode, threshold_pps,
          threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence,
          confidence::float8, enabled, owner, `+policyEditableSQL("", actor)+`, created_at, updated_at
FROM rules
WHERE `+policyListWhere("", actor)+`
ORDER BY priority, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Rule, 0)
	for rows.Next() {
		var rule Rule
		if err := scanRule(rows, &rule); err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) ExpireTTLRules(ctx context.Context) (int, error) {
	if ownerUserIDFromContext(ctx) == "" {
		adminCount, adminErr := s.expireAdminGlobalTTLRules(ctx)
		ownerUserIDs, err := s.activeOwnerUserIDs(ctx)
		if err != nil {
			return adminCount, errors.Join(adminErr, err)
		}
		total := adminCount
		var joined error = adminErr
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

	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode,
       threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
       ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, false, created_at, updated_at
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
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode,
          threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
          ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, false, created_at, updated_at`, before.ID), &after)
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

func (s *Store) expireAdminGlobalTTLRules(ctx context.Context) (int, error) {
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode,
       threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
       ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, false, created_at, updated_at
FROM rules
WHERE enabled AND expires_at IS NOT NULL AND expires_at <= now()
  AND scope_type = 'admin_global'
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
WHERE id=$1 AND scope_type = 'admin_global'
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode,
          threshold_pps, threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom,
          ttl_seconds, expires_at, evidence, confidence::float8, enabled, owner, false, created_at, updated_at`, before.ID), &after)
		if err != nil {
			return 0, err
		}
		if err := insertAudit(ctx, tx, nil, "expire_rule", "rule", before.ID, before, after, "ttl expired", ""); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	if _, err := s.rebuildAllActiveUserSnapshots(ctx, nil, "ttl expired"); err != nil {
		return len(expired), err
	}
	return len(expired), nil
}

func scanRule(row rowScanner, rule *Rule) error {
	var expires *time.Time
	if err := row.Scan(
		&rule.ID,
		&rule.EBPFID,
		&rule.ServiceID,
		&rule.ScopeType,
		&rule.Name,
		&rule.Priority,
		&rule.MatchExpr,
		&rule.Action,
		&rule.Mode,
		&rule.ThresholdPPS,
		&rule.ThresholdBPS,
		&rule.ThresholdCPS,
		&rule.Dimension,
		&rule.BurstPackets,
		&rule.BurstBytes,
		&rule.SampleDenom,
		&rule.TTLSeconds,
		&expires,
		&rule.Evidence,
		&rule.Confidence,
		&rule.Enabled,
		&rule.Owner,
		&rule.Editable,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	); err != nil {
		return err
	}
	rule.ExpiresAt = expires
	return nil
}

func (s *Store) CreateBlacklistEntry(ctx context.Context, actor *Actor, input BlacklistInput, reason string) (BlacklistEntry, error) {
	scope, err := requirePolicyMutation(actor, input.ScopeType, "", input.ServiceID)
	if err != nil {
		return BlacklistEntry{}, err
	}
	input.ScopeType = scope.ScopeType
	if scope.ScopeType != ScopeTypeService {
		input.ServiceID = ""
	}
	if err := validateBlacklistInput(input); err != nil {
		return BlacklistEntry{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return BlacklistEntry{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return BlacklistEntry{}, err
	}
	enabled := boolDefault(input.Enabled, true)
	var ruleID any
	if strings.TrimSpace(input.RuleID) != "" {
		ruleID = strings.TrimSpace(input.RuleID)
	}
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
	}
	var expires any
	if !input.ExpiresAt.IsZero() {
		expires = input.ExpiresAt
	}
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return BlacklistEntry{}, err
	}
	defer tx.Rollback(ctx)
	if strings.TrimSpace(input.ServiceID) != "" {
		if _, err := s.getService(ctx, tx, strings.TrimSpace(input.ServiceID)); err != nil {
			return BlacklistEntry{}, err
		}
	}
	if strings.TrimSpace(input.RuleID) != "" {
		if _, err := getRule(ctx, tx, strings.TrimSpace(input.RuleID), scope); err != nil {
			return BlacklistEntry{}, err
		}
	}
	var entry BlacklistEntry
	err = scanBlacklistEntry(tx.QueryRow(ctx, `INSERT INTO manual_blacklist_entries(id, owner_user_id, scope_type, service_id, ip_or_cidr, score, action, source, rule_id, reason, owner, expires_at, enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
RETURNING id::text, ebpf_id, ip_or_cidr::text, scope_type, COALESCE(service_id::text, ''), score, action, source, COALESCE(rule_id::text, ''), reason, owner, expires_at, enabled, true, created_at, updated_at`,
		id,
		scope.OwnerUserID,
		scope.ScopeType,
		serviceID,
		input.CIDR,
		input.Score,
		normalizeBlacklistAction(input.Action),
		input.Source,
		ruleID,
		reason,
		scope.Owner,
		expires,
		enabled,
	), &entry)
	if err != nil {
		return BlacklistEntry{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_blacklist", "manual_blacklist_entry", entry.ID, nil, entry, reason, ""); err != nil {
		return BlacklistEntry{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return BlacklistEntry{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) ListBlacklistEntries(ctx context.Context, actor *Actor, query BlacklistEntryQuery) ([]BlacklistEntry, error) {
	where, args := blacklistEntryWhere(actor, query)
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT b.id::text, b.ebpf_id, b.ip_or_cidr::text, b.scope_type, COALESCE(b.service_id::text, ''), b.score, b.action, b.source, COALESCE(b.rule_id::text, ''), b.reason, b.owner, b.expires_at, b.enabled, `+policyEditableSQL("b", actor)+`, b.created_at, b.updated_at
FROM manual_blacklist_entries b
LEFT JOIN rules r ON r.id = b.rule_id
`+where+` ORDER BY b.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]BlacklistEntry, 0)
	for rows.Next() {
		var entry BlacklistEntry
		if err := scanBlacklistEntry(rows, &entry); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) ListBlacklistEntryRows(ctx context.Context, actor *Actor, query BlacklistEntriesQuery) (BlacklistEntriesPage, error) {
	query = normalizeBlacklistEntriesQuery(query)
	where, args := blacklistEntriesWhere(actor, query)
	page := BlacklistEntriesPage{Page: query.Page, PageSize: query.PageSize}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return page, err
	}
	defer tx.Rollback(ctx)

	countSQL := blacklistEntriesCTE() + ` SELECT count(*) FROM combined c ` + where
	var total int64
	if err := tx.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return page, err
	}
	page.Total = uint32(total)

	limitArg := len(args) + 1
	offsetArg := len(args) + 2
	args = append(args, int64(query.PageSize), int64(query.Page)*int64(query.PageSize))
	rows, err := tx.Query(ctx, blacklistEntriesCTE()+`
SELECT c.id, c.ebpf_id, c.cidr, c.score, c.action, c.source, c.source_name, c.rule_id, c.reason, c.expires_at,
       c.enabled, c.status, c.origin, (c.origin = 'manual' AND `+policyEditableSQL("c", actor)+`) AS editable,
       c.created_at, c.updated_at, c.scope_type, c.service_id, c.owner
FROM combined c
`+where+fmt.Sprintf(` ORDER BY c.created_at DESC, c.origin, c.cidr, c.id LIMIT $%d OFFSET $%d`, limitArg, offsetArg), args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	page.Items = make([]BlacklistEntryRow, 0)
	for rows.Next() {
		var row BlacklistEntryRow
		if err := scanBlacklistEntryRow(rows, &row); err != nil {
			return page, err
		}
		page.Items = append(page.Items, row)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	return page, tx.Commit(ctx)
}

func parseBlacklistEntryQuery(values map[string][]string) (BlacklistEntryQuery, error) {
	query := BlacklistEntryQuery{
		Search:    first(values, "q"),
		Source:    strings.TrimSpace(first(values, "source")),
		ScopeType: blacklistQueryValue(first(values, "scope_type"), "all"),
		ServiceID: first(values, "service_id"),
		State:     blacklistQueryValue(first(values, "state"), "all"),
		Expiry:    blacklistQueryValue(first(values, "expiry"), "all"),
	}
	switch query.ScopeType {
	case "all", ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
	default:
		return query, fmt.Errorf("scope_type must be all, admin_global, user_global, or service")
	}
	switch query.State {
	case "all", "enabled", "disabled":
	default:
		return query, fmt.Errorf("state must be all, enabled, or disabled")
	}
	switch query.Expiry {
	case "all", "valid", "expired", "none":
	default:
		return query, fmt.Errorf("expiry must be all, valid, expired, or none")
	}
	return query, nil
}

func parseBlacklistEntriesQuery(values map[string][]string) (BlacklistEntriesQuery, error) {
	query := BlacklistEntriesQuery{
		Search:    first(values, "q"),
		Source:    strings.TrimSpace(first(values, "source")),
		Origin:    blacklistQueryValue(first(values, "origin"), "all"),
		ScopeType: blacklistQueryValue(first(values, "scope_type"), "all"),
		ServiceID: first(values, "service_id"),
		State:     blacklistQueryValue(first(values, "state"), "all"),
		Expiry:    blacklistQueryValue(first(values, "expiry"), "all"),
	}
	switch query.Origin {
	case "all", "manual", "feed":
	default:
		return query, fmt.Errorf("origin must be all, manual, or feed")
	}
	switch query.ScopeType {
	case "all", ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
	default:
		return query, fmt.Errorf("scope_type must be all, admin_global, user_global, or service")
	}
	switch query.State {
	case "all", "enabled", "disabled":
	default:
		return query, fmt.Errorf("state must be all, enabled, or disabled")
	}
	switch query.Expiry {
	case "all", "valid", "expired", "none":
	default:
		return query, fmt.Errorf("expiry must be all, valid, expired, or none")
	}
	page, err := parseOptionalUintQuery(values, "page")
	if err != nil {
		return query, err
	}
	pageSize, err := parseOptionalUintQuery(values, "page_size")
	if err != nil {
		return query, err
	}
	query.Page = page
	query.PageSize = pageSize
	return normalizeBlacklistEntriesQuery(query), nil
}

func blacklistQueryValue(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func normalizeBlacklistEntriesQuery(query BlacklistEntriesQuery) BlacklistEntriesQuery {
	if query.Origin == "" {
		query.Origin = "all"
	}
	if query.ScopeType == "" {
		query.ScopeType = "all"
	}
	if query.State == "" {
		query.State = "all"
	}
	if query.Expiry == "" {
		query.Expiry = "all"
	}
	if query.PageSize == 0 {
		query.PageSize = 25
	}
	if query.PageSize > 100 {
		query.PageSize = 100
	}
	return query
}

func parseOptionalUintQuery(values map[string][]string, key string) (uint32, error) {
	raw := strings.TrimSpace(first(values, key))
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return uint32(parsed), nil
}

func blacklistEntryWhere(actor *Actor, query BlacklistEntryQuery) (string, []any) {
	clauses := []string{policyListWhere("b", actor)}
	args := make([]any, 0)

	if search := strings.TrimSpace(query.Search); search != "" {
		args = append(args, "%"+search+"%")
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf(`(b.ip_or_cidr::text ILIKE $%d OR b.source ILIKE $%d OR b.reason ILIKE $%d OR COALESCE(b.rule_id::text, '') ILIKE $%d OR COALESCE(r.name, '') ILIKE $%d)`, idx, idx, idx, idx, idx))
	}
	if source := strings.TrimSpace(query.Source); source != "" {
		args = append(args, source)
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf("LOWER(b.source) = LOWER($%d)", idx))
	}
	switch blacklistQueryValue(query.ScopeType, "all") {
	case ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
		args = append(args, query.ScopeType)
		clauses = append(clauses, fmt.Sprintf("b.scope_type = $%d", len(args)))
	}
	if serviceID := strings.TrimSpace(query.ServiceID); serviceID != "" {
		args = append(args, serviceID)
		clauses = append(clauses, fmt.Sprintf("b.service_id = $%d", len(args)))
	}
	switch blacklistQueryValue(query.State, "all") {
	case "enabled":
		clauses = append(clauses, "b.enabled")
	case "disabled":
		clauses = append(clauses, "NOT b.enabled")
	}
	switch blacklistQueryValue(query.Expiry, "all") {
	case "valid":
		clauses = append(clauses, "(b.expires_at IS NULL OR b.expires_at > now())")
	case "expired":
		clauses = append(clauses, "b.expires_at IS NOT NULL AND b.expires_at <= now()")
	case "none":
		clauses = append(clauses, "b.expires_at IS NULL")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

func blacklistEntriesWhere(actor *Actor, query BlacklistEntriesQuery) (string, []any) {
	clauses := []string{policyListWhere("c", actor)}
	args := make([]any, 0)

	if search := strings.TrimSpace(query.Search); search != "" {
		args = append(args, "%"+search+"%")
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf(`(c.cidr ILIKE $%d OR c.source ILIKE $%d OR c.source_name ILIKE $%d OR c.reason ILIKE $%d OR c.rule_id ILIKE $%d OR c.rule_name ILIKE $%d OR c.status ILIKE $%d)`, idx, idx, idx, idx, idx, idx, idx))
	}
	if source := strings.TrimSpace(query.Source); source != "" {
		args = append(args, source)
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf("(LOWER(c.source) = LOWER($%d) OR LOWER(c.source_name) = LOWER($%d))", idx, idx))
	}
	switch blacklistQueryValue(query.Origin, "all") {
	case "manual":
		clauses = append(clauses, "c.origin = 'manual'")
	case "feed":
		clauses = append(clauses, "c.origin = 'feed'")
	}
	switch blacklistQueryValue(query.ScopeType, "all") {
	case ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
		args = append(args, query.ScopeType)
		clauses = append(clauses, fmt.Sprintf("c.scope_type = $%d", len(args)))
	}
	if serviceID := strings.TrimSpace(query.ServiceID); serviceID != "" {
		args = append(args, serviceID)
		clauses = append(clauses, fmt.Sprintf("c.service_id = $%d", len(args)))
	}
	switch blacklistQueryValue(query.State, "all") {
	case "enabled":
		clauses = append(clauses, "c.enabled")
	case "disabled":
		clauses = append(clauses, "NOT c.enabled")
	}
	switch blacklistQueryValue(query.Expiry, "all") {
	case "valid":
		clauses = append(clauses, "(c.expires_at IS NULL OR c.expires_at > now())")
	case "expired":
		clauses = append(clauses, "c.expires_at IS NOT NULL AND c.expires_at <= now()")
	case "none":
		clauses = append(clauses, "c.expires_at IS NULL")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

func blacklistEntriesCTE() string {
	return `WITH combined AS (
SELECT b.id::text AS id,
       b.ebpf_id AS ebpf_id,
       b.ip_or_cidr::text AS cidr,
       b.score AS score,
       b.action AS action,
       b.source AS source,
       ''::text AS source_name,
       COALESCE(b.rule_id::text, '') AS rule_id,
       b.reason AS reason,
       b.expires_at AS expires_at,
       b.enabled AS enabled,
       CASE WHEN b.enabled THEN 'enabled' ELSE 'disabled' END AS status,
       'manual'::text AS origin,
       true AS editable,
       b.created_at AS created_at,
       b.updated_at AS updated_at,
       b.owner_user_id AS owner_user_id,
       COALESCE(r.name, '') AS rule_name,
       b.scope_type AS scope_type,
       COALESCE(b.service_id::text, '') AS service_id,
       b.owner AS owner
FROM manual_blacklist_entries b
LEFT JOIN rules r ON r.id = b.rule_id
UNION ALL
SELECT re.id::text AS id,
       re.ebpf_id AS ebpf_id,
       re.ip_or_cidr::text AS cidr,
       re.score AS score,
       re.action AS action,
       fs.type AS source,
       fs.name AS source_name,
       ''::text AS rule_id,
       re.reason AS reason,
       re.expires_at AS expires_at,
       (fs.enabled AND re.status = 'active' AND (re.expires_at IS NULL OR re.expires_at > now())) AS enabled,
       re.status AS status,
       'feed'::text AS origin,
       false AS editable,
       re.first_seen_at AS created_at,
       re.last_seen_at AS updated_at,
       NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid AS owner_user_id,
       ''::text AS rule_name,
       'admin_global'::text AS scope_type,
       ''::text AS service_id,
       fs.name AS owner
FROM reputation_entries re
JOIN feed_sources fs ON fs.id = re.source_id
WHERE fs.owner_user_id IS NULL AND re.owner_user_id IS NULL
)`
}

func scanBlacklistEntry(row rowScanner, entry *BlacklistEntry) error {
	var expires *time.Time
	if err := row.Scan(
		&entry.ID,
		&entry.EBPFID,
		&entry.CIDR,
		&entry.ScopeType,
		&entry.ServiceID,
		&entry.Score,
		&entry.Action,
		&entry.Source,
		&entry.RuleID,
		&entry.Reason,
		&entry.Owner,
		&expires,
		&entry.Enabled,
		&entry.Editable,
		&entry.CreatedAt,
		&entry.UpdatedAt,
	); err != nil {
		return err
	}
	entry.ExpiresAt = expires
	return nil
}

func scanBlacklistEntryRow(row rowScanner, entry *BlacklistEntryRow) error {
	var expires *time.Time
	if err := row.Scan(
		&entry.ID,
		&entry.EBPFID,
		&entry.CIDR,
		&entry.Score,
		&entry.Action,
		&entry.Source,
		&entry.SourceName,
		&entry.RuleID,
		&entry.Reason,
		&expires,
		&entry.Enabled,
		&entry.Status,
		&entry.Origin,
		&entry.Editable,
		&entry.CreatedAt,
		&entry.UpdatedAt,
		&entry.ScopeType,
		&entry.ServiceID,
		&entry.Owner,
	); err != nil {
		return err
	}
	entry.ExpiresAt = expires
	return nil
}

func (s *Store) CreateUDPSourcePortBlock(ctx context.Context, actor *Actor, input UDPSourcePortBlockInput, reason string) (UDPSourcePortBlock, error) {
	scope, err := requirePolicyMutation(actor, input.ScopeType, "", input.ServiceID)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	input.ScopeType = scope.ScopeType
	if scope.ScopeType != ScopeTypeService {
		input.ServiceID = ""
	}
	if err := validateUDPSourcePortBlockInput(input); err != nil {
		return UDPSourcePortBlock{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return UDPSourcePortBlock{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	enabled := boolDefault(input.Enabled, true)
	var expires any
	if !input.ExpiresAt.IsZero() {
		expires = input.ExpiresAt
	}
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	defer tx.Rollback(ctx)
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
		if _, err := s.getService(ctx, tx, strings.TrimSpace(input.ServiceID)); err != nil {
			return UDPSourcePortBlock{}, err
		}
	}
	var entry UDPSourcePortBlock
	err = scanUDPSourcePortBlock(tx.QueryRow(ctx, `INSERT INTO udp_source_port_blocks(id, owner_user_id, scope_type, service_id, port, label, reason, owner, expires_at, enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING id::text, ebpf_id, port, scope_type, COALESCE(service_id::text, ''), label, reason, owner, expires_at, enabled, true, created_at, updated_at`,
		id,
		scope.OwnerUserID,
		scope.ScopeType,
		serviceID,
		input.Port,
		strings.TrimSpace(input.Label),
		reason,
		scope.Owner,
		expires,
		enabled,
	), &entry)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_udp_source_port_block", "udp_source_port_block", entry.ID, nil, entry, reason, ""); err != nil {
		return UDPSourcePortBlock{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return UDPSourcePortBlock{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) ListUDPSourcePortBlocks(ctx context.Context, actor *Actor, query UDPSourcePortBlockQuery) ([]UDPSourcePortBlock, error) {
	where, args := udpSourcePortBlockWhere(actor, query)
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, ebpf_id, port, scope_type, COALESCE(service_id::text, ''), label, reason, owner, expires_at, enabled, `+policyEditableSQL("", actor)+`, created_at, updated_at
FROM udp_source_port_blocks
`+where+` ORDER BY port ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]UDPSourcePortBlock, 0)
	for rows.Next() {
		var entry UDPSourcePortBlock
		if err := scanUDPSourcePortBlock(rows, &entry); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func parseUDPSourcePortBlockQuery(values map[string][]string) (UDPSourcePortBlockQuery, error) {
	query := UDPSourcePortBlockQuery{
		Search:    first(values, "q"),
		ScopeType: blacklistQueryValue(first(values, "scope_type"), "all"),
		ServiceID: first(values, "service_id"),
		State:     blacklistQueryValue(first(values, "state"), "all"),
		Expiry:    blacklistQueryValue(first(values, "expiry"), "all"),
	}
	switch query.ScopeType {
	case "all", ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
	default:
		return query, fmt.Errorf("scope_type must be all, admin_global, user_global, or service")
	}
	switch query.State {
	case "all", "enabled", "disabled":
	default:
		return query, fmt.Errorf("state must be all, enabled, or disabled")
	}
	switch query.Expiry {
	case "all", "valid", "expired", "none":
	default:
		return query, fmt.Errorf("expiry must be all, valid, expired, or none")
	}
	return query, nil
}

func udpSourcePortBlockWhere(actor *Actor, query UDPSourcePortBlockQuery) (string, []any) {
	clauses := []string{policyListWhere("", actor)}
	args := make([]any, 0)

	if search := strings.TrimSpace(query.Search); search != "" {
		args = append(args, "%"+search+"%")
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf(`(port::text ILIKE $%d OR label ILIKE $%d OR reason ILIKE $%d OR owner ILIKE $%d)`, idx, idx, idx, idx))
	}
	switch blacklistQueryValue(query.ScopeType, "all") {
	case ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService:
		args = append(args, query.ScopeType)
		clauses = append(clauses, fmt.Sprintf("scope_type = $%d", len(args)))
	}
	if serviceID := strings.TrimSpace(query.ServiceID); serviceID != "" {
		args = append(args, serviceID)
		clauses = append(clauses, fmt.Sprintf("service_id = $%d", len(args)))
	}
	switch blacklistQueryValue(query.State, "all") {
	case "enabled":
		clauses = append(clauses, "enabled")
	case "disabled":
		clauses = append(clauses, "NOT enabled")
	}
	switch blacklistQueryValue(query.Expiry, "all") {
	case "valid":
		clauses = append(clauses, "(expires_at IS NULL OR expires_at > now())")
	case "expired":
		clauses = append(clauses, "expires_at IS NOT NULL AND expires_at <= now()")
	case "none":
		clauses = append(clauses, "expires_at IS NULL")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

func scanUDPSourcePortBlock(row rowScanner, entry *UDPSourcePortBlock) error {
	var expires *time.Time
	var port int32
	if err := row.Scan(
		&entry.ID,
		&entry.EBPFID,
		&port,
		&entry.ScopeType,
		&entry.ServiceID,
		&entry.Label,
		&entry.Reason,
		&entry.Owner,
		&expires,
		&entry.Enabled,
		&entry.Editable,
		&entry.CreatedAt,
		&entry.UpdatedAt,
	); err != nil {
		return err
	}
	entry.Port = uint16(port)
	entry.ExpiresAt = expires
	return nil
}

func (s *Store) CreateFeedSource(ctx context.Context, actor *Actor, input FeedSourceInput, reason string) (FeedSource, error) {
	if err := requireGlobalFeedAdmin(actor); err != nil {
		return FeedSource{}, err
	}
	if err := validateFeedSourceInput(input); err != nil {
		return FeedSource{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return FeedSource{}, errors.New("reason is required")
	}
	id, err := newUUID()
	if err != nil {
		return FeedSource{}, err
	}
	enabled := boolDefault(input.Enabled, false)
	quota := defaultJSON(input.QuotaMetadata)
	credentialRef := feedCredentialForCreate(input.CredentialRef)
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return FeedSource{}, err
	}
	defer tx.Rollback(ctx)
	var source FeedSource
	err = scanFeedSource(tx.QueryRow(ctx, `INSERT INTO feed_sources(
    id, owner_user_id, name, type, url, credential_ref, required_for_production, enabled, interval_seconds, license_note, quota_metadata, status
) VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
RETURNING `+feedSourceColumns(),
		id,
		input.Name,
		normalizeFeedType(input.Type),
		input.URL,
		credentialRef,
		input.RequiredForProduction,
		enabled,
		effectiveFeedIntervalSeconds(FeedSource{Type: input.Type, IntervalSeconds: defaultInterval(input.IntervalSeconds)}),
		input.LicenseNote,
		quota,
		defaultString(input.Status, "placeholder"),
	), &source)
	if err != nil {
		return FeedSource{}, err
	}
	if err := insertAudit(ctx, tx, actor, "create_feed_source", "feed_source", source.ID, nil, maskFeedSourceCredential(source), reason, ""); err != nil {
		return FeedSource{}, err
	}
	return source, tx.Commit(ctx)
}

func (s *Store) ListFeedSources(ctx context.Context) ([]FeedSource, error) {
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, feedSourceSelectSQL()+` WHERE owner_user_id IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]FeedSource, 0)
	for rows.Next() {
		var source FeedSource
		if err := scanFeedSource(rows, &source); err != nil {
			return nil, err
		}
		out = append(out, source)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func scanFeedSource(row rowScanner, source *FeedSource) error {
	return row.Scan(
		&source.ID,
		&source.Name,
		&source.Type,
		&source.URL,
		&source.CredentialRef,
		&source.RequiredForProduction,
		&source.Enabled,
		&source.IntervalSeconds,
		&source.LicenseNote,
		&source.QuotaMetadata,
		&source.Status,
		&source.LastSuccessAt,
		&source.LastErrorAt,
		&source.LastError,
		&source.NextRunAt,
		&source.ActiveEntries,
		&source.ConflictCount,
		&source.ParseErrorCount,
		&source.CreatedAt,
		&source.UpdatedAt,
	)
}

func feedSourceColumns() string {
	return `id::text, name, type, url, credential_ref, required_for_production, enabled, interval_seconds,
       license_note, quota_metadata, status, last_success_at, last_error_at, last_error, next_run_at,
       active_entries, conflict_count, parse_error_count, created_at, updated_at`
}

func feedSourceSelectSQL() string {
	return `SELECT ` + feedSourceColumns() + ` FROM feed_sources`
}

func mutationReason(headerReason, bodyReason string) string {
	if strings.TrimSpace(bodyReason) != "" {
		return strings.TrimSpace(bodyReason)
	}
	return strings.TrimSpace(headerReason)
}

func boolDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func defaultPriority(value uint32) uint32 {
	if value == 0 {
		return 100
	}
	return value
}

func defaultInterval(value uint32) uint32 {
	if value == 0 {
		return 3600
	}
	return value
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func defaultJSON(value json.RawMessage) json.RawMessage {
	if len(value) == 0 || strings.TrimSpace(string(value)) == "" {
		return json.RawMessage(`{}`)
	}
	return value
}

func mustJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

func int32Ports(ports []uint16) []int32 {
	out := make([]int32, 0, len(ports))
	for _, port := range ports {
		out = append(out, int32(port))
	}
	return out
}

func uint16Ports(ports []int32) []uint16 {
	out := make([]uint16, 0, len(ports))
	for _, port := range ports {
		out = append(out, uint16(port))
	}
	return out
}

func textArray(values []string) pgtype.FlatArray[string] {
	if values == nil {
		values = []string{}
	}
	return pgtype.FlatArray[string](values)
}

func normalizeProtocol(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "observe"
	}
	return value
}

func normalizeRuleAction(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "observe"
	}
	return value
}

func normalizeRuleDimension(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "source_service":
		return "source_service"
	case "src", "source_ip":
		return "source"
	default:
		return value
	}
}

func normalizeBlacklistAction(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "drop"
	}
	return value
}

func normalizeForwardingAction(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "redirect"
	}
	return value
}

func normalizeScope(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "service_scoped":
		return "service"
	case "":
		return "global"
	default:
		return value
	}
}

func neighborStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unresolved"
	}
	return value
}

func validateServiceInput(input ServiceInput) error {
	var errs []error
	if strings.TrimSpace(input.Name) == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if _, err := parseCIDR(input.BackendCIDR); err != nil {
		errs = append(errs, fmt.Errorf("backend_cidr: %w", err))
	}
	proto := normalizeProtocol(input.Protocol)
	switch proto {
	case "tcp", "udp":
		if len(input.AllowedPorts) == 0 {
			errs = append(errs, errors.New("tcp/udp services require at least one allowed port"))
		}
		for _, port := range input.AllowedPorts {
			if port == 0 {
				errs = append(errs, errors.New("tcp/udp allowed ports must be non-zero"))
			}
		}
	case "icmp":
		for _, port := range input.AllowedPorts {
			if port != 0 {
				errs = append(errs, errors.New("icmp allowed port must be 0"))
			}
		}
	default:
		errs = append(errs, fmt.Errorf("unsupported protocol %q", input.Protocol))
	}
	if strings.TrimSpace(input.OutputInterface) == "" {
		errs = append(errs, errors.New("output_interface is required"))
	}
	if strings.TrimSpace(input.Owner) == "" {
		errs = append(errs, errors.New("owner is required"))
	}
	mode := strings.ToLower(strings.TrimSpace(input.ProtectionMode))
	if mode != "observe" && mode != "enforce" {
		errs = append(errs, errors.New("protection_mode must be observe or enforce"))
	}
	if input.ResolvedNextHopMAC != "" {
		if _, err := net.ParseMAC(input.ResolvedNextHopMAC); err != nil {
			errs = append(errs, fmt.Errorf("resolved_next_hop_mac: %w", err))
		}
	}
	if input.ResolvedSourceMAC != "" {
		if _, err := net.ParseMAC(input.ResolvedSourceMAC); err != nil {
			errs = append(errs, fmt.Errorf("resolved_src_mac: %w", err))
		}
	}
	return errors.Join(errs...)
}

func validateForwardingPolicyInput(input ForwardingPolicyInput) error {
	var errs []error
	if strings.TrimSpace(input.ServiceID) == "" {
		errs = append(errs, errors.New("service_id is required"))
	}
	if _, err := parseCIDR(input.BackendTarget); err != nil {
		errs = append(errs, fmt.Errorf("backend_target: %w", err))
	}
	proto := normalizeProtocol(input.MatchProtocol)
	switch proto {
	case "tcp", "udp":
		if input.MatchDstPort == 0 {
			errs = append(errs, errors.New("tcp/udp forwarding policies require match_dst_port"))
		}
	case "icmp":
		if input.MatchDstPort != 0 {
			errs = append(errs, errors.New("icmp match_dst_port must be 0"))
		}
	default:
		errs = append(errs, fmt.Errorf("unsupported match_protocol %q", input.MatchProtocol))
	}
	if normalizeForwardingAction(input.Action) != "redirect" {
		errs = append(errs, errors.New("forwarding policy action must be redirect"))
	}
	if strings.TrimSpace(input.OutputInterface) == "" {
		errs = append(errs, errors.New("output_interface is required"))
	}
	if strings.TrimSpace(input.Owner) == "" {
		errs = append(errs, errors.New("owner is required"))
	}
	return errors.Join(errs...)
}

func validateWhitelistInput(input WhitelistInput) error {
	var errs []error
	if _, err := parseCIDR(input.CIDR); err != nil {
		errs = append(errs, fmt.Errorf("cidr: %w", err))
	}
	legacyScope := normalizeScope(input.Scope)
	if legacyScope != "global" && legacyScope != "service" {
		errs = append(errs, errors.New("scope must be global or service"))
	}
	scopeType := effectiveScopeType(input.ScopeType, input.Scope, input.ServiceID)
	if err := validatePolicyScope(scopeType, strings.TrimSpace(input.ServiceID)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func validateRuleInput(input RuleInput) error {
	var errs []error
	if strings.TrimSpace(input.Name) == "" {
		errs = append(errs, errors.New("name is required"))
	}
	action := normalizeRuleAction(input.Action)
	switch action {
	case "observe", "drop", "rate_limit", "sample":
	default:
		errs = append(errs, fmt.Errorf("unsupported rule action %q", input.Action))
	}
	mode := normalizeMode(input.Mode)
	if mode != "observe" && mode != "enforce" {
		errs = append(errs, errors.New("mode must be observe or enforce"))
	}
	if input.SampleDenom > 1000000 {
		errs = append(errs, errors.New("sample_denom exceeds max 1000000"))
	}
	switch normalizeRuleDimension(input.Dimension) {
	case "source", "service", "source_service":
	default:
		errs = append(errs, errors.New("dimension must be source, service or source_service"))
	}
	scopeType := effectiveScopeType(input.ScopeType, "", input.ServiceID)
	if err := validatePolicyScope(scopeType, strings.TrimSpace(input.ServiceID)); err != nil {
		errs = append(errs, err)
	}
	if len(input.MatchExpr) > 0 && !json.Valid(input.MatchExpr) {
		errs = append(errs, errors.New("match_expr must be valid JSON"))
	}
	if len(input.Evidence) > 0 && !json.Valid(input.Evidence) {
		errs = append(errs, errors.New("evidence must be valid JSON"))
	}
	return errors.Join(errs...)
}

func validateBlacklistInput(input BlacklistInput) error {
	var errs []error
	if _, err := parseCIDR(input.CIDR); err != nil {
		errs = append(errs, fmt.Errorf("cidr: %w", err))
	}
	if normalizeBlacklistAction(input.Action) != "drop" {
		errs = append(errs, errors.New("manual blacklist action must be drop"))
	}
	if strings.TrimSpace(input.Source) == "" {
		errs = append(errs, errors.New("source is required"))
	}
	scopeType := effectiveScopeType(input.ScopeType, "", input.ServiceID)
	if err := validatePolicyScope(scopeType, strings.TrimSpace(input.ServiceID)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func validateUDPSourcePortBlockInput(input UDPSourcePortBlockInput) error {
	var errs []error
	scopeType := effectiveScopeType(input.ScopeType, "", input.ServiceID)
	if err := validatePolicyScope(scopeType, strings.TrimSpace(input.ServiceID)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func validateFeedSourceInput(input FeedSourceInput) error {
	var errs []error
	if strings.TrimSpace(input.Name) == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if strings.TrimSpace(input.Type) == "" {
		errs = append(errs, errors.New("type is required"))
	}
	if len(input.QuotaMetadata) > 0 && !json.Valid(input.QuotaMetadata) {
		errs = append(errs, errors.New("quota_metadata must be valid JSON"))
	}
	return errors.Join(errs...)
}

func parseCIDR(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("CIDR is required")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, errors.New("IPv6 is reserved but not supported in phase 05 active policy")
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !addr.Is4() {
		return netip.Prefix{}, errors.New("IPv6 is reserved but not supported in phase 05 active policy")
	}
	return netip.PrefixFrom(addr, 32), nil
}

func policyProtoNumber(proto string) (uint8, error) {
	switch normalizeProtocol(proto) {
	case "icmp":
		return 1, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", proto)
	}
}

func ruleActionNumber(action string) uint32 {
	switch normalizeRuleAction(action) {
	case "drop":
		return ActionDrop
	case "rate_limit":
		return ActionRateLimit
	case "sample":
		return ActionSample
	default:
		return ActionObserve
	}
}

func ruleModeNumber(mode string) uint32 {
	if normalizeMode(mode) == "enforce" {
		return 1
	}
	return 0
}

func ruleDimensionNumber(dimension string) uint32 {
	switch normalizeRuleDimension(dimension) {
	case "source":
		return 0
	case "service":
		return 2
	default:
		return 3
	}
}

func (s *Store) ListUserAllocatedCIDRs(ctx context.Context, targetUserID string) ([]AllocatedCIDR, error) {
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT id::text, user_id::text, cidr::text, created_at, updated_at 
FROM allocated_cidrs WHERE user_id=$1 ORDER BY cidr`, targetUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cidrs []AllocatedCIDR
	for rows.Next() {
		var c AllocatedCIDR
		if err := rows.Scan(&c.ID, &c.UserID, &c.CIDR, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		cidrs = append(cidrs, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cidrs, tx.Commit(ctx)
}

func (s *Store) ListMeAllocatedCIDRs(ctx context.Context, actor *Actor) ([]AllocatedCIDR, error) {
	if actor == nil {
		return nil, errors.New("authentication required")
	}
	return s.ListUserAllocatedCIDRs(ctx, actor.ID)
}

func (s *Store) CreateAllocatedCIDR(ctx context.Context, actor *Actor, targetUserID string, input AllocatedCIDRInput, reason string) (AllocatedCIDR, error) {
	if err := requireAdmin(actor); err != nil {
		return AllocatedCIDR{}, err
	}
	targetUserID = strings.TrimSpace(targetUserID)
	cidrStr := strings.TrimSpace(input.CIDR)
	if targetUserID == "" || cidrStr == "" {
		return AllocatedCIDR{}, errors.New("user_id and cidr are required")
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return AllocatedCIDR{}, errors.New("reason is required")
	}

	// Validate CIDR format
	_, _, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return AllocatedCIDR{}, fmt.Errorf("invalid cidr format: %w", err)
	}

	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return AllocatedCIDR{}, err
	}
	defer tx.Rollback(ctx)

	// Check if this CIDR overlaps with ANY other user's CIDR allocations
	var conflictUser string
	var conflictCIDR string
	err = tx.QueryRow(ctx, `
		SELECT u.username, a.cidr::text
		FROM allocated_cidrs a
		JOIN app_users u ON u.id = a.user_id
		WHERE a.user_id <> $1 AND a.cidr && $2::inet
		LIMIT 1
	`, targetUserID, cidrStr).Scan(&conflictUser, &conflictCIDR)

	if err == nil {
		return AllocatedCIDR{}, fmt.Errorf("CIDR overlaps with user %s's allocation: %s", conflictUser, conflictCIDR)
	} else if err != pgx.ErrNoRows {
		return AllocatedCIDR{}, err
	}

	id, err := newUUID()
	if err != nil {
		return AllocatedCIDR{}, err
	}

	var c AllocatedCIDR
	err = tx.QueryRow(ctx, `
		INSERT INTO allocated_cidrs (id, user_id, cidr)
		VALUES ($1, $2, $3)
		RETURNING id::text, user_id::text, cidr::text, created_at, updated_at
	`, id, targetUserID, cidrStr).Scan(&c.ID, &c.UserID, &c.CIDR, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return AllocatedCIDR{}, err
	}

	if err := insertAudit(ctx, tx, actor, "create_allocated_cidr", "allocated_cidr", c.ID, nil, c, reason, ""); err != nil {
		return AllocatedCIDR{}, err
	}

	return c, tx.Commit(ctx)
}

func (s *Store) DeleteAllocatedCIDR(ctx context.Context, actor *Actor, targetUserID string, id string, reason string) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("allocation id is required")
	}
	if reason == "" {
		return errors.New("reason is required")
	}

	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Retrieve the allocation to check what we are deleting and for audit trails
	var c AllocatedCIDR
	err = tx.QueryRow(ctx, `
		SELECT id::text, user_id::text, cidr::text, created_at, updated_at
		FROM allocated_cidrs
		WHERE id=$1
	`, id).Scan(&c.ID, &c.UserID, &c.CIDR, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return err
	}

	// Verify that targetUserID matches the allocation's user_id
	if c.UserID != targetUserID {
		return errors.New("user ID mismatch")
	}

	// Block deletion if any active backend service of the user falls within this allocation CIDR
	var inUse bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM backend_services
			WHERE owner_user_id = $1 AND deleted_at IS NULL AND backend_cidr <<= $2::inet
		)
	`, c.UserID, c.CIDR).Scan(&inUse)
	if err != nil {
		return err
	}

	if inUse {
		// Let's get the list of blocking services for a clear error message
		rows, err := tx.Query(ctx, `
			SELECT name FROM backend_services
			WHERE owner_user_id = $1 AND deleted_at IS NULL AND backend_cidr <<= $2::inet
		`, c.UserID, c.CIDR)
		if err != nil {
			return err
		}
		defer rows.Close()
		var serviceNames []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			serviceNames = append(serviceNames, name)
		}
		return fmt.Errorf("cannot delete allocation: still used by active service(s) (%s)", strings.Join(serviceNames, ", "))
	}

	_, err = tx.Exec(ctx, `DELETE FROM allocated_cidrs WHERE id=$1`, id)
	if err != nil {
		return err
	}

	if err := insertAudit(ctx, tx, actor, "delete_allocated_cidr", "allocated_cidr", id, c, nil, reason, ""); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) ValidateServiceCIDR(ctx context.Context, tx pgx.Tx, ownerUserID string, backendCIDR string) error {
	ownerUserID = strings.TrimSpace(ownerUserID)
	backendCIDR = strings.TrimSpace(backendCIDR)
	if ownerUserID == "" {
		return errors.New("owner user ID is required")
	}
	if backendCIDR == "" {
		return errors.New("backend CIDR is required")
	}

	var hasAllocations bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM allocated_cidrs)`).Scan(&hasAllocations)
	if err != nil {
		return err
	}
	if !hasAllocations {
		return nil
	}

	var valid bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM allocated_cidrs
			WHERE user_id = $1 AND $2::inet <<= cidr
		)
	`, ownerUserID, backendCIDR).Scan(&valid)
	if err != nil {
		return err
	}

	if !valid {
		return fmt.Errorf("backend CIDR %s is not contained within your allocated blocks", backendCIDR)
	}
	return nil
}


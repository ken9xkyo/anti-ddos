package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Store) UpdateUser(ctx context.Context, actor *Actor, id string, input UserUpdateInput, reason string) (User, error) {
	if err := requireAdmin(actor); err != nil {
		return User{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return User{}, errors.New("reason is required")
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.getUser(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	role := before.Role
	if strings.TrimSpace(input.Role) != "" {
		role = strings.ToLower(strings.TrimSpace(input.Role))
	}
	status := before.Status
	if strings.TrimSpace(input.Status) != "" {
		status = strings.ToLower(strings.TrimSpace(input.Status))
	}
	forcePasswordChange := before.ForcePasswordChange
	if input.ForcePasswordChange != nil {
		forcePasswordChange = *input.ForcePasswordChange
	}
	defaultOutputInterface := before.DefaultOutputInterface
	if input.DefaultOutputInterface != nil {
		defaultOutputInterface = strings.TrimSpace(*input.DefaultOutputInterface)
	}
	if err := validateUserRoleStatus(role, status); err != nil {
		return User{}, err
	}
	var after User
	if err := ensureActiveAdminRemains(ctx, tx, before, role, status); err != nil {
		return User{}, err
	}
	if err := tx.QueryRow(ctx, `UPDATE app_users
SET role=$2, status=$3, force_password_change=$4, default_output_interface=$5, updated_at=now()
WHERE id=$1
RETURNING id::text, username, role, status, force_password_change, default_output_interface, created_at, last_login_at`,
		id, role, status, forcePasswordChange, defaultOutputInterface,
	).Scan(&after.ID, &after.Username, &after.Role, &after.Status, &after.ForcePasswordChange, &after.DefaultOutputInterface, &after.CreatedAt, &after.LastLoginAt); err != nil {
		return User{}, err
	}
	if status != StatusActive {
		if _, err := tx.Exec(ctx, `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id); err != nil {
			return User{}, err
		}
	}
	if role == RoleUser {
		if err := seedDefaultUDPSourcePortBlocks(ctx, tx, id); err != nil {
			return User{}, err
		}
	}
	if role != RoleAdmin {
		if _, err := tx.Exec(ctx, `UPDATE user_sessions SET view_owner_user_id=NULL WHERE view_owner_user_id=$1`, id); err != nil {
			return User{}, err
		}
	}
	if err := insertAudit(ctx, tx, actor, "update_user", "user", id, before, after, reason, ""); err != nil {
		return User{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) ResetUserPassword(ctx context.Context, actor *Actor, id string, input PasswordResetInput, reason string) (User, error) {
	if err := requireAdmin(actor); err != nil {
		return User{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return User{}, errors.New("reason is required")
	}
	if len(input.Password) < 12 {
		return User{}, errors.New("password must be at least 12 characters")
	}
	forcePasswordChange := true
	if input.ForcePasswordChange != nil {
		forcePasswordChange = *input.ForcePasswordChange
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.getUser(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	var after User
	if err := tx.QueryRow(ctx, `UPDATE app_users
SET password_hash=$2, force_password_change=$3, updated_at=now()
WHERE id=$1
RETURNING id::text, username, role, status, force_password_change, created_at, last_login_at`,
		id, string(hash), forcePasswordChange,
	).Scan(&after.ID, &after.Username, &after.Role, &after.Status, &after.ForcePasswordChange, &after.CreatedAt, &after.LastLoginAt); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id); err != nil {
		return User{}, err
	}
	after, err = s.getUser(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	if err := insertAudit(ctx, tx, actor, "reset_user_password", "user", id, before, after, reason, ""); err != nil {
		return User{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) RevokeUserSessions(ctx context.Context, actor *Actor, id, reason string) (User, error) {
	if err := requireAdmin(actor); err != nil {
		return User{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return User{}, errors.New("reason is required")
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	user, err := s.getUser(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id); err != nil {
		return User{}, err
	}
	if err := insertAudit(ctx, tx, actor, "revoke_user_sessions", "user", id, user, user, strings.TrimSpace(reason), ""); err != nil {
		return User{}, err
	}
	return user, tx.Commit(ctx)
}

func (s *Store) ChangeOwnPassword(ctx context.Context, actor *Actor, input OwnPasswordInput, currentToken string) (User, error) {
	if actor == nil {
		return User{}, errors.New("authentication required")
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		return User{}, errors.New("reason is required")
	}
	if len(input.NewPassword) < 12 {
		return User{}, errors.New("new_password must be at least 12 characters")
	}
	var passwordHash string
	if err := s.pool.QueryRow(ctx, `SELECT password_hash FROM app_users WHERE id=$1`, actor.ID).Scan(&passwordHash); err != nil {
		return User{}, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(input.CurrentPassword)); err != nil {
		return User{}, errors.New("current password is invalid")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.getUser(ctx, tx, actor.ID)
	if err != nil {
		return User{}, err
	}
	var after User
	if err := tx.QueryRow(ctx, `UPDATE app_users
SET password_hash=$2, force_password_change=false, updated_at=now()
WHERE id=$1
RETURNING id::text, username, role, status, force_password_change, created_at, last_login_at`,
		actor.ID, string(hash),
	).Scan(&after.ID, &after.Username, &after.Role, &after.Status, &after.ForcePasswordChange, &after.CreatedAt, &after.LastLoginAt); err != nil {
		return User{}, err
	}
	tokenHash := hashToken(currentToken)
	if _, err := tx.Exec(ctx, `UPDATE user_sessions SET revoked_at=now()
WHERE user_id=$1 AND token_hash <> $2 AND revoked_at IS NULL`, actor.ID, tokenHash); err != nil {
		return User{}, err
	}
	if err := insertAudit(ctx, tx, actor, "change_own_password", "user", actor.ID, before, after, reason, ""); err != nil {
		return User{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) UpdateRule(ctx context.Context, actor *Actor, id string, input RuleInput, reason string) (Rule, error) {
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
	if input.TTLSeconds > 0 && input.ExpiresAt.IsZero() {
		input.ExpiresAt = time.Now().UTC().Add(time.Duration(input.TTLSeconds) * time.Second)
	}
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return Rule{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getRule(ctx, tx, id, scope)
	if err != nil {
		return Rule{}, err
	}
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
	}
	var expires any
	if !input.ExpiresAt.IsZero() {
		expires = input.ExpiresAt
	}
	if strings.TrimSpace(input.ServiceID) != "" {
		if _, err := s.getService(ctx, tx, strings.TrimSpace(input.ServiceID)); err != nil {
			return Rule{}, err
		}
	}
	rule := Rule{}
	err = scanRule(tx.QueryRow(ctx, `UPDATE rules SET
    scope_type=$2, service_id=$3, name=$4, priority=$5, match_expr=$6, action=$7, mode=$8,
    threshold_pps=$9, threshold_bps=$10, threshold_cps=$11, dimension=$12,
    burst_packets=$13, burst_bytes=$14, sample_denom=$15, ttl_seconds=$16,
    expires_at=$17, evidence=$18, confidence=$19, enabled=$20, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode, threshold_pps,
          threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence,
          confidence::float8, enabled, owner, true, created_at, updated_at`,
		id,
		scope.ScopeType,
		serviceID,
		input.Name,
		defaultPriority(input.Priority),
		defaultJSON(input.MatchExpr),
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
		defaultJSON(input.Evidence),
		input.Confidence,
		boolDefault(input.Enabled, before.Enabled),
	), &rule)
	if err != nil {
		return Rule{}, err
	}
	if err := insertAudit(ctx, tx, actor, "update_rule", "rule", id, before, rule, reason, ""); err != nil {
		return Rule{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return Rule{}, err
	}
	return rule, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) DisableRule(ctx context.Context, actor *Actor, id, reason string) (Rule, error) {
	scope, err := requirePolicyMutation(actor, "", "", "")
	if err != nil {
		return Rule{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return Rule{}, errors.New("reason is required")
	}
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return Rule{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getRule(ctx, tx, id, scope)
	if err != nil {
		return Rule{}, err
	}
	var rule Rule
	if err := scanRule(tx.QueryRow(ctx, `UPDATE rules SET enabled=false, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode, threshold_pps,
          threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence,
          confidence::float8, enabled, owner, true, created_at, updated_at`, id), &rule); err != nil {
		return Rule{}, err
	}
	if err := insertAudit(ctx, tx, actor, "disable_rule", "rule", id, before, rule, strings.TrimSpace(reason), ""); err != nil {
		return Rule{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return Rule{}, err
	}
	return rule, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) UpdateWhitelistEntry(ctx context.Context, actor *Actor, id string, input WhitelistInput, reason string) (WhitelistEntry, error) {
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
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return WhitelistEntry{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getWhitelistEntry(ctx, tx, id, scope)
	if err != nil {
		return WhitelistEntry{}, err
	}
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
	err = scanWhitelistEntry(tx.QueryRow(ctx, `UPDATE whitelist_entries SET
    ip_or_cidr=$2, scope=$3, scope_type=$4, service_id=$5, label=$6, reason=$7,
    priority=$8, expires_at=$9, enabled=$10, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, ip_or_cidr::text, scope, scope_type, COALESCE(service_id::text, ''), label, reason, owner, priority,
          expires_at, enabled, true, created_at, updated_at`,
		id,
		input.CIDR,
		normalizeScope(input.Scope),
		scope.ScopeType,
		serviceID,
		input.Label,
		reason,
		defaultPriority(input.Priority),
		expires,
		boolDefault(input.Enabled, before.Enabled),
	), &entry)
	if err != nil {
		return WhitelistEntry{}, err
	}
	if err := insertAudit(ctx, tx, actor, "update_whitelist", "whitelist_entry", id, before, entry, reason, ""); err != nil {
		return WhitelistEntry{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return WhitelistEntry{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) DisableWhitelistEntry(ctx context.Context, actor *Actor, id, reason string) (WhitelistEntry, error) {
	scope, err := requirePolicyMutation(actor, "", "", "")
	if err != nil {
		return WhitelistEntry{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return WhitelistEntry{}, errors.New("reason is required")
	}
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return WhitelistEntry{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getWhitelistEntry(ctx, tx, id, scope)
	if err != nil {
		return WhitelistEntry{}, err
	}
	var entry WhitelistEntry
	if err := scanWhitelistEntry(tx.QueryRow(ctx, `UPDATE whitelist_entries SET enabled=false, reason=$2, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, ip_or_cidr::text, scope, scope_type, COALESCE(service_id::text, ''), label, reason, owner, priority,
          expires_at, enabled, true, created_at, updated_at`, id, strings.TrimSpace(reason)), &entry); err != nil {
		return WhitelistEntry{}, err
	}
	if err := insertAudit(ctx, tx, actor, "disable_whitelist", "whitelist_entry", id, before, entry, strings.TrimSpace(reason), ""); err != nil {
		return WhitelistEntry{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return WhitelistEntry{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) UpdateBlacklistEntry(ctx context.Context, actor *Actor, id string, input BlacklistInput, reason string) (BlacklistEntry, error) {
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
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return BlacklistEntry{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getBlacklistEntry(ctx, tx, id, scope)
	if err != nil {
		return BlacklistEntry{}, err
	}
	var ruleID any
	if strings.TrimSpace(input.RuleID) != "" {
		ruleID = strings.TrimSpace(input.RuleID)
		if _, err := getRule(ctx, tx, strings.TrimSpace(input.RuleID), scope); err != nil {
			return BlacklistEntry{}, err
		}
	}
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
		if _, err := s.getService(ctx, tx, strings.TrimSpace(input.ServiceID)); err != nil {
			return BlacklistEntry{}, err
		}
	}
	var expires any
	if !input.ExpiresAt.IsZero() {
		expires = input.ExpiresAt
	}
	var entry BlacklistEntry
	err = scanBlacklistEntry(tx.QueryRow(ctx, `UPDATE manual_blacklist_entries SET
    scope_type=$2, service_id=$3, ip_or_cidr=$4, score=$5, action=$6, source=$7, rule_id=$8, reason=$9,
    expires_at=$10, enabled=$11, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, ip_or_cidr::text, scope_type, COALESCE(service_id::text, ''), score, action, source, COALESCE(rule_id::text, ''), reason, owner, expires_at, enabled, true, created_at, updated_at`,
		id,
		scope.ScopeType,
		serviceID,
		input.CIDR,
		input.Score,
		normalizeBlacklistAction(input.Action),
		input.Source,
		ruleID,
		reason,
		expires,
		boolDefault(input.Enabled, before.Enabled),
	), &entry)
	if err != nil {
		return BlacklistEntry{}, err
	}
	if err := insertAudit(ctx, tx, actor, "update_blacklist", "manual_blacklist_entry", id, before, entry, reason, ""); err != nil {
		return BlacklistEntry{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return BlacklistEntry{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) DisableBlacklistEntry(ctx context.Context, actor *Actor, id, reason string) (BlacklistEntry, error) {
	scope, err := requirePolicyMutation(actor, "", "", "")
	if err != nil {
		return BlacklistEntry{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return BlacklistEntry{}, errors.New("reason is required")
	}
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return BlacklistEntry{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getBlacklistEntry(ctx, tx, id, scope)
	if err != nil {
		return BlacklistEntry{}, err
	}
	var entry BlacklistEntry
	if err := scanBlacklistEntry(tx.QueryRow(ctx, `UPDATE manual_blacklist_entries SET enabled=false, reason=$2, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, ip_or_cidr::text, scope_type, COALESCE(service_id::text, ''), score, action, source, COALESCE(rule_id::text, ''), reason, owner, expires_at, enabled, true, created_at, updated_at`, id, strings.TrimSpace(reason)), &entry); err != nil {
		return BlacklistEntry{}, err
	}
	if err := insertAudit(ctx, tx, actor, "disable_blacklist", "manual_blacklist_entry", id, before, entry, strings.TrimSpace(reason), ""); err != nil {
		return BlacklistEntry{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return BlacklistEntry{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) UpdateUDPSourcePortBlock(ctx context.Context, actor *Actor, id string, input UDPSourcePortBlockInput, reason string) (UDPSourcePortBlock, error) {
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
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getUDPSourcePortBlock(ctx, tx, id, scope)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
		if _, err := s.getService(ctx, tx, strings.TrimSpace(input.ServiceID)); err != nil {
			return UDPSourcePortBlock{}, err
		}
	}
	var expires any
	if !input.ExpiresAt.IsZero() {
		expires = input.ExpiresAt
	}
	var entry UDPSourcePortBlock
	err = scanUDPSourcePortBlock(tx.QueryRow(ctx, `UPDATE udp_source_port_blocks SET
    scope_type=$2, service_id=$3, port=$4, label=$5, reason=$6, expires_at=$7, enabled=$8, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, port, scope_type, COALESCE(service_id::text, ''), label, reason, owner, expires_at, enabled, true, created_at, updated_at`,
		id,
		scope.ScopeType,
		serviceID,
		input.Port,
		strings.TrimSpace(input.Label),
		reason,
		expires,
		boolDefault(input.Enabled, before.Enabled),
	), &entry)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	if err := insertAudit(ctx, tx, actor, "update_udp_source_port_block", "udp_source_port_block", id, before, entry, reason, ""); err != nil {
		return UDPSourcePortBlock{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return UDPSourcePortBlock{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) DisableUDPSourcePortBlock(ctx context.Context, actor *Actor, id, reason string) (UDPSourcePortBlock, error) {
	scope, err := requirePolicyMutation(actor, "", "", "")
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return UDPSourcePortBlock{}, errors.New("reason is required")
	}
	tx, err := s.beginPolicyMutationTx(ctx, actor, scope)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	defer tx.Rollback(ctx)
	before, err := getUDPSourcePortBlock(ctx, tx, id, scope)
	if err != nil {
		return UDPSourcePortBlock{}, err
	}
	var entry UDPSourcePortBlock
	if err := scanUDPSourcePortBlock(tx.QueryRow(ctx, `UPDATE udp_source_port_blocks SET enabled=false, reason=$2, updated_at=now()
WHERE id=$1 AND `+policyMutationWhere("", scope)+`
RETURNING id::text, ebpf_id, port, scope_type, COALESCE(service_id::text, ''), label, reason, owner, expires_at, enabled, true, created_at, updated_at`, id, strings.TrimSpace(reason)), &entry); err != nil {
		return UDPSourcePortBlock{}, err
	}
	if err := insertAudit(ctx, tx, actor, "disable_udp_source_port_block", "udp_source_port_block", id, before, entry, strings.TrimSpace(reason), ""); err != nil {
		return UDPSourcePortBlock{}, err
	}
	if err := s.rebuildPolicyMutationInTx(ctx, tx, actor, scope, reason); err != nil {
		return UDPSourcePortBlock{}, err
	}
	return entry, s.commitPolicyMutation(ctx, tx, actor, scope, reason)
}

func (s *Store) DisableFeedSource(ctx context.Context, actor *Actor, id, reason string) (FeedSource, error) {
	if err := requireGlobalFeedAdmin(actor); err != nil {
		return FeedSource{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return FeedSource{}, errors.New("reason is required")
	}
	before, err := s.GetFeedSource(ctx, id)
	if err != nil {
		return FeedSource{}, err
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return FeedSource{}, err
	}
	defer tx.Rollback(ctx)
	var source FeedSource
	if err := scanFeedSource(tx.QueryRow(ctx, `UPDATE feed_sources
SET enabled=false, status='disabled', next_run_at=NULL, updated_at=now()
WHERE id=$1 AND owner_user_id IS NULL
RETURNING `+feedSourceColumns(), id), &source); err != nil {
		return FeedSource{}, err
	}
	if err := insertAudit(ctx, tx, actor, "disable_feed_source", "feed_source", id, maskFeedSourceCredential(before), maskFeedSourceCredential(source), strings.TrimSpace(reason), ""); err != nil {
		return FeedSource{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FeedSource{}, err
	}
	if before.Enabled {
		if _, err := s.rebuildAllActiveUserSnapshots(ctx, actor, strings.TrimSpace(reason)); err != nil {
			return FeedSource{}, err
		}
	}
	return source, nil
}

func validateUserRoleStatus(role, status string) error {
	switch role {
	case RoleAdmin, RoleUser:
	default:
		return errors.New("role must be admin or user")
	}
	switch status {
	case StatusActive, StatusRevoked:
	default:
		return errors.New("status must be active or revoked")
	}
	return nil
}

func ensureActiveAdminRemains(ctx context.Context, q dbQuerier, before User, role, status string) error {
	if before.Role != RoleAdmin || (role == RoleAdmin && status == StatusActive) {
		return nil
	}
	var remaining int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM app_users
WHERE id <> $1 AND role='admin' AND status='active'`, before.ID).Scan(&remaining); err != nil {
		return err
	}
	if remaining == 0 {
		return errors.New("at least one active admin is required")
	}
	return nil
}

func getRule(ctx context.Context, q dbQuerier, id string, scope policyMutationScope) (Rule, error) {
	var rule Rule
	err := scanRule(q.QueryRow(ctx, `SELECT id::text, ebpf_id, COALESCE(service_id::text, ''), scope_type, name, priority, match_expr, action, mode, threshold_pps,
          threshold_bps, threshold_cps, dimension, burst_packets, burst_bytes, sample_denom, ttl_seconds, expires_at, evidence,
          confidence::float8, enabled, owner, true, created_at, updated_at
FROM rules WHERE id=$1 AND `+policyMutationWhere("", scope), id), &rule)
	return rule, err
}

func getWhitelistEntry(ctx context.Context, q dbQuerier, id string, scope policyMutationScope) (WhitelistEntry, error) {
	var entry WhitelistEntry
	err := scanWhitelistEntry(q.QueryRow(ctx, `SELECT id::text, ebpf_id, ip_or_cidr::text, scope, scope_type, COALESCE(service_id::text, ''), label, reason, owner, priority,
	          expires_at, enabled, true, created_at, updated_at
FROM whitelist_entries WHERE id=$1 AND `+policyMutationWhere("", scope), id), &entry)
	return entry, err
}

func getBlacklistEntry(ctx context.Context, q dbQuerier, id string, scope policyMutationScope) (BlacklistEntry, error) {
	var entry BlacklistEntry
	err := scanBlacklistEntry(q.QueryRow(ctx, `SELECT id::text, ebpf_id, ip_or_cidr::text, scope_type, COALESCE(service_id::text, ''), score, action, source, COALESCE(rule_id::text, ''), reason, owner, expires_at, enabled, true, created_at, updated_at
FROM manual_blacklist_entries WHERE id=$1 AND `+policyMutationWhere("", scope), id), &entry)
	return entry, err
}

func getUDPSourcePortBlock(ctx context.Context, q dbQuerier, id string, scope policyMutationScope) (UDPSourcePortBlock, error) {
	var entry UDPSourcePortBlock
	err := scanUDPSourcePortBlock(q.QueryRow(ctx, `SELECT id::text, ebpf_id, port, scope_type, COALESCE(service_id::text, ''), label, reason, owner, expires_at, enabled, true, created_at, updated_at
FROM udp_source_port_blocks WHERE id=$1 AND `+policyMutationWhere("", scope), id), &entry)
	return entry, err
}

func mustRawJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage("{}")
	}
	return raw
}

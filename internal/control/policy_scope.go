package control

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

type policyMutationScope struct {
	ScopeType   string
	OwnerUserID string
	Owner       string
	AdminGlobal bool
}

func normalizeScopeType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func effectiveScopeType(scopeType, legacyScope, serviceID string) string {
	scopeType = normalizeScopeType(scopeType)
	if scopeType != "" {
		return scopeType
	}
	if normalizeScope(legacyScope) == ScopeTypeService || strings.TrimSpace(serviceID) != "" {
		return ScopeTypeService
	}
	return ScopeTypeUserGlobal
}

func legacyScopeForScopeType(scopeType string) string {
	if scopeType == ScopeTypeService {
		return "service"
	}
	return "global"
}

func scopeTypeRank(scopeType string) int {
	switch normalizeScopeType(scopeType) {
	case ScopeTypeService:
		return 3
	case ScopeTypeUserGlobal:
		return 2
	case ScopeTypeAdminGlobal:
		return 1
	default:
		return 0
	}
}

func requirePolicyMutation(actor *Actor, requestedScopeType, legacyScope, serviceID string) (policyMutationScope, error) {
	if actor == nil {
		return policyMutationScope{}, errors.New("authentication required")
	}
	scopeType := normalizeScopeType(requestedScopeType)
	if actor.Role == RoleAdmin && !actor.ReadOnly && actor.ViewingUser == nil {
		if scopeType == "" {
			scopeType = ScopeTypeAdminGlobal
		}
		if scopeType != ScopeTypeAdminGlobal {
			return policyMutationScope{}, authorizationError("admin can only mutate admin_global policy config")
		}
		return policyMutationScope{
			ScopeType:   ScopeTypeAdminGlobal,
			OwnerUserID: actor.ID,
			Owner:       actor.Username,
			AdminGlobal: true,
		}, nil
	}
	if !actorCanMutateConfig(actor) {
		return policyMutationScope{}, authorizationError("user role required for config changes")
	}
	scopeType = effectiveScopeType(scopeType, legacyScope, serviceID)
	switch scopeType {
	case ScopeTypeUserGlobal, ScopeTypeService:
	default:
		return policyMutationScope{}, fmt.Errorf("scope_type must be %s or %s", ScopeTypeUserGlobal, ScopeTypeService)
	}
	return policyMutationScope{
		ScopeType:   scopeType,
		OwnerUserID: actorOwnerUserID(actor),
		Owner:       actor.Username,
	}, nil
}

func validatePolicyScope(scopeType, serviceID string) error {
	scopeType = normalizeScopeType(scopeType)
	serviceID = strings.TrimSpace(serviceID)
	switch scopeType {
	case ScopeTypeAdminGlobal, ScopeTypeUserGlobal:
		if serviceID != "" {
			return errors.New("service_id is only allowed for service scope")
		}
	case ScopeTypeService:
		if serviceID == "" {
			return errors.New("service scope requires service_id")
		}
	default:
		return fmt.Errorf("scope_type must be %s, %s, or %s", ScopeTypeAdminGlobal, ScopeTypeUserGlobal, ScopeTypeService)
	}
	return nil
}

func policyListWhere(alias string, actor *Actor) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	if actor != nil && actor.Role == RoleAdmin && !actor.ReadOnly && actor.ViewingUser == nil {
		return prefix + "scope_type = '" + ScopeTypeAdminGlobal + "'"
	}
	return "(" + prefix + "scope_type = '" + ScopeTypeAdminGlobal + "' OR " + prefix + ownerSQL() + ")"
}

func policyEditableSQL(alias string, actor *Actor) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	if actor != nil && actor.Role == RoleAdmin && !actor.ReadOnly && actor.ViewingUser == nil {
		return "(" + prefix + "scope_type = '" + ScopeTypeAdminGlobal + "')"
	}
	if actor != nil && actorCanMutateConfig(actor) {
		return "(" + prefix + "scope_type <> '" + ScopeTypeAdminGlobal + "' AND " + prefix + ownerSQL() + ")"
	}
	return "false"
}

func policyMutationWhere(alias string, scope policyMutationScope) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	if scope.AdminGlobal {
		return prefix + "scope_type = '" + ScopeTypeAdminGlobal + "'"
	}
	return prefix + "scope_type <> '" + ScopeTypeAdminGlobal + "' AND " + prefix + ownerSQL()
}

func (s *Store) beginPolicyMutationTx(ctx context.Context, actor *Actor, scope policyMutationScope) (pgx.Tx, error) {
	if scope.AdminGlobal {
		return s.beginUnscopedTx(ctx)
	}
	return s.beginActorOwnerTx(ctx, actor)
}

func (s *Store) rebuildPolicyMutationInTx(ctx context.Context, tx pgx.Tx, actor *Actor, scope policyMutationScope, reason string) error {
	if scope.AdminGlobal {
		return nil
	}
	_, err := s.rebuildSnapshotInTx(ctx, tx, actor, nil, reason)
	return err
}

func (s *Store) commitPolicyMutation(ctx context.Context, tx pgx.Tx, actor *Actor, scope policyMutationScope, reason string) error {
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if scope.AdminGlobal {
		_, err := s.rebuildAllActiveUserSnapshots(ctx, actor, reason)
		return err
	}
	return nil
}

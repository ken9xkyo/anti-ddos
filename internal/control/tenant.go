package control

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

type tenantContextKey struct{}

func contextWithTenant(ctx context.Context, tenantID string) context.Context {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ctx
	}
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

func tenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if tenantID, ok := ctx.Value(tenantContextKey{}).(string); ok {
		return strings.TrimSpace(tenantID)
	}
	return ""
}

func (s *Store) beginContextTenantTx(ctx context.Context) (pgx.Tx, error) {
	return s.beginTenantTx(ctx, tenantIDFromContext(ctx))
}

func (s *Store) beginActorTenantTx(ctx context.Context, actor *Actor) (pgx.Tx, error) {
	if actor == nil {
		return nil, errors.New("authentication required")
	}
	tenantID := actorTenantID(actor)
	if tenantID != "" {
		actor.TenantID = tenantID
	}
	if actor.TenantSlug == "" {
		actor.TenantSlug = actorTenantSlug(actor)
	}
	return s.beginTenantTx(ctx, tenantID)
}

func (s *Store) beginContextOrPlatformTx(ctx context.Context) (pgx.Tx, error) {
	if tenantID := tenantIDFromContext(ctx); tenantID != "" {
		return s.beginTenantTx(ctx, tenantID)
	}
	return s.beginPlatformTx(ctx)
}

func (s *Store) beginTenantTx(ctx context.Context, tenantID string) (pgx.Tx, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant context required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('anti_ddos.tenant_id', $1, true), set_config('anti_ddos.platform', '', true)`, tenantID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

func (s *Store) beginPlatformTx(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('anti_ddos.tenant_id', '', true), set_config('anti_ddos.platform', 'true', true)`); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

func (s *Store) activeTenantIDs(ctx context.Context) ([]string, error) {
	tx, err := s.beginPlatformTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text FROM tenants WHERE status='active' ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, tx.Commit(ctx)
}

func (s *Store) contextWithDefaultTenant(ctx context.Context) (context.Context, error) {
	if tenantIDFromContext(ctx) != "" {
		return ctx, nil
	}
	tx, err := s.beginPlatformTx(ctx)
	if err != nil {
		return ctx, err
	}
	defer tx.Rollback(ctx)
	tenant, err := defaultTenant(ctx, tx)
	if err != nil {
		return ctx, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ctx, err
	}
	return contextWithTenant(ctx, tenant.ID), nil
}

func (s *Store) tenantContextForService(ctx context.Context, serviceID string) (context.Context, error) {
	if tenantIDFromContext(ctx) != "" {
		return ctx, nil
	}
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		return s.contextWithDefaultTenant(ctx)
	}
	tx, err := s.beginPlatformTx(ctx)
	if err != nil {
		return ctx, err
	}
	defer tx.Rollback(ctx)
	var tenantID string
	if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM backend_services WHERE id=$1`, serviceID).Scan(&tenantID); err != nil {
		return ctx, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ctx, err
	}
	return contextWithTenant(ctx, tenantID), nil
}

func (s *Store) tenantContextForFeedSource(ctx context.Context, sourceID string) (context.Context, error) {
	if tenantIDFromContext(ctx) != "" {
		return ctx, nil
	}
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return s.contextWithDefaultTenant(ctx)
	}
	tx, err := s.beginPlatformTx(ctx)
	if err != nil {
		return ctx, err
	}
	defer tx.Rollback(ctx)
	var tenantID string
	if err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM feed_sources WHERE id=$1`, sourceID).Scan(&tenantID); err != nil {
		return ctx, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ctx, err
	}
	return contextWithTenant(ctx, tenantID), nil
}

func tenantRoleAllowsOperator(role string) bool {
	switch role {
	case RoleAdmin, RoleOperator:
		return true
	default:
		return false
	}
}

func tenantRoleAllowsAdmin(role string) bool {
	return role == RoleAdmin
}

func actorTenantID(actor *Actor) string {
	if actor == nil {
		return ""
	}
	if tenantID := strings.TrimSpace(actor.TenantID); tenantID != "" {
		return tenantID
	}
	if actor.ActiveTenant != nil {
		return strings.TrimSpace(actor.ActiveTenant.ID)
	}
	for _, access := range actor.Tenants {
		if access.Status == StatusActive && strings.TrimSpace(access.TenantID) != "" {
			return strings.TrimSpace(access.TenantID)
		}
	}
	return ""
}

func actorTenantSlug(actor *Actor) string {
	if actor == nil {
		return ""
	}
	if slug := strings.TrimSpace(actor.TenantSlug); slug != "" {
		return slug
	}
	if actor.ActiveTenant != nil {
		return strings.TrimSpace(actor.ActiveTenant.Slug)
	}
	for _, access := range actor.Tenants {
		if access.Status == StatusActive && strings.TrimSpace(access.Slug) != "" {
			return strings.TrimSpace(access.Slug)
		}
	}
	return ""
}

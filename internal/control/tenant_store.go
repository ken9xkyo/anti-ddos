package control

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func defaultTenant(ctx context.Context, q dbQuerier) (Tenant, error) {
	var tenant Tenant
	err := q.QueryRow(ctx, `SELECT id::text, slug, name, status, created_at, updated_at FROM tenants WHERE slug='default'`).Scan(
		&tenant.ID, &tenant.Slug, &tenant.Name, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	return tenant, err
}

func (s *Store) ensureUserIdentity(ctx context.Context, q dbQuerier, username, password, legacyRole string) (User, bool, error) {
	var user User
	err := q.QueryRow(ctx, `SELECT id::text, username, role, platform_role, status, force_password_change, created_at, last_login_at
FROM app_users WHERE username=$1`, username).Scan(
		&user.ID,
		&user.Username,
		&user.Role,
		&user.PlatformRole,
		&user.Status,
		&user.ForcePasswordChange,
		&user.CreatedAt,
		&user.LastLoginAt,
	)
	if err == nil {
		return user, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return User{}, false, err
	}
	id, err := newUUID()
	if err != nil {
		return User{}, false, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, false, err
	}
	err = q.QueryRow(ctx, `INSERT INTO app_users(id, username, password_hash, role, status)
VALUES ($1, $2, $3, $4, 'active')
RETURNING id::text, username, role, platform_role, status, force_password_change, created_at, last_login_at`,
		id, username, string(hash), legacyRole,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Role,
		&user.PlatformRole,
		&user.Status,
		&user.ForcePasswordChange,
		&user.CreatedAt,
		&user.LastLoginAt,
	)
	if err != nil {
		return User{}, false, err
	}
	return user, true, nil
}

func (s *Store) resolveUserTenantAccess(ctx context.Context, userID, platformRole, selector string) ([]TenantAccess, TenantAccess, error) {
	selector = strings.TrimSpace(selector)
	accesses, err := s.userTenantAccesses(ctx, userID, platformRole)
	if err != nil {
		return nil, TenantAccess{}, err
	}
	if len(accesses) == 0 {
		return nil, TenantAccess{}, errors.New("user has no active tenant")
	}
	if platformRole != PlatformRoleAdmin && tenantAccessesContainOperator(accesses) && len(accesses) > 1 {
		return nil, TenantAccess{}, authorizationError("operator identity cannot have active memberships in multiple tenants")
	}
	var fallback TenantAccess
	for i, access := range accesses {
		if i == 0 || access.Slug == "default" {
			fallback = access
		}
		if selector != "" && (access.TenantID == selector || access.Slug == selector) {
			return accesses, access, nil
		}
	}
	if selector != "" {
		return nil, TenantAccess{}, authorizationError("tenant is not available for user")
	}
	return accesses, fallback, nil
}

func (s *Store) userTenantAccesses(ctx context.Context, userID, platformRole string) ([]TenantAccess, error) {
	if platformRole == PlatformRoleAdmin {
		rows, err := s.pool.Query(ctx, `SELECT id::text, slug, name, 'admin', status, created_at, updated_at
FROM tenants
WHERE status='active'
ORDER BY slug`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := make([]TenantAccess, 0)
		for rows.Next() {
			var access TenantAccess
			if err := rows.Scan(&access.TenantID, &access.Slug, &access.Name, &access.Role, &access.Status, &access.CreatedAt, &access.UpdatedAt); err != nil {
				return nil, err
			}
			out = append(out, access)
		}
		return out, rows.Err()
	}

	rows, err := s.pool.Query(ctx, `SELECT t.id::text, t.slug, t.name, m.role, m.status, m.created_at, m.updated_at
FROM tenant_memberships m
JOIN tenants t ON t.id = m.tenant_id
WHERE m.user_id=$1 AND m.status='active' AND t.status='active'
ORDER BY t.slug`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TenantAccess, 0)
	for rows.Next() {
		var access TenantAccess
		if err := rows.Scan(&access.TenantID, &access.Slug, &access.Name, &access.Role, &access.Status, &access.CreatedAt, &access.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, access)
	}
	return out, rows.Err()
}

func (s *Store) ListTenants(ctx context.Context, actor *Actor, includeRevoked bool) ([]TenantAccess, error) {
	if actor == nil {
		return nil, errors.New("authentication required")
	}
	if includeRevoked {
		if actor.PlatformRole != PlatformRoleAdmin {
			return nil, authorizationError("platform_admin role required")
		}
		rows, err := s.pool.Query(ctx, `SELECT id::text, slug, name, 'admin', status, created_at, updated_at
FROM tenants
ORDER BY slug`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := make([]TenantAccess, 0)
		for rows.Next() {
			var access TenantAccess
			if err := rows.Scan(&access.TenantID, &access.Slug, &access.Name, &access.Role, &access.Status, &access.CreatedAt, &access.UpdatedAt); err != nil {
				return nil, err
			}
			out = append(out, access)
		}
		return out, rows.Err()
	}
	accesses, err := s.userTenantAccesses(ctx, actor.ID, actor.PlatformRole)
	if err != nil {
		return nil, err
	}
	if actor.PlatformRole != PlatformRoleAdmin && tenantAccessesContainOperator(accesses) && len(accesses) > 1 {
		return nil, authorizationError("operator identity cannot have active memberships in multiple tenants")
	}
	return accesses, nil
}

func (s *Store) CreateTenant(ctx context.Context, actor *Actor, input TenantInput) (Tenant, error) {
	if actor == nil || actor.PlatformRole != PlatformRoleAdmin {
		return Tenant{}, authorizationError("platform_admin role required")
	}
	slug := normalizeTenantSlug(input.Slug)
	if slug == "" {
		return Tenant{}, errors.New("tenant slug is required")
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = slug
	}
	status := strings.TrimSpace(input.Status)
	if status == "" {
		status = StatusActive
	}
	if status != StatusActive && status != StatusRevoked {
		return Tenant{}, errors.New("tenant status must be active or revoked")
	}
	id, err := newUUID()
	if err != nil {
		return Tenant{}, err
	}
	tx, err := s.beginPlatformTx(ctx)
	if err != nil {
		return Tenant{}, err
	}
	defer tx.Rollback(ctx)
	var tenant Tenant
	if err := tx.QueryRow(ctx, `INSERT INTO tenants(id, slug, name, status)
VALUES ($1, $2, $3, $4)
RETURNING id::text, slug, name, status, created_at, updated_at`,
		id, slug, name, status,
	).Scan(&tenant.ID, &tenant.Slug, &tenant.Name, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt); err != nil {
		return Tenant{}, err
	}
	if err := insertAudit(contextWithTenant(ctx, tenant.ID), tx, actor, "create_tenant", "tenant", tenant.ID, nil, tenant, "create tenant", ""); err != nil {
		return Tenant{}, err
	}
	return tenant, tx.Commit(ctx)
}

func (s *Store) UpdateTenant(ctx context.Context, actor *Actor, id string, input TenantInput) (Tenant, error) {
	if actor == nil || actor.PlatformRole != PlatformRoleAdmin {
		return Tenant{}, authorizationError("platform_admin role required")
	}
	status := strings.TrimSpace(input.Status)
	if status == "" {
		status = StatusActive
	}
	if status != StatusActive && status != StatusRevoked {
		return Tenant{}, errors.New("tenant status must be active or revoked")
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = strings.TrimSpace(input.Slug)
	}
	tx, err := s.beginPlatformTx(ctx)
	if err != nil {
		return Tenant{}, err
	}
	defer tx.Rollback(ctx)
	before, err := tenantByID(ctx, tx, id)
	if err != nil {
		return Tenant{}, err
	}
	if name == "" {
		name = before.Name
	}
	var after Tenant
	if err := tx.QueryRow(ctx, `UPDATE tenants SET name=$2, status=$3, updated_at=now()
WHERE id=$1
RETURNING id::text, slug, name, status, created_at, updated_at`,
		id, name, status,
	).Scan(&after.ID, &after.Slug, &after.Name, &after.Status, &after.CreatedAt, &after.UpdatedAt); err != nil {
		return Tenant{}, err
	}
	if err := insertAudit(contextWithTenant(ctx, after.ID), tx, actor, "update_tenant", "tenant", after.ID, before, after, "update tenant", ""); err != nil {
		return Tenant{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) SwitchTenant(ctx context.Context, actor *Actor, token string, input TenantSwitchInput) (Session, error) {
	if actor == nil {
		return Session{}, errors.New("authentication required")
	}
	selector := strings.TrimSpace(input.TenantID)
	if selector == "" {
		selector = strings.TrimSpace(input.TenantSlug)
	}
	accesses, access, err := s.resolveUserTenantAccess(ctx, actor.ID, actor.PlatformRole, selector)
	if err != nil {
		return Session{}, err
	}
	tx, err := s.beginPlatformTx(ctx)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback(ctx)
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `UPDATE user_sessions SET active_tenant_id=$2
WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > now()
RETURNING expires_at`,
		hashToken(token), access.TenantID,
	).Scan(&expiresAt); err != nil {
		return Session{}, err
	}
	if err := insertAudit(contextWithTenant(ctx, access.TenantID), tx, actor, "switch_tenant", "tenant", access.TenantID, actor.ActiveTenant, access, "switch tenant", ""); err != nil {
		return Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Session{}, err
	}
	user := actor.User
	user.Role = access.Role
	user.Status = access.Status
	user.ActiveTenant = &Tenant{ID: access.TenantID, Slug: access.Slug, Name: access.Name, Status: access.Status, CreatedAt: access.CreatedAt, UpdatedAt: access.UpdatedAt}
	user.Tenants = accesses
	return Session{Token: token, ExpiresAt: expiresAt, User: user}, nil
}

func (s *Store) ResolveTenantID(ctx context.Context, tenantID, slug string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	slug = strings.TrimSpace(slug)
	if tenantID == "" && slug == "" {
		return "", errors.New("tenant header is required")
	}
	var id string
	var err error
	if tenantID != "" {
		err = s.pool.QueryRow(ctx, `SELECT id::text FROM tenants WHERE id=$1 AND status='active'`, tenantID).Scan(&id)
	} else {
		err = s.pool.QueryRow(ctx, `SELECT id::text FROM tenants WHERE slug=$1 AND status='active'`, slug).Scan(&id)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("tenant not found")
		}
		return "", err
	}
	return id, nil
}

func tenantByID(ctx context.Context, q dbQuerier, id string) (Tenant, error) {
	var tenant Tenant
	err := q.QueryRow(ctx, `SELECT id::text, slug, name, status, created_at, updated_at FROM tenants WHERE id=$1`, id).Scan(
		&tenant.ID, &tenant.Slug, &tenant.Name, &tenant.Status, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	return tenant, err
}

func normalizeTenantSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

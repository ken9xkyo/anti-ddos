package control

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

type ownerContextKey struct{}

var errForbidden = errors.New("forbidden")

type forbiddenError struct {
	msg string
}

func (e forbiddenError) Error() string {
	return e.msg
}

func (e forbiddenError) Is(target error) bool {
	return target == errForbidden
}

func authorizationError(message string) error {
	return forbiddenError{msg: message}
}

func contextWithOwner(ctx context.Context, ownerUserID string) context.Context {
	ownerUserID = strings.TrimSpace(ownerUserID)
	if ownerUserID == "" {
		return ctx
	}
	return context.WithValue(ctx, ownerContextKey{}, ownerUserID)
}

func ownerUserIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if ownerUserID, ok := ctx.Value(ownerContextKey{}).(string); ok {
		return strings.TrimSpace(ownerUserID)
	}
	return ""
}

func (s *Store) beginContextOwnerTx(ctx context.Context) (pgx.Tx, error) {
	return s.beginOwnerTx(ctx, ownerUserIDFromContext(ctx))
}

func (s *Store) beginActorOwnerTx(ctx context.Context, actor *Actor) (pgx.Tx, error) {
	if actor == nil {
		return nil, errors.New("authentication required")
	}
	ownerUserID := actorOwnerUserID(actor)
	if ownerUserID != "" {
		actor.ViewOwnerUserID = ownerUserID
	}
	return s.beginOwnerTx(ctx, ownerUserID)
}

func (s *Store) beginContextOrUnscopedTx(ctx context.Context) (pgx.Tx, error) {
	if ownerUserID := ownerUserIDFromContext(ctx); ownerUserID != "" {
		return s.beginOwnerTx(ctx, ownerUserID)
	}
	return s.beginUnscopedTx(ctx)
}

func (s *Store) beginOwnerTx(ctx context.Context, ownerUserID string) (pgx.Tx, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	if ownerUserID == "" {
		return nil, errors.New("owner user context required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('anti_ddos.owner_user_id', $1, true)`, ownerUserID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

func (s *Store) beginUnscopedTx(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('anti_ddos.owner_user_id', '', true)`); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

func ownerSQL() string {
	return "owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid"
}

func ownerValueSQL() string {
	return "NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid"
}

func actorOwnerUserID(actor *Actor) string {
	if actor == nil {
		return ""
	}
	if ownerUserID := strings.TrimSpace(actor.ViewOwnerUserID); ownerUserID != "" {
		return ownerUserID
	}
	if actor.ViewingUser != nil && strings.TrimSpace(actor.ViewingUser.ID) != "" {
		return strings.TrimSpace(actor.ViewingUser.ID)
	}
	return strings.TrimSpace(actor.ID)
}

func actorCanMutateConfig(actor *Actor) bool {
	return actor != nil && actor.Role == RoleUser && actorOwnerUserID(actor) == actor.ID
}

func requireConfigMutation(actor *Actor) error {
	if actor == nil {
		return errors.New("authentication required")
	}
	if !actorCanMutateConfig(actor) {
		return authorizationError("user role required for config changes")
	}
	return nil
}

func requireAdmin(actor *Actor) error {
	if actor == nil {
		return errors.New("authentication required")
	}
	if actor.Role != RoleAdmin {
		return authorizationError("admin role required")
	}
	return nil
}

func validUserRole(role string) bool {
	return role == RoleAdmin || role == RoleUser
}

func (s *Store) activeOwnerUserIDs(ctx context.Context) ([]string, error) {
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text FROM app_users WHERE role='user' AND status='active' ORDER BY username`)
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

func (s *Store) ResolveOwnerUserID(ctx context.Context, userID, username string) (string, error) {
	userID = strings.TrimSpace(userID)
	username = strings.TrimSpace(username)
	if userID == "" && username == "" {
		return "", errors.New("owner user id or username is required")
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var ownerUserID string
	if userID != "" {
		err = tx.QueryRow(ctx, `SELECT id::text FROM app_users WHERE id=$1 AND role='user' AND status='active'`, userID).Scan(&ownerUserID)
	} else {
		err = tx.QueryRow(ctx, `SELECT id::text FROM app_users WHERE username=$1 AND role='user' AND status='active'`, username).Scan(&ownerUserID)
	}
	if err != nil {
		return "", err
	}
	return ownerUserID, tx.Commit(ctx)
}

func (s *Store) ownerContextForService(ctx context.Context, serviceID string) (context.Context, error) {
	if ownerUserIDFromContext(ctx) != "" {
		return ctx, nil
	}
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		return ctx, errors.New("owner user context required")
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return ctx, err
	}
	defer tx.Rollback(ctx)
	var ownerUserID string
	if err := tx.QueryRow(ctx, `SELECT owner_user_id::text FROM backend_services WHERE id=$1`, serviceID).Scan(&ownerUserID); err != nil {
		return ctx, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ctx, err
	}
	return contextWithOwner(ctx, ownerUserID), nil
}

func (s *Store) ownerContextForFeedSource(ctx context.Context, sourceID string) (context.Context, error) {
	if ownerUserIDFromContext(ctx) != "" {
		return ctx, nil
	}
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return ctx, errors.New("owner user context required")
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return ctx, err
	}
	defer tx.Rollback(ctx)
	var ownerUserID string
	if err := tx.QueryRow(ctx, `SELECT owner_user_id::text FROM feed_sources WHERE id=$1`, sourceID).Scan(&ownerUserID); err != nil {
		return ctx, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ctx, err
	}
	return contextWithOwner(ctx, ownerUserID), nil
}

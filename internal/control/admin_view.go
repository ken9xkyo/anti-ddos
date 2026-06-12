package control

import (
	"context"
	"errors"
	"strings"
	"time"
)

type AdminViewUserInput struct {
	UserID string `json:"user_id"`
}

func (s *Store) ViewUserConfig(ctx context.Context, actor *Actor, token string, input AdminViewUserInput) (Session, error) {
	if err := requireAdmin(actor); err != nil {
		return Session{}, err
	}
	targetID := strings.TrimSpace(input.UserID)
	if targetID == "" {
		return Session{}, errors.New("user_id is required")
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback(ctx)
	target, err := s.getUser(ctx, tx, targetID)
	if err != nil {
		return Session{}, err
	}
	if target.Status != StatusActive {
		return Session{}, errors.New("target user is not active")
	}
	if target.Role != RoleUser {
		return Session{}, errors.New("admin can only view user config")
	}
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `UPDATE user_sessions SET view_owner_user_id=$2
WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > now()
RETURNING expires_at`, hashToken(token), target.ID).Scan(&expiresAt); err != nil {
		return Session{}, err
	}
	if err := insertAudit(contextWithOwner(ctx, target.ID), tx, actor, "view_user_config", "user", target.ID, actor.User.ViewingUser, target, "view user config", ""); err != nil {
		return Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Session{}, err
	}
	user := actor.User
	user.ViewingUser = &ViewingUser{ID: target.ID, Username: target.Username}
	user.ReadOnly = true
	return Session{Token: token, ExpiresAt: expiresAt, User: user}, nil
}

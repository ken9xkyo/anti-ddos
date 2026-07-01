package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ken9xkyo/anti-ddos/internal/agent"
	"golang.org/x/crypto/bcrypt"
)

type dbQuerier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Store struct {
	pool           *pgxpool.Pool
	cfg            Config
	logger         *slog.Logger
	feedHTTPClient *http.Client
	telegramClient *TelegramClient
	alertRetryBase time.Duration
	feedMu         sync.Mutex
	feedLocks      map[string]*sync.Mutex
	metrics        *ControlMetrics
}

type Actor struct {
	User
	ViewOwnerUserID string
}

func OpenPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func NewStore(pool *pgxpool.Pool, cfg Config, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		pool:           pool,
		cfg:            cfg,
		logger:         logger,
		feedHTTPClient: &http.Client{Timeout: 15 * time.Second},
		telegramClient: NewTelegramClient(cfg.TelegramAPIURL, &http.Client{Timeout: 5 * time.Second}),
		alertRetryBase: time.Second,
		feedLocks:      map[string]*sync.Mutex{},
	}
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

const defaultUDPSourcePortSeedReason = "seeded UDP reflection source-port candidate from CISA/Cloudflare guidance"

type udpSourcePortSeed struct {
	port  int
	label string
}

var defaultUDPSourcePortSeeds = []udpSourcePortSeed{
	{0, "reserved source port"},
	{19, "CHARGEN"},
	{53, "DNS"},
	{69, "TFTP"},
	{111, "SunRPC"},
	{123, "NTP"},
	{137, "NetBIOS"},
	{161, "SNMP"},
	{162, "SNMP trap"},
	{389, "CLDAP"},
	{427, "SLP"},
	{520, "RIP"},
	{1194, "OpenVPN"},
	{1900, "SSDP"},
	{3702, "WS-Discovery"},
	{5353, "mDNS"},
	{10001, "Ubiquiti discovery"},
	{11211, "Memcached"},
	{20800, "Call of Duty"},
	{27005, "SRCDS"},
}

func seedDefaultUDPSourcePortBlocks(ctx context.Context, q dbQuerier, ownerUserID string) error {
	ownerUserID = strings.TrimSpace(ownerUserID)
	if ownerUserID == "" {
		return errors.New("owner user id is required")
	}
	for _, seed := range defaultUDPSourcePortSeeds {
		id, err := newUUID()
		if err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `INSERT INTO udp_source_port_blocks(id, owner_user_id, port, label, reason, owner, scope_type, enabled)
VALUES ($1, $2, $3, $4, $5, 'system', 'user_global', false)
ON CONFLICT (id) DO NOTHING`,
			id, ownerUserID, seed.port, seed.label, defaultUDPSourcePortSeedReason,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) BootstrapAdmin(ctx context.Context, username, password string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username is required")
	}
	if len(password) < 12 {
		return User{}, errors.New("admin password must be at least 12 characters")
	}

	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	var admins int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_users WHERE role='admin' AND status='active'`).Scan(&admins); err != nil {
		return User{}, err
	}
	if admins > 0 {
		return User{}, errors.New("admin user already exists")
	}

	id, err := newUUID()
	if err != nil {
		return User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	var user User
	if err := tx.QueryRow(ctx, `INSERT INTO app_users(id, username, password_hash, role, status, force_password_change)
VALUES ($1, $2, $3, 'admin', 'active', true)
RETURNING id::text, username, role, status, force_password_change, created_at, last_login_at`,
		id, username, string(hash)).Scan(&user.ID, &user.Username, &user.Role, &user.Status, &user.ForcePasswordChange, &user.CreatedAt, &user.LastLoginAt); err != nil {
		return User{}, err
	}
	if err := insertAudit(ctx, tx, nil, "bootstrap_admin", "user", user.ID, nil, user, "one-time bootstrap admin", ""); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) Authenticate(ctx context.Context, username, password string, ttl time.Duration) (Session, error) {
	var user User
	var passwordHash string
	err := s.pool.QueryRow(ctx, `SELECT id::text, username, role, status, force_password_change, created_at, last_login_at, password_hash
FROM app_users WHERE username = $1`, strings.TrimSpace(username)).Scan(
		&user.ID,
		&user.Username,
		&user.Role,
		&user.Status,
		&user.ForcePasswordChange,
		&user.CreatedAt,
		&user.LastLoginAt,
		&passwordHash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, errors.New("invalid username or password")
		}
		return Session{}, err
	}
	if user.Status != StatusActive {
		return Session{}, errors.New("user is not active")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return Session{}, errors.New("invalid username or password")
	}

	id, err := newUUID()
	if err != nil {
		return Session{}, err
	}
	token, tokenHash, err := newBearerToken()
	if err != nil {
		return Session{}, err
	}
	expiresAt := time.Now().UTC().Add(ttl)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO user_sessions(id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`, id, user.ID, tokenHash, expiresAt); err != nil {
		return Session{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE app_users SET last_login_at = now(), updated_at = now() WHERE id = $1`, user.ID); err != nil {
		return Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Session{}, err
	}
	return Session{Token: token, ExpiresAt: expiresAt, User: user}, nil
}

func (s *Store) AuthenticateToken(ctx context.Context, token string) (*Actor, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("missing bearer token")
	}
	var user User
	var viewOwnerUserID string
	err := s.pool.QueryRow(ctx, `SELECT u.id::text, u.username, u.role, u.status, u.force_password_change, u.default_output_interface, u.created_at, u.last_login_at, COALESCE(s.view_owner_user_id::text, '')
FROM user_sessions s
JOIN app_users u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.revoked_at IS NULL
	AND s.expires_at > now()
	AND u.status = 'active'`,
		hashToken(token),
	).Scan(&user.ID, &user.Username, &user.Role, &user.Status, &user.ForcePasswordChange, &user.DefaultOutputInterface, &user.CreatedAt, &user.LastLoginAt, &viewOwnerUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("invalid or expired session")
		}
		return nil, err
	}
	actor := &Actor{User: user, ViewOwnerUserID: user.ID}
	if user.Role == RoleAdmin && strings.TrimSpace(viewOwnerUserID) != "" {
		target, err := s.userSummary(ctx, viewOwnerUserID)
		if err != nil {
			return nil, err
		}
		user.ViewingUser = &target
		user.ReadOnly = true
		actor.User = user
		actor.ViewOwnerUserID = target.ID
	}
	return actor, nil
}

func (s *Store) RevokeToken(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `UPDATE user_sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hashToken(token))
	return err
}

func (s *Store) CreateUser(ctx context.Context, actor *Actor, username, password, role, reason string) (User, error) {
	username = strings.TrimSpace(username)
	role = strings.TrimSpace(strings.ToLower(role))
	if username == "" {
		return User{}, errors.New("username is required")
	}
	if !validUserRole(role) {
		return User{}, fmt.Errorf("unsupported role %q", role)
	}
	if err := requireAdmin(actor); err != nil {
		return User{}, err
	}
	if len(password) < 12 {
		return User{}, errors.New("password must be at least 12 characters")
	}
	if strings.TrimSpace(reason) == "" {
		return User{}, errors.New("reason is required")
	}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	user, created, err := s.ensureUserIdentity(ctx, tx, username, password, role)
	if err != nil {
		return User{}, err
	}
	user, err = s.getUser(ctx, tx, user.ID)
	if err != nil {
		return User{}, err
	}
	if user.Role == RoleUser {
		if err := seedDefaultUDPSourcePortBlocks(ctx, tx, user.ID); err != nil {
			return User{}, err
		}
	}
	action := "reactivate_user"
	if created {
		action = "create_user"
	}
	if err := insertAudit(ctx, tx, actor, action, "user", user.ID, nil, user, reason, ""); err != nil {
		return User{}, err
	}
	return user, tx.Commit(ctx)
}

func (s *Store) ensureUserIdentity(ctx context.Context, q dbQuerier, username, password, role string) (User, bool, error) {
	id, err := newUUID()
	if err != nil {
		return User{}, false, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, false, err
	}
	var user User
	var created bool
	err = q.QueryRow(ctx, `INSERT INTO app_users(id, username, password_hash, role, status, force_password_change)
VALUES ($1,$2,$3,$4,'active',true)
ON CONFLICT (username) DO UPDATE SET
    password_hash=EXCLUDED.password_hash,
    role=EXCLUDED.role,
    status='active',
    force_password_change=true,
    updated_at=now()
RETURNING id::text, username, role, status, force_password_change, default_output_interface, created_at, last_login_at, (xmax = 0)`,
		id, username, string(hash), role,
	).Scan(&user.ID, &user.Username, &user.Role, &user.Status, &user.ForcePasswordChange, &user.DefaultOutputInterface, &user.CreatedAt, &user.LastLoginAt, &created)
	if err != nil {
		return User{}, false, err
	}
	return user, created, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, username, role, status, force_password_change, default_output_interface, created_at, last_login_at
FROM app_users
ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Role, &user.Status, &user.ForcePasswordChange, &user.DefaultOutputInterface, &user.CreatedAt, &user.LastLoginAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, tx.Commit(ctx)
}

func (s *Store) RevokeUser(ctx context.Context, actor *Actor, id, reason string) (User, error) {
	if strings.TrimSpace(reason) == "" {
		return User{}, errors.New("reason is required")
	}
	if err := requireAdmin(actor); err != nil {
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
	if err := ensureActiveAdminRemains(ctx, tx, before, before.Role, StatusRevoked); err != nil {
		return User{}, err
	}
	var after User
	if _, err := tx.Exec(ctx, `UPDATE app_users SET status='revoked', updated_at=now()
WHERE id=$1`, id); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_sessions SET revoked_at=now()
WHERE user_id=$1 AND revoked_at IS NULL`, id); err != nil {
		return User{}, err
	}
	after, err = s.getUser(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	if err := insertAudit(ctx, tx, actor, "revoke_user", "user", id, before, after, reason, ""); err != nil {
		return User{}, err
	}
	return after, tx.Commit(ctx)
}

func (s *Store) getUser(ctx context.Context, q dbQuerier, id string) (User, error) {
	var user User
	err := q.QueryRow(ctx, `SELECT id::text, username, role, status, force_password_change, default_output_interface, created_at, last_login_at
FROM app_users
WHERE id = $1`, id).Scan(
		&user.ID, &user.Username, &user.Role, &user.Status, &user.ForcePasswordChange, &user.DefaultOutputInterface, &user.CreatedAt, &user.LastLoginAt,
	)
	return user, err
}

func (s *Store) userSummary(ctx context.Context, id string) (ViewingUser, error) {
	var user ViewingUser
	if err := s.pool.QueryRow(ctx, `SELECT id::text, username FROM app_users WHERE id=$1 AND status='active'`, strings.TrimSpace(id)).Scan(&user.ID, &user.Username); err != nil {
		return ViewingUser{}, err
	}
	return user, nil
}

func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, created_at, COALESCE(actor_id::text, ''), actor_username, action, entity_type, entity_id,
       COALESCE(before, 'null'::jsonb), COALESCE(after, 'null'::jsonb), COALESCE(reason, ''), request_id
FROM audit_events
WHERE owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
   OR EXISTS (
       SELECT 1 FROM app_users
       WHERE id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
         AND role = 'admin'
   )
ORDER BY created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(
			&event.ID,
			&event.CreatedAt,
			&event.ActorID,
			&event.ActorUsername,
			&event.Action,
			&event.EntityType,
			&event.EntityID,
			&event.Before,
			&event.After,
			&event.Reason,
			&event.RequestID,
		); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, tx.Commit(ctx)
}

func insertAudit(ctx context.Context, q dbQuerier, actor *Actor, action, entityType, entityID string, before, after any, reason, requestID string) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	var actorID any
	var username string
	ownerUserID := ownerUserIDFromContext(ctx)
	if actor != nil {
		actorID = actor.ID
		username = actor.Username
		if ownerUserID == "" {
			ownerUserID = actorOwnerUserID(actor)
		}
	}
	beforeJSON, err := marshalRedactedJSON(before)
	if err != nil {
		return err
	}
	afterJSON, err := marshalRedactedJSON(after)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_events(id, owner_user_id, actor_id, actor_username, action, entity_type, entity_id, before, after, reason, request_id)
VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), $11)`,
		id, ownerUserID, actorID, username, action, entityType, entityID, beforeJSON, afterJSON, strings.TrimSpace(reason), requestID,
	)
	return err
}

func marshalRedactedJSON(value any) ([]byte, error) {
	if value == nil {
		return []byte("null"), nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	redactValue(decoded)
	return json.Marshal(decoded)
}

func redactValue(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if agent.IsSensitiveKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			if str, ok := child.(string); ok {
				typed[key] = agent.RedactString(str)
				continue
			}
			redactValue(child)
		}
	case []any:
		for _, child := range typed {
			redactValue(child)
		}
	}
}

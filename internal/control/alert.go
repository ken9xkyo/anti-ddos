package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

const (
	alertStatusPending  = "pending"
	alertStatusSent     = "sent"
	alertStatusFailed   = "failed"
	alertStatusDeduped  = "deduped"
	alertStatusRetrying = "retrying"

	defaultAlertRateLimitSeconds = 300
	defaultAlertMaxAttempts      = 3
	maxTelegramMessageBytes      = 4000
	telegramTokenMask            = "*****"
)

type alertPolicy struct {
	RateLimitSeconds uint32
	MaxAttempts      uint32
	Template         string
	Enabled          bool
}

type TelegramClient struct {
	baseURL string
	client  *http.Client
}

type telegramSendResult struct {
	Retryable bool
	Response  json.RawMessage
}

func NewTelegramClient(baseURL string, client *http.Client) *TelegramClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = defaultTelegramAPI
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &TelegramClient{baseURL: baseURL, client: client}
}

func (c *TelegramClient) SendMessage(ctx context.Context, token, chatID, parseMode, text string) (telegramSendResult, error) {
	token = strings.TrimSpace(token)
	chatID = strings.TrimSpace(chatID)
	if token == "" {
		return telegramSendResult{}, errors.New("telegram token is missing")
	}
	if chatID == "" {
		return telegramSendResult{}, errors.New("telegram chat_id is required")
	}
	body := map[string]any{"chat_id": chatID, "text": trimTelegramMessage(text)}
	if strings.TrimSpace(parseMode) != "" {
		body["parse_mode"] = strings.TrimSpace(parseMode)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return telegramSendResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/bot"+token+"/sendMessage", bytes.NewReader(raw))
	if err != nil {
		return telegramSendResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return telegramSendResult{Retryable: true}, err
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return telegramSendResult{Retryable: true}, readErr
	}
	result := telegramSendResult{Response: safeJSONResponse(respBody)}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		result.Retryable = true
		return result, fmt.Errorf("telegram status %d", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("telegram status %d", resp.StatusCode)
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		result.Retryable = true
		return result, err
	}
	if !decoded.OK {
		result.Retryable = true
		return result, errors.New("telegram response ok=false")
	}
	return result, nil
}

func trimTelegramMessage(text string) string {
	text = strings.TrimSpace(text)
	if len(text) <= maxTelegramMessageBytes {
		return text
	}
	out := text[:maxTelegramMessageBytes-32]
	return strings.TrimSpace(out) + "\n[truncated]"
}

func safeJSONResponse(raw []byte) json.RawMessage {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return json.RawMessage(`{}`)
	}
	if json.Valid(raw) {
		return json.RawMessage(raw)
	}
	return mustJSON(map[string]string{"body": string(raw)})
}

func (s *Store) UpsertTelegramConfig(ctx context.Context, actor *Actor, input TelegramConfigInput, reason string) (TelegramConfig, error) {
	if err := requireGlobalFeedAdmin(actor); err != nil {
		return TelegramConfig{}, err
	}
	tokenInput := strings.TrimSpace(input.BotTokenRef)
	if err := validateTelegramConfigInput(input); err != nil {
		return TelegramConfig{}, err
	}
	reason = mutationReason(reason, input.Reason)
	if reason == "" {
		return TelegramConfig{}, errors.New("reason is required")
	}
	tx, err := s.beginActorOwnerTx(ctx, actor)
	if err != nil {
		return TelegramConfig{}, err
	}
	defer tx.Rollback(ctx)
	beforeRaw, err := scanTelegramConfig(tx.QueryRow(ctx, `SELECT bot_token_ref, chat_id, parse_mode, enabled, created_at, updated_at
FROM telegram_configs
WHERE id=1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid`))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return TelegramConfig{}, err
	}
	token := strings.TrimSpace(beforeRaw.BotTokenRef)
	if tokenInput != "" && tokenInput != telegramTokenMask {
		token = tokenInput
	}
	if token == "" {
		return TelegramConfig{}, errors.New("bot_token_ref is required")
	}
	before := maskTelegramConfig(beforeRaw)
	enabled := boolDefault(input.Enabled, true)
	row := tx.QueryRow(ctx, `INSERT INTO telegram_configs(owner_user_id, id, bot_token_ref, chat_id, parse_mode, enabled)
VALUES (NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid, 1,$1,$2,$3,$4)
ON CONFLICT (owner_user_id, id) DO UPDATE SET
    bot_token_ref=EXCLUDED.bot_token_ref,
    chat_id=EXCLUDED.chat_id,
    parse_mode=EXCLUDED.parse_mode,
    enabled=EXCLUDED.enabled,
    updated_at=now()
RETURNING bot_token_ref, chat_id, parse_mode, enabled, created_at, updated_at`,
		token, strings.TrimSpace(input.ChatID), normalizeTelegramParseMode(input.ParseMode), enabled)
	cfg, err := scanTelegramConfig(row)
	if err != nil {
		return TelegramConfig{}, err
	}
	masked := maskTelegramConfig(cfg)
	if err := insertAudit(ctx, tx, actor, "configure_telegram", "telegram_config", "1", before, masked, reason, ""); err != nil {
		return TelegramConfig{}, err
	}
	return masked, tx.Commit(ctx)
}

func (s *Store) GetTelegramConfig(ctx context.Context) (TelegramConfig, error) {
	cfg, err := s.getTelegramConfigRaw(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return TelegramConfig{}, nil
	}
	return maskTelegramConfig(cfg), err
}

func (s *Store) getTelegramConfigRaw(ctx context.Context) (TelegramConfig, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return TelegramConfig{}, err
	}
	defer tx.Rollback(ctx)
	cfg, err := scanTelegramConfig(tx.QueryRow(ctx, `SELECT bot_token_ref, chat_id, parse_mode, enabled, created_at, updated_at
FROM telegram_configs
WHERE id=1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid`))
	if err != nil {
		return TelegramConfig{}, err
	}
	return cfg, tx.Commit(ctx)
}

func (s *Store) getAdminTelegramConfigRaw(ctx context.Context) (TelegramConfig, error) {
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return TelegramConfig{}, err
	}
	defer tx.Rollback(ctx)
	cfg, err := scanTelegramConfig(tx.QueryRow(ctx, `SELECT tc.bot_token_ref, tc.chat_id, tc.parse_mode, tc.enabled, tc.created_at, tc.updated_at
FROM telegram_configs tc
JOIN app_users u ON u.id = tc.owner_user_id
WHERE tc.id = 1 AND u.role = 'admin' AND u.status = 'active'`))
	if err != nil {
		return TelegramConfig{}, err
	}
	return cfg, tx.Commit(ctx)
}


func scanTelegramConfig(row rowScanner) (TelegramConfig, error) {
	var cfg TelegramConfig
	if err := row.Scan(&cfg.BotTokenRef, &cfg.ChatID, &cfg.ParseMode, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
		return TelegramConfig{}, err
	}
	_, status := resolveTelegramBotToken(cfg.BotTokenRef)
	cfg.BotTokenPresent = status == "present"
	return cfg, nil
}

func validateTelegramConfigInput(input TelegramConfigInput) error {
	if strings.TrimSpace(input.ChatID) == "" {
		return errors.New("chat_id is required")
	}
	if mode := normalizeTelegramParseMode(input.ParseMode); mode != "" && mode != "HTML" && mode != "MarkdownV2" && mode != "Markdown" {
		return errors.New("unsupported telegram parse_mode")
	}
	return nil
}

func maskTelegramConfig(cfg TelegramConfig) TelegramConfig {
	if strings.TrimSpace(cfg.BotTokenRef) != "" {
		cfg.BotTokenRef = telegramTokenMask
	}
	return cfg
}

func resolveTelegramBotToken(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "none"
	}
	if value == telegramTokenMask {
		return "", "masked"
	}
	if isLegacyCredentialRef(value) {
		return resolveCredentialRef(value)
	}
	return value, "present"
}

func isLegacyCredentialRef(value string) bool {
	return strings.HasPrefix(value, "env://") || strings.HasPrefix(value, "secret://anti-ddos/")
}

func normalizeTelegramParseMode(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "":
		return ""
	case "html":
		return "HTML"
	case "markdownv2":
		return "MarkdownV2"
	case "markdown":
		return "Markdown"
	default:
		return value
	}
}

func (s *Store) CreateAlert(ctx context.Context, actor *Actor, input AlertInput) (Alert, error) {
	if err := requireConfigMutation(actor); err != nil {
		if requireAdmin(actor) != nil {
			return Alert{}, err
		}
	}
	return s.createAlert(ctx, actor, input)
}

func (s *Store) CreateSystemAlert(ctx context.Context, input AlertInput) (Alert, error) {
	return s.createAlert(ctx, nil, input)
}

func (s *Store) createAlert(ctx context.Context, actor *Actor, input AlertInput) (Alert, error) {
	if err := validateAlertInput(input); err != nil {
		return Alert{}, err
	}
	id, err := newUUID()
	if err != nil {
		return Alert{}, err
	}
	var serviceID any
	if strings.TrimSpace(input.ServiceID) != "" {
		serviceID = strings.TrimSpace(input.ServiceID)
	}
	var actorID any
	if actor != nil {
		actorID = actor.ID
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback(ctx)
	alert, err := scanAlert(tx.QueryRow(ctx, `INSERT INTO alerts(
    id, owner_user_id, severity, type, dedupe_key, service_id, affected_service, vector, evidence, recommended_action, created_by
) VALUES ($1, NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid, $2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING id::text, severity, type, dedupe_key, COALESCE(service_id::text, ''), affected_service, vector,
          evidence, recommended_action, status, COALESCE(created_by::text, ''), created_at, updated_at, resolved_at`,
		id, normalizeAlertSeverity(input.Severity), strings.TrimSpace(input.Type), strings.TrimSpace(input.DedupeKey),
		serviceID, strings.TrimSpace(input.AffectedService), strings.TrimSpace(input.Vector), defaultJSON(input.Evidence),
		strings.TrimSpace(input.RecommendedAction), actorID))
	if err != nil {
		return Alert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Alert{}, err
	}
	if s.metrics != nil {
		s.metrics.alertsCreated.WithLabelValues(boundedMetricValue(alert.Type), alert.Severity).Inc()
	}
	if delivered, err := s.deliverAlert(ctx, alert); err == nil {
		alert = delivered
	} else {
		s.logger.Warn("alert delivery failed", "alert_id", alert.ID, "error", agent.RedactString(err.Error()))
	}
	deliveries, _ := s.ListAlertDeliveries(ctx, alert.ID)
	alert.Deliveries = deliveries
	return alert, nil
}

func validateAlertInput(input AlertInput) error {
	if normalizeAlertSeverity(input.Severity) == "" {
		return errors.New("severity is required")
	}
	if strings.TrimSpace(input.Type) == "" {
		return errors.New("type is required")
	}
	if strings.TrimSpace(input.DedupeKey) == "" {
		return errors.New("dedupe_key is required")
	}
	return nil
}

func normalizeAlertSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info", "warning", "critical":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func (s *Store) ListAlerts(ctx context.Context, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, severity, type, dedupe_key, COALESCE(service_id::text, ''), affected_service,
       vector, evidence, recommended_action, status, COALESCE(created_by::text, ''), created_at, updated_at, resolved_at
FROM alerts
WHERE owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
ORDER BY created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Alert, 0)
	for rows.Next() {
		alert, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, alert)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		deliveries, err := s.ListAlertDeliveries(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Deliveries = deliveries
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) ListAlertDeliveries(ctx context.Context, alertID string) ([]AlertDelivery, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text, alert_id::text, channel, status, attempt, error, response, created_at, sent_at
FROM alert_deliveries
WHERE alert_id=$1
  AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
ORDER BY created_at`, strings.TrimSpace(alertID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AlertDelivery, 0)
	for rows.Next() {
		delivery, err := scanAlertDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) deliverAlert(ctx context.Context, alert Alert) (Alert, error) {
	policy, err := s.alertPolicy(ctx, alert.Type, alert.Severity)
	if err != nil {
		return alert, err
	}
	if !policy.Enabled {
		return s.setAlertStatus(ctx, alert.ID, alertStatusDeduped)
	}
	deduped, err := s.recentAlertSent(ctx, alert, time.Duration(policy.RateLimitSeconds)*time.Second)
	if err != nil {
		return alert, err
	}
	if deduped {
		if _, err := s.recordAlertDelivery(ctx, alert.ID, "telegram", alertStatusDeduped, 0, "dedupe window active", nil); err != nil {
			return alert, err
		}
		return s.setAlertStatus(ctx, alert.ID, alertStatusDeduped)
	}
	cfg, err := s.getAdminTelegramConfigRaw(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			msg := "telegram config is not configured for admin"
			if _, err := s.recordAlertDelivery(ctx, alert.ID, "telegram", alertStatusFailed, 0, msg, nil); err != nil {
				return alert, err
			}
			if s.metrics != nil {
				s.metrics.alertsFailed.WithLabelValues("telegram", "config").Inc()
			}
			return s.setAlertStatus(ctx, alert.ID, alertStatusFailed)
		}
		return alert, err
	}
	token, status := resolveTelegramBotToken(cfg.BotTokenRef)
	if !cfg.Enabled || status != "present" {
		msg := "telegram config is disabled or token is missing"
		if _, err := s.recordAlertDelivery(ctx, alert.ID, "telegram", alertStatusFailed, 0, msg, nil); err != nil {
			return alert, err
		}
		if s.metrics != nil {
			s.metrics.alertsFailed.WithLabelValues("telegram", "config").Inc()
		}
		return s.setAlertStatus(ctx, alert.ID, alertStatusFailed)
	}
	text := renderAlertMessage(alert, policy.Template)
	maxAttempts := policy.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = defaultAlertMaxAttempts
	}
	var lastErr error
	for attempt := uint32(1); attempt <= maxAttempts; attempt++ {
		result, err := s.telegram().SendMessage(ctx, token, cfg.ChatID, cfg.ParseMode, text)
		if err == nil {
			if _, err := s.recordAlertDelivery(ctx, alert.ID, "telegram", alertStatusSent, attempt, "", result.Response); err != nil {
				return alert, err
			}
			if s.metrics != nil {
				s.metrics.alertsSent.WithLabelValues("telegram", alert.Severity).Inc()
			}
			return s.setAlertStatus(ctx, alert.ID, alertStatusSent)
		}
		lastErr = err
		status := alertStatusFailed
		if result.Retryable && attempt < maxAttempts {
			status = alertStatusRetrying
		}
		if _, recErr := s.recordAlertDelivery(ctx, alert.ID, "telegram", status, attempt, agent.RedactString(err.Error()), result.Response); recErr != nil {
			return alert, recErr
		}
		if !result.Retryable || attempt == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return alert, ctx.Err()
		case <-time.After(s.alertRetryDelay(attempt)):
		}
	}
	if s.metrics != nil {
		s.metrics.alertsFailed.WithLabelValues("telegram", boundedMetricValue(errorClass(lastErr))).Inc()
	}
	return s.setAlertStatus(ctx, alert.ID, alertStatusFailed)
}

func (s *Store) telegram() *TelegramClient {
	if s.telegramClient == nil {
		s.telegramClient = NewTelegramClient(s.cfg.TelegramAPIURL, nil)
	}
	return s.telegramClient
}

func (s *Store) alertRetryDelay(attempt uint32) time.Duration {
	base := s.alertRetryBase
	if base <= 0 {
		base = time.Second
	}
	return base * time.Duration(1<<(attempt-1))
}

func (s *Store) alertPolicy(ctx context.Context, alertType, severity string) (alertPolicy, error) {
	policy := alertPolicy{RateLimitSeconds: defaultAlertRateLimitSeconds, MaxAttempts: defaultAlertMaxAttempts, Enabled: true}
	tx, err := s.beginUnscopedTx(ctx)
	if err != nil {
		return policy, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `SELECT ap.rate_limit_seconds, ap.max_attempts, ap.template, ap.enabled
FROM alert_policies ap
JOIN app_users u ON u.id = ap.owner_user_id
WHERE ap.alert_type=$1 AND ap.severity=$2 AND ap.channel='telegram'
  AND u.role = 'admin' AND u.status = 'active'
LIMIT 1`, alertType, severity).Scan(&policy.RateLimitSeconds, &policy.MaxAttempts, &policy.Template, &policy.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return policy, nil
	}
	if err != nil {
		return policy, err
	}
	return policy, tx.Commit(ctx)
}

func (s *Store) recentAlertSent(ctx context.Context, alert Alert, window time.Duration) (bool, error) {
	if window <= 0 {
		return false, nil
	}
	var exists bool
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1
    FROM alerts a
    JOIN alert_deliveries d ON d.alert_id = a.id
    WHERE a.id <> $1
      AND a.dedupe_key = $2
      AND a.owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
      AND d.owner_user_id = a.owner_user_id
      AND d.status = 'sent'
      AND d.created_at >= now() - ($3::text)::interval
)`, alert.ID, alert.DedupeKey, fmt.Sprintf("%d seconds", int(window.Seconds()))).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, tx.Commit(ctx)
}

func (s *Store) RecentAlertExists(ctx context.Context, dedupeKey string, window time.Duration) bool {
	if strings.TrimSpace(dedupeKey) == "" || window <= 0 {
		return false
	}
	var exists bool
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return false
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1 FROM alerts
    WHERE dedupe_key=$1
      AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
      AND created_at >= now() - ($2::text)::interval
)`, strings.TrimSpace(dedupeKey), fmt.Sprintf("%d seconds", int(window.Seconds()))).Scan(&exists)
	return err == nil && exists
}

func (s *Store) setAlertStatus(ctx context.Context, id, status string) (Alert, error) {
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback(ctx)
	alert, err := scanAlert(tx.QueryRow(ctx, `UPDATE alerts SET status=$2, updated_at=now()
WHERE id=$1 AND owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
RETURNING id::text, severity, type, dedupe_key, COALESCE(service_id::text, ''), affected_service, vector,
          evidence, recommended_action, status, COALESCE(created_by::text, ''), created_at, updated_at, resolved_at`, id, status))
	if err != nil {
		return Alert{}, err
	}
	return alert, tx.Commit(ctx)
}

func (s *Store) recordAlertDelivery(ctx context.Context, alertID, channel, status string, attempt uint32, errText string, response json.RawMessage) (AlertDelivery, error) {
	id, err := newUUID()
	if err != nil {
		return AlertDelivery{}, err
	}
	var sentAt any
	if status == alertStatusSent {
		sentAt = time.Now().UTC()
	}
	tx, err := s.beginContextOwnerTx(ctx)
	if err != nil {
		return AlertDelivery{}, err
	}
	defer tx.Rollback(ctx)
	delivery, err := scanAlertDelivery(tx.QueryRow(ctx, `INSERT INTO alert_deliveries(id, owner_user_id, alert_id, channel, status, attempt, error, response, sent_at)
VALUES ($1, NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid, $2,$3,$4,$5,$6,$7,$8)
RETURNING id::text, alert_id::text, channel, status, attempt, error, response, created_at, sent_at`,
		id, alertID, channel, status, attempt, errText, defaultJSON(response), sentAt))
	if err != nil {
		return AlertDelivery{}, err
	}
	return delivery, tx.Commit(ctx)
}

func scanAlert(row rowScanner) (Alert, error) {
	var alert Alert
	if err := row.Scan(
		&alert.ID,
		&alert.Severity,
		&alert.Type,
		&alert.DedupeKey,
		&alert.ServiceID,
		&alert.AffectedService,
		&alert.Vector,
		&alert.Evidence,
		&alert.RecommendedAction,
		&alert.Status,
		&alert.CreatedBy,
		&alert.CreatedAt,
		&alert.UpdatedAt,
		&alert.ResolvedAt,
	); err != nil {
		return Alert{}, err
	}
	return alert, nil
}

func scanAlertDelivery(row rowScanner) (AlertDelivery, error) {
	var delivery AlertDelivery
	if err := row.Scan(
		&delivery.ID,
		&delivery.AlertID,
		&delivery.Channel,
		&delivery.Status,
		&delivery.Attempt,
		&delivery.Error,
		&delivery.Response,
		&delivery.CreatedAt,
		&delivery.SentAt,
	); err != nil {
		return AlertDelivery{}, err
	}
	return delivery, nil
}

func renderAlertMessage(alert Alert, template string) string {
	if strings.TrimSpace(template) != "" {
		return trimTelegramMessage(strings.NewReplacer(
			"{{severity}}", strings.ToUpper(alert.Severity),
			"{{type}}", alert.Type,
			"{{affected_service}}", alert.AffectedService,
			"{{vector}}", alert.Vector,
			"{{recommended_action}}", alert.RecommendedAction,
		).Replace(template))
	}
	lines := []string{
		fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Type),
		"dedupe: " + alert.DedupeKey,
	}
	if alert.AffectedService != "" {
		lines = append(lines, "service: "+alert.AffectedService)
	}
	if alert.Vector != "" {
		lines = append(lines, "vector: "+alert.Vector)
	}
	if alert.RecommendedAction != "" {
		lines = append(lines, "action: "+alert.RecommendedAction)
	}
	if len(alert.Evidence) > 0 && string(alert.Evidence) != "{}" {
		lines = append(lines, "evidence: "+string(alert.Evidence))
	}
	return trimTelegramMessage(strings.Join(lines, "\n"))
}

func errorClass(err error) string {
	if err == nil {
		return "unknown"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "429"):
		return "rate_limited"
	case strings.Contains(text, "timeout"), strings.Contains(text, "deadline"):
		return "timeout"
	case strings.Contains(text, "status 5"):
		return "server"
	case strings.Contains(text, "status 4"):
		return "client"
	default:
		return "error"
	}
}

func (s *Store) EvaluateISPEscalation(ctx context.Context, actor *Actor, input ISPEscalationInput) (Alert, error) {
	if err := requireAdmin(actor); err != nil {
		return Alert{}, err
	}
	payload, err := s.buildISPEscalationPayload(ctx, input)
	if err != nil {
		return Alert{}, err
	}
	raw := mustJSON(payload)
	return s.createAlert(ctx, actor, AlertInput{
		Severity:          "critical",
		Type:              "isp_escalation_needed",
		DedupeKey:         "isp:" + strings.TrimSpace(payload["target"].(string)) + ":" + strings.TrimSpace(payload["vector"].(string)),
		ServiceID:         strings.TrimSpace(input.ServiceID),
		AffectedService:   strings.TrimSpace(payload["affected_service"].(string)),
		Vector:            strings.TrimSpace(payload["vector"].(string)),
		Evidence:          raw,
		RecommendedAction: "manual ISP escalation; no automatic BGP/RTBH/FlowSpec",
	})
}

func (s *Store) buildISPEscalationPayload(ctx context.Context, input ISPEscalationInput) (map[string]any, error) {
	target := strings.TrimSpace(input.Target)
	affected := target
	if strings.TrimSpace(input.ServiceID) != "" {
		service, err := s.getService(ctx, s.pool, input.ServiceID)
		if err != nil {
			return nil, err
		}
		affected = service.Name
		if target == "" {
			target = service.BackendCIDR
		}
	}
	if target == "" {
		return nil, errors.New("target or service_id is required")
	}
	vector := strings.TrimSpace(input.Vector)
	if vector == "" {
		vector = "link_saturation"
	}
	start := input.StartTime
	if start.IsZero() {
		start = time.Now().UTC()
	}
	top, err := s.SecurityEventSummary(ctx, SecurityEventQuery{Since: time.Now().Add(-5 * time.Minute), Until: time.Now(), Limit: 10})
	if err != nil {
		return nil, err
	}
	evidence := map[string]any{}
	_ = json.Unmarshal(defaultJSON(input.Evidence), &evidence)
	return map[string]any{
		"manual_only":       true,
		"runbook":           "manual ISP escalation; do not automate BGP/RTBH/FlowSpec in MVP",
		"target":            target,
		"affected_service":  affected,
		"vector":            vector,
		"start_time":        start.UTC().Format(time.RFC3339),
		"peak_bps":          input.PeakBPS,
		"peak_pps":          input.PeakPPS,
		"packet_loss_ratio": input.PacketLossRatio,
		"route_failure":     strings.TrimSpace(input.RouteFailure),
		"top_sources":       top.TopSources,
		"operator_payload":  evidence,
		"checklist": []string{
			"Confirm local XDP/drop/redirect counters and service impact",
			"Capture peak bps/pps, start time, vector and target",
			"Send payload to ISP NOC through approved manual channel",
			"Track ISP ticket and update incident timeline",
		},
	}, nil
}

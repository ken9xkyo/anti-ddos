package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTelegramClientSendMessageClassifiesResponses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		retryable bool
		wantErr   bool
	}{
		{name: "success", status: http.StatusOK, body: `{"ok":true}`},
		{name: "rate limit", status: http.StatusTooManyRequests, body: `{"ok":false}`, retryable: true, wantErr: true},
		{name: "server error", status: http.StatusBadGateway, body: `bad gateway`, retryable: true, wantErr: true},
		{name: "malformed", status: http.StatusOK, body: `not-json`, retryable: true, wantErr: true},
		{name: "auth failure", status: http.StatusUnauthorized, body: `{"ok":false}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			result, err := NewTelegramClient(server.URL, server.Client()).SendMessage(context.Background(), "token", "chat", "", "hello")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if result.Retryable != tt.retryable {
				t.Fatalf("retryable=%v want=%v", result.Retryable, tt.retryable)
			}
			if !json.Valid(defaultJSON(result.Response)) {
				t.Fatalf("response must be valid json: %s", result.Response)
			}
		})
	}
}

func TestAlertHelpers(t *testing.T) {
	input := AlertInput{Severity: "CRITICAL", Type: "isp_escalation_needed", DedupeKey: "k"}
	if err := validateAlertInput(input); err != nil {
		t.Fatal(err)
	}
	msg := renderAlertMessage(Alert{
		Severity:          "critical",
		Type:              "isp_escalation_needed",
		DedupeKey:         "k",
		AffectedService:   "api",
		Vector:            "udp_flood",
		RecommendedAction: "manual escalation",
		Evidence:          json.RawMessage(`{"peak_bps":1000}`),
	}, "")
	for _, want := range []string{"CRITICAL", "isp_escalation_needed", "api", "udp_flood", "manual escalation"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q missing %q", msg, want)
		}
	}
	if got := trimTelegramMessage(strings.Repeat("x", maxTelegramMessageBytes+100)); len(got) > maxTelegramMessageBytes {
		t.Fatalf("telegram trim failed len=%d", len(got))
	}
	store := &Store{alertRetryBase: time.Millisecond}
	if got := store.alertRetryDelay(3); got != 4*time.Millisecond {
		t.Fatalf("backoff=%s", got)
	}
}

func TestTelegramTokenResolutionAndMasking(t *testing.T) {
	rawToken := "123456:abcdefghijklmnopqrstuvwxyzABCDEF"
	token, status := resolveTelegramBotToken(rawToken)
	if token != rawToken || status != "present" {
		t.Fatalf("raw token resolution token=%q status=%q", token, status)
	}
	token, status = resolveTelegramBotToken(telegramTokenMask)
	if token != "" || status != "masked" {
		t.Fatalf("masked token should not resolve token=%q status=%q", token, status)
	}
	t.Setenv("TELEGRAM_LEGACY_TOKEN", rawToken)
	token, status = resolveTelegramBotToken("env://TELEGRAM_LEGACY_TOKEN")
	if token != rawToken || status != "present" {
		t.Fatalf("legacy ref resolution token=%q status=%q", token, status)
	}
	cfg := maskTelegramConfig(TelegramConfig{BotTokenRef: rawToken, BotTokenPresent: true})
	if cfg.BotTokenRef != telegramTokenMask || !cfg.BotTokenPresent {
		t.Fatalf("token not masked: %#v", cfg)
	}
}

func TestAlertingIntegration(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	var mode atomic.Value
	mode.Store("success")
	var calls atomic.Int32
	var retryCalls atomic.Int32
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch mode.Load().(string) {
		case "retry":
			if retryCalls.Add(1) < 3 {
				http.Error(w, "temporary", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "auth":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		default:
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		}
	}))
	defer telegram.Close()
	telegramToken := "123456:abcdefghijklmnopqrstuvwxyzABCDEF"

	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret", TelegramAPIURL: telegram.URL, EventSampleDenom: 1, AgentStaleAfter: time.Minute}
	store := NewStore(pool, cfg, nil)
	store.alertRetryBase = time.Millisecond
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	owner, err := store.CreateUser(ctx, adminActor, "user", "user password phrase", RoleUser, "create user")
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx := contextWithOwner(ctx, owner.ID)
	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	userToken := login(t, server.URL, "user", "user password phrase")

	// Regular user must get 403 Forbidden when accessing Telegram config/test
	resp := authedJSON(t, http.MethodGet, server.URL+"/v1/telegram/config", userToken, nil)
	requireHTTPStatus(t, resp, http.StatusForbidden)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", userToken, TelegramConfigInput{
		Reason:      "user configures Telegram",
		BotTokenRef: telegramToken,
		ChatID:      "1234",
		Enabled:     boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/test", userToken, map[string]string{"reason": "user test"})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	// Admin must succeed in configuring Telegram
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", adminToken, TelegramConfigInput{
		Reason:      "admin configures Telegram",
		BotTokenRef: telegramToken,
		ChatID:      "1234",
		Enabled:     boolPtr(true),
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("admin Telegram config status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"bot_token_ref":"*****"`) || strings.Contains(resp.Body.String(), "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("admin Telegram config masking failed: %s", resp.Body.String())
	}

	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/telegram/config", adminToken, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("admin get Telegram config status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", adminToken, TelegramConfigInput{
		Reason:      "keep Telegram token",
		BotTokenRef: "*****",
		ChatID:      "1234",
		Enabled:     boolPtr(true),
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("keep Telegram token status=%d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("telegram token leaked in masked config response: %s", resp.Body.String())
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/test", adminToken, map[string]string{"reason": "admin test"})
	if resp.Code != http.StatusOK {
		t.Fatalf("test alert status=%d body=%s", resp.Code, resp.Body.String())
	}
	var testAlert Alert
	if err := json.Unmarshal(resp.Body.Bytes(), &testAlert); err != nil {
		t.Fatal(err)
	}
	if testAlert.Status != alertStatusSent || len(testAlert.Deliveries) == 0 || testAlert.Deliveries[0].Status != alertStatusSent {
		t.Fatalf("test alert not sent: %#v", testAlert)
	}

	// Create a viewing/read-only session for the admin
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/admin/view-user", adminToken, AdminViewUserInput{UserID: owner.ID})
	requireHTTPStatus(t, resp, http.StatusOK)
	var viewSession Session
	decodeTestBody(t, resp, &viewSession)
	readOnlyToken := viewSession.Token

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/test", readOnlyToken, map[string]string{"reason": "read-only"})
	if resp.Code != http.StatusForbidden && resp.Code != http.StatusBadRequest {
		t.Fatalf("read-only test alert should fail status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", userToken, AlertInput{
		Severity:          "warning",
		Type:              "operator_notice",
		DedupeKey:         "manual:dedupe",
		AffectedService:   "api",
		Vector:            "udp_flood",
		Evidence:          json.RawMessage(`{"pps":1000}`),
		RecommendedAction: "investigate",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("create alert status=%d body=%s", resp.Code, resp.Body.String())
	}
	before := calls.Load()
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", userToken, AlertInput{
		Severity:          "warning",
		Type:              "operator_notice",
		DedupeKey:         "manual:dedupe",
		AffectedService:   "api",
		Vector:            "udp_flood",
		RecommendedAction: "investigate",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("create duplicate alert status=%d body=%s", resp.Code, resp.Body.String())
	}
	var dup Alert
	if err := json.Unmarshal(resp.Body.Bytes(), &dup); err != nil {
		t.Fatal(err)
	}
	if dup.Status != alertStatusDeduped || calls.Load() != before {
		t.Fatalf("duplicate should be deduped without Telegram call alert=%#v before=%d after=%d", dup, before, calls.Load())
	}

	mode.Store("retry")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", userToken, AlertInput{
		Severity:          "critical",
		Type:              "redirect_failure",
		DedupeKey:         "retry:redirect",
		AffectedService:   "node-a",
		Vector:            "devmap",
		RecommendedAction: "inspect forwarding",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("retry alert status=%d body=%s", resp.Code, resp.Body.String())
	}
	var retry Alert
	if err := json.Unmarshal(resp.Body.Bytes(), &retry); err != nil {
		t.Fatal(err)
	}
	if retry.Status != alertStatusSent || len(retry.Deliveries) != 3 {
		t.Fatalf("retry alert expected two retries and sent: %#v", retry)
	}

	mode.Store("auth")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", userToken, AlertInput{
		Severity:        "critical",
		Type:            "neighbor_unresolved",
		DedupeKey:       "auth:neighbor",
		AffectedService: "node-a",
		Vector:          "neighbor",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("auth alert status=%d body=%s", resp.Code, resp.Body.String())
	}
	var failed Alert
	if err := json.Unmarshal(resp.Body.Bytes(), &failed); err != nil {
		t.Fatal(err)
	}
	if failed.Status != alertStatusFailed || len(failed.Deliveries) != 1 {
		t.Fatalf("auth failure should not retry: %#v", failed)
	}
	mode.Store("success")

	feedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "feed unavailable", http.StatusInternalServerError)
	}))
	defer feedServer.Close()
	source, err := store.CreateFeedSource(ctx, adminActor, FeedSourceInput{
		Reason:          "create failing feed",
		Name:            "alerting-failing-feed",
		Type:            "internal_json",
		URL:             feedServer.URL,
		Enabled:         boolPtr(true),
		IntervalSeconds: 3600,
	}, "create failing feed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SyncFeedSource(ctx, source.ID, adminActor, "trigger feed failure"); err == nil {
		t.Fatal("expected feed sync failure")
	}
	agentResp, err := store.RegisterAgent(ownerCtx, AgentRegisterRequest{Hostname: "node-a", XDPMode: "native", DevmapSupport: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAgentApply(ownerCtx, agentResp.AgentID, AgentApplyRequest{PolicyVersion: 1, Status: "failed", ErrorStage: "neighbor", ErrorReason: "neighbor unresolved"}); err != nil {
		t.Fatal(err)
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts/evaluate-isp-escalation", userToken, ISPEscalationInput{
		Reason:          "manual escalation fixture",
		Target:          "203.0.113.10/32",
		Vector:          "udp_flood",
		PeakBPS:         3_000_000_000,
		PeakPPS:         300_000,
		PacketLossRatio: 0.25,
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("isp escalation status=%d body=%s", resp.Code, resp.Body.String())
	}
	var isp Alert
	if err := json.Unmarshal(resp.Body.Bytes(), &isp); err != nil {
		t.Fatal(err)
	}
	if isp.Type != "isp_escalation_needed" || !strings.Contains(string(isp.Evidence), "manual_only") || !strings.Contains(isp.RecommendedAction, "no automatic") {
		t.Fatalf("bad isp alert: %#v", isp)
	}

	seen := map[string]bool{}
	alerts, err := store.ListAlerts(ownerCtx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, alert := range alerts {
		seen[alert.Type] = true
	}
	adminCtx := contextWithOwner(ctx, admin.ID)
	adminAlerts, err := store.ListAlerts(adminCtx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, alert := range adminAlerts {
		seen[alert.Type] = true
	}
	for _, typ := range []string{"test_alert", "operator_notice", "feed_failure", "neighbor_unresolved", "isp_escalation_needed"} {
		if !seen[typ] {
			t.Fatalf("missing alert type %s in %#v", typ, seen)
		}
	}
	audits, err := store.ListAuditEvents(ownerCtx, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if strings.Contains(string(audit.After), "abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("telegram token leaked in audit: %#v", audit)
		}
	}
}

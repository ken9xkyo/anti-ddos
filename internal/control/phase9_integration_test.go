package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPhase09TelegramAlertingIntegration(t *testing.T) {
	dsn := os.Getenv("ANTI_DDOS_CONTROL_TEST_DSN")
	if dsn == "" {
		t.Skip("ANTI_DDOS_CONTROL_TEST_DSN is not set")
	}
	ctx := context.Background()
	pool, err := OpenPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("idempotent migration run: %v", err)
	}

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
	t.Setenv("PHASE9_TELEGRAM_TOKEN", "123456:abcdefghijklmnopqrstuvwxyzABCDEF")

	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret", TelegramAPIURL: telegram.URL, EventSampleDenom: 1, AgentStaleAfter: time.Minute}
	store := NewStore(pool, cfg, nil)
	store.alertRetryBase = time.Millisecond
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	if _, err := store.CreateUser(ctx, adminActor, "viewer", "viewer password phrase", RoleViewer, "create viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(ctx, adminActor, "operator", "operator password phrase", RoleOperator, "create operator"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	viewerToken := login(t, server.URL, "viewer", "viewer password phrase")
	operatorToken := login(t, server.URL, "operator", "operator password phrase")

	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", operatorToken, TelegramConfigInput{
		Reason:      "operator should not set token",
		BotTokenRef: "env://PHASE9_TELEGRAM_TOKEN",
		ChatID:      "1234",
		Enabled:     boolPtr(true),
	})
	if resp.Code != http.StatusForbidden && resp.Code != http.StatusBadRequest {
		t.Fatalf("operator token config should fail status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", adminToken, TelegramConfigInput{
		Reason:      "configure Telegram",
		BotTokenRef: "env://PHASE9_TELEGRAM_TOKEN",
		ChatID:      "1234",
		Enabled:     boolPtr(true),
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("configure Telegram status=%d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("telegram token leaked in config response: %s", resp.Body.String())
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/test", viewerToken, map[string]string{"reason": "viewer"})
	if resp.Code != http.StatusForbidden && resp.Code != http.StatusBadRequest {
		t.Fatalf("viewer test alert should fail status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/test", operatorToken, map[string]string{"reason": "operator test"})
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

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", operatorToken, AlertInput{
		Severity:          "warning",
		Type:              "anomaly",
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
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", operatorToken, AlertInput{
		Severity:          "warning",
		Type:              "anomaly",
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
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", operatorToken, AlertInput{
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
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts", operatorToken, AlertInput{
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
		Name:            "phase9-failing-feed",
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
	agentResp, err := store.RegisterAgent(ctx, AgentRegisterRequest{Hostname: "node-a", XDPMode: "native", DevmapSupport: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAgentApply(ctx, agentResp.AgentID, AgentApplyRequest{PolicyVersion: 1, Status: "failed", ErrorStage: "neighbor", ErrorReason: "neighbor unresolved"}); err != nil {
		t.Fatal(err)
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts/evaluate-isp-escalation", operatorToken, ISPEscalationInput{
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

	alerts, err := store.ListAlerts(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, alert := range alerts {
		seen[alert.Type] = true
	}
	for _, typ := range []string{"test_alert", "anomaly", "feed_failure", "neighbor_unresolved", "isp_escalation_needed"} {
		if !seen[typ] {
			t.Fatalf("missing alert type %s in %#v", typ, seen)
		}
	}
	audits, err := store.ListAuditEvents(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if strings.Contains(string(audit.After), "abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("telegram token leaked in audit: %#v", audit)
		}
	}
}

package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdminDashboardCoverageIntegration(t *testing.T) {
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

	var queryMu sync.Mutex
	var queries []string
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		queryMu.Lock()
		queries = append(queries, query)
		queryMu.Unlock()
		value := "300000"
		switch {
		case strings.Contains(query, "xdp_bytes"):
			value = "3000000000"
		case strings.Contains(query, `tcp_syn="1"`):
			value = "30000"
		case strings.Contains(query, `action="1"`):
			value = "30000"
		case strings.Contains(query, "anti_ddos_redirected_packets_total"):
			value = "5"
		case strings.Contains(query, "anti_ddos_not_allowed_service_total"):
			value = "3"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result": []any{map[string]any{
					"value": []any{float64(1), value},
				}},
			},
		})
	}))
	defer prom.Close()

	var telegramCalls atomic.Int32
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		telegramCalls.Add(1)
		if !strings.Contains(r.URL.Path, "/sendMessage") {
			t.Fatalf("unexpected telegram path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer telegram.Close()
	t.Setenv("ADMIN_DASHBOARD_TELEGRAM_TOKEN", "123456:abcdefghijklmnopqrstuvwxyzABCDEF")

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{"cidr": "192.0.2.0/25", "score": 95, "action": "drop", "ttl_seconds": 3600, "reason": "whitelist conflict fixture"},
				{"cidr": "198.51.100.128/25", "score": 90, "action": "drop", "ttl_seconds": 3600, "reason": "dashboard fixture"},
				{"cidr": "2001:db8::/32", "score": 80, "action": "drop"},
			},
		})
	}))
	defer feed.Close()

	cfg := Config{
		Addr:             "127.0.0.1:0",
		DBDSN:            dsn,
		SessionTTL:       time.Hour,
		XDPObject:        "missing-ok.o",
		AgentSharedToken: "agent-secret",
		AgentStaleAfter:  time.Minute,
		PrometheusURL:    prom.URL,
		TelegramAPIURL:   telegram.URL,
		EventSampleDenom: 10,
	}
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

	requireEmptyDashboardArrays(t, server.URL, viewerToken)

	service := createDashboardService(t, server.URL, adminToken)
	baseline := createDashboardBaseline(t, server.URL, adminToken, service.ID)
	rule := createDashboardRule(t, server.URL, adminToken, service.ID)
	agentID := registerDashboardAgent(t, server.URL)
	ingestDashboardEvent(t, server.URL, agentID, service.EBPFID, rule.EBPFID)

	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/whitelist", adminToken, WhitelistInput{
		Reason: "trusted customer source for feed conflict",
		CIDR:   "192.0.2.10/32",
		Scope:  "global",
		Owner:  "sre",
	})
	requireHTTPStatus(t, resp, http.StatusOK)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources", adminToken, FeedSourceInput{
		Reason:                "configure dashboard feed",
		Name:                  "dashboard-internal-feed",
		Type:                  "internal_json",
		URL:                   feed.URL,
		RequiredForProduction: true,
		Enabled:               boolPtr(true),
		IntervalSeconds:       3600,
		LicenseNote:           "fixture",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var source FeedSource
	decodeTestBody(t, resp, &source)

	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/feed-sources/"+source.ID, operatorToken, FeedSourceInput{
		Reason:          "operator cannot change credential",
		Name:            source.Name,
		Type:            source.Type,
		URL:             source.URL,
		CredentialRef:   "env://ADMIN_DASHBOARD_FEED_TOKEN",
		Enabled:         boolPtr(true),
		IntervalSeconds: source.IntervalSeconds,
	})
	requireHTTPStatusOneOf(t, resp, http.StatusForbidden, http.StatusBadRequest)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources/"+source.ID+"/sync", viewerToken, map[string]string{"reason": "viewer sync denied"})
	requireHTTPStatusOneOf(t, resp, http.StatusForbidden, http.StatusBadRequest)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources/"+source.ID+"/sync", operatorToken, map[string]string{"reason": "operator feed sync"})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"parse_errors":1`)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", operatorToken, TelegramConfigInput{
		Reason:      "operator token change denied",
		BotTokenRef: "env://ADMIN_DASHBOARD_TELEGRAM_TOKEN",
		ChatID:      "1234",
		Enabled:     boolPtr(true),
	})
	requireHTTPStatusOneOf(t, resp, http.StatusForbidden, http.StatusBadRequest)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", adminToken, TelegramConfigInput{
		Reason:      "configure dashboard Telegram",
		BotTokenRef: "env://ADMIN_DASHBOARD_TELEGRAM_TOKEN",
		ChatID:      "1234",
		Enabled:     boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	if strings.Contains(resp.Body.String(), "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("telegram token leaked in config response: %s", resp.Body.String())
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/test", viewerToken, map[string]string{"reason": "viewer denied"})
	requireHTTPStatusOneOf(t, resp, http.StatusForbidden, http.StatusBadRequest)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/test", operatorToken, map[string]string{"reason": "operator dashboard test"})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"type":"test_alert"`)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/anomalies/evaluate", operatorToken, map[string]string{"reason": "dashboard anomaly evaluation"})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"auto_enforced":true`)
	assertObservedQuery(t, &queryMu, &queries, `service_id="`+uint32String(service.EBPFID)+`"`)
	assertObservedQuery(t, &queryMu, &queries, `tcp_syn="1"`)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/alerts/evaluate-isp-escalation", operatorToken, ISPEscalationInput{
		Reason:          "dashboard ISP runbook",
		ServiceID:       service.ID,
		Vector:          "udp_flood",
		PeakBPS:         8_000_000,
		PeakPPS:         1000,
		PacketLossRatio: 0.15,
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"manual_only":true`)
	requireBodyContains(t, resp, "no automatic")

	version, err := store.LatestPolicyVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp = agentJSON(t, http.MethodPost, server.URL+"/v1/agents/"+agentID+"/apply", "agent-secret", AgentApplyRequest{
		PolicyVersion: version,
		Status:        "applied",
		MapStats:      json.RawMessage(`{"service_allowlist":{"entries":1},"rule_config":{"entries":2}}`),
		DevmapStats:   json.RawMessage(`{"updated":1}`),
	})
	requireHTTPStatus(t, resp, http.StatusOK)

	readCases := []struct {
		name string
		path string
		want string
	}{
		{"overview", "/v1/dashboard/overview", `"configured":true`},
		{"agents", "/v1/dashboard/agents", "node-a"},
		{"services", "/v1/dashboard/services", "api-https"},
		{"rules", "/v1/dashboard/rules", "dashboard-ttl-rule"},
		{"events", "/v1/security-events?src=198.51.100.10", "198.51.100.10"},
		{"summary", "/v1/security-events/summary", `"total":1`},
		{"investigate", "/v1/security-events/investigate?target=198.51.100.10&limit=10", "198.51.100.10"},
		{"baselines", "/v1/baselines", baseline.ID},
		{"anomalies", "/v1/anomalies?limit=10", `"auto_enforced":true`},
		{"feed sources", "/v1/feed-sources", "dashboard-internal-feed"},
		{"feed runs", "/v1/feed-runs?limit=10", `"status":"success"`},
		{"feed conflicts", "/v1/feed-conflicts", "192.0.2.0/25"},
		{"telegram config", "/v1/telegram/config", `"bot_token_present":true`},
		{"alerts", "/v1/alerts?limit=20", "isp_escalation_needed"},
	}
	for _, tc := range readCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := authedJSON(t, http.MethodGet, server.URL+tc.path, viewerToken, nil)
			requireHTTPStatus(t, resp, http.StatusOK)
			requireBodyContains(t, resp, tc.want)
		})
	}

	overview, err := store.BuildDashboardOverview(ctx, NewPrometheusClient("", nil), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if overview.Prometheus.Configured || overview.Prometheus.Healthy || overview.Prometheus.Error == "" {
		t.Fatalf("expected unconfigured prometheus status, got %#v", overview.Prometheus)
	}
	badProm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "prometheus unavailable", http.StatusInternalServerError)
	}))
	defer badProm.Close()
	overview, err = store.BuildDashboardOverview(ctx, NewPrometheusClient(badProm.URL, nil), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !overview.Prometheus.Configured || overview.Prometheus.Healthy || !strings.Contains(overview.Prometheus.Error, "status 500") {
		t.Fatalf("expected unhealthy prometheus status, got %#v", overview.Prometheus)
	}

	metricsResp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metricsBody, _ := io.ReadAll(metricsResp.Body)
	_ = metricsResp.Body.Close()
	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", metricsResp.StatusCode, string(metricsBody))
	}
	metricsText := string(metricsBody)
	for _, forbidden := range []string{"src_ip", "198.51.100.10", "abcdefghijklmnopqrstuvwxyz", "viewer password"} {
		if strings.Contains(metricsText, forbidden) {
			t.Fatalf("sensitive or high-cardinality metrics label leaked %q in %s", forbidden, metricsText)
		}
	}
	if telegramCalls.Load() == 0 {
		t.Fatal("expected dashboard alert actions to send Telegram messages")
	}
	audits, err := store.ListAuditEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if strings.Contains(string(audit.After), "abcdefghijklmnopqrstuvwxyz") || strings.Contains(string(audit.Before), "abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("telegram token leaked in audit: %#v", audit)
		}
	}
}

func createDashboardService(t *testing.T, baseURL, token string) Service {
	t.Helper()
	resp := authedJSON(t, http.MethodPost, baseURL+"/v1/services", token, ServiceInput{
		Reason:                   "publish dashboard service",
		Name:                     "api-https",
		BackendCIDR:              "203.0.113.10/32",
		Protocol:                 "tcp",
		AllowedPorts:             []uint16{443},
		OutputInterface:          "backend0",
		Owner:                    "sre",
		Criticality:              "high",
		ProtectionMode:           "enforce",
		ResolvedIfindex:          7,
		ResolvedNextHopMAC:       "02:00:00:00:00:02",
		ResolvedSourceMAC:        "02:00:00:00:00:01",
		NeighborResolutionStatus: "resolved",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var service Service
	decodeTestBody(t, resp, &service)
	return service
}

func createDashboardBaseline(t *testing.T, baseURL, token, serviceID string) BaselineProfile {
	t.Helper()
	resp := authedJSON(t, http.MethodPost, baseURL+"/v1/baselines", token, BaselineProfileInput{
		Reason:       "create dashboard baseline",
		ServiceID:    serviceID,
		Interface:    "wan0",
		Protocol:     "tcp",
		Port:         443,
		Window:       "5m",
		ExpectedPPS:  100,
		ExpectedBPS:  10000,
		ExpectedCPS:  10,
		HistoryHours: 24,
		Confidence:   0.95,
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var baseline BaselineProfile
	decodeTestBody(t, resp, &baseline)
	resp = authedJSON(t, http.MethodPost, baseURL+"/v1/baselines/"+baseline.ID+"/approve", token, map[string]string{"reason": "approve dashboard baseline"})
	requireHTTPStatus(t, resp, http.StatusOK)
	return baseline
}

func createDashboardRule(t *testing.T, baseURL, token, serviceID string) Rule {
	t.Helper()
	resp := authedJSON(t, http.MethodPost, baseURL+"/v1/rules", token, RuleInput{
		Reason:       "create dashboard TTL rule",
		ServiceID:    serviceID,
		Name:         "dashboard-ttl-rule",
		Action:       "observe",
		Mode:         "observe",
		Dimension:    "source_service",
		ThresholdPPS: 500,
		ThresholdBPS: 500000,
		ThresholdCPS: 50,
		TTLSeconds:   900,
		BurstPackets: 1,
		Confidence:   0.8,
		Owner:        "soc",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var rule Rule
	decodeTestBody(t, resp, &rule)
	return rule
}

func registerDashboardAgent(t *testing.T, baseURL string) string {
	t.Helper()
	resp := agentJSON(t, http.MethodPost, baseURL+"/v1/agents/register", "agent-secret", AgentRegisterRequest{
		Hostname:      "node-a",
		XDPMode:       "native",
		DevmapSupport: true,
		Interfaces: []AgentInterface{{
			Name:         "wan0",
			Ifindex:      7,
			MAC:          "02:00:00:00:00:01",
			Role:         "wan",
			LinkSpeedBPS: 10_000_000_000,
		}},
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var reg AgentRegisterResponse
	decodeTestBody(t, resp, &reg)
	resp = agentJSON(t, http.MethodPost, baseURL+"/v1/agents/"+reg.AgentID+"/heartbeat", "agent-secret", AgentHeartbeatRequest{
		Status:              "online",
		ActivePolicyVersion: 1,
		XDPMode:             "native",
		MapUtilization:      json.RawMessage(`{"service_allowlist":{"entries":1,"capacity":16384}}`),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	return reg.AgentID
}

func ingestDashboardEvent(t *testing.T, baseURL, agentID string, serviceID, ruleID uint32) {
	t.Helper()
	resp := agentJSON(t, http.MethodPost, baseURL+"/v1/agents/"+agentID+"/events", "agent-secret", SecurityEventBatch{Events: []SecurityEventInput{{
		EventTime:     time.Now().UTC(),
		PolicyVersion: 1,
		SrcIP:         "198.51.100.10",
		DstIP:         "203.0.113.10",
		SrcPort:       12345,
		DstPort:       443,
		Protocol:      6,
		TCPFlags:      2,
		Action:        uint8(ActionDrop),
		Reason:        5,
		ServiceID:     serviceID,
		RuleID:        ruleID,
		PktLen:        60,
		SampleRate:    10,
	}}})
	requireHTTPStatus(t, resp, http.StatusOK)
}

func requireHTTPStatus(t *testing.T, resp *testHTTPResponse, want int) {
	t.Helper()
	if resp.Code != want {
		t.Fatalf("status=%d want=%d body=%s", resp.Code, want, resp.Body.String())
	}
}

func requireHTTPStatusOneOf(t *testing.T, resp *testHTTPResponse, wants ...int) {
	t.Helper()
	for _, want := range wants {
		if resp.Code == want {
			return
		}
	}
	t.Fatalf("status=%d want one of %v body=%s", resp.Code, wants, resp.Body.String())
}

func requireBodyContains(t *testing.T, resp *testHTTPResponse, want string) {
	t.Helper()
	if !strings.Contains(resp.Body.String(), want) {
		t.Fatalf("response body missing %q: %s", want, resp.Body.String())
	}
}

func requireEmptyDashboardArrays(t *testing.T, baseURL, token string) {
	t.Helper()
	resp := authedJSON(t, http.MethodGet, baseURL+"/v1/dashboard/overview", token, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	for _, want := range []string{`"top_sources":[]`, `"top_ports":[]`, `"by_decision":[]`, `"latest_apply_status":[]`} {
		requireBodyContains(t, resp, want)
	}

	for _, path := range []string{
		"/v1/dashboard/agents",
		"/v1/dashboard/services",
		"/v1/dashboard/rules",
		"/v1/security-events?limit=50",
		"/v1/baselines",
		"/v1/anomalies?limit=30",
		"/v1/feed-sources",
		"/v1/feed-runs?limit=20",
		"/v1/feed-conflicts",
		"/v1/alerts?limit=30",
	} {
		resp := authedJSON(t, http.MethodGet, baseURL+path, token, nil)
		requireHTTPStatus(t, resp, http.StatusOK)
		if strings.TrimSpace(resp.Body.String()) != "[]" {
			t.Fatalf("%s returned non-empty-array body: %s", path, resp.Body.String())
		}
	}
}

func decodeTestBody(t *testing.T, resp *testHTTPResponse, out any) {
	t.Helper()
	if err := json.Unmarshal(resp.Body.Bytes(), out); err != nil {
		t.Fatalf("decode body %s: %v", resp.Body.String(), err)
	}
}

func uint32String(value uint32) string {
	if value == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}

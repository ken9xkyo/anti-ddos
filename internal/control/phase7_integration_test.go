package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPhase07BaselineAnomalyAutoEnforceIntegration(t *testing.T) {
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
	resetQueries := func() {
		queryMu.Lock()
		defer queryMu.Unlock()
		queries = nil
	}
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

	cfg := Config{
		Addr:             "127.0.0.1:0",
		DBDSN:            dsn,
		SessionTTL:       time.Hour,
		XDPObject:        "missing-ok.o",
		AgentSharedToken: "agent-secret",
		AgentStaleAfter:  time.Minute,
		PrometheusURL:    prom.URL,
		EventSampleDenom: 10,
	}
	store := NewStore(pool, cfg, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")

	serviceReq := ServiceInput{
		Reason:                   "publish service",
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
	}
	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/services", adminToken, serviceReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create service status=%d body=%s", resp.Code, resp.Body.String())
	}
	var service Service
	if err := json.Unmarshal(resp.Body.Bytes(), &service); err != nil {
		t.Fatal(err)
	}

	resetQueries()
	if _, err := store.BuildDashboardOverview(ctx, NewPrometheusClient(prom.URL, nil), time.Minute); err != nil {
		t.Fatal(err)
	}
	assertObservedQuery(t, &queryMu, &queries, `tcp_syn="1"`)
	assertObservedQuery(t, &queryMu, &queries, `action=~"0|1|6"`)

	evals, err := store.EvaluateAnomalies(ctx, NewPrometheusClient("", nil), "unconfigured prometheus")
	if err != nil || len(evals) != 0 {
		t.Fatalf("unconfigured prometheus should skip cleanly evals=%#v err=%v", evals, err)
	}
	badProm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "prometheus unavailable", http.StatusInternalServerError)
	}))
	defer badProm.Close()
	if _, err := store.EvaluateAnomalies(ctx, NewPrometheusClient(badProm.URL, nil), "unhealthy prometheus"); err == nil {
		t.Fatal("configured unhealthy prometheus should return an evaluator error")
	}

	manualRule, err := store.CreateRule(ctx, adminActor, RuleInput{
		Reason:       "manual ttl regression rule",
		ServiceID:    service.ID,
		Name:         "manual-ttl-regression",
		Priority:     1000,
		Action:       "observe",
		Mode:         "observe",
		Dimension:    "source_service",
		TTLSeconds:   900,
		BurstPackets: 1,
		Owner:        "sre",
	}, "manual ttl regression rule")
	if err != nil {
		t.Fatal(err)
	}
	if manualRule.ExpiresAt == nil {
		t.Fatalf("manual ttl rule did not derive expires_at: %#v", manualRule)
	}

	baselineReq := BaselineProfileInput{
		Reason:       "initial low confidence baseline",
		ServiceID:    service.ID,
		Interface:    "wan0",
		Protocol:     "tcp",
		Port:         443,
		Window:       "5m",
		ExpectedPPS:  1000,
		ExpectedBPS:  10000,
		ExpectedCPS:  100,
		HistoryHours: 1,
		Confidence:   0.25,
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/baselines", adminToken, baselineReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create baseline status=%d body=%s", resp.Code, resp.Body.String())
	}
	var baseline BaselineProfile
	if err := json.Unmarshal(resp.Body.Bytes(), &baseline); err != nil {
		t.Fatal(err)
	}

	ingestSecurityEvent(t, server.URL, service.EBPFID, "198.51.100.10")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/anomalies/evaluate", adminToken, map[string]string{"reason": "low confidence evaluation"})
	if resp.Code != http.StatusOK {
		t.Fatalf("low confidence evaluate status=%d body=%s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), `"auto_enforced":true`) {
		t.Fatalf("low-confidence baseline should not auto-enforce: %s", resp.Body.String())
	}

	baselineReq.HistoryHours = 24
	baselineReq.Confidence = 0.95
	baselineReq.Reason = "recalibrate with approved 24h history"
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/baselines/"+baseline.ID+"/recalibrate", adminToken, baselineReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("recalibrate baseline status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/baselines/"+baseline.ID+"/approve", adminToken, map[string]string{"reason": "approve baseline"})
	if resp.Code != http.StatusOK {
		t.Fatalf("approve baseline status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/whitelist", adminToken, WhitelistInput{
		Reason:    "expired trusted source should not block auto enforce",
		CIDR:      "198.51.100.10/32",
		Scope:     "global",
		Owner:     "sre",
		ExpiresAt: time.Now().UTC().Add(-time.Minute),
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("create expired whitelist status=%d body=%s", resp.Code, resp.Body.String())
	}

	resetQueries()
	concurrentProm := NewPrometheusClient(prom.URL, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			evals, err := store.EvaluateAnomalies(ctx, concurrentProm, "concurrent auto enforce evaluation")
			if err != nil {
				errs <- err
				return
			}
			if len(evals) == 0 {
				errs <- errors.New("expected anomaly evaluation")
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertObservedQuery(t, &queryMu, &queries, `service_id="`+strconv.FormatUint(uint64(service.EBPFID), 10)+`"`)
	assertObservedQuery(t, &queryMu, &queries, `tcp_syn="1"`)
	assertObservedQuery(t, &queryMu, &queries, `action=~"0|1|6"`)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/anomalies/evaluate", adminToken, map[string]string{"reason": "auto enforce evaluation"})
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"auto_enforced":true`) {
		t.Fatalf("auto enforce evaluate status=%d body=%s", resp.Code, resp.Body.String())
	}
	rules, err := store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var autoRule Rule
	for _, rule := range rules {
		if rule.Owner == "system:auto-enforce" {
			if autoRule.ID != "" && rule.Enabled {
				t.Fatalf("concurrent auto-enforce created more than one active rule: %#v", rules)
			}
			autoRule = rule
		}
	}
	if autoRule.ID == "" || autoRule.Action != "rate_limit" || autoRule.Mode != "enforce" || autoRule.Dimension != "source_service" {
		t.Fatalf("auto-enforce rule not created correctly: %#v", rules)
	}
	if autoRule.ExpiresAt == nil || autoRule.TTLSeconds != autoTTLSeconds {
		t.Fatalf("auto-enforce TTL missing: %#v", autoRule)
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/whitelist", adminToken, WhitelistInput{
		Reason: "trusted source conflict",
		CIDR:   "198.51.100.10/32",
		Scope:  "global",
		Owner:  "sre",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("create whitelist status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/anomalies/evaluate", adminToken, map[string]string{"reason": "whitelist conflict evaluation"})
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"status":"blocked_whitelist"`) {
		t.Fatalf("whitelist conflict did not block auto-enforce status=%d body=%s", resp.Code, resp.Body.String())
	}

	rollback, err := store.RollbackSnapshot(ctx, adminActor, 1, "rollback auto-enforce snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if rollback.RollbackFrom == nil {
		t.Fatalf("rollback_from missing: %#v", rollback)
	}

	var snapshotBeforeExpiry uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotBeforeExpiry); err != nil {
		t.Fatal(err)
	}
	var auditBeforeExpiry int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='expire_rule'`).Scan(&auditBeforeExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE rules SET expires_at=now() - interval '1 second' WHERE id::text = ANY($1)`, []string{autoRule.ID, manualRule.ID}); err != nil {
		t.Fatal(err)
	}
	expired, err := store.ExpireTTLRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if expired < 2 {
		t.Fatalf("expected expired auto and manual rules to be disabled, got %d", expired)
	}
	var snapshotAfterExpiry uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotAfterExpiry); err != nil {
		t.Fatal(err)
	}
	if snapshotAfterExpiry <= snapshotBeforeExpiry {
		t.Fatalf("ttl expiry did not create a new snapshot: before=%d after=%d", snapshotBeforeExpiry, snapshotAfterExpiry)
	}
	var auditAfterExpiry int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='expire_rule'`).Scan(&auditAfterExpiry); err != nil {
		t.Fatal(err)
	}
	if auditAfterExpiry < auditBeforeExpiry+2 {
		t.Fatalf("ttl expiry audit missing: before=%d after=%d", auditBeforeExpiry, auditAfterExpiry)
	}
	rules, err = store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if (rule.ID == autoRule.ID || rule.ID == manualRule.ID) && rule.Enabled {
			t.Fatalf("expired rule still enabled: %#v", rule)
		}
	}
}

func ingestSecurityEvent(t *testing.T, baseURL string, serviceID uint32, source string) {
	t.Helper()
	resp := agentJSON(t, http.MethodPost, baseURL+"/v1/agents/register", "agent-secret", AgentRegisterRequest{
		Hostname:      "node-a",
		XDPMode:       "native",
		DevmapSupport: true,
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("agent register status=%d body=%s", resp.Code, resp.Body.String())
	}
	var reg AgentRegisterResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	resp = agentJSON(t, http.MethodPost, baseURL+"/v1/agents/"+reg.AgentID+"/events", "agent-secret", SecurityEventBatch{Events: []SecurityEventInput{{
		EventTime:     time.Now().UTC(),
		PolicyVersion: 1,
		SrcIP:         source,
		DstIP:         "203.0.113.10",
		SrcPort:       12345,
		DstPort:       443,
		Protocol:      6,
		TCPFlags:      2,
		Action:        uint8(ActionDrop),
		Reason:        5,
		ServiceID:     serviceID,
		PktLen:        60,
		SampleRate:    10,
	}}})
	if resp.Code != http.StatusOK {
		t.Fatalf("event ingest status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func assertObservedQuery(t *testing.T, mu *sync.Mutex, queries *[]string, want string) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	for _, query := range *queries {
		if strings.Contains(query, want) {
			return
		}
	}
	t.Fatalf("expected prometheus query containing %q, got %#v", want, *queries)
}

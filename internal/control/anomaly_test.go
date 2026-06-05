package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAnomalyAlertOnlyIntegration(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
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
	overview, err := store.BuildDashboardOverview(ctx, NewPrometheusClient(prom.URL, nil), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	queryMu.Lock()
	overviewQueries := append([]string(nil), queries...)
	queryMu.Unlock()
	if len(overviewQueries) != 0 {
		t.Fatalf("tenant dashboard should not query global prometheus traffic, got %#v", overviewQueries)
	}
	if !strings.Contains(overview.Prometheus.Error, "tenant-scoped prometheus labels unavailable") {
		t.Fatalf("dashboard overview did not report tenant-scoped prometheus fallback: %#v", overview.Prometheus)
	}

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
	lowConfidenceEvals := decodeAnomalyResponse(t, resp)
	if len(lowConfidenceEvals) != 1 {
		t.Fatalf("expected one low confidence anomaly evaluation: %#v", lowConfidenceEvals)
	}
	if lowConfidenceEvals[0].AutoEnforced || lowConfidenceEvals[0].ProposedRuleID != "" || lowConfidenceEvals[0].ProposedTTLSeconds != 0 {
		t.Fatalf("baseline anomaly should not auto-enforce: %#v", lowConfidenceEvals[0])
	}
	if lowConfidenceEvals[0].Status != "alert_only" || lowConfidenceEvals[0].Recommendation != "manual_mitigation" || lowConfidenceEvals[0].RecommendedAction != "rate_limit" {
		t.Fatalf("high score anomaly should be alert-only with manual mitigation guidance: %#v", lowConfidenceEvals[0])
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
		Reason:    "expired trusted source should not suppress alert",
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
			evals, err := store.EvaluateAnomalies(ctx, concurrentProm, "concurrent alert-only evaluation")
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

	var snapshotBeforeEvaluate uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotBeforeEvaluate); err != nil {
		t.Fatal(err)
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/anomalies/evaluate", adminToken, map[string]string{"reason": "alert-only evaluation"})
	if resp.Code != http.StatusOK {
		t.Fatalf("alert-only evaluate status=%d body=%s", resp.Code, resp.Body.String())
	}
	alertOnlyEvals := decodeAnomalyResponse(t, resp)
	if len(alertOnlyEvals) != 1 {
		t.Fatalf("expected one alert-only anomaly evaluation: %#v", alertOnlyEvals)
	}
	if alertOnlyEvals[0].AutoEnforced || alertOnlyEvals[0].ProposedRuleID != "" || alertOnlyEvals[0].ProposedTTLSeconds != 0 {
		t.Fatalf("alert-only anomaly should not create proposed/enforced rule fields: %#v", alertOnlyEvals[0])
	}
	if alertOnlyEvals[0].Status != "alert_only" || alertOnlyEvals[0].Recommendation != "manual_mitigation" || alertOnlyEvals[0].RecommendedAction != "rate_limit" {
		t.Fatalf("unexpected alert-only evaluation guidance: %#v", alertOnlyEvals[0])
	}
	var snapshotAfterEvaluate uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotAfterEvaluate); err != nil {
		t.Fatal(err)
	}
	if snapshotAfterEvaluate != snapshotBeforeEvaluate {
		t.Fatalf("alert-only anomaly evaluation should not rebuild snapshots: before=%d after=%d", snapshotBeforeEvaluate, snapshotAfterEvaluate)
	}
	rules, err := store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Owner == legacyAutoEnforceOwner || string(rule.Evidence) == `{"auto_enforce":true}` {
			t.Fatalf("anomaly evaluation created legacy auto-enforce rule: %#v", rules)
		}
	}
	alerts, err := store.ListAlerts(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	foundAnomalyAlert := false
	for _, alert := range alerts {
		if alert.Type == "anomaly" && alert.Severity == "critical" && alert.RecommendedAction == "rate_limit" {
			foundAnomalyAlert = true
			break
		}
	}
	if !foundAnomalyAlert {
		t.Fatalf("alert-only anomaly did not create anomaly alert: %#v", alerts)
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
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"status":"alert_only"`) || !strings.Contains(resp.Body.String(), `"whitelist_conflict":true`) {
		t.Fatalf("whitelist conflict should be alert evidence only status=%d body=%s", resp.Code, resp.Body.String())
	}

	legacyOwnerRule, err := store.CreateSystemRule(ctx, RuleInput{
		ServiceID:    service.ID,
		Name:         "legacy-owner-auto-rate-limit",
		Action:       "rate_limit",
		Mode:         "enforce",
		Dimension:    "source_service",
		ThresholdPPS: 1000,
		TTLSeconds:   900,
		Owner:        legacyAutoEnforceOwner,
	}, "seed legacy owner auto-enforce rule")
	if err != nil {
		t.Fatal(err)
	}
	legacyEvidenceRule, err := store.CreateSystemRule(ctx, RuleInput{
		ServiceID:    service.ID,
		Name:         "legacy-evidence-auto-rate-limit",
		Action:       "rate_limit",
		Mode:         "enforce",
		Dimension:    "source_service",
		ThresholdPPS: 1000,
		TTLSeconds:   900,
		Evidence:     mustJSON(map[string]any{"auto_enforce": true}),
		Owner:        "system",
	}, "seed legacy evidence auto-enforce rule")
	if err != nil {
		t.Fatal(err)
	}
	var snapshotBeforeCleanup uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotBeforeCleanup); err != nil {
		t.Fatal(err)
	}
	disabled, err := store.DisableLegacyAutoEnforceRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if disabled != 2 {
		t.Fatalf("expected 2 legacy auto-enforce rules disabled, got %d", disabled)
	}
	var snapshotAfterCleanup uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotAfterCleanup); err != nil {
		t.Fatal(err)
	}
	if snapshotAfterCleanup <= snapshotBeforeCleanup {
		t.Fatalf("legacy auto-enforce cleanup did not rebuild snapshot: before=%d after=%d", snapshotBeforeCleanup, snapshotAfterCleanup)
	}
	var cleanupAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='disable_legacy_auto_enforce_rule'`).Scan(&cleanupAudits); err != nil {
		t.Fatal(err)
	}
	if cleanupAudits < 2 {
		t.Fatalf("legacy cleanup audit missing: got %d", cleanupAudits)
	}
	rules, err = store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if (rule.ID == legacyOwnerRule.ID || rule.ID == legacyEvidenceRule.ID) && rule.Enabled {
			t.Fatalf("legacy auto-enforce rule still enabled: %#v", rule)
		}
		if rule.ID == manualRule.ID && !rule.Enabled {
			t.Fatalf("manual rule should not be disabled by legacy cleanup: %#v", rule)
		}
	}

	var snapshotBeforeExpiry uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotBeforeExpiry); err != nil {
		t.Fatal(err)
	}
	var auditBeforeExpiry int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='expire_rule'`).Scan(&auditBeforeExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE rules SET expires_at=now() - interval '1 second' WHERE id::text = $1`, manualRule.ID); err != nil {
		t.Fatal(err)
	}
	expired, err := store.ExpireTTLRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if expired != 1 {
		t.Fatalf("expected expired manual rule to be disabled, got %d", expired)
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
	if auditAfterExpiry < auditBeforeExpiry+1 {
		t.Fatalf("ttl expiry audit missing: before=%d after=%d", auditBeforeExpiry, auditAfterExpiry)
	}
	rules, err = store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.ID == manualRule.ID && rule.Enabled {
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

func decodeAnomalyResponse(t *testing.T, resp *testHTTPResponse) []AnomalyEvaluation {
	t.Helper()
	var evals []AnomalyEvaluation
	if err := json.Unmarshal(resp.Body.Bytes(), &evals); err != nil {
		t.Fatal(err)
	}
	return evals
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

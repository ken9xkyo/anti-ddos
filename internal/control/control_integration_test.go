package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPhase05Integration(t *testing.T) {
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

	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret"}
	store := NewStore(pool, cfg, nil)
	store.SetForwardingResolver(nil)

	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	if _, err := store.CreateUser(ctx, adminActor, "viewer", "viewer password phrase", RoleViewer, "create viewer for RBAC test"); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	viewerToken := login(t, server.URL, "viewer", "viewer password phrase")

	viewerReq := ServiceInput{
		Reason:                   "viewer should not mutate",
		Name:                     "blocked-viewer",
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
	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/services", viewerToken, viewerReq)
	if resp.Code != http.StatusBadRequest && resp.Code != http.StatusForbidden {
		t.Fatalf("viewer mutate status = %d body=%s", resp.Code, resp.Body.String())
	}

	serviceReq := viewerReq
	serviceReq.Reason = "publish HTTPS service"
	serviceReq.Name = "api-https"
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/services", adminToken, serviceReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create service status = %d body=%s", resp.Code, resp.Body.String())
	}
	var service Service
	if err := json.Unmarshal(resp.Body.Bytes(), &service); err != nil {
		t.Fatal(err)
	}
	if service.EBPFID == 0 {
		t.Fatalf("service missing ebpf_id: %#v", service)
	}

	whitelistReq := WhitelistInput{Reason: "allow trusted monitor", CIDR: "198.51.100.10/32", Scope: "global", Owner: "sre", Priority: 10}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/whitelist", adminToken, whitelistReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create whitelist status = %d body=%s", resp.Code, resp.Body.String())
	}
	ruleReq := RuleInput{Reason: "manual emergency drop rule", Name: "drop-suspect", Action: "drop", Mode: "enforce", Owner: "soc", Priority: 20}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/rules", adminToken, ruleReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create rule status = %d body=%s", resp.Code, resp.Body.String())
	}
	blacklistReq := BlacklistInput{Reason: "manual attack source", CIDR: "198.51.100.200/32", Source: "manual", Action: "drop", Score: 90}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/blacklist", adminToken, blacklistReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create blacklist status = %d body=%s", resp.Code, resp.Body.String())
	}

	snapshots, err := store.ListSnapshots(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) < 3 {
		t.Fatalf("expected snapshots from mutations, got %d", len(snapshots))
	}
	beforeCount := len(snapshots)
	unchanged, err := store.RebuildSnapshot(ctx, adminActor, "confirm unchanged snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != nil {
		t.Fatalf("expected unchanged rebuild to skip new version, got %#v", unchanged)
	}
	afterUnchanged, _ := store.ListSnapshots(ctx, false)
	if len(afterUnchanged) != beforeCount {
		t.Fatalf("unchanged rebuild created snapshot: before=%d after=%d", beforeCount, len(afterUnchanged))
	}

	rollback, err := store.RollbackSnapshot(ctx, adminActor, 1, "rollback to service-only snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if rollback.RollbackFrom == nil || *rollback.RollbackFrom == 0 {
		t.Fatalf("rollback_from not set: %#v", rollback)
	}

	agentResp := agentJSON(t, http.MethodPost, server.URL+"/v1/agents/register", "agent-secret", AgentRegisterRequest{
		Hostname:      "node-a",
		XDPMode:       "native",
		DevmapSupport: true,
	})
	if agentResp.Code != http.StatusOK {
		t.Fatalf("agent register status = %d body=%s", agentResp.Code, agentResp.Body.String())
	}
	var reg AgentRegisterResponse
	if err := json.Unmarshal(agentResp.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	if reg.AgentID == "" || reg.DesiredPolicyVersion != rollback.Version {
		t.Fatalf("bad register response: %#v", reg)
	}
	heartbeatResp := agentJSON(t, http.MethodPost, server.URL+"/v1/agents/"+reg.AgentID+"/heartbeat", "agent-secret", AgentHeartbeatRequest{
		Status:              "online",
		ActivePolicyVersion: 0,
		XDPMode:             "native",
	})
	if heartbeatResp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d body=%s", heartbeatResp.Code, heartbeatResp.Body.String())
	}
	fetchReq, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/agents/"+reg.AgentID+"/snapshot?active_version=0", nil)
	fetchReq.Header.Set("Authorization", "Bearer agent-secret")
	fetchHTTPResp, err := http.DefaultClient.Do(fetchReq)
	if err != nil {
		t.Fatal(err)
	}
	fetchBody, _ := io.ReadAll(fetchHTTPResp.Body)
	_ = fetchHTTPResp.Body.Close()
	if fetchHTTPResp.StatusCode != http.StatusOK || !strings.Contains(string(fetchBody), `"snapshot"`) {
		t.Fatalf("fetch snapshot status=%d body=%s", fetchHTTPResp.StatusCode, string(fetchBody))
	}
	ackResp := agentJSON(t, http.MethodPost, server.URL+"/v1/agents/"+reg.AgentID+"/apply", "agent-secret", AgentApplyRequest{
		PolicyVersion: rollback.Version,
		Status:        "applied",
		MapStats:      json.RawMessage(`{"service_allowlist":{"entries":1}}`),
		DevmapStats:   json.RawMessage(`{"updated":1}`),
	})
	if ackResp.Code != http.StatusOK {
		t.Fatalf("apply ack status = %d body=%s", ackResp.Code, ackResp.Body.String())
	}

	events, err := store.ListAuditEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	var sawServiceReason bool
	for _, event := range events {
		if event.EntityType == "backend_service" && event.Reason == "publish HTTPS service" {
			sawServiceReason = true
		}
	}
	if !sawServiceReason {
		t.Fatalf("service audit reason missing in events: %#v", events)
	}
}

func TestAuditRedaction(t *testing.T) {
	raw, err := marshalRedactedJSON(map[string]any{
		"password":       "plain",
		"telegram_token": "123456:abcdefghijklmnopqrstuvwxyzABCDEF",
		"feed_api_key":   "secret-key",
		"nested": map[string]any{
			"authorization": "Bearer top-secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "plain") || strings.Contains(text, "top-secret") || strings.Contains(text, "secret-key") {
		t.Fatalf("secret leaked in redacted JSON: %s", text)
	}
}

func login(t *testing.T, baseURL, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(baseURL+"/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var session Session
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	return session.Token
}

type testHTTPResponse struct {
	Code int
	Body bytes.Buffer
}

func authedJSON(t *testing.T, method, url, token string, body any) *testHTTPResponse {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return doTestHTTP(t, req)
}

func agentJSON(t *testing.T, method, url, token string, body any) *testHTTPResponse {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return doTestHTTP(t, req)
}

func doTestHTTP(t *testing.T, req *http.Request) *testHTTPResponse {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out testHTTPResponse
	out.Code = resp.StatusCode
	_, _ = io.Copy(&out.Body, resp.Body)
	return &out
}

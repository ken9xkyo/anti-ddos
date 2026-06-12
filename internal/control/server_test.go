package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControlCoreIntegration(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret"}
	store := NewStore(pool, cfg, nil)

	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	owner, err := store.CreateUser(ctx, adminActor, "user", "user password phrase", RoleUser, "create user for RBAC test")
	if err != nil {
		t.Fatal(err)
	}
	ownerActor := &Actor{User: owner}
	ownerCtx := contextWithOwner(ctx, owner.ID)

	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	userToken := login(t, server.URL, "user", "user password phrase")
	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/admin/view-user", adminToken, AdminViewUserInput{UserID: owner.ID})
	requireHTTPStatus(t, resp, http.StatusOK)
	var viewSession Session
	decodeTestBody(t, resp, &viewSession)

	readOnlyReq := ServiceInput{
		Reason:                   "admin read-only should not mutate",
		Name:                     "blocked-read-only",
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
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/services", viewSession.Token, readOnlyReq)
	if resp.Code != http.StatusBadRequest && resp.Code != http.StatusForbidden {
		t.Fatalf("read-only mutate status = %d body=%s", resp.Code, resp.Body.String())
	}

	serviceReq := readOnlyReq
	serviceReq.Reason = "publish HTTPS service"
	serviceReq.Name = "api-https"
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/services", userToken, serviceReq)
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
	retiredReq := serviceReq
	retiredReq.Reason = "publish temporary service"
	retiredReq.Name = "retired-api"
	retiredReq.BackendCIDR = "203.0.113.11/32"
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/services", userToken, retiredReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create retired service status = %d body=%s", resp.Code, resp.Body.String())
	}
	var retired Service
	if err := json.Unmarshal(resp.Body.Bytes(), &retired); err != nil {
		t.Fatal(err)
	}
	deleteReq, err := http.NewRequest(http.MethodDelete, server.URL+"/v1/services/"+retired.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteReq.Header.Set("X-Audit-Reason", "retire temporary service")
	deleteReq.Header.Set("Authorization", "Bearer "+userToken)
	resp = doTestHTTP(t, deleteReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("delete service status = %d body=%s", resp.Code, resp.Body.String())
	}

	whitelistReq := WhitelistInput{Reason: "allow trusted monitor", CIDR: "198.51.100.10/32", Scope: "global", Owner: "sre", Priority: 10}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/whitelist", userToken, whitelistReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create whitelist status = %d body=%s", resp.Code, resp.Body.String())
	}
	ruleReq := RuleInput{Reason: "manual emergency drop rule", Name: "drop-suspect", Action: "drop", Mode: "enforce", Owner: "soc", Priority: 20}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/rules", userToken, ruleReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create rule status = %d body=%s", resp.Code, resp.Body.String())
	}
	blacklistReq := BlacklistInput{Reason: "manual attack source", CIDR: "198.51.100.200/32", Source: "manual", Action: "drop", Score: 90}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/blacklist", userToken, blacklistReq)
	if resp.Code != http.StatusOK {
		t.Fatalf("create blacklist status = %d body=%s", resp.Code, resp.Body.String())
	}

	snapshots, err := store.ListSnapshots(ownerCtx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) < 3 {
		t.Fatalf("expected snapshots from mutations, got %d", len(snapshots))
	}
	beforeCount := len(snapshots)
	unchanged, err := store.RebuildSnapshot(ownerCtx, ownerActor, "confirm unchanged snapshot")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != nil {
		t.Fatalf("expected unchanged rebuild to skip new version, got %#v", unchanged)
	}
	afterUnchanged, _ := store.ListSnapshots(ownerCtx, false)
	if len(afterUnchanged) != beforeCount {
		t.Fatalf("unchanged rebuild created snapshot: before=%d after=%d", beforeCount, len(afterUnchanged))
	}

	rollback, err := store.RollbackSnapshot(ownerCtx, ownerActor, 1, "rollback to service-only snapshot")
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
		Interfaces: []AgentInterface{{
			Name:    "backend0",
			Ifindex: 8,
			MAC:     "02:00:00:00:00:08",
			Role:    "backend",
		}},
	})
	if heartbeatResp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d body=%s", heartbeatResp.Code, heartbeatResp.Body.String())
	}
	dashboardAgents, err := store.ListDashboardAgents(ownerCtx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(dashboardAgents) != 1 || len(dashboardAgents[0].Interfaces) != 1 || dashboardAgents[0].Interfaces[0].Name != "backend0" {
		t.Fatalf("dashboard agent interfaces = %#v", dashboardAgents)
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

	events, err := store.ListAuditEvents(ownerCtx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	var sawServiceReason, sawDeleteReason bool
	for _, event := range events {
		if event.EntityType == "backend_service" && event.Reason == "publish HTTPS service" {
			sawServiceReason = true
		}
		if event.EntityType == "backend_service" && event.Action == "disable_service" && event.Reason == "retire temporary service" {
			sawDeleteReason = true
		}
	}
	if !sawServiceReason {
		t.Fatalf("service audit reason missing in events: %#v", events)
	}
	if !sawDeleteReason {
		t.Fatalf("service delete audit reason missing in events: %#v", events)
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

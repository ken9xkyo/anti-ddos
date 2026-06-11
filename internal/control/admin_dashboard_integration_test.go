package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDashboardAPIIntegration(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
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
	adminCtx := contextWithOwner(ctx, admin.ID)
	owner, err := store.CreateUser(ctx, adminActor, "user", "user password phrase", RoleUser, "create user")
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx := contextWithOwner(ctx, owner.ID)

	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	userToken := login(t, server.URL, "user", "user password phrase")
	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/admin/view-user", adminToken, AdminViewUserInput{UserID: owner.ID})
	requireHTTPStatus(t, resp, http.StatusOK)
	var viewSession Session
	decodeTestBody(t, resp, &viewSession)
	readOnlyToken := viewSession.Token

	requireEmptyDashboardArrays(t, server.URL, readOnlyToken)

	service := createDashboardService(t, server.URL, userToken)
	baseline := createDashboardBaseline(t, server.URL, userToken, service.ID)
	rule := createDashboardRule(t, server.URL, userToken, service.ID)
	agentID := registerDashboardAgent(t, server.URL)
	ingestDashboardEvent(t, server.URL, agentID, service.EBPFID, rule.EBPFID)

	version, err := store.LatestPolicyVersion(ownerCtx)
	if err != nil {
		t.Fatal(err)
	}
	resp = agentJSON(t, http.MethodPost, server.URL+"/v1/agents/"+agentID+"/apply", "agent-secret", AgentApplyRequest{
		PolicyVersion: version,
		Status:        "applied",
		MapStats:      json.RawMessage(`{"service_allowlist":{"entries":1},"rule_config":{"entries":1}}`),
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
		{"security events", "/v1/security-events?src=198.51.100.10", "198.51.100.10"},
		{"baselines", "/v1/baselines", baseline.ID},
	}
	for _, tc := range readCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := authedJSON(t, http.MethodGet, server.URL+tc.path, readOnlyToken, nil)
			requireHTTPStatus(t, resp, http.StatusOK)
			requireBodyContains(t, resp, tc.want)
		})
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users", adminToken, map[string]string{
		"reason":   "create console user",
		"username": "console-user",
		"password": "temporary password phrase",
		"role":     RoleUser,
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var consoleUser User
	decodeTestBody(t, resp, &consoleUser)
	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/users/"+consoleUser.ID, adminToken, UserUpdateInput{
		Reason: "promote console user",
		Role:   RoleUser,
		Status: StatusActive,
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users/"+consoleUser.ID+"/password-reset", adminToken, PasswordResetInput{
		Reason:   "reset console user",
		Password: "replacement password phrase",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	replacementToken := login(t, server.URL, "console-user", "replacement password phrase")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users/"+consoleUser.ID+"/sessions/revoke", adminToken, map[string]string{"reason": "revoke console sessions"})
	requireHTTPStatus(t, resp, http.StatusOK)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/me", replacementToken, nil)
	requireHTTPStatus(t, resp, http.StatusUnauthorized)

	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/rules/"+rule.ID, userToken, RuleInput{
		Reason:       "tighten dashboard rule",
		ServiceID:    service.ID,
		Name:         rule.Name,
		Action:       "rate_limit",
		Mode:         "enforce",
		Dimension:    "source_service",
		ThresholdPPS: 400,
		ThresholdBPS: 400000,
		ThresholdCPS: 40,
		TTLSeconds:   900,
		BurstPackets: 2,
		Confidence:   0.9,
		Enabled:      boolPtr(true),
		Owner:        "soc",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	deleteReq, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/rules/"+rule.ID, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+userToken)
	deleteReq.Header.Set("X-Audit-Reason", "disable dashboard rule")
	resp = doTestHTTP(t, deleteReq)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"enabled":false`)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/whitelist", userToken, WhitelistInput{
		Reason: "trusted customer source",
		CIDR:   "192.0.2.10/32",
		Scope:  "global",
		Owner:  "sre",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var whitelist WhitelistEntry
	decodeTestBody(t, resp, &whitelist)
	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/whitelist/"+whitelist.ID, userToken, WhitelistInput{
		Reason:  "extend trusted customer source",
		CIDR:    "192.0.2.10/32",
		Scope:   "global",
		Label:   "trusted-customer",
		Owner:   "sre",
		Enabled: boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	deleteReq, _ = http.NewRequest(http.MethodDelete, server.URL+"/v1/whitelist/"+whitelist.ID, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+userToken)
	deleteReq.Header.Set("X-Audit-Reason", "disable trusted customer source")
	resp = doTestHTTP(t, deleteReq)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"enabled":false`)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/blacklist", readOnlyToken, BlacklistInput{
		Reason: "read-only should not block",
		CIDR:   "198.51.100.201/32",
		Source: "manual",
		Action: "drop",
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/blacklist", userToken, BlacklistInput{
		Reason:  "manual scanner block",
		CIDR:    "198.51.100.200/32",
		Source:  "manual",
		Action:  "drop",
		Score:   85,
		Enabled: boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var blacklist BlacklistEntry
	decodeTestBody(t, resp, &blacklist)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/blacklist?q=scanner&source=manual&state=enabled&expiry=none", readOnlyToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, "198.51.100.200/32")
	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/blacklist/"+blacklist.ID, userToken, BlacklistInput{
		Reason:  "raise scanner block score",
		CIDR:    "198.51.100.200/32",
		Source:  "manual",
		Action:  "drop",
		Score:   95,
		Enabled: boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"score":95`)
	deleteReq, _ = http.NewRequest(http.MethodDelete, server.URL+"/v1/blacklist/"+blacklist.ID, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+userToken)
	deleteReq.Header.Set("X-Audit-Reason", "disable scanner block")
	resp = doTestHTTP(t, deleteReq)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"enabled":false`)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/blacklist?state=disabled", readOnlyToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, "198.51.100.200/32")

	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/udp-source-port-blocks?q=NTP&state=disabled", readOnlyToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"port":123`)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/udp-source-port-blocks", readOnlyToken, UDPSourcePortBlockInput{
		Reason: "read-only should not block UDP port",
		Port:   65000,
		Label:  "test-reflection",
		Owner:  "soc",
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/udp-source-port-blocks", userToken, UDPSourcePortBlockInput{
		Reason:  "block UDP reflection source port",
		Port:    65000,
		Label:   "test-reflection",
		Owner:   "soc",
		Enabled: boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var udpPortBlock UDPSourcePortBlock
	decodeTestBody(t, resp, &udpPortBlock)
	activeSnapshot := latestPolicySnapshot(t, store, ownerCtx)
	if len(activeSnapshot.UDPSourcePortBlocks) != 1 || activeSnapshot.UDPSourcePortBlocks[0].Port != 65000 {
		t.Fatalf("active snapshot missing UDP source port block: %#v", activeSnapshot.UDPSourcePortBlocks)
	}
	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/udp-source-port-blocks/"+udpPortBlock.ID, userToken, UDPSourcePortBlockInput{
		Reason:  "rename UDP reflection source port",
		Port:    65000,
		Label:   "renamed-reflection",
		Owner:   "soc",
		Enabled: boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"label":"renamed-reflection"`)
	deleteReq, _ = http.NewRequest(http.MethodDelete, server.URL+"/v1/udp-source-port-blocks/"+udpPortBlock.ID, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+userToken)
	deleteReq.Header.Set("X-Audit-Reason", "disable UDP reflection source port")
	resp = doTestHTTP(t, deleteReq)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"enabled":false`)

	snapshots, err := store.ListSnapshots(ownerCtx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) < 2 {
		t.Fatalf("expected at least two snapshots, got %d", len(snapshots))
	}
	latest, previous := snapshots[0].Version, snapshots[1].Version
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/snapshots/"+uint32String(latest), readOnlyToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"snapshot":`)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/snapshots/diff?from="+uint32String(previous)+"&to="+uint32String(latest), readOnlyToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"from_version":`)
	requireBodyContains(t, resp, `"rules":`)

	audits, err := store.ListAuditEvents(adminCtx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if strings.Contains(string(audit.After), "replacement password phrase") ||
			strings.Contains(string(audit.Before), "replacement password phrase") ||
			strings.Contains(string(audit.After), "temporary password phrase") ||
			strings.Contains(string(audit.Before), "temporary password phrase") {
			t.Fatalf("password leaked in audit: %#v", audit)
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
	} {
		resp := authedJSON(t, http.MethodGet, baseURL+path, token, nil)
		requireHTTPStatus(t, resp, http.StatusOK)
		if strings.TrimSpace(resp.Body.String()) != "[]" {
			t.Fatalf("%s returned non-empty-array body: %s", path, resp.Body.String())
		}
	}
}

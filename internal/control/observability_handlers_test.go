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

func TestObservabilityHandlersIntegration(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	cfg := Config{
		Addr:             "127.0.0.1:0",
		DBDSN:            dsn,
		SessionTTL:       time.Hour,
		XDPObject:        "missing-ok.o",
		AgentSharedToken: "agent-secret",
		AgentStaleAfter:  time.Minute,
		EventSampleDenom: 10,
	}
	store := NewStore(pool, cfg, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	owner, err := store.CreateUser(ctx, adminActor, "user", "user password phrase", RoleUser, "create user")
	if err != nil {
		t.Fatal(err)
	}
	ownerActor := &Actor{User: owner}
	if _, err := store.CreateService(contextWithOwner(ctx, owner.ID), ownerActor, ServiceInput{
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
	}, "publish service"); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/admin/view-user", adminToken, AdminViewUserInput{UserID: owner.ID})
	requireHTTPStatus(t, resp, http.StatusOK)
	var viewSession Session
	decodeTestBody(t, resp, &viewSession)
	readOnlyToken := viewSession.Token

	regResp := agentJSON(t, http.MethodPost, server.URL+"/v1/agents/register", "agent-secret", AgentRegisterRequest{
		Hostname:      "node-a",
		XDPMode:       "native",
		DevmapSupport: true,
	})
	if regResp.Code != http.StatusOK {
		t.Fatalf("agent register status = %d body=%s", regResp.Code, regResp.Body.String())
	}
	var reg AgentRegisterResponse
	if err := json.Unmarshal(regResp.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	eventsResp := agentJSON(t, http.MethodPost, server.URL+"/v1/agents/"+reg.AgentID+"/events", "agent-secret", SecurityEventBatch{Events: []SecurityEventInput{{
		EventTime:     time.Now().UTC(),
		PolicyVersion: 1,
		SrcIP:         "198.51.100.10",
		DstIP:         "203.0.113.10",
		SrcPort:       12345,
		DstPort:       443,
		Protocol:      6,
		Action:        uint8(ActionDrop),
		Reason:        4,
		ServiceID:     1,
		PktLen:        60,
	}}})
	if eventsResp.Code != http.StatusOK {
		t.Fatalf("event ingest status = %d body=%s", eventsResp.Code, eventsResp.Body.String())
	}
	if !strings.Contains(eventsResp.Body.String(), `"accepted":1`) {
		t.Fatalf("bad ingest response: %s", eventsResp.Body.String())
	}

	listResp := authedJSON(t, http.MethodGet, server.URL+"/v1/security-events?src=198.51.100.10", readOnlyToken, nil)
	if listResp.Code != http.StatusOK || !strings.Contains(listResp.Body.String(), "198.51.100.10") {
		t.Fatalf("security event query status=%d body=%s", listResp.Code, listResp.Body.String())
	}
	summaryResp := authedJSON(t, http.MethodGet, server.URL+"/v1/security-events/summary", readOnlyToken, nil)
	if summaryResp.Code != http.StatusOK || !strings.Contains(summaryResp.Body.String(), `"total":1`) {
		t.Fatalf("summary status=%d body=%s", summaryResp.Code, summaryResp.Body.String())
	}
	overviewResp := authedJSON(t, http.MethodGet, server.URL+"/v1/dashboard/overview", readOnlyToken, nil)
	if overviewResp.Code != http.StatusOK || !strings.Contains(overviewResp.Body.String(), `"configured":false`) {
		t.Fatalf("overview status=%d body=%s", overviewResp.Code, overviewResp.Body.String())
	}

	metricsResp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(metricsResp.Body)
	_ = metricsResp.Body.Close()
	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", metricsResp.StatusCode, string(body))
	}
	text := string(body)
	for _, forbidden := range []string{"src_ip", "198.51.100.10", "correct horse", "user password"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("high-cardinality or sensitive label leaked in metrics: %q", forbidden)
		}
	}
	if !strings.Contains(text, "anti_ddos_control_security_events_ingested_total") {
		t.Fatalf("control metrics missing security event counter: %s", text)
	}
}

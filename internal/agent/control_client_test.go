package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlClientRegisterHeartbeatFetchAck(t *testing.T) {
	snapshot := signedTestPolicySnapshot(t, 9)
	var sawAck bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared" {
			t.Fatalf("missing auth header on %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/agents/register":
			var req controlRegisterRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.Hostname == "" {
				t.Fatal("register hostname missing")
			}
			if len(req.Interfaces) != 1 || req.Interfaces[0].Name != "wan0" {
				t.Fatalf("register interfaces = %#v", req.Interfaces)
			}
			_ = json.NewEncoder(w).Encode(controlRegisterResponse{AgentID: "agent-1", DesiredPolicyVersion: 9})
		case "/v1/agents/agent-1/heartbeat":
			var req controlHeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.ActivePolicyVersion != 8 {
				t.Fatalf("heartbeat active version = %d", req.ActivePolicyVersion)
			}
			if len(req.Interfaces) != 1 || req.Interfaces[0].Name != "wan0" {
				t.Fatalf("heartbeat interfaces = %#v", req.Interfaces)
			}
			_ = json.NewEncoder(w).Encode(controlHeartbeatResponse{DesiredPolicyVersion: 9})
		case "/v1/agents/agent-1/snapshot":
			_ = json.NewEncoder(w).Encode(controlSnapshotResponse{Snapshot: snapshot})
		case "/v1/agents/agent-1/apply":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["policy_version"].(float64) != 9 {
				t.Fatalf("ack policy_version payload = %#v", payload)
			}
			sawAck = true
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := controlClient{baseURL: server.URL, token: "shared", client: server.Client()}
	ifaces := []controlAgentInterface{{Name: "wan0", Ifindex: 7, MAC: "02:00:00:00:00:01", Role: "wan"}}
	register, err := client.register(context.Background(), controlRegisterRequest{Hostname: "node", Interfaces: ifaces})
	if err != nil {
		t.Fatal(err)
	}
	if register.AgentID != "agent-1" || register.DesiredPolicyVersion != 9 {
		t.Fatalf("register response = %#v", register)
	}
	heartbeat, err := client.heartbeat(context.Background(), "agent-1", controlHeartbeatRequest{ActivePolicyVersion: 8, Interfaces: ifaces})
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.DesiredPolicyVersion != 9 {
		t.Fatalf("heartbeat response = %#v", heartbeat)
	}
	fetched, ok, err := client.fetchSnapshot(context.Background(), "agent-1", 8)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || fetched.Version != 9 || fetched.Checksum == "" {
		t.Fatalf("snapshot response ok=%v snapshot=%#v", ok, fetched)
	}
	if err := client.ack(context.Background(), "agent-1", PolicyApplyResult{Version: 9, Status: policyApplyStatusApplied}); err != nil {
		t.Fatal(err)
	}
	if !sawAck {
		t.Fatal("ack endpoint not called")
	}
}

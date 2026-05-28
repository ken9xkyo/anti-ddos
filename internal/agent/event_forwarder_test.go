package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestControlEventFromRecordConvertsIPv4(t *testing.T) {
	event := controlEventFromRecord(EventRecord{
		TsMonoNS:      123,
		PolicyVersion: 7,
		SrcV4:         0x010200c0,
		DstV4:         0x0a7100cb,
		SrcPort:       12345,
		DstPort:       443,
		Proto:         l4TCP,
		Action:        actionDrop,
		Reason:        reasonNotAllowedService,
		ServiceID:     10,
		RuleID:        20,
		PktLen:        64,
	}, time.Unix(10, 0).UTC(), 100)

	if event.SrcIP != "192.0.2.1" || event.DstIP != "203.0.113.10" {
		t.Fatalf("unexpected IP conversion: %#v", event)
	}
	if event.SampleRate != 100 || event.PolicyVersion != 7 || event.MonoTSNS != 123 {
		t.Fatalf("unexpected event fields: %#v", event)
	}
}

func TestSecurityEventForwarderFlushesBatch(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := saveControlState(statePath, controlState{AgentID: "agent-1"}); err != nil {
		t.Fatal(err)
	}
	var got controlSecurityEventBatch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/agent-1/events" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer shared" {
			t.Fatalf("missing auth header")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(got.Events)})
	}))
	defer server.Close()

	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	forwarder := &SecurityEventForwarder{
		client:     controlClient{baseURL: server.URL, token: "shared", client: server.Client()},
		statePath:  statePath,
		queue:      make(chan controlSecurityEvent, 1),
		batchSize:  1,
		sampleRate: 10,
		metrics:    metrics,
	}
	forwarder.Enqueue(EventRecord{SrcV4: 0x010200c0, DstV4: 0x0a7100cb, Proto: l4UDP, PktLen: 42})
	event := <-forwarder.queue
	forwarder.flush(context.Background(), []controlSecurityEvent{event})

	if len(got.Events) != 1 {
		t.Fatalf("events posted = %d", len(got.Events))
	}
	if got.Events[0].SampleRate != 10 || got.Events[0].SrcIP != "192.0.2.1" {
		t.Fatalf("posted event = %#v", got.Events[0])
	}
}

func TestSecurityEventForwarderDropsWhenQueueFull(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	forwarder := &SecurityEventForwarder{
		queue:      make(chan controlSecurityEvent, 1),
		sampleRate: 1,
		metrics:    metrics,
	}
	forwarder.Enqueue(EventRecord{SrcV4: 0x010200c0, DstV4: 0x0a7100cb})
	forwarder.Enqueue(EventRecord{SrcV4: 0x010200c0, DstV4: 0x0a7100cb})

	families, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, family := range families {
		if family.GetName() == "anti_ddos_agent_control_events_dropped_total" && len(family.GetMetric()) == 1 {
			found = family.GetMetric()[0].GetCounter().GetValue() == 1
		}
	}
	if !found {
		t.Fatal("expected one queue_full drop metric")
	}
}

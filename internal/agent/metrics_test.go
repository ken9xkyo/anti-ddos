package agent

import "testing"

func TestMetricsGather(t *testing.T) {
	metrics, err := NewMetrics()
	if err != nil {
		t.Fatalf("NewMetrics() error = %v", err)
	}

	metrics.SetAgentUp(true)
	metrics.SetXDPMode("generic")
	metrics.SetSnapshotVersion(7)
	metrics.SetCounters([]AggregatedCounter{{
		Key:     CounterKey{Reason: reasonMapError, Action: actionDrop, Proto: 6},
		Packets: 3,
		Bytes:   180,
	}})
	metrics.SetForwardingCounters([]AggregatedCounter{
		{
			Key:     CounterKey{Reason: reasonNone, Action: actionRedirect, Proto: l4TCP, ServiceID: 10},
			Packets: 5,
			Bytes:   300,
		},
		{
			Key:     CounterKey{Reason: reasonRedirectError, Action: actionDrop, Proto: l4TCP, ServiceID: 10},
			Packets: 1,
			Bytes:   60,
		},
		{
			Key:     CounterKey{Reason: reasonNotAllowedService, Action: actionDrop, Proto: l4UDP},
			Packets: 2,
			Bytes:   120,
		},
	}, LastValidSnapshot{Policy: &PolicySnapshot{Services: []PolicyService{{
		ServiceID:      10,
		OutputIfindex:  7,
		NeighborStatus: neighborResolved,
	}}}})

	families, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	names := map[string]bool{}
	for _, family := range families {
		names[family.GetName()] = true
	}
	for _, name := range []string{
		"anti_ddos_agent_up",
		"anti_ddos_xdp_mode",
		"anti_ddos_xdp_packets_total",
		"anti_ddos_agent_last_valid_snapshot_version",
		"anti_ddos_redirected_packets_total",
		"anti_ddos_redirect_errors_total",
		"anti_ddos_not_allowed_service_total",
		"anti_ddos_neighbor_resolution_status",
	} {
		if !names[name] {
			t.Fatalf("missing metric family %s", name)
		}
	}
}

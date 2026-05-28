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
	} {
		if !names[name] {
			t.Fatalf("missing metric family %s", name)
		}
	}
}

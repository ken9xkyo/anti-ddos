package control

import (
	"errors"
	"strings"
	"testing"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

type recordingForwardingResolver struct {
	called bool
}

func (r *recordingForwardingResolver) ResolveService(agent.ServiceResolveRequest) (agent.ResolvedService, error) {
	r.called = true
	return agent.ResolvedService{}, errors.New("lookup output interface enp134s0f1: Link not found")
}

func TestMakePolicyServiceRequiresCompleteResolvedMetadata(t *testing.T) {
	req := agent.ServiceResolveRequest{
		ServiceID:          10,
		ForwardingPolicyID: 10,
		DstV4:              "203.0.113.10",
		DstPort:            443,
		Proto:              6,
		Priority:           10,
		OutputInterface:    "enp134s0f1",
		DevmapKey:          10,
	}

	tests := []struct {
		name    string
		ifindex uint32
		dstMAC  string
		srcMAC  string
		want    string
	}{
		{
			name:    "missing next-hop MAC",
			ifindex: 7,
			srcMAC:  "90:e2:ba:24:9b:b6",
			want:    "resolved_next_hop_mac is required",
		},
		{
			name:   "missing ifindex",
			dstMAC: "02:00:00:00:00:02",
			srcMAC: "90:e2:ba:24:9b:b6",
			want:   "resolved_ifindex is required",
		},
		{
			name:    "missing source MAC",
			ifindex: 7,
			dstMAC:  "02:00:00:00:00:02",
			want:    "resolved_src_mac is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &recordingForwardingResolver{}
			store := &Store{resolver: resolver}
			if _, err := store.makePolicyService(req, tc.ifindex, tc.dstMAC, tc.srcMAC); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("makePolicyService() error = %v, want containing %q", err, tc.want)
			}
			if resolver.called {
				t.Fatal("resolver should not be called for partial resolved forwarding metadata")
			}
		})
	}
}

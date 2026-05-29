package control

import (
	"errors"
	"strings"
	"testing"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

type recordingForwardingResolver struct {
	called  bool
	service agent.PolicyService
	err     error
}

func (r *recordingForwardingResolver) ResolveService(req agent.ServiceResolveRequest) (agent.ResolvedService, error) {
	r.called = true
	if r.err != nil {
		return agent.ResolvedService{}, r.err
	}
	service := r.service
	if service.ServiceID == 0 {
		service = agent.PolicyService{
			ServiceID:          req.ServiceID,
			ForwardingPolicyID: req.ForwardingPolicyID,
			DstV4:              req.DstV4,
			DstPort:            req.DstPort,
			Proto:              req.Proto,
			Action:             ActionRedirect,
			Priority:           req.Priority,
			OutputIfindex:      7,
			DevmapKey:          req.DevmapKey,
			NeighborStatus:     NeighborResolved,
			DstMAC:             "02:00:00:00:00:02",
			SrcMAC:             "90:e2:ba:24:9b:b6",
		}
	}
	return agent.ResolvedService{Service: service}, nil
}

func TestMakePolicyServiceFallsBackToResolverWhenNextHopMissing(t *testing.T) {
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
	resolver := &recordingForwardingResolver{}
	store := &Store{resolver: resolver}

	service, err := store.makePolicyService(req, 7, "", "90:e2:ba:24:9b:b6")
	if err != nil {
		t.Fatalf("makePolicyService() error = %v", err)
	}
	if !resolver.called {
		t.Fatal("resolver should be called when next-hop MAC is not pre-resolved")
	}
	if service.DstMAC != "02:00:00:00:00:02" || service.SrcMAC != "90:e2:ba:24:9b:b6" || service.OutputIfindex != 7 {
		t.Fatalf("resolved service = %#v", service)
	}
}

func TestMakePolicyServiceRequiresCompletePreResolvedMetadata(t *testing.T) {
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
			resolver := &recordingForwardingResolver{err: errors.New("resolver should not be called")}
			store := &Store{resolver: resolver}
			if _, err := store.makePolicyService(req, tc.ifindex, tc.dstMAC, tc.srcMAC); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("makePolicyService() error = %v, want containing %q", err, tc.want)
			}
			if resolver.called {
				t.Fatal("resolver should not be called for incomplete pre-resolved forwarding metadata")
			}
		})
	}
}

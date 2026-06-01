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

func TestCollectionDiffClassifiesSnapshotItems(t *testing.T) {
	type item struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}

	diff := collectionDiff(
		[]item{{ID: "1", Value: "same"}, {ID: "2", Value: "removed"}, {ID: "3", Value: "before"}},
		[]item{{ID: "1", Value: "same"}, {ID: "3", Value: "after"}, {ID: "4", Value: "added"}},
		func(value item) string { return value.ID },
	)

	if diff.Unchanged != 1 || len(diff.Added) != 1 || len(diff.Removed) != 1 || len(diff.Changed) != 1 {
		t.Fatalf("unexpected diff: %#v", diff)
	}
	if diff.Added[0].Key != "4" || diff.Removed[0].Key != "2" || diff.Changed[0].Key != "3" {
		t.Fatalf("unexpected diff keys: %#v", diff)
	}
	if !strings.Contains(string(diff.Changed[0].Before), "before") || !strings.Contains(string(diff.Changed[0].After), "after") {
		t.Fatalf("changed values not marshaled: %#v", diff.Changed[0])
	}
}

func TestSnapshotJSONHelpers(t *testing.T) {
	if !jsonEqual(map[string]int{"a": 1}, map[string]int{"a": 1}) {
		t.Fatal("jsonEqual should match equivalent values")
	}
	if jsonEqual(map[string]int{"a": 1}, map[string]int{"a": 2}) {
		t.Fatal("jsonEqual should detect different values")
	}
	if got := string(marshalSnapshotValue(make(chan int))); got != "{}" {
		t.Fatalf("marshalSnapshotValue() = %s, want {}", got)
	}
}

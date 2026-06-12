package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

func TestRebuildAndRollbackAllowUnresolvedServiceSnapshots(t *testing.T) {
	ctx, pool, _ := resetControlTestDB(t)
	objectPath := filepath.Join(t.TempDir(), "xdp.o")
	if err := os.WriteFile(objectPath, []byte("test object"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool, Config{XDPObject: objectPath}, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := store.CreateService(ctx, &Actor{User: admin}, ServiceInput{
		Reason:                   "enable unresolved service",
		Name:                     "api",
		BackendCIDR:              "203.0.113.10/32",
		Protocol:                 "tcp",
		AllowedPorts:             []uint16{443},
		OutputInterface:          "enp134s0f1",
		Owner:                    "sre",
		Criticality:              "high",
		ProtectionMode:           "enforce",
		Enabled:                  &enabled,
		ResolvedIfindex:          7,
		ResolvedSourceMAC:        "90:e2:ba:24:9b:b6",
		NeighborResolutionStatus: "unresolved",
	}, "enable unresolved service"); err != nil {
		t.Fatalf("CreateService() should build unresolved snapshot without control netlink: %v", err)
	}

	snapshot, err := store.FetchSnapshot(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot == nil || len(snapshot.Services) != 1 {
		t.Fatalf("expected one snapshot service, got %#v", snapshot)
	}
	service := snapshot.Services[0]
	if service.OutputInterface != "enp134s0f1" || service.OutputIfindex != 0 || service.DstMAC != "" || service.SrcMAC != "" {
		t.Fatalf("snapshot should carry unresolved forwarding intent: %#v", service)
	}
	if _, err := store.RollbackSnapshot(ctx, &Actor{User: admin}, snapshot.Version, "rollback unresolved service snapshot"); err != nil {
		t.Fatalf("RollbackSnapshot() should verify unresolved target snapshot: %v", err)
	}
}

func TestBuildSnapshotFlagsServiceScopedWhitelist(t *testing.T) {
	ctx, pool, _ := resetControlTestDB(t)
	objectPath := filepath.Join(t.TempDir(), "xdp.o")
	if err := os.WriteFile(objectPath, []byte("test object"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool, Config{XDPObject: objectPath}, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	actor := &Actor{User: admin}
	enabled := true
	service, err := store.CreateService(ctx, actor, ServiceInput{
		Reason:                   "create api service",
		Name:                     "api",
		BackendCIDR:              "203.0.113.10/32",
		Protocol:                 "tcp",
		AllowedPorts:             []uint16{443},
		OutputInterface:          "backend0",
		Owner:                    "sre",
		Criticality:              "high",
		ProtectionMode:           "enforce",
		Enabled:                  &enabled,
		ResolvedIfindex:          7,
		ResolvedNextHopMAC:       "02:00:00:00:00:02",
		ResolvedSourceMAC:        "02:00:00:00:00:01",
		NeighborResolutionStatus: "resolved",
	}, "create api service")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateWhitelistEntry(ctx, actor, WhitelistInput{
		Reason:    "allow monitor for api",
		CIDR:      "198.51.100.20/32",
		Scope:     "service",
		ServiceID: service.ID,
		Owner:     "sre",
		Priority:  10,
	}, "allow monitor for api"); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.FetchSnapshot(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshotHasFeatureFlag(snapshot.FeatureFlags, "service_scoped_whitelist_v4") {
		t.Fatalf("snapshot feature flags = %#v, want service_scoped_whitelist_v4", snapshot.FeatureFlags)
	}
	if len(snapshot.WhitelistV4) != 1 {
		t.Fatalf("snapshot whitelist = %#v, want one service-scoped entry", snapshot.WhitelistV4)
	}
	entry := snapshot.WhitelistV4[0]
	if entry.Scope != PolicyScopeService || entry.ServiceID != service.EBPFID {
		t.Fatalf("snapshot whitelist entry = %#v, want service scope service_id %d", entry, service.EBPFID)
	}
}

func TestMakePolicyServiceEmitsUnresolvedForwardingIntentWhenNextHopMissing(t *testing.T) {
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
	store := &Store{}

	service, err := store.makePolicyService(req, 7, "", "90:e2:ba:24:9b:b6")
	if err != nil {
		t.Fatalf("makePolicyService() error = %v", err)
	}
	if service.OutputInterface != "enp134s0f1" || service.OutputIfindex != 0 || service.NeighborStatus != 0 {
		t.Fatalf("service should carry unresolved output intent: %#v", service)
	}
	if service.DstMAC != "" || service.SrcMAC != "" {
		t.Fatalf("unresolved service should not carry MAC metadata: %#v", service)
	}
	snapshot := agent.PolicySnapshot{
		SchemaVersion:  1,
		Version:        1,
		ObjectChecksum: "obj",
		Runtime:        agent.PolicyRuntimeConfig{MalformedPolicy: ActionDrop},
		Services:       []agent.PolicyService{service},
	}
	signed, err := agent.SignPolicySnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.VerifyPolicySnapshot(signed, agent.PolicySnapshotVerifyOptions{AllowUnresolvedServices: true}); err != nil {
		t.Fatalf("unresolved service should verify for control snapshots: %v", err)
	}
}

func TestMakePolicyServiceUsesPreResolvedMetadataWhenNextHopPresent(t *testing.T) {
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
	store := &Store{}

	service, err := store.makePolicyService(req, 7, "02:00:00:00:00:02", "90:e2:ba:24:9b:b6")
	if err != nil {
		t.Fatalf("makePolicyService() error = %v", err)
	}
	if service.OutputInterface != "enp134s0f1" || service.OutputIfindex != 7 || service.NeighborStatus != NeighborResolved {
		t.Fatalf("service should carry pre-resolved metadata: %#v", service)
	}
	if service.DstMAC != "02:00:00:00:00:02" || service.SrcMAC != "90:e2:ba:24:9b:b6" {
		t.Fatalf("unexpected MAC metadata: %#v", service)
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
			store := &Store{}
			if _, err := store.makePolicyService(req, tc.ifindex, tc.dstMAC, tc.srcMAC); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("makePolicyService() error = %v, want containing %q", err, tc.want)
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

func snapshotHasFeatureFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

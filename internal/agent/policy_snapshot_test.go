package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestCanonicalPolicyChecksumIgnoresFieldAndSliceOrder(t *testing.T) {
	left := testPolicySnapshot(t, 2)
	right := left
	right.FeatureFlags = []string{"tx_devmap", "ipv4"}
	right.WhitelistV4 = []PolicyCIDREntry{left.WhitelistV4[1], left.WhitelistV4[0]}
	right.BlacklistV4 = []PolicyCIDREntry{left.BlacklistV4[0]}

	leftSum, err := CanonicalPolicyChecksum(left)
	if err != nil {
		t.Fatal(err)
	}
	rightSum, err := CanonicalPolicyChecksum(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftSum != rightSum {
		t.Fatalf("canonical checksum changed with ordering: %s != %s", leftSum, rightSum)
	}

	raw := []byte(`{"checksum":"` + leftSum + `","version":2,"runtime":{"sample_denom":1,"malformed_policy":1},"schema_version":1,"object_checksum":"obj","feature_flags":["ipv4","tx_devmap"],"blacklist_v4":[{"entry_id":3,"cidr":"198.51.100.10/32","priority":10,"action":1,"source_type":1,"scope":0,"rule_id":77}],"whitelist_v4":[{"entry_id":2,"cidr":"198.51.100.0/24","priority":10,"action":0,"source_type":1,"scope":0},{"entry_id":1,"cidr":"203.0.113.10/32","priority":10,"action":0,"source_type":1,"scope":0}],"services":[{"service_id":10,"forwarding_policy_id":20,"dst_v4":"203.0.113.10","dst_port":443,"proto":6,"action":6,"priority":10,"output_ifindex":1,"devmap_key":3,"neighbor_status":1,"dst_mac":"02:00:00:00:00:02","src_mac":"02:00:00:00:00:01"}],"rules":[{"rule_id":2,"priority":10,"action":1,"mode":1}]}`)
	decoded, err := DecodePolicySnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Checksum != leftSum {
		t.Fatalf("decoded checksum mismatch: %s", decoded.Checksum)
	}
}

func TestVerifyPolicySnapshotRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(PolicySnapshot) PolicySnapshot
		options PolicySnapshotVerifyOptions
		want    string
	}{
		{
			name: "bad checksum",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.Checksum = strings.Repeat("0", 64)
				return snapshot
			},
			want: "checksum mismatch",
		},
		{
			name:    "stale version",
			options: PolicySnapshotVerifyOptions{CurrentVersion: 2},
			want:    "not newer",
		},
		{
			name: "unknown feature",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.FeatureFlags = append(snapshot.FeatureFlags, "ipv6")
				snapshot = resignTestPolicySnapshot(t, snapshot)
				return snapshot
			},
			want: "unsupported policy feature flag",
		},
		{
			name:    "object checksum mismatch",
			options: PolicySnapshotVerifyOptions{ObjectChecksum: "different"},
			want:    "object_checksum mismatch",
		},
		{
			name: "expired ttl",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.BlacklistV4[0].ExpiresAtUnixNS = uint64(time.Now().Add(-time.Second).UnixNano())
				snapshot = resignTestPolicySnapshot(t, snapshot)
				return snapshot
			},
			want: "expired",
		},
		{
			name: "ipv6 rejected",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.BlacklistV4[0].CIDR = "2001:db8::/32"
				snapshot = resignTestPolicySnapshot(t, snapshot)
				return snapshot
			},
			want: "IPv6",
		},
		{
			name: "service action must redirect",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.Services[0].Action = actionDrop
				snapshot = resignTestPolicySnapshot(t, snapshot)
				return snapshot
			},
			want: "ACTION_REDIRECT",
		},
		{
			name: "unsupported service proto",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.Services[0].Proto = 99
				snapshot = resignTestPolicySnapshot(t, snapshot)
				return snapshot
			},
			want: "unsupported service proto",
		},
		{
			name: "tcp service requires port",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.Services[0].DstPort = 0
				snapshot = resignTestPolicySnapshot(t, snapshot)
				return snapshot
			},
			want: "tcp/udp service dst_port",
		},
		{
			name: "icmp service uses zero port",
			mutate: func(snapshot PolicySnapshot) PolicySnapshot {
				snapshot.Services[0].Proto = l4ICMP
				snapshot.Services[0].DstPort = 443
				snapshot = resignTestPolicySnapshot(t, snapshot)
				return snapshot
			},
			want: "icmp service dst_port",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := signedTestPolicySnapshot(t, 2)
			if tc.mutate != nil {
				snapshot = tc.mutate(snapshot)
			}
			if _, err := VerifyPolicySnapshot(snapshot, tc.options); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyPolicySnapshot() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestVerifyPolicySnapshotRejectsCapacityOverflows(t *testing.T) {
	valid := signedTestPolicySnapshot(t, 2)

	tests := []struct {
		name      string
		overrides map[string]uint32
		want      string
	}{
		{name: "blacklist", overrides: map[string]uint32{"blacklist_v4": 0}, want: "blacklist_v4"},
		{name: "service", overrides: map[string]uint32{"service_allowlist": 0}, want: "service_allowlist"},
		{name: "rule", overrides: map[string]uint32{"rule_config": 1}, want: "rule_config"},
		{name: "devmap", overrides: map[string]uint32{"tx_devmap": 1}, want: "devmap_key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyPolicySnapshot(valid, PolicySnapshotVerifyOptions{CapacityOverrides: tc.overrides}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyPolicySnapshot() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestApplyPolicySnapshotFlipsRuntimeAndPersistsLastValid(t *testing.T) {
	runtime := newPolicyApplyTestRuntime(t, false)
	path := filepath.Join(t.TempDir(), "last-valid.json")
	snapshot := signedTestPolicySnapshot(t, 2)

	result, err := ApplyPolicySnapshot(runtime, snapshot, PolicyApplyOptions{
		SnapshotPath:   path,
		ObjectChecksum: "obj",
		Now:            time.Now(),
	})
	if err != nil {
		t.Fatalf("ApplyPolicySnapshot() error = %v", err)
	}
	if result.Status != policyApplyStatusApplied || result.ActiveSlot != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}

	cfg, err := readRuntimeConfig(runtime.Collection.Maps["runtime_config"])
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PolicyVersion != 2 || cfg.ActiveSlot != 1 {
		t.Fatalf("runtime_config = %#v", cfg)
	}

	key, err := cidrPolicyKey(snapshot.BlacklistV4[0])
	if err != nil {
		t.Fatal(err)
	}
	var value CIDRPolicyValue
	if err := runtime.Collection.Maps["blacklist_v4_b"].Lookup(&key, &value); err != nil {
		t.Fatalf("blacklist_v4_b missing entry: %v", err)
	}
	if value.RuleID != 77 {
		t.Fatalf("unexpected blacklist value: %#v", value)
	}

	loaded, err := LoadLastValidSnapshot(path)
	if err != nil {
		t.Fatalf("LoadLastValidSnapshot() error = %v", err)
	}
	if loaded.Policy == nil || loaded.Policy.Version != 2 {
		t.Fatalf("last-valid policy not persisted: %#v", loaded)
	}
}

func TestApplyPolicySnapshotRollbackKeepsActiveSlotOnPopulateFailure(t *testing.T) {
	runtime := newPolicyApplyTestRuntime(t, true)
	path := filepath.Join(t.TempDir(), "last-valid.json")
	snapshot := signedTestPolicySnapshot(t, 2)

	result, err := ApplyPolicySnapshot(runtime, snapshot, PolicyApplyOptions{
		SnapshotPath:   path,
		ObjectChecksum: "obj",
		Now:            time.Now(),
	})
	if err == nil {
		t.Fatal("expected apply failure")
	}
	if result.ErrorStage != "populate_blacklist" {
		t.Fatalf("unexpected failure result: %#v", result)
	}

	cfg, err := readRuntimeConfig(runtime.Collection.Maps["runtime_config"])
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PolicyVersion != 1 || cfg.ActiveSlot != 0 {
		t.Fatalf("runtime_config changed after failed apply: %#v", cfg)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("last-valid snapshot should not be written on failure, stat err=%v", err)
	}
	key, err := cidrPolicyKey(snapshot.WhitelistV4[0])
	if err != nil {
		t.Fatal(err)
	}
	var value CIDRPolicyValue
	if err := runtime.Collection.Maps["whitelist_v4_b"].Lookup(&key, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("inactive whitelist was not rolled back, lookup err=%v value=%#v", err, value)
	}
}

func TestLastValidSnapshotBackwardCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	legacy := DefaultSnapshot("obj")
	legacy.PolicyVersion = 9
	if err := SaveLastValidSnapshot(path, legacy); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadLastValidSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Policy != nil || loaded.PolicyVersion != 9 {
		t.Fatalf("legacy snapshot changed: %#v", loaded)
	}

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policy := signedTestPolicySnapshot(t, 10)
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadLastValidSnapshot(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Policy == nil || loaded.PolicyVersion != 10 {
		t.Fatalf("standalone policy did not load as last-valid: %#v", loaded)
	}
}

func signedTestPolicySnapshot(t *testing.T, version uint32) PolicySnapshot {
	t.Helper()
	return resignTestPolicySnapshot(t, testPolicySnapshot(t, version))
}

func resignTestPolicySnapshot(t *testing.T, snapshot PolicySnapshot) PolicySnapshot {
	t.Helper()
	signed, err := SignPolicySnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func testPolicySnapshot(t *testing.T, version uint32) PolicySnapshot {
	t.Helper()
	return PolicySnapshot{
		SchemaVersion:  policySnapshotSchemaVersion,
		Version:        version,
		ObjectChecksum: "obj",
		FeatureFlags:   []string{"tx_devmap", "ipv4"},
		Runtime: PolicyRuntimeConfig{
			MalformedPolicy: actionDrop,
			SampleDenom:     1,
		},
		WhitelistV4: []PolicyCIDREntry{
			{EntryID: 1, CIDR: "203.0.113.10/32", Priority: 10, Action: actionPass, SourceType: 1, Scope: policyScopeGlobal},
			{EntryID: 2, CIDR: "198.51.100.0/24", Priority: 10, Action: actionPass, SourceType: 1, Scope: policyScopeGlobal},
		},
		BlacklistV4: []PolicyCIDREntry{
			{EntryID: 3, CIDR: "198.51.100.10/32", Priority: 10, Action: actionDrop, SourceType: 1, Scope: policyScopeGlobal, RuleID: 77},
		},
		Services: []PolicyService{
			{
				ServiceID:          10,
				ForwardingPolicyID: 20,
				DstV4:              "203.0.113.10",
				DstPort:            443,
				Proto:              6,
				Action:             actionRedirect,
				Priority:           10,
				OutputIfindex:      1,
				DevmapKey:          3,
				NeighborStatus:     neighborResolved,
				DstMAC:             "02:00:00:00:00:02",
				SrcMAC:             "02:00:00:00:00:01",
			},
		},
		Rules: []PolicyRule{
			{RuleID: 2, Priority: 10, Action: actionDrop, Mode: 1},
		},
	}
}

func newPolicyApplyTestRuntime(t *testing.T, brokenBlacklist bool) *Runtime {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock() error = %v", err)
	}

	maps := map[string]*ebpf.Map{
		"runtime_config": newTestMap(t, &ebpf.MapSpec{
			Name:       "runtime_config",
			Type:       ebpf.Array,
			KeySize:    uint32(unsafe.Sizeof(uint32(0))),
			ValueSize:  uint32(unsafe.Sizeof(RuntimeConfigValue{})),
			MaxEntries: 1,
		}),
		"whitelist_v4_a":      newCIDRTestMap(t, "whitelist_v4_a", false),
		"whitelist_v4_b":      newCIDRTestMap(t, "whitelist_v4_b", false),
		"blacklist_v4_a":      newCIDRTestMap(t, "blacklist_v4_a", false),
		"blacklist_v4_b":      newCIDRTestMap(t, "blacklist_v4_b", brokenBlacklist),
		"service_allowlist_a": newServiceTestMap(t, "service_allowlist_a"),
		"service_allowlist_b": newServiceTestMap(t, "service_allowlist_b"),
		"rule_config_a":       newRuleTestMap(t, "rule_config_a"),
		"rule_config_b":       newRuleTestMap(t, "rule_config_b"),
		"tx_devmap": newTestMap(t, &ebpf.MapSpec{
			Name:       "tx_devmap_test",
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(uint32(0))),
			ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
			MaxEntries: 8,
		}),
	}
	t.Cleanup(func() {
		for _, m := range maps {
			_ = m.Close()
		}
	})

	key := uint32(0)
	cfg := RuntimeConfigValue{
		ActiveSlot:        0,
		PolicyVersion:     1,
		MalformedPolicy:   actionDrop,
		SampleDenom:       1,
		UpdatedAtUnixNano: 1,
	}
	if err := maps["runtime_config"].Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed runtime_config: %v", err)
	}

	return &Runtime{
		Collection:     &ebpf.Collection{Maps: maps},
		ObjectChecksum: "obj",
	}
}

func newCIDRTestMap(t *testing.T, name string, brokenValue bool) *ebpf.Map {
	t.Helper()
	valueSize := uint32(unsafe.Sizeof(CIDRPolicyValue{}))
	if brokenValue {
		valueSize = 1
	}
	return newTestMap(t, &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(LPMV4Key{})),
		ValueSize:  valueSize,
		MaxEntries: 16,
		Flags:      uint32(unix.BPF_F_NO_PREALLOC),
	})
}

func newServiceTestMap(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	return newTestMap(t, &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(ServiceKey{})),
		ValueSize:  uint32(unsafe.Sizeof(ServiceValue{})),
		MaxEntries: 16,
	})
}

func newRuleTestMap(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	return newTestMap(t, &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(RuleValue{})),
		MaxEntries: 8,
	})
}

func newTestMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("creating eBPF map %s requires BPF privileges: %v", spec.Name, err)
		}
		t.Fatalf("NewMap(%s) error = %v", spec.Name, err)
	}
	return m
}

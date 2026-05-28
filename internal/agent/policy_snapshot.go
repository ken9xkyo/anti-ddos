package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
	"unsafe"
)

const policySnapshotSchemaVersion = 1

type PolicySnapshot struct {
	SchemaVersion  int      `json:"schema_version"`
	Version        uint32   `json:"version"`
	Checksum       string   `json:"checksum"`
	ObjectChecksum string   `json:"object_checksum"`
	FeatureFlags   []string `json:"feature_flags,omitempty"`

	Runtime     PolicyRuntimeConfig `json:"runtime"`
	WhitelistV4 []PolicyCIDREntry   `json:"whitelist_v4,omitempty"`
	BlacklistV4 []PolicyCIDREntry   `json:"blacklist_v4,omitempty"`
	Services    []PolicyService     `json:"services,omitempty"`
	Rules       []PolicyRule        `json:"rules,omitempty"`
}

type PolicyRuntimeConfig struct {
	MalformedPolicy uint32 `json:"malformed_policy"`
	SampleDenom     uint32 `json:"sample_denom"`
}

type PolicyCIDREntry struct {
	EntryID         uint32 `json:"entry_id"`
	CIDR            string `json:"cidr"`
	Priority        uint32 `json:"priority"`
	Action          uint32 `json:"action"`
	SourceType      uint32 `json:"source_type"`
	Scope           uint32 `json:"scope"`
	ServiceID       uint32 `json:"service_id,omitempty"`
	Score           uint32 `json:"score,omitempty"`
	RuleID          uint32 `json:"rule_id,omitempty"`
	ExpiresAtUnixNS uint64 `json:"expires_at_unix_ns,omitempty"`
}

type PolicyService struct {
	ServiceID          uint32 `json:"service_id"`
	ForwardingPolicyID uint32 `json:"forwarding_policy_id"`
	DstV4              string `json:"dst_v4"`
	DstPort            uint16 `json:"dst_port"`
	Proto              uint8  `json:"proto"`
	Action             uint32 `json:"action"`
	Priority           uint32 `json:"priority"`
	DefaultRuleID      uint32 `json:"default_rule_id,omitempty"`
	OutputIfindex      uint32 `json:"output_ifindex"`
	DevmapKey          uint32 `json:"devmap_key"`
	NeighborStatus     uint32 `json:"neighbor_status"`
	DstMAC             string `json:"dst_mac"`
	SrcMAC             string `json:"src_mac"`
}

type PolicyRule struct {
	RuleID          uint32 `json:"rule_id"`
	Priority        uint32 `json:"priority"`
	Action          uint32 `json:"action"`
	Mode            uint32 `json:"mode"`
	ServiceID       uint32 `json:"service_id,omitempty"`
	ThresholdPPS    uint32 `json:"threshold_pps,omitempty"`
	ThresholdBPS    uint32 `json:"threshold_bps,omitempty"`
	ThresholdCPS    uint32 `json:"threshold_cps,omitempty"`
	BurstPackets    uint32 `json:"burst_packets,omitempty"`
	BurstBytes      uint32 `json:"burst_bytes,omitempty"`
	SampleDenom     uint32 `json:"sample_denom,omitempty"`
	ExpiresAtUnixNS uint64 `json:"expires_at_unix_ns,omitempty"`
}

type PolicySnapshotVerifyOptions struct {
	CurrentVersion    uint32
	ObjectChecksum    string
	Now               time.Time
	CapacityOverrides map[string]uint32
	MemoryBudgetBytes uint64
}

type PolicyMapStat struct {
	Entries              uint32 `json:"entries"`
	Capacity             uint32 `json:"capacity"`
	EstimatedMemoryBytes uint64 `json:"estimated_memory_bytes"`
}

type PolicySnapshotStats struct {
	Maps                 map[string]PolicyMapStat `json:"maps"`
	EstimatedMemoryBytes uint64                   `json:"estimated_memory_bytes"`
}

type canonicalPolicySnapshot struct {
	SchemaVersion  int                 `json:"schema_version"`
	Version        uint32              `json:"version"`
	ObjectChecksum string              `json:"object_checksum"`
	FeatureFlags   []string            `json:"feature_flags,omitempty"`
	Runtime        PolicyRuntimeConfig `json:"runtime"`
	WhitelistV4    []PolicyCIDREntry   `json:"whitelist_v4,omitempty"`
	BlacklistV4    []PolicyCIDREntry   `json:"blacklist_v4,omitempty"`
	Services       []PolicyService     `json:"services,omitempty"`
	Rules          []PolicyRule        `json:"rules,omitempty"`
}

var supportedPolicyFeatureFlags = map[string]struct{}{
	"policy_snapshot_v1": {},
	"ipv4":               {},
	"ab_policy_maps":     {},
	"tx_devmap":          {},
}

func LoadPolicySnapshot(path string) (PolicySnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PolicySnapshot{}, err
	}
	return DecodePolicySnapshot(raw)
}

func DecodePolicySnapshot(raw []byte) (PolicySnapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var snapshot PolicySnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return PolicySnapshot{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return PolicySnapshot{}, errors.New("policy snapshot contains trailing JSON values")
	} else if !errors.Is(err, io.EOF) {
		return PolicySnapshot{}, err
	}
	return snapshot, nil
}

func CanonicalPolicyChecksum(snapshot PolicySnapshot) (string, error) {
	canonical, err := canonicalizePolicySnapshot(snapshot)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func SignPolicySnapshot(snapshot PolicySnapshot) (PolicySnapshot, error) {
	checksum, err := CanonicalPolicyChecksum(snapshot)
	if err != nil {
		return PolicySnapshot{}, err
	}
	snapshot = normalizePolicySnapshot(snapshot)
	snapshot.Checksum = checksum
	return snapshot, nil
}

func VerifyPolicySnapshot(snapshot PolicySnapshot, options PolicySnapshotVerifyOptions) (PolicySnapshotStats, error) {
	providedChecksum := snapshot.Checksum
	snapshot = normalizePolicySnapshot(snapshot)
	snapshot.Checksum = providedChecksum
	if options.Now.IsZero() {
		options.Now = time.Now()
	}

	var errs []error
	if snapshot.SchemaVersion != policySnapshotSchemaVersion {
		errs = append(errs, fmt.Errorf("unsupported policy snapshot schema_version %d", snapshot.SchemaVersion))
	}
	if snapshot.Version == 0 {
		errs = append(errs, errors.New("policy snapshot version must be non-zero"))
	}
	if strings.TrimSpace(snapshot.ObjectChecksum) == "" {
		errs = append(errs, errors.New("policy snapshot object_checksum is required"))
	}
	if options.CurrentVersion != 0 && snapshot.Version <= options.CurrentVersion {
		errs = append(errs, fmt.Errorf("policy snapshot version %d is not newer than active version %d", snapshot.Version, options.CurrentVersion))
	}
	if options.ObjectChecksum != "" && snapshot.ObjectChecksum != "" && snapshot.ObjectChecksum != options.ObjectChecksum {
		errs = append(errs, fmt.Errorf("policy snapshot object_checksum mismatch: expected %s got %s", options.ObjectChecksum, snapshot.ObjectChecksum))
	}
	if snapshot.Checksum == "" {
		errs = append(errs, errors.New("policy snapshot checksum is required"))
	} else if expected, err := CanonicalPolicyChecksum(snapshot); err != nil {
		errs = append(errs, err)
	} else if expected != snapshot.Checksum {
		errs = append(errs, fmt.Errorf("policy snapshot checksum mismatch: expected %s got %s", expected, snapshot.Checksum))
	}
	if snapshot.Runtime.MalformedPolicy != actionDrop {
		errs = append(errs, fmt.Errorf("runtime.malformed_policy must be ACTION_DROP (%d)", actionDrop))
	}
	if snapshot.Runtime.SampleDenom > maxEventSampleDenom {
		errs = append(errs, fmt.Errorf("runtime.sample_denom exceeds max %d", maxEventSampleDenom))
	}
	for _, flag := range snapshot.FeatureFlags {
		if _, ok := supportedPolicyFeatureFlags[flag]; !ok {
			errs = append(errs, fmt.Errorf("unsupported policy feature flag %q", flag))
		}
	}

	stats, statsErr := validatePolicyEntries(snapshot, options)
	if statsErr != nil {
		errs = append(errs, statsErr)
	}
	if len(errs) > 0 {
		return stats, errors.Join(errs...)
	}
	return stats, nil
}

func canonicalizePolicySnapshot(snapshot PolicySnapshot) (canonicalPolicySnapshot, error) {
	snapshot = normalizePolicySnapshot(snapshot)
	return canonicalPolicySnapshot{
		SchemaVersion:  snapshot.SchemaVersion,
		Version:        snapshot.Version,
		ObjectChecksum: snapshot.ObjectChecksum,
		FeatureFlags:   snapshot.FeatureFlags,
		Runtime:        snapshot.Runtime,
		WhitelistV4:    snapshot.WhitelistV4,
		BlacklistV4:    snapshot.BlacklistV4,
		Services:       snapshot.Services,
		Rules:          snapshot.Rules,
	}, nil
}

func normalizePolicySnapshot(snapshot PolicySnapshot) PolicySnapshot {
	snapshot.Checksum = ""
	snapshot.FeatureFlags = append([]string(nil), snapshot.FeatureFlags...)
	snapshot.WhitelistV4 = append([]PolicyCIDREntry(nil), snapshot.WhitelistV4...)
	snapshot.BlacklistV4 = append([]PolicyCIDREntry(nil), snapshot.BlacklistV4...)
	snapshot.Services = append([]PolicyService(nil), snapshot.Services...)
	snapshot.Rules = append([]PolicyRule(nil), snapshot.Rules...)
	if snapshot.Runtime.MalformedPolicy == 0 {
		snapshot.Runtime.MalformedPolicy = actionDrop
	}
	sort.Strings(snapshot.FeatureFlags)
	sort.Slice(snapshot.WhitelistV4, func(i, j int) bool {
		return cidrEntryLess(snapshot.WhitelistV4[i], snapshot.WhitelistV4[j])
	})
	sort.Slice(snapshot.BlacklistV4, func(i, j int) bool {
		return cidrEntryLess(snapshot.BlacklistV4[i], snapshot.BlacklistV4[j])
	})
	sort.Slice(snapshot.Services, func(i, j int) bool {
		left := snapshot.Services[i]
		right := snapshot.Services[j]
		if left.DstV4 != right.DstV4 {
			return left.DstV4 < right.DstV4
		}
		if left.Proto != right.Proto {
			return left.Proto < right.Proto
		}
		if left.DstPort != right.DstPort {
			return left.DstPort < right.DstPort
		}
		return left.ServiceID < right.ServiceID
	})
	sort.Slice(snapshot.Rules, func(i, j int) bool {
		left := snapshot.Rules[i]
		right := snapshot.Rules[j]
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.Priority < right.Priority
	})
	return snapshot
}

func cidrEntryLess(left, right PolicyCIDREntry) bool {
	if left.CIDR != right.CIDR {
		return left.CIDR < right.CIDR
	}
	if left.Scope != right.Scope {
		return left.Scope < right.Scope
	}
	if left.ServiceID != right.ServiceID {
		return left.ServiceID < right.ServiceID
	}
	return left.EntryID < right.EntryID
}

func validatePolicyEntries(snapshot PolicySnapshot, options PolicySnapshotVerifyOptions) (PolicySnapshotStats, error) {
	capacity := func(name string) uint32 {
		if options.CapacityOverrides != nil {
			if value, ok := options.CapacityOverrides[name]; ok {
				return value
			}
		}
		switch name {
		case "whitelist_v4":
			return ExpectedMaps["whitelist_v4_a"].MaxEntries
		case "blacklist_v4":
			return ExpectedMaps["blacklist_v4_a"].MaxEntries
		case "service_allowlist":
			return ExpectedMaps["service_allowlist_a"].MaxEntries
		case "rule_config":
			return ExpectedMaps["rule_config_a"].MaxEntries
		case "tx_devmap":
			return ExpectedMaps["tx_devmap"].MaxEntries
		default:
			return 0
		}
	}

	stats := PolicySnapshotStats{Maps: make(map[string]PolicyMapStat)}
	var errs []error

	addStat := func(name string, entries uint32, keySize, valueSize uintptr) {
		cap := capacity(name)
		estimate := uint64(entries) * uint64(keySize+valueSize)
		stats.Maps[name] = PolicyMapStat{
			Entries:              entries,
			Capacity:             cap,
			EstimatedMemoryBytes: estimate,
		}
		stats.EstimatedMemoryBytes += estimate
		if entries > cap {
			errs = append(errs, fmt.Errorf("%s entries %d exceed capacity %d", name, entries, cap))
		}
	}

	nowNS := uint64(options.Now.UnixNano())
	whitelistKeys := make(map[string]struct{}, len(snapshot.WhitelistV4))
	for _, entry := range snapshot.WhitelistV4 {
		key, err := cidrPolicyKey(entry)
		if err != nil {
			errs = append(errs, fmt.Errorf("whitelist_v4 entry %d: %w", entry.EntryID, err))
			continue
		}
		if entry.ExpiresAtUnixNS != 0 && entry.ExpiresAtUnixNS <= nowNS {
			errs = append(errs, fmt.Errorf("whitelist_v4 entry %d is expired", entry.EntryID))
		}
		mapKey := fmt.Sprintf("%d:%d", key.PrefixLen, key.Addr)
		if _, ok := whitelistKeys[mapKey]; ok {
			errs = append(errs, fmt.Errorf("duplicate whitelist_v4 key %s", entry.CIDR))
		}
		whitelistKeys[mapKey] = struct{}{}
	}
	addStat("whitelist_v4", uint32(len(snapshot.WhitelistV4)), unsafe.Sizeof(LPMV4Key{}), unsafe.Sizeof(CIDRPolicyValue{}))

	blacklistKeys := make(map[string]struct{}, len(snapshot.BlacklistV4))
	for _, entry := range snapshot.BlacklistV4 {
		key, err := cidrPolicyKey(entry)
		if err != nil {
			errs = append(errs, fmt.Errorf("blacklist_v4 entry %d: %w", entry.EntryID, err))
			continue
		}
		if entry.ExpiresAtUnixNS != 0 && entry.ExpiresAtUnixNS <= nowNS {
			errs = append(errs, fmt.Errorf("blacklist_v4 entry %d is expired", entry.EntryID))
		}
		mapKey := fmt.Sprintf("%d:%d", key.PrefixLen, key.Addr)
		if _, ok := blacklistKeys[mapKey]; ok {
			errs = append(errs, fmt.Errorf("duplicate blacklist_v4 key %s", entry.CIDR))
		}
		blacklistKeys[mapKey] = struct{}{}
	}
	addStat("blacklist_v4", uint32(len(snapshot.BlacklistV4)), unsafe.Sizeof(LPMV4Key{}), unsafe.Sizeof(CIDRPolicyValue{}))

	serviceKeys := make(map[ServiceKey]struct{}, len(snapshot.Services))
	devmapTargets := make(map[uint32]uint32)
	serviceCap := capacity("service_allowlist")
	devmapCap := capacity("tx_devmap")
	for _, service := range snapshot.Services {
		key, value, err := serviceMapEntry(service)
		if err != nil {
			errs = append(errs, fmt.Errorf("service %d: %w", service.ServiceID, err))
			continue
		}
		if serviceCap > 0 && uint32(len(snapshot.Services)) > serviceCap {
			continue
		}
		if _, ok := serviceKeys[key]; ok {
			errs = append(errs, fmt.Errorf("duplicate service_allowlist key dst=%s proto=%d port=%d", service.DstV4, service.Proto, service.DstPort))
		}
		serviceKeys[key] = struct{}{}
		if devmapCap > 0 && value.DevmapKey >= devmapCap {
			errs = append(errs, fmt.Errorf("service %d devmap_key %d exceeds capacity %d", service.ServiceID, value.DevmapKey, devmapCap))
		}
		if existing, ok := devmapTargets[value.DevmapKey]; ok && existing != value.OutputIfindex {
			errs = append(errs, fmt.Errorf("devmap_key %d has conflicting output_ifindex values %d and %d", value.DevmapKey, existing, value.OutputIfindex))
		}
		devmapTargets[value.DevmapKey] = value.OutputIfindex
	}
	addStat("service_allowlist", uint32(len(snapshot.Services)), unsafe.Sizeof(ServiceKey{}), unsafe.Sizeof(ServiceValue{}))
	addStat("tx_devmap", uint32(len(devmapTargets)), unsafe.Sizeof(uint32(0)), unsafe.Sizeof(uint32(0)))

	ruleIDs := make(map[uint32]struct{}, len(snapshot.Rules))
	ruleCap := capacity("rule_config")
	for _, rule := range snapshot.Rules {
		if ruleCap > 0 && rule.RuleID >= ruleCap {
			errs = append(errs, fmt.Errorf("rule_config rule_id %d exceeds max index %d", rule.RuleID, ruleCap-1))
		}
		if rule.ExpiresAtUnixNS != 0 && rule.ExpiresAtUnixNS <= nowNS {
			errs = append(errs, fmt.Errorf("rule_config rule_id %d is expired", rule.RuleID))
		}
		if rule.SampleDenom > maxEventSampleDenom {
			errs = append(errs, fmt.Errorf("rule_config rule_id %d sample_denom exceeds max %d", rule.RuleID, maxEventSampleDenom))
		}
		if _, ok := ruleIDs[rule.RuleID]; ok {
			errs = append(errs, fmt.Errorf("duplicate rule_config rule_id %d", rule.RuleID))
		}
		ruleIDs[rule.RuleID] = struct{}{}
	}
	addStat("rule_config", uint32(len(snapshot.Rules)), unsafe.Sizeof(uint32(0)), unsafe.Sizeof(RuleValue{}))

	if options.MemoryBudgetBytes > 0 && stats.EstimatedMemoryBytes > options.MemoryBudgetBytes {
		errs = append(errs, fmt.Errorf("policy estimated memory %d exceeds budget %d", stats.EstimatedMemoryBytes, options.MemoryBudgetBytes))
	}
	if len(errs) > 0 {
		return stats, errors.Join(errs...)
	}
	return stats, nil
}

func cidrPolicyKey(entry PolicyCIDREntry) (LPMV4Key, error) {
	prefix, err := parseV4Prefix(entry.CIDR)
	if err != nil {
		return LPMV4Key{}, err
	}
	addr := prefix.Masked().Addr().As4()
	return LPMV4Key{
		PrefixLen: uint32(prefix.Bits()),
		Addr:      binary.LittleEndian.Uint32(addr[:]),
	}, nil
}

func cidrPolicyValue(entry PolicyCIDREntry) CIDRPolicyValue {
	return CIDRPolicyValue{
		EntryID:         entry.EntryID,
		Priority:        entry.Priority,
		Action:          entry.Action,
		SourceType:      entry.SourceType,
		Scope:           entry.Scope,
		ServiceID:       entry.ServiceID,
		Score:           entry.Score,
		RuleID:          entry.RuleID,
		ExpiresAtUnixNS: entry.ExpiresAtUnixNS,
	}
}

func serviceMapEntry(service PolicyService) (ServiceKey, ServiceValue, error) {
	addr, err := parseV4Addr(service.DstV4)
	if err != nil {
		return ServiceKey{}, ServiceValue{}, err
	}
	if service.ServiceID == 0 {
		return ServiceKey{}, ServiceValue{}, errors.New("service_id must be non-zero")
	}
	if service.Action != actionRedirect {
		return ServiceKey{}, ServiceValue{}, fmt.Errorf("action must be ACTION_REDIRECT (%d)", actionRedirect)
	}
	switch service.Proto {
	case l4TCP, l4UDP:
		if service.DstPort == 0 {
			return ServiceKey{}, ServiceValue{}, errors.New("tcp/udp service dst_port must be non-zero")
		}
	case l4ICMP:
		if service.DstPort != 0 {
			return ServiceKey{}, ServiceValue{}, errors.New("icmp service dst_port must be 0")
		}
	default:
		return ServiceKey{}, ServiceValue{}, fmt.Errorf("unsupported service proto %d", service.Proto)
	}
	if service.OutputIfindex == 0 {
		return ServiceKey{}, ServiceValue{}, errors.New("output_ifindex must be non-zero")
	}
	if service.NeighborStatus != neighborResolved {
		return ServiceKey{}, ServiceValue{}, fmt.Errorf("neighbor_status must be resolved (%d)", neighborResolved)
	}
	dstMAC, err := parsePolicyMAC(service.DstMAC)
	if err != nil {
		return ServiceKey{}, ServiceValue{}, fmt.Errorf("dst_mac: %w", err)
	}
	srcMAC, err := parsePolicyMAC(service.SrcMAC)
	if err != nil {
		return ServiceKey{}, ServiceValue{}, fmt.Errorf("src_mac: %w", err)
	}
	key := ServiceKey{
		DstV4:   binary.LittleEndian.Uint32(addr[:]),
		DstPort: service.DstPort,
		Proto:   service.Proto,
	}
	value := ServiceValue{
		ServiceID:          service.ServiceID,
		ForwardingPolicyID: service.ForwardingPolicyID,
		Action:             service.Action,
		Priority:           service.Priority,
		DefaultRuleID:      service.DefaultRuleID,
		OutputIfindex:      service.OutputIfindex,
		DevmapKey:          service.DevmapKey,
		NeighborStatus:     service.NeighborStatus,
		DstMAC:             dstMAC,
		SrcMAC:             srcMAC,
	}
	return key, value, nil
}

func ruleMapEntry(rule PolicyRule) (uint32, RuleValue) {
	return rule.RuleID, RuleValue{
		RuleID:          rule.RuleID,
		Priority:        rule.Priority,
		Action:          rule.Action,
		Mode:            rule.Mode,
		ServiceID:       rule.ServiceID,
		ThresholdPPS:    rule.ThresholdPPS,
		ThresholdBPS:    rule.ThresholdBPS,
		ThresholdCPS:    rule.ThresholdCPS,
		BurstPackets:    rule.BurstPackets,
		BurstBytes:      rule.BurstBytes,
		SampleDenom:     rule.SampleDenom,
		ExpiresAtUnixNS: rule.ExpiresAtUnixNS,
	}
}

func parseV4Prefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("CIDR is required")
	}
	if !strings.Contains(value, "/") {
		addr, err := parseV4Addr(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(netip.AddrFrom4(addr), 32), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("IPv6 prefix %q is not supported in phase 03", value)
	}
	return prefix.Masked(), nil
}

func parseV4Addr(value string) ([4]byte, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return [4]byte{}, err
	}
	if !addr.Is4() {
		return [4]byte{}, fmt.Errorf("IPv6 address %q is not supported in phase 03", value)
	}
	return addr.As4(), nil
}

func parsePolicyMAC(value string) ([6]byte, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		return [6]byte{}, err
	}
	if len(parsed) != 6 {
		return [6]byte{}, fmt.Errorf("expected 6-byte MAC, got %d bytes", len(parsed))
	}
	var out [6]byte
	copy(out[:], parsed)
	var zero [6]byte
	if out == zero {
		return [6]byte{}, errors.New("zero MAC is not allowed")
	}
	return out, nil
}

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

	Runtime             PolicyRuntimeConfig        `json:"runtime"`
	WhitelistV4         []PolicyCIDREntry          `json:"whitelist_v4,omitempty"`
	BlacklistV4         []PolicyCIDREntry          `json:"blacklist_v4,omitempty"`
	UDPSourcePortBlocks []PolicyUDPSourcePortBlock `json:"udp_source_port_blocks,omitempty"`
	Services            []PolicyService            `json:"services,omitempty"`
	Rules               []PolicyRule               `json:"rules,omitempty"`
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

type PolicyUDPSourcePortBlock struct {
	EntryID         uint32 `json:"entry_id"`
	Port            uint16 `json:"port"`
	Scope           uint32 `json:"scope,omitempty"`
	ServiceID       uint32 `json:"service_id,omitempty"`
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
	OutputInterface    string `json:"output_interface,omitempty"`
	OutputIfindex      uint32 `json:"output_ifindex"`
	DevmapKey          uint32 `json:"devmap_key"`
	NeighborStatus     uint32 `json:"neighbor_status"`
	DstMAC             string `json:"dst_mac"`
	SrcMAC             string `json:"src_mac"`
}

type PolicyRule struct {
	RuleID          uint32 `json:"rule_id"`
	ScopeType       string `json:"scope_type,omitempty"`
	Priority        uint32 `json:"priority"`
	Action          uint32 `json:"action"`
	Mode            uint32 `json:"mode"`
	ServiceID       uint32 `json:"service_id,omitempty"`
	Dimension       uint32 `json:"dimension,omitempty"`
	ThresholdPPS    uint32 `json:"threshold_pps,omitempty"`
	ThresholdBPS    uint32 `json:"threshold_bps,omitempty"`
	ThresholdCPS    uint32 `json:"threshold_cps,omitempty"`
	BurstPackets    uint32 `json:"burst_packets,omitempty"`
	BurstBytes      uint32 `json:"burst_bytes,omitempty"`
	SampleDenom     uint32 `json:"sample_denom,omitempty"`
	ExpiresAtUnixNS uint64 `json:"expires_at_unix_ns,omitempty"`
}

type PolicySnapshotVerifyOptions struct {
	CurrentVersion          uint32
	ObjectChecksum          string
	Now                     time.Time
	CapacityOverrides       map[string]uint32
	MemoryBudgetBytes       uint64
	AllowUnresolvedServices bool
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
	SchemaVersion       int                        `json:"schema_version"`
	Version             uint32                     `json:"version"`
	ObjectChecksum      string                     `json:"object_checksum"`
	FeatureFlags        []string                   `json:"feature_flags,omitempty"`
	Runtime             PolicyRuntimeConfig        `json:"runtime"`
	WhitelistV4         []PolicyCIDREntry          `json:"whitelist_v4,omitempty"`
	BlacklistV4         []PolicyCIDREntry          `json:"blacklist_v4,omitempty"`
	UDPSourcePortBlocks []PolicyUDPSourcePortBlock `json:"udp_source_port_blocks,omitempty"`
	Services            []PolicyService            `json:"services,omitempty"`
	Rules               []PolicyRule               `json:"rules,omitempty"`
}

var supportedPolicyFeatureFlags = map[string]struct{}{
	"policy_snapshot_v1":                {},
	"ipv4":                              {},
	"ab_policy_maps":                    {},
	"tx_devmap":                         {},
	"udp_src_port_block":                {},
	"service_scoped_whitelist_v4":       {},
	"service_scoped_blacklist_v4":       {},
	"service_scoped_udp_src_port_block": {},
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
		SchemaVersion:       snapshot.SchemaVersion,
		Version:             snapshot.Version,
		ObjectChecksum:      snapshot.ObjectChecksum,
		FeatureFlags:        snapshot.FeatureFlags,
		Runtime:             snapshot.Runtime,
		WhitelistV4:         snapshot.WhitelistV4,
		BlacklistV4:         snapshot.BlacklistV4,
		UDPSourcePortBlocks: snapshot.UDPSourcePortBlocks,
		Services:            snapshot.Services,
		Rules:               snapshot.Rules,
	}, nil
}

func normalizePolicySnapshot(snapshot PolicySnapshot) PolicySnapshot {
	snapshot.Checksum = ""
	snapshot.FeatureFlags = append([]string(nil), snapshot.FeatureFlags...)
	snapshot.WhitelistV4 = append([]PolicyCIDREntry(nil), snapshot.WhitelistV4...)
	snapshot.BlacklistV4 = append([]PolicyCIDREntry(nil), snapshot.BlacklistV4...)
	snapshot.UDPSourcePortBlocks = append([]PolicyUDPSourcePortBlock(nil), snapshot.UDPSourcePortBlocks...)
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
	sort.Slice(snapshot.UDPSourcePortBlocks, func(i, j int) bool {
		left := snapshot.UDPSourcePortBlocks[i]
		right := snapshot.UDPSourcePortBlocks[j]
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Scope != right.Scope {
			return left.Scope < right.Scope
		}
		if left.ServiceID != right.ServiceID {
			return left.ServiceID < right.ServiceID
		}
		return left.EntryID < right.EntryID
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
		case "whitelist_service_v4":
			return ExpectedMaps["whitelist_service_v4_a"].MaxEntries
		case "blacklist_v4":
			return ExpectedMaps["blacklist_v4_a"].MaxEntries
		case "blacklist_service_v4":
			return ExpectedMaps["blacklist_service_v4_a"].MaxEntries
		case "udp_source_port_blocks":
			return ExpectedMaps["udp_src_port_blocks_a"].MaxEntries
		case "udp_source_port_service_blocks":
			return ExpectedMaps["udp_src_port_service_blocks_a"].MaxEntries
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
	whitelistGlobalKeys := make(map[string]struct{}, len(snapshot.WhitelistV4))
	whitelistServiceKeys := make(map[string]struct{}, len(snapshot.WhitelistV4))
	var whitelistGlobalEntries uint32
	var whitelistServiceEntries uint32
	for _, entry := range snapshot.WhitelistV4 {
		if entry.ExpiresAtUnixNS != 0 && entry.ExpiresAtUnixNS <= nowNS {
			errs = append(errs, fmt.Errorf("whitelist_v4 entry %d is expired", entry.EntryID))
		}
		switch entry.Scope {
		case policyScopeGlobal:
			key, err := cidrPolicyKey(entry)
			if err != nil {
				errs = append(errs, fmt.Errorf("whitelist_v4 entry %d: %w", entry.EntryID, err))
				continue
			}
			mapKey := fmt.Sprintf("%d:%d", key.PrefixLen, key.Addr)
			if _, ok := whitelistGlobalKeys[mapKey]; ok {
				errs = append(errs, fmt.Errorf("duplicate whitelist_v4 key %s", entry.CIDR))
			}
			whitelistGlobalKeys[mapKey] = struct{}{}
			whitelistGlobalEntries++
		case policyScopeService:
			key, err := serviceCIDRPolicyKey(entry)
			if err != nil {
				errs = append(errs, fmt.Errorf("whitelist_service_v4 entry %d: %w", entry.EntryID, err))
				continue
			}
			mapKey := fmt.Sprintf("%d:%d:%d", key.ServiceID, key.PrefixLen, key.Addr)
			if _, ok := whitelistServiceKeys[mapKey]; ok {
				errs = append(errs, fmt.Errorf("duplicate whitelist_service_v4 key service_id=%d cidr=%s", entry.ServiceID, entry.CIDR))
			}
			whitelistServiceKeys[mapKey] = struct{}{}
			whitelistServiceEntries++
		default:
			errs = append(errs, fmt.Errorf("whitelist_v4 entry %d has unsupported scope %d", entry.EntryID, entry.Scope))
		}
	}
	addStat("whitelist_v4", whitelistGlobalEntries, unsafe.Sizeof(LPMV4Key{}), unsafe.Sizeof(CIDRPolicyValue{}))
	addStat("whitelist_service_v4", whitelistServiceEntries, unsafe.Sizeof(ServiceLPMV4Key{}), unsafe.Sizeof(CIDRPolicyValue{}))

	blacklistGlobalKeys := make(map[string]struct{}, len(snapshot.BlacklistV4))
	blacklistServiceKeys := make(map[string]struct{}, len(snapshot.BlacklistV4))
	var blacklistGlobalEntries uint32
	var blacklistServiceEntries uint32
	for _, entry := range snapshot.BlacklistV4 {
		if entry.ExpiresAtUnixNS != 0 && entry.ExpiresAtUnixNS <= nowNS {
			errs = append(errs, fmt.Errorf("blacklist_v4 entry %d is expired", entry.EntryID))
		}
		switch entry.Scope {
		case policyScopeGlobal:
			key, err := cidrPolicyKey(entry)
			if err != nil {
				errs = append(errs, fmt.Errorf("blacklist_v4 entry %d: %w", entry.EntryID, err))
				continue
			}
			mapKey := fmt.Sprintf("%d:%d", key.PrefixLen, key.Addr)
			if _, ok := blacklistGlobalKeys[mapKey]; ok {
				errs = append(errs, fmt.Errorf("duplicate blacklist_v4 key %s", entry.CIDR))
			}
			blacklistGlobalKeys[mapKey] = struct{}{}
			blacklistGlobalEntries++
		case policyScopeService:
			key, err := serviceCIDRPolicyKey(entry)
			if err != nil {
				errs = append(errs, fmt.Errorf("blacklist_service_v4 entry %d: %w", entry.EntryID, err))
				continue
			}
			mapKey := fmt.Sprintf("%d:%d:%d", key.ServiceID, key.PrefixLen, key.Addr)
			if _, ok := blacklistServiceKeys[mapKey]; ok {
				errs = append(errs, fmt.Errorf("duplicate blacklist_service_v4 key service_id=%d cidr=%s", entry.ServiceID, entry.CIDR))
			}
			blacklistServiceKeys[mapKey] = struct{}{}
			blacklistServiceEntries++
		default:
			errs = append(errs, fmt.Errorf("blacklist_v4 entry %d has unsupported scope %d", entry.EntryID, entry.Scope))
		}
	}
	addStat("blacklist_v4", blacklistGlobalEntries, unsafe.Sizeof(LPMV4Key{}), unsafe.Sizeof(CIDRPolicyValue{}))
	addStat("blacklist_service_v4", blacklistServiceEntries, unsafe.Sizeof(ServiceLPMV4Key{}), unsafe.Sizeof(CIDRPolicyValue{}))

	udpPortKeys := make(map[uint16]struct{}, len(snapshot.UDPSourcePortBlocks))
	udpServiceKeys := make(map[ServiceUDPSourcePortKey]struct{}, len(snapshot.UDPSourcePortBlocks))
	var udpGlobalEntries uint32
	var udpServiceEntries uint32
	for _, entry := range snapshot.UDPSourcePortBlocks {
		if entry.ExpiresAtUnixNS != 0 && entry.ExpiresAtUnixNS <= nowNS {
			errs = append(errs, fmt.Errorf("udp_source_port_blocks entry %d is expired", entry.EntryID))
		}
		switch entry.Scope {
		case policyScopeGlobal:
			if _, ok := udpPortKeys[entry.Port]; ok {
				errs = append(errs, fmt.Errorf("duplicate udp_source_port_blocks port %d", entry.Port))
			}
			udpPortKeys[entry.Port] = struct{}{}
			udpGlobalEntries++
		case policyScopeService:
			if entry.ServiceID == 0 {
				errs = append(errs, fmt.Errorf("udp_source_port_blocks entry %d service scope requires service_id", entry.EntryID))
				continue
			}
			key := ServiceUDPSourcePortKey{ServiceID: entry.ServiceID, Port: uint32(entry.Port)}
			if _, ok := udpServiceKeys[key]; ok {
				errs = append(errs, fmt.Errorf("duplicate udp_source_port_service_blocks service_id=%d port %d", entry.ServiceID, entry.Port))
			}
			udpServiceKeys[key] = struct{}{}
			udpServiceEntries++
		default:
			errs = append(errs, fmt.Errorf("udp_source_port_blocks entry %d has unsupported scope %d", entry.EntryID, entry.Scope))
		}
	}
	addStat("udp_source_port_blocks", udpGlobalEntries, unsafe.Sizeof(uint32(0)), unsafe.Sizeof(UDPSourcePortBlockValue{}))
	addStat("udp_source_port_service_blocks", udpServiceEntries, unsafe.Sizeof(ServiceUDPSourcePortKey{}), unsafe.Sizeof(UDPSourcePortBlockValue{}))

	serviceKeys := make(map[ServiceKey]struct{}, len(snapshot.Services))
	devmapTargets := make(map[uint32]uint32)
	devmapKeys := make(map[uint32]struct{})
	devmapCap := capacity("tx_devmap")
	for _, service := range snapshot.Services {
		key, err := serviceMapKey(service)
		if err != nil {
			errs = append(errs, fmt.Errorf("service %d: %w", service.ServiceID, err))
			continue
		}
		if _, ok := serviceKeys[key]; ok {
			errs = append(errs, fmt.Errorf("duplicate service_allowlist key dst=%s proto=%d port=%d", service.DstV4, service.Proto, service.DstPort))
		}
		serviceKeys[key] = struct{}{}
		if devmapCap > 0 && service.DevmapKey >= devmapCap {
			errs = append(errs, fmt.Errorf("service %d devmap_key %d exceeds capacity %d", service.ServiceID, service.DevmapKey, devmapCap))
		}
		devmapKeys[service.DevmapKey] = struct{}{}
		if serviceNeedsResolution(service) {
			if !options.AllowUnresolvedServices {
				if _, _, err := serviceMapEntry(service); err != nil {
					errs = append(errs, fmt.Errorf("service %d: %w", service.ServiceID, err))
				}
				continue
			}
			if strings.TrimSpace(service.OutputInterface) == "" {
				errs = append(errs, fmt.Errorf("service %d output_interface is required for unresolved forwarding metadata", service.ServiceID))
			}
			continue
		}
		_, value, err := serviceMapEntry(service)
		if err != nil {
			errs = append(errs, fmt.Errorf("service %d: %w", service.ServiceID, err))
			continue
		}
		if existing, ok := devmapTargets[value.DevmapKey]; ok && existing != value.OutputIfindex {
			errs = append(errs, fmt.Errorf("devmap_key %d has conflicting output_ifindex values %d and %d", value.DevmapKey, existing, value.OutputIfindex))
		}
		devmapTargets[value.DevmapKey] = value.OutputIfindex
	}
	addStat("service_allowlist", uint32(len(snapshot.Services)), unsafe.Sizeof(ServiceKey{}), unsafe.Sizeof(ServiceValue{}))
	addStat("tx_devmap", uint32(len(devmapKeys)), unsafe.Sizeof(uint32(0)), unsafe.Sizeof(uint32(0)))

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

func serviceCIDRPolicyKey(entry PolicyCIDREntry) (ServiceLPMV4Key, error) {
	if entry.ServiceID == 0 {
		return ServiceLPMV4Key{}, errors.New("service-scoped CIDR entry requires service_id")
	}
	prefix, err := parseV4Prefix(entry.CIDR)
	if err != nil {
		return ServiceLPMV4Key{}, err
	}
	addr := prefix.Masked().Addr().As4()
	return ServiceLPMV4Key{
		PrefixLen: uint32(32 + prefix.Bits()),
		ServiceID: entry.ServiceID,
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

func udpSourcePortBlockMapEntry(entry PolicyUDPSourcePortBlock) (uint32, UDPSourcePortBlockValue) {
	return uint32(entry.Port), UDPSourcePortBlockValue{
		EntryID:         entry.EntryID,
		Port:            uint32(entry.Port),
		Scope:           entry.Scope,
		ServiceID:       entry.ServiceID,
		ExpiresAtUnixNS: entry.ExpiresAtUnixNS,
	}
}

func udpSourcePortServiceBlockMapEntry(entry PolicyUDPSourcePortBlock) (ServiceUDPSourcePortKey, UDPSourcePortBlockValue) {
	return ServiceUDPSourcePortKey{ServiceID: entry.ServiceID, Port: uint32(entry.Port)}, UDPSourcePortBlockValue{
		EntryID:         entry.EntryID,
		Port:            uint32(entry.Port),
		Scope:           entry.Scope,
		ServiceID:       entry.ServiceID,
		ExpiresAtUnixNS: entry.ExpiresAtUnixNS,
	}
}

func serviceNeedsResolution(service PolicyService) bool {
	return service.OutputIfindex == 0 ||
		service.NeighborStatus != neighborResolved ||
		strings.TrimSpace(service.DstMAC) == "" ||
		strings.TrimSpace(service.SrcMAC) == ""
}

func serviceMapKey(service PolicyService) (ServiceKey, error) {
	addr, err := parseV4Addr(service.DstV4)
	if err != nil {
		return ServiceKey{}, err
	}
	if service.ServiceID == 0 {
		return ServiceKey{}, errors.New("service_id must be non-zero")
	}
	if service.Action != actionRedirect {
		return ServiceKey{}, fmt.Errorf("action must be ACTION_REDIRECT (%d)", actionRedirect)
	}
	switch service.Proto {
	case l4TCP, l4UDP:
		if service.DstPort == 0 {
			return ServiceKey{}, errors.New("tcp/udp service dst_port must be non-zero")
		}
	case l4ICMP:
		if service.DstPort != 0 {
			return ServiceKey{}, errors.New("icmp service dst_port must be 0")
		}
	default:
		return ServiceKey{}, fmt.Errorf("unsupported service proto %d", service.Proto)
	}
	return ServiceKey{
		DstV4:   binary.LittleEndian.Uint32(addr[:]),
		DstPort: service.DstPort,
		Proto:   service.Proto,
	}, nil
}

func serviceMapEntry(service PolicyService) (ServiceKey, ServiceValue, error) {
	key, err := serviceMapKey(service)
	if err != nil {
		return ServiceKey{}, ServiceValue{}, err
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
		Dimension:       rule.Dimension,
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

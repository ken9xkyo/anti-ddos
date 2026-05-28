package agent

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cilium/ebpf"
)

const (
	policyApplyStatusApplied = "applied"
	policyApplyStatusFailed  = "failed"
)

type PolicyApplyOptions struct {
	SnapshotPath      string
	ObjectChecksum    string
	Now               time.Time
	CapacityOverrides map[string]uint32
	MemoryBudgetBytes uint64
	Metrics           *Metrics
}

type PolicyDevmapStats struct {
	Touched    uint32 `json:"touched"`
	Updated    uint32 `json:"updated"`
	RolledBack uint32 `json:"rolled_back"`
}

type PolicyApplyResult struct {
	Version         uint32                   `json:"version"`
	PreviousVersion uint32                   `json:"previous_version"`
	Status          string                   `json:"status"`
	ActiveSlot      uint32                   `json:"active_slot"`
	MapStats        map[string]PolicyMapStat `json:"map_stats,omitempty"`
	DevmapStats     PolicyDevmapStats        `json:"devmap_stats"`
	ErrorStage      string                   `json:"error_stage,omitempty"`
	ErrorReason     string                   `json:"error_reason,omitempty"`
}

func ApplyPolicySnapshot(runtime *Runtime, snapshot PolicySnapshot, options PolicyApplyOptions) (PolicyApplyResult, error) {
	if runtime == nil || runtime.Collection == nil {
		return PolicyApplyResult{Version: snapshot.Version, Status: policyApplyStatusFailed, ErrorStage: "runtime", ErrorReason: "nil runtime collection"}, errors.New("nil runtime collection")
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if options.ObjectChecksum == "" {
		options.ObjectChecksum = runtime.ObjectChecksum
	}

	result := PolicyApplyResult{
		Version: snapshot.Version,
		Status:  policyApplyStatusFailed,
	}
	runtimeConfig := runtime.Collection.Maps["runtime_config"]
	currentConfig, err := readRuntimeConfig(runtimeConfig)
	if err != nil {
		return failPolicyApply(result, "runtime_config", err)
	}
	result.PreviousVersion = currentConfig.PolicyVersion
	result.ActiveSlot = currentConfig.ActiveSlot
	if currentConfig.ActiveSlot > 1 {
		return failPolicyApply(result, "runtime_config", fmt.Errorf("invalid active_slot %d", currentConfig.ActiveSlot))
	}

	verifyStats, err := VerifyPolicySnapshot(snapshot, PolicySnapshotVerifyOptions{
		CurrentVersion:    currentConfig.PolicyVersion,
		ObjectChecksum:    options.ObjectChecksum,
		Now:               options.Now,
		CapacityOverrides: options.CapacityOverrides,
		MemoryBudgetBytes: options.MemoryBudgetBytes,
	})
	result.MapStats = verifyStats.Maps
	if err != nil {
		return failPolicyApply(result, "validate", err)
	}

	checksum := snapshot.Checksum
	snapshot = normalizePolicySnapshot(snapshot)
	snapshot.Checksum = checksum
	inactiveSlot := uint32(1 - currentConfig.ActiveSlot)

	if err := clearInactivePolicySlot(runtime.Collection.Maps, inactiveSlot); err != nil {
		return failPolicyApply(result, "clear_inactive", err)
	}

	rollbackInactive := func() {
		_ = clearInactivePolicySlot(runtime.Collection.Maps, inactiveSlot)
	}

	if err := populateCIDRPolicyMap(policySlotMap(runtime.Collection.Maps, "whitelist_v4", inactiveSlot), snapshot.WhitelistV4); err != nil {
		rollbackInactive()
		return failPolicyApply(result, "populate_whitelist", err)
	}
	if err := populateCIDRPolicyMap(policySlotMap(runtime.Collection.Maps, "blacklist_v4", inactiveSlot), snapshot.BlacklistV4); err != nil {
		rollbackInactive()
		return failPolicyApply(result, "populate_blacklist", err)
	}
	if err := populateServiceMap(policySlotMap(runtime.Collection.Maps, "service_allowlist", inactiveSlot), snapshot.Services); err != nil {
		rollbackInactive()
		return failPolicyApply(result, "populate_services", err)
	}
	if err := populateRuleMap(policySlotMap(runtime.Collection.Maps, "rule_config", inactiveSlot), snapshot.Rules); err != nil {
		rollbackInactive()
		return failPolicyApply(result, "populate_rules", err)
	}

	devmapStats, rollbackDevmap, err := updateDevmapTargets(runtime.Collection.Maps["tx_devmap"], snapshot.Services)
	result.DevmapStats = devmapStats
	if err != nil {
		if rollbackDevmap != nil {
			result.DevmapStats.RolledBack = rollbackDevmap()
		}
		rollbackInactive()
		return failPolicyApply(result, "populate_tx_devmap", err)
	}

	nextConfig := RuntimeConfigValue{
		ActiveSlot:        inactiveSlot,
		PolicyVersion:     snapshot.Version,
		MalformedPolicy:   snapshot.Runtime.MalformedPolicy,
		SampleDenom:       snapshot.Runtime.SampleDenom,
		UpdatedAtUnixNano: uint64(options.Now.UnixNano()),
	}
	key := uint32(0)
	if err := runtimeConfig.Update(&key, &nextConfig, ebpf.UpdateAny); err != nil {
		if rollbackDevmap != nil {
			result.DevmapStats.RolledBack = rollbackDevmap()
		}
		rollbackInactive()
		return failPolicyApply(result, "runtime_flip", err)
	}

	lastValid := LastValidFromPolicySnapshot(snapshot, inactiveSlot, options.ObjectChecksum, options.Now)
	if options.SnapshotPath != "" {
		if err := SaveLastValidSnapshot(options.SnapshotPath, lastValid); err != nil {
			_ = runtimeConfig.Update(&key, &currentConfig, ebpf.UpdateAny)
			if rollbackDevmap != nil {
				result.DevmapStats.RolledBack = rollbackDevmap()
			}
			rollbackInactive()
			return failPolicyApply(result, "persist_last_valid", err)
		}
	}

	runtime.Snapshot = lastValid
	if options.Metrics != nil {
		options.Metrics.SetSnapshotVersion(snapshot.Version)
	}
	result.Status = policyApplyStatusApplied
	result.ActiveSlot = inactiveSlot
	return result, nil
}

func failPolicyApply(result PolicyApplyResult, stage string, err error) (PolicyApplyResult, error) {
	result.Status = policyApplyStatusFailed
	result.ErrorStage = stage
	result.ErrorReason = err.Error()
	return result, err
}

func readRuntimeConfig(runtimeConfig *ebpf.Map) (RuntimeConfigValue, error) {
	if runtimeConfig == nil {
		return RuntimeConfigValue{}, errors.New("runtime_config map not loaded")
	}
	key := uint32(0)
	var cfg RuntimeConfigValue
	if err := runtimeConfig.Lookup(&key, &cfg); err != nil {
		return RuntimeConfigValue{}, fmt.Errorf("lookup runtime_config[0]: %w", err)
	}
	return cfg, nil
}

func clearInactivePolicySlot(maps map[string]*ebpf.Map, slot uint32) error {
	if err := clearCIDRPolicyMap(policySlotMap(maps, "whitelist_v4", slot)); err != nil {
		return fmt.Errorf("clear whitelist_v4 slot %d: %w", slot, err)
	}
	if err := clearCIDRPolicyMap(policySlotMap(maps, "blacklist_v4", slot)); err != nil {
		return fmt.Errorf("clear blacklist_v4 slot %d: %w", slot, err)
	}
	if err := clearServicePolicyMap(policySlotMap(maps, "service_allowlist", slot)); err != nil {
		return fmt.Errorf("clear service_allowlist slot %d: %w", slot, err)
	}
	if err := clearRulePolicyMap(policySlotMap(maps, "rule_config", slot)); err != nil {
		return fmt.Errorf("clear rule_config slot %d: %w", slot, err)
	}
	return nil
}

func policySlotMap(maps map[string]*ebpf.Map, logical string, slot uint32) *ebpf.Map {
	suffix := "a"
	if slot == 1 {
		suffix = "b"
	}
	return maps[logical+"_"+suffix]
}

func clearCIDRPolicyMap(m *ebpf.Map) error {
	if m == nil {
		return errors.New("map not loaded")
	}
	var keys []LPMV4Key
	var key LPMV4Key
	var value CIDRPolicyValue
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func clearServicePolicyMap(m *ebpf.Map) error {
	if m == nil {
		return errors.New("map not loaded")
	}
	var keys []ServiceKey
	var key ServiceKey
	var value ServiceValue
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func clearRulePolicyMap(m *ebpf.Map) error {
	if m == nil {
		return errors.New("map not loaded")
	}
	var zero RuleValue
	for key := uint32(0); key < m.MaxEntries(); key++ {
		if err := m.Update(&key, &zero, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func populateCIDRPolicyMap(m *ebpf.Map, entries []PolicyCIDREntry) error {
	if m == nil {
		return errors.New("map not loaded")
	}
	for _, entry := range entries {
		key, err := cidrPolicyKey(entry)
		if err != nil {
			return err
		}
		value := cidrPolicyValue(entry)
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update cidr %s: %w", entry.CIDR, err)
		}
	}
	return nil
}

func populateServiceMap(m *ebpf.Map, services []PolicyService) error {
	if m == nil {
		return errors.New("map not loaded")
	}
	for _, service := range services {
		key, value, err := serviceMapEntry(service)
		if err != nil {
			return err
		}
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update service %d: %w", service.ServiceID, err)
		}
	}
	return nil
}

func populateRuleMap(m *ebpf.Map, rules []PolicyRule) error {
	if m == nil {
		return errors.New("map not loaded")
	}
	for _, rule := range rules {
		key, value := ruleMapEntry(rule)
		if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update rule %d: %w", rule.RuleID, err)
		}
	}
	return nil
}

type devmapBackup struct {
	value  uint32
	exists bool
}

func updateDevmapTargets(m *ebpf.Map, services []PolicyService) (PolicyDevmapStats, func() uint32, error) {
	stats := PolicyDevmapStats{}
	targets := make(map[uint32]uint32)
	for _, service := range services {
		if existing, ok := targets[service.DevmapKey]; ok && existing != service.OutputIfindex {
			return stats, nil, fmt.Errorf("devmap_key %d has conflicting output_ifindex values %d and %d", service.DevmapKey, existing, service.OutputIfindex)
		}
		targets[service.DevmapKey] = service.OutputIfindex
	}
	if len(targets) == 0 {
		return stats, func() uint32 { return 0 }, nil
	}
	if m == nil {
		return stats, nil, errors.New("tx_devmap map not loaded")
	}

	keys := make([]uint32, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	backups := make(map[uint32]devmapBackup, len(keys))
	updatedKeys := make([]uint32, 0, len(keys))
	rollback := func() uint32 {
		var rolledBack uint32
		for i := len(updatedKeys) - 1; i >= 0; i-- {
			key := updatedKeys[i]
			backup := backups[key]
			var err error
			if backup.exists {
				err = m.Update(&key, &backup.value, ebpf.UpdateAny)
			} else {
				err = m.Delete(&key)
			}
			if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
				rolledBack++
			}
		}
		return rolledBack
	}

	for _, key := range keys {
		desired := targets[key]
		stats.Touched++
		var existing uint32
		err := m.Lookup(&key, &existing)
		if err == nil {
			backups[key] = devmapBackup{value: existing, exists: true}
			if existing != desired {
				return stats, rollback, fmt.Errorf("tx_devmap key %d already points to ifindex %d, refusing to change to %d while policy is active", key, existing, desired)
			}
		} else if errors.Is(err, ebpf.ErrKeyNotExist) {
			backups[key] = devmapBackup{}
		} else {
			return stats, rollback, fmt.Errorf("lookup tx_devmap key %d: %w", key, err)
		}
		if err := m.Update(&key, &desired, ebpf.UpdateAny); err != nil {
			return stats, rollback, fmt.Errorf("update tx_devmap key %d: %w", key, err)
		}
		stats.Updated++
		updatedKeys = append(updatedKeys, key)
	}
	return stats, rollback, nil
}

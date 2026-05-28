package agent

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type MapExpectation struct {
	Type       ebpf.MapType
	MaxEntries uint32
}

var ExpectedMaps = map[string]MapExpectation{
	"whitelist_v4_a":      {Type: ebpf.LPMTrie, MaxEntries: 65536},
	"whitelist_v4_b":      {Type: ebpf.LPMTrie, MaxEntries: 65536},
	"blacklist_v4_a":      {Type: ebpf.LPMTrie, MaxEntries: 1000000},
	"blacklist_v4_b":      {Type: ebpf.LPMTrie, MaxEntries: 1000000},
	"service_allowlist_a": {Type: ebpf.Hash, MaxEntries: 16384},
	"service_allowlist_b": {Type: ebpf.Hash, MaxEntries: 16384},
	"tx_devmap":           {Type: ebpf.DevMap, MaxEntries: 128},
	"rate_state":          {Type: ebpf.LRUHash, MaxEntries: 2000000},
	"rule_config_a":       {Type: ebpf.Array, MaxEntries: 4096},
	"rule_config_b":       {Type: ebpf.Array, MaxEntries: 4096},
	"drop_counters":       {Type: ebpf.PerCPUHash, MaxEntries: 262144},
	"events":              {Type: ebpf.RingBuf, MaxEntries: 64 * 1024 * 1024},
	"runtime_config":      {Type: ebpf.Array, MaxEntries: 1},
	"prog_array":          {Type: ebpf.ProgramArray, MaxEntries: 16},
}

func ValidateCollectionSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("nil collection spec")
	}
	if _, ok := spec.Programs["xdp_entry"]; !ok {
		return fmt.Errorf("missing xdp_entry program")
	}
	for name, expected := range ExpectedMaps {
		mapSpec, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("missing BPF map %s", name)
		}
		if mapSpec.Type != expected.Type {
			return fmt.Errorf("%s: expected map type %s, got %s", name, expected.Type, mapSpec.Type)
		}
		if mapSpec.MaxEntries != expected.MaxEntries {
			return fmt.Errorf("%s: expected max_entries %d, got %d", name, expected.MaxEntries, mapSpec.MaxEntries)
		}
	}
	return nil
}

func EnableMapPinning(spec *ebpf.CollectionSpec) {
	for name := range ExpectedMaps {
		if mapSpec, ok := spec.Maps[name]; ok {
			mapSpec.Pinning = ebpf.PinByName
		}
	}
}

package agent

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
)

type AggregatedCounter struct {
	Key     CounterKey
	Packets uint64
	Bytes   uint64
}

func SumCounterValues(values []CounterValue) CounterValue {
	var out CounterValue
	for _, value := range values {
		out.Packets += value.Packets
		out.Bytes += value.Bytes
	}
	return out
}

func CollectDropCounters(counterMap *ebpf.Map) ([]AggregatedCounter, error) {
	if counterMap == nil {
		return nil, fmt.Errorf("nil drop counter map")
	}

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}

	var out []AggregatedCounter
	var key CounterKey
	values := make([]CounterValue, possibleCPUs)
	iter := counterMap.Iterate()
	for iter.Next(&key, &values) {
		sum := SumCounterValues(values)
		out = append(out, AggregatedCounter{
			Key:     key,
			Packets: sum.Packets,
			Bytes:   sum.Bytes,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		left := out[i].Key
		right := out[j].Key
		if left.Reason != right.Reason {
			return left.Reason < right.Reason
		}
		if left.Action != right.Action {
			return left.Action < right.Action
		}
		if left.Proto != right.Proto {
			return left.Proto < right.Proto
		}
		if left.ServiceID != right.ServiceID {
			return left.ServiceID < right.ServiceID
		}
		return left.RuleID < right.RuleID
	})

	return out, nil
}

func CountMapEntries(m *ebpf.Map) (uint64, error) {
	if m == nil {
		return 0, fmt.Errorf("nil map")
	}

	var count uint64
	var key, nextKey []byte
	keySize := int(m.KeySize())
	if keySize == 0 {
		return 0, nil
	}
	nextKey = make([]byte, keySize)

	for {
		err := m.NextKey(key, nextKey)
		if err != nil {
			if err == ebpf.ErrKeyNotExist {
				return count, nil
			}
			return 0, err
		}
		count++
		key = append([]byte(nil), nextKey...)
	}
}

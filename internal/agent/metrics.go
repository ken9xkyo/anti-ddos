package agent

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	registry *prometheus.Registry

	agentUp          prometheus.Gauge
	xdpMode          *prometheus.GaugeVec
	attachErrors     *prometheus.CounterVec
	xdpPackets       *prometheus.GaugeVec
	xdpBytes         *prometheus.GaugeVec
	mapEntries       *prometheus.GaugeVec
	mapCapacity      *prometheus.GaugeVec
	mapUtilization   *prometheus.GaugeVec
	ringbufEvents    prometheus.Counter
	ringbufErrors    prometheus.Counter
	lastSnapshotVer  prometheus.Gauge
	loadedObjectInfo *prometheus.GaugeVec
}

func NewMetrics() (*Metrics, error) {
	m := &Metrics{registry: prometheus.NewRegistry()}
	m.agentUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "anti_ddos_agent_up",
		Help: "Whether the anti-ddos node agent is running.",
	})
	m.xdpMode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_xdp_mode",
		Help: "Current XDP attach mode, with value 1 for the active mode.",
	}, []string{"mode"})
	m.attachErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_xdp_attach_errors_total",
		Help: "Total XDP attach errors by attempted mode.",
	}, []string{"mode"})
	m.xdpPackets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_xdp_packets_total",
		Help: "Cumulative XDP packets from eBPF counters.",
	}, []string{"reason", "action", "proto", "service_id", "rule_id"})
	m.xdpBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_xdp_bytes_total",
		Help: "Cumulative XDP bytes from eBPF counters.",
	}, []string{"reason", "action", "proto", "service_id", "rule_id"})
	m.mapEntries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_ebpf_map_entries",
		Help: "Current eBPF map entry count.",
	}, []string{"map"})
	m.mapCapacity = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_ebpf_map_capacity",
		Help: "Configured eBPF map max entries.",
	}, []string{"map"})
	m.mapUtilization = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_ebpf_map_utilization_ratio",
		Help: "Current eBPF map entry utilization ratio.",
	}, []string{"map"})
	m.ringbufEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "anti_ddos_ringbuf_events_consumed_total",
		Help: "Total sampled ringbuf events consumed by the agent.",
	})
	m.ringbufErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "anti_ddos_ringbuf_consume_errors_total",
		Help: "Total ringbuf consume errors observed by the agent.",
	})
	m.lastSnapshotVer = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "anti_ddos_agent_last_valid_snapshot_version",
		Help: "Last valid local snapshot policy version loaded by the agent.",
	})
	m.loadedObjectInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_xdp_program_info",
		Help: "Loaded XDP object metadata. Value is always 1.",
	}, []string{"checksum"})

	collectors := []prometheus.Collector{
		m.agentUp,
		m.xdpMode,
		m.attachErrors,
		m.xdpPackets,
		m.xdpBytes,
		m.mapEntries,
		m.mapCapacity,
		m.mapUtilization,
		m.ringbufEvents,
		m.ringbufErrors,
		m.lastSnapshotVer,
		m.loadedObjectInfo,
	}
	for _, collector := range collectors {
		if err := m.registry.Register(collector); err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

func (m *Metrics) SetAgentUp(up bool) {
	if up {
		m.agentUp.Set(1)
		return
	}
	m.agentUp.Set(0)
}

func (m *Metrics) SetXDPMode(mode string) {
	for _, candidate := range []string{"native", "generic", "detached"} {
		value := 0.0
		if candidate == mode {
			value = 1
		}
		m.xdpMode.WithLabelValues(candidate).Set(value)
	}
}

func (m *Metrics) IncAttachError(mode string) {
	m.attachErrors.WithLabelValues(mode).Inc()
}

func (m *Metrics) IncRingbufEvent() {
	m.ringbufEvents.Inc()
}

func (m *Metrics) IncRingbufError() {
	m.ringbufErrors.Inc()
}

func (m *Metrics) SetSnapshotVersion(version uint32) {
	m.lastSnapshotVer.Set(float64(version))
}

func (m *Metrics) SetObjectChecksum(checksum string) {
	m.loadedObjectInfo.Reset()
	m.loadedObjectInfo.WithLabelValues(checksum).Set(1)
}

func (m *Metrics) SetCounters(counters []AggregatedCounter) {
	m.xdpPackets.Reset()
	m.xdpBytes.Reset()
	for _, counter := range counters {
		labels := counterLabels(counter.Key)
		m.xdpPackets.WithLabelValues(labels...).Set(float64(counter.Packets))
		m.xdpBytes.WithLabelValues(labels...).Set(float64(counter.Bytes))
	}
}

func (m *Metrics) SetMapStats(maps map[string]*ebpf.Map) {
	for name, bpfMap := range maps {
		if bpfMap == nil {
			continue
		}
		capacity := float64(bpfMap.MaxEntries())
		m.mapCapacity.WithLabelValues(name).Set(capacity)

		entries, err := CountMapEntries(bpfMap)
		if err != nil {
			continue
		}
		m.mapEntries.WithLabelValues(name).Set(float64(entries))
		if capacity > 0 {
			m.mapUtilization.WithLabelValues(name).Set(float64(entries) / capacity)
		}
	}
}

func counterLabels(key CounterKey) []string {
	return []string{
		fmt.Sprint(key.Reason),
		fmt.Sprint(key.Action),
		fmt.Sprint(key.Proto),
		fmt.Sprint(key.ServiceID),
		fmt.Sprint(key.RuleID),
	}
}

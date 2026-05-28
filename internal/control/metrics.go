package control

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type ControlMetrics struct {
	registry *prometheus.Registry

	httpRequests      *prometheus.CounterVec
	httpDuration      *prometheus.HistogramVec
	dbUp              prometheus.Gauge
	snapshotVersion   prometheus.Gauge
	applyStatus       *prometheus.GaugeVec
	agentHealth       *prometheus.GaugeVec
	agentStale        *prometheus.GaugeVec
	securityEvents    *prometheus.CounterVec
	eventRejects      *prometheus.CounterVec
	prometheusQueries *prometheus.CounterVec
}

func NewControlMetrics() (*ControlMetrics, error) {
	m := &ControlMetrics{registry: prometheus.NewRegistry()}
	m.httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_control_http_requests_total",
		Help: "Total Control API HTTP requests by method, route, and status class.",
	}, []string{"method", "route", "status"})
	m.httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "anti_ddos_control_http_request_duration_seconds",
		Help:    "Control API request latency by method and route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})
	m.dbUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "anti_ddos_control_db_up",
		Help: "Whether the Control API can reach PostgreSQL.",
	})
	m.snapshotVersion = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "anti_ddos_control_policy_snapshot_version",
		Help: "Latest policy snapshot version known to the Control API.",
	})
	m.applyStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_control_policy_apply_status",
		Help: "Latest policy apply status count by status.",
	}, []string{"status"})
	m.agentHealth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_control_agents",
		Help: "Registered agents by status and XDP mode.",
	}, []string{"status", "xdp_mode"})
	m.agentStale = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_control_agent_stale",
		Help: "Registered agent stale status, 1 stale and 0 fresh.",
	}, []string{"status", "xdp_mode"})
	m.securityEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_control_security_events_ingested_total",
		Help: "Sampled security events accepted by the Control API.",
	}, []string{"action", "reason", "protocol"})
	m.eventRejects = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_control_security_events_rejected_total",
		Help: "Sampled security event batches rejected by the Control API.",
	}, []string{"reason"})
	m.prometheusQueries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_control_prometheus_queries_total",
		Help: "Prometheus query attempts proxied by the Control API.",
	}, []string{"result"})

	for _, collector := range []prometheus.Collector{
		m.httpRequests,
		m.httpDuration,
		m.dbUp,
		m.snapshotVersion,
		m.applyStatus,
		m.agentHealth,
		m.agentStale,
		m.securityEvents,
		m.eventRejects,
		m.prometheusQueries,
	} {
		if err := m.registry.Register(collector); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *ControlMetrics) Registry() *prometheus.Registry {
	return m.registry
}

func (m *ControlMetrics) ObserveHTTP(method, route string, status int, duration time.Duration) {
	statusClass := fmt.Sprintf("%dxx", status/100)
	m.httpRequests.WithLabelValues(method, route, statusClass).Inc()
	m.httpDuration.WithLabelValues(method, route).Observe(duration.Seconds())
}

func (m *ControlMetrics) IncSecurityEvent(event SecurityEventInput) {
	m.securityEvents.WithLabelValues(
		strconv.FormatUint(uint64(event.Action), 10),
		strconv.FormatUint(uint64(event.Reason), 10),
		strconv.FormatUint(uint64(event.Protocol), 10),
	).Inc()
}

func (m *ControlMetrics) IncSecurityEventReject(reason string) {
	m.eventRejects.WithLabelValues(reason).Inc()
}

func (m *ControlMetrics) IncPrometheusQuery(result string) {
	m.prometheusQueries.WithLabelValues(result).Inc()
}

func (s *Store) RefreshControlMetrics(ctx context.Context, metrics *ControlMetrics, staleAfter time.Duration) error {
	if metrics == nil {
		return nil
	}
	if err := s.pool.Ping(ctx); err != nil {
		metrics.dbUp.Set(0)
		return err
	}
	metrics.dbUp.Set(1)

	version, err := s.LatestPolicyVersion(ctx)
	if err == nil {
		metrics.snapshotVersion.Set(float64(version))
	}

	metrics.applyStatus.Reset()
	rows, err := s.pool.Query(ctx, `SELECT status, count(*) FROM policy_apply_status GROUP BY status`)
	if err == nil {
		for rows.Next() {
			var status string
			var count int64
			if scanErr := rows.Scan(&status, &count); scanErr == nil {
				metrics.applyStatus.WithLabelValues(status).Set(float64(count))
			}
		}
		rows.Close()
	}

	metrics.agentHealth.Reset()
	metrics.agentStale.Reset()
	rows, err = s.pool.Query(ctx, `SELECT status, COALESCE(NULLIF(xdp_mode, ''), 'unknown'), last_seen_at FROM agents`)
	if err != nil {
		return err
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var status, mode string
		var lastSeen *time.Time
		if err := rows.Scan(&status, &mode, &lastSeen); err != nil {
			return err
		}
		metrics.agentHealth.WithLabelValues(status, mode).Inc()
		stale := 1.0
		if lastSeen != nil && now.Sub(*lastSeen) <= staleAfter {
			stale = 0
		}
		metrics.agentStale.WithLabelValues(status, mode).Set(stale)
	}
	return rows.Err()
}

type metricResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *metricResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

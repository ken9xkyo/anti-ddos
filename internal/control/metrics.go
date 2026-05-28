package control

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	feedSyncSuccess   *prometheus.CounterVec
	feedSyncErrors    *prometheus.CounterVec
	feedEntries       *prometheus.GaugeVec
	feedConflicts     *prometheus.GaugeVec
	alertsCreated     *prometheus.CounterVec
	alertsSent        *prometheus.CounterVec
	alertsFailed      *prometheus.CounterVec
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
	m.feedSyncSuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_feed_sync_success_total",
		Help: "Threat feed sync successes by bounded source name.",
	}, []string{"source"})
	m.feedSyncErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_feed_sync_errors_total",
		Help: "Threat feed sync errors by bounded source name and reason.",
	}, []string{"source", "reason"})
	m.feedEntries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_feed_entries_active",
		Help: "Active threat feed reputation entries by bounded source name.",
	}, []string{"source"})
	m.feedConflicts = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "anti_ddos_feed_conflicts_active",
		Help: "Active whitelist/feed conflicts by bounded source name.",
	}, []string{"source"})
	m.alertsCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_alerts_created_total",
		Help: "Alert instances created by type and severity.",
	}, []string{"type", "severity"})
	m.alertsSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_alerts_sent_total",
		Help: "Successful alert deliveries by channel and severity.",
	}, []string{"channel", "severity"})
	m.alertsFailed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "anti_ddos_alerts_failed_total",
		Help: "Failed alert deliveries by channel and bounded reason.",
	}, []string{"channel", "reason"})

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
		m.feedSyncSuccess,
		m.feedSyncErrors,
		m.feedEntries,
		m.feedConflicts,
		m.alertsCreated,
		m.alertsSent,
		m.alertsFailed,
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
	if err := rows.Err(); err != nil {
		return err
	}

	metrics.feedEntries.Reset()
	metrics.feedConflicts.Reset()
	rows, err = s.pool.Query(ctx, `SELECT name, active_entries, conflict_count FROM feed_sources`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var active, conflicts float64
		if err := rows.Scan(&name, &active, &conflicts); err != nil {
			return err
		}
		source := boundedMetricValue(name)
		metrics.feedEntries.WithLabelValues(source).Set(active)
		metrics.feedConflicts.WithLabelValues(source).Set(conflicts)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	return nil
}

func boundedMetricValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	return strings.Trim(b.String(), "_")
}

type metricResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *metricResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

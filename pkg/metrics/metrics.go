// Package metrics exposes Prometheus counters aggregated from BPF percpu maps.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	m "github.com/anti-ddos/antiddosd/pkg/maps"
)

// Collector polls BPF stats and publishes Prometheus gauges/counters.
type Collector struct {
	h      *m.Handles
	log    *zap.Logger
	addr   string
	gauges map[m.StatIdx]prometheus.Gauge
	reg    *prometheus.Registry
}

// New builds a collector bound to the given maps.
func New(addr string, h *m.Handles, log *zap.Logger) *Collector {
	if log == nil {
		log = zap.NewNop()
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(
		prometheus.ProcessCollectorOpts{}))

	gauges := make(map[m.StatIdx]prometheus.Gauge, m.StatMax)
	for idx := m.StatIdx(0); idx < m.StatMax; idx++ {
		name := m.StatNames[idx]
		if name == "" {
			continue
		}
		g := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "antiddos",
			Name:      name,
			Help:      "BPF counter: " + name,
		})
		reg.MustRegister(g)
		gauges[idx] = g
	}
	return &Collector{h: h, log: log, addr: addr, gauges: gauges, reg: reg}
}

// Run starts the HTTP exporter and polls the BPF maps periodically.
func (c *Collector) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(c.reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: c.addr, Handler: mux}

	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	go c.pollLoop(ctx)

	c.log.Info("metrics listening", zap.String("addr", c.addr))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (c *Collector) pollLoop(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s, err := c.h.ReadStats()
			if err != nil {
				c.log.Warn("read stats", zap.Error(err))
				continue
			}
			for idx, g := range c.gauges {
				g.Set(float64(s[idx]))
			}
		}
	}
}

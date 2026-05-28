package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Agent struct {
	cfg     Config
	metrics *Metrics
	logger  *slog.Logger
	ready   atomic.Bool
}

func New(cfg Config, logger *slog.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	metrics, err := NewMetrics()
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, metrics: metrics, logger: logger}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	a.metrics.SetAgentUp(false)
	a.metrics.SetXDPMode("detached")

	server := a.httpServer()
	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	runtime, err := LoadAndAttach(a.cfg, a.metrics, a.logger)
	if err != nil {
		return err
	}
	a.ready.Store(true)
	a.metrics.SetAgentUp(true)
	defer func() {
		a.ready.Store(false)
		a.metrics.SetAgentUp(false)
		a.metrics.SetXDPMode("detached")
		runtime.Close(a.cfg.SafeDetachOnExit)
	}()

	ringCtx, cancelRing := context.WithCancel(ctx)
	defer cancelRing()
	go func() {
		if err := ConsumeRingbuf(ringCtx, runtime.Collection.Maps["events"], a.metrics, a.logger); err != nil {
			a.logger.Warn("ringbuf consumer stopped", "error", RedactString(err.Error()))
		}
	}()
	if a.cfg.ControlURL != "" {
		go RunControlSync(ctx, a.cfg, runtime, a.metrics, a.logger)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	if err := a.collect(runtime); err != nil {
		a.logger.Warn("initial metrics collection failed", "error", RedactString(err.Error()))
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serverErr:
			if err != nil {
				return fmt.Errorf("metrics server: %w", err)
			}
			return nil
		case <-ticker.C:
			if err := a.collect(runtime); err != nil {
				a.logger.Warn("metrics collection failed", "error", RedactString(err.Error()))
			}
		}
	}
}

func (a *Agent) httpServer() *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(a.metrics.Registry(), promhttp.HandlerOpts{Registry: a.metrics.Registry()}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !a.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("starting\n"))
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return &http.Server{
		Addr:              a.cfg.MetricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func (a *Agent) collect(runtime *Runtime) error {
	counterMap := runtime.Collection.Maps["drop_counters"]
	counters, err := CollectDropCounters(counterMap)
	if err != nil {
		return err
	}
	a.metrics.SetCounters(counters)
	a.metrics.SetForwardingCounters(counters, runtime.Snapshot)
	a.metrics.SetMapStats(runtime.Collection.Maps)
	return nil
}

// Command antiddosd is the control-plane daemon for the XDP anti-DDoS
// mitigator. It loads the compiled eBPF object, attaches it to the ingress
// interfaces in native XDP mode, wires the egress devmap, serves the admin
// REST API and Prometheus metrics, and pumps the events ringbuf to logs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"go.uber.org/zap"

	"github.com/anti-ddos/antiddosd/pkg/api"
	"github.com/anti-ddos/antiddosd/pkg/config"
	"github.com/anti-ddos/antiddosd/pkg/events"
	"github.com/anti-ddos/antiddosd/pkg/loader"
	m "github.com/anti-ddos/antiddosd/pkg/maps"
	"github.com/anti-ddos/antiddosd/pkg/metrics"
)

var version = "dev"

func main() {
	var (
		cfgPath = flag.String("config", "/etc/antiddosd/config.yaml", "config path")
		objPath = flag.String("bpf-obj", "", "BPF object path (defaults to binary dir)")
		logJSON = flag.Bool("log-json", false, "emit logs as JSON")
	)
	flag.Parse()

	log := mustLogger(*logJSON)
	defer log.Sync() //nolint:errcheck

	log.Info("antiddosd starting", zap.String("version", version))

	// --- config ----------------------------------------------------------
	fcfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Warn("config load failed, using defaults", zap.Error(err))
		fcfg = config.Defaults()
	}

	// --- loader ----------------------------------------------------------
	ld := loader.New(loader.Options{
		IngressIfaces: fcfg.Ingress,
		EgressIface:   fcfg.Egress,
		Mode:          fcfg.XDPMode,
		PinPath:       fcfg.PinPath,
		Logger:        log,
	})
	if err := ld.Load(*objPath); err != nil {
		log.Fatal("load BPF", zap.Error(err))
	}
	defer ld.Close()

	handles, err := m.FromCollection(ld.Collection())
	if err != nil {
		log.Fatal("map handles", zap.Error(err))
	}

	if err := ld.SetupDevmap(); err != nil {
		log.Error("devmap setup (continuing)", zap.Error(err))
	}
	if err := ld.Attach(); err != nil {
		log.Fatal("attach XDP", zap.Error(err))
	}

	// --- config watcher --------------------------------------------------
	watcher := config.NewWatcher(*cfgPath, handles, log, nil)
	if err := watcher.Apply(fcfg); err != nil {
		log.Fatal("apply initial config", zap.Error(err))
	}

	// --- context & signals ----------------------------------------------
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigc {
			switch sig {
			case syscall.SIGHUP:
				log.Info("SIGHUP: reloading config")
				if cfg2, err := config.Load(*cfgPath); err != nil {
					log.Error("reload failed", zap.Error(err))
				} else {
					_ = watcher.Apply(cfg2)
				}
			default:
				log.Info("signal received, shutting down", zap.String("sig", sig.String()))
				cancel()
				return
			}
		}
	}()

	// --- goroutines ------------------------------------------------------
	var wg sync.WaitGroup

	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("subsystem failed", zap.String("name", name), zap.Error(err))
				cancel()
			}
		}()
	}

	// Config file watcher.
	run("config-watcher", watcher.Run)

	// Metrics.
	mc := metrics.New(fcfg.MetricsAddr, handles, log)
	run("metrics", mc.Run)

	// Admin API.
	apiSrv := api.New(fcfg.APIAddr, handles, watcher, log)
	run("api", apiSrv.Run)

	// Event consumer.
	er := events.New(handles.Events, log, func(ev events.Event) {
		log.Info("event",
			zap.Stringer("src", ev.SrcIP()),
			zap.Uint8("proto", ev.Proto),
			zap.Uint16("sport", ev.Sport),
			zap.Uint16("dport", ev.Dport),
			zap.Uint8("action", ev.Action),
			zap.Uint8("reason", ev.Reason),
			zap.Uint32("bytes", ev.Bytes),
		)
	})
	run("events", er.Run)

	wg.Wait()
	log.Info("antiddosd stopped")
}

func mustLogger(jsonFmt bool) *zap.Logger {
	var (
		l   *zap.Logger
		err error
	)
	if jsonFmt {
		l, err = zap.NewProduction()
	} else {
		l, err = zap.NewDevelopment()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "zap:", err)
		os.Exit(2)
	}
	return l
}

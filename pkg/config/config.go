// Package config parses the YAML config file and pushes updates to BPF maps.
package config

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	m "github.com/anti-ddos/antiddosd/pkg/maps"
)

// File is the on-disk layout.
type File struct {
	XDPMode    string   `yaml:"xdp_mode"` // native | skb | hw
	Ingress    []string `yaml:"ingress_ifaces"`
	Egress     string   `yaml:"egress_iface"`
	APIAddr    string   `yaml:"api_addr"`
	MetricsAddr string  `yaml:"metrics_addr"`
	PinPath    string   `yaml:"pin_path"`

	Features struct {
		DropFragments bool `yaml:"drop_fragments"`
		DropReflect   bool `yaml:"drop_reflection"`
		Syncookie     bool `yaml:"syncookie"`
		Conntrack     bool `yaml:"conntrack"`
		RateLimit     bool `yaml:"rate_limit"`
		Redirect      bool `yaml:"redirect"`
	} `yaml:"features"`

	Rate struct {
		SynPPS    uint32 `yaml:"syn_pps"`
		UDPPPS    uint32 `yaml:"udp_pps"`
		ICMPPPS   uint32 `yaml:"icmp_pps"`
		GlobalPPS uint32 `yaml:"global_pps"`
		Burst     uint32 `yaml:"burst"`
	} `yaml:"rate"`

	SampleEvery uint32 `yaml:"sample_every"`

	Whitelist []string `yaml:"whitelist"`
	Blocklist []string `yaml:"blocklist"`
}

// Defaults returns sensible defaults.
func Defaults() File {
	var f File
	f.XDPMode = "native"
	f.APIAddr = "127.0.0.1:8080"
	f.MetricsAddr = "127.0.0.1:9090"
	f.PinPath = "/sys/fs/bpf/antiddos"
	f.Features.DropFragments = true
	f.Features.DropReflect = true
	f.Features.RateLimit = true
	f.Features.Conntrack = true
	f.Features.Redirect = true
	f.Rate.SynPPS = 2000
	f.Rate.UDPPPS = 5000
	f.Rate.ICMPPPS = 200
	f.Rate.GlobalPPS = 20000
	f.Rate.Burst = 500
	f.SampleEvery = 1024
	return f
}

// Load reads + parses a YAML file; missing fields retain defaults.
func Load(path string) (File, error) {
	f := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("parse %s: %w", path, err)
	}
	return f, nil
}

// ToBPFConfig converts to the BPF-facing struct.
func (f File) ToBPFConfig() m.Config {
	var feats uint32
	if f.Features.DropFragments { feats |= m.FeatDropFragments }
	if f.Features.DropReflect   { feats |= m.FeatDropReflect }
	if f.Features.Syncookie     { feats |= m.FeatSyncookie }
	if f.Features.Conntrack     { feats |= m.FeatConntrack }
	if f.Features.RateLimit     { feats |= m.FeatRateLimit }
	if f.Features.Redirect      { feats |= m.FeatRedirect }

	sample := f.SampleEvery
	if sample == 0 {
		sample = 1024
	}
	return m.Config{
		FeatureFlags:  feats,
		SampleEvery:   sample,
		SynRatePPS:    f.Rate.SynPPS,
		UDPRatePPS:    f.Rate.UDPPPS,
		ICMPRatePPS:   f.Rate.ICMPPPS,
		GlobalRatePPS: f.Rate.GlobalPPS,
		BucketBurst:   f.Rate.Burst,
	}
}

// Watcher reloads config on SIGHUP / fsnotify events.
type Watcher struct {
	path   string
	log    *zap.Logger
	maps   *m.Handles
	mu     sync.RWMutex
	cur    File
	onLoad func(File)
}

// NewWatcher creates a watcher that pushes updates into the BPF config map.
func NewWatcher(path string, h *m.Handles, log *zap.Logger, onLoad func(File)) *Watcher {
	if log == nil { log = zap.NewNop() }
	return &Watcher{path: path, log: log, maps: h, onLoad: onLoad}
}

// Current returns the last-loaded config (copy).
func (w *Watcher) Current() File {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cur
}

// Apply pushes cfg into the BPF config map and calls onLoad.
func (w *Watcher) Apply(cfg File) error {
	if err := w.maps.PutConfig(cfg.ToBPFConfig()); err != nil {
		return fmt.Errorf("put config: %w", err)
	}
	// Whitelist/blocklist bulk-apply.
	for _, s := range cfg.Whitelist {
		pfx, err := parsePrefix(s)
		if err != nil {
			w.log.Warn("bad whitelist entry", zap.String("cidr", s), zap.Error(err))
			continue
		}
		_ = w.maps.AddPrefix("whitelist", pfx, 0)
	}
	for _, s := range cfg.Blocklist {
		pfx, err := parsePrefix(s)
		if err != nil {
			w.log.Warn("bad blocklist entry", zap.String("cidr", s), zap.Error(err))
			continue
		}
		_ = w.maps.AddPrefix("block", pfx, 0)
	}
	w.mu.Lock()
	w.cur = cfg
	w.mu.Unlock()
	if w.onLoad != nil {
		w.onLoad(cfg)
	}
	w.log.Info("config applied", zap.String("path", w.path))
	return nil
}

// Run watches the file for changes until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	wr, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer wr.Close()
	if err := wr.Add(w.path); err != nil {
		return err
	}
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-wr.Events:
			if ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				debounce.Reset(250 * time.Millisecond)
			}
		case <-debounce.C:
			cfg, err := Load(w.path)
			if err != nil {
				w.log.Error("reload failed", zap.Error(err))
				continue
			}
			if err := w.Apply(cfg); err != nil {
				w.log.Error("apply failed", zap.Error(err))
			}
		case err := <-wr.Errors:
			w.log.Warn("fsnotify error", zap.Error(err))
		}
	}
}

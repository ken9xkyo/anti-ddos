package control

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfigFromEnvDefaultsAndOverrides(t *testing.T) {
	keys := []string{
		"ANTI_DDOS_CONTROL_ADDR",
		"ANTI_DDOS_DB_DSN",
		"ANTI_DDOS_SESSION_TTL",
		"ANTI_DDOS_XDP_OBJECT",
		"ANTI_DDOS_AGENT_SHARED_TOKEN",
		"ANTI_DDOS_PROMETHEUS_URL",
		"ANTI_DDOS_AGENT_STALE_AFTER",
		"ANTI_DDOS_EVENT_SAMPLE_DENOM",
		"ANTI_DDOS_TELEGRAM_API_URL",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}

	cfg := LoadConfigFromEnv()
	if cfg.Addr != defaultControlAddr || cfg.SessionTTL != defaultSessionTTL || cfg.XDPObject != defaultXDPObject {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	if cfg.EventSampleDenom != 1 || cfg.TelegramAPIURL != defaultTelegramAPI {
		t.Fatalf("default telemetry config not applied: %#v", cfg)
	}

	t.Setenv("ANTI_DDOS_CONTROL_ADDR", " 127.0.0.1:18080 ")
	t.Setenv("ANTI_DDOS_DB_DSN", " postgres://control ")
	t.Setenv("ANTI_DDOS_SESSION_TTL", "30m")
	t.Setenv("ANTI_DDOS_XDP_OBJECT", " /tmp/xdp.o ")
	t.Setenv("ANTI_DDOS_AGENT_SHARED_TOKEN", " secret ")
	t.Setenv("ANTI_DDOS_PROMETHEUS_URL", " http://prometheus:9090/ ")
	t.Setenv("ANTI_DDOS_AGENT_STALE_AFTER", "45")
	t.Setenv("ANTI_DDOS_EVENT_SAMPLE_DENOM", "25")
	t.Setenv("ANTI_DDOS_TELEGRAM_API_URL", " http://telegram.local/ ")

	cfg = LoadConfigFromEnv()
	if cfg.Addr != "127.0.0.1:18080" ||
		cfg.DBDSN != "postgres://control" ||
		cfg.SessionTTL != 30*time.Minute ||
		cfg.XDPObject != "/tmp/xdp.o" ||
		cfg.AgentSharedToken != "secret" ||
		cfg.PrometheusURL != "http://prometheus:9090" ||
		cfg.AgentStaleAfter != 45*time.Second ||
		cfg.EventSampleDenom != 25 ||
		cfg.TelegramAPIURL != "http://telegram.local" {
		t.Fatalf("env overrides not applied: %#v", cfg)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		requireDB bool
		wantErrs  []string
	}{
		{
			name: "valid without required db",
			cfg:  Config{Addr: "127.0.0.1:0", SessionTTL: time.Hour, XDPObject: "xdp.o", AgentStaleAfter: time.Second},
		},
		{
			name:      "missing db when required",
			cfg:       Config{Addr: "127.0.0.1:0", SessionTTL: time.Hour, XDPObject: "xdp.o", AgentStaleAfter: time.Second},
			requireDB: true,
			wantErrs:  []string{"ANTI_DDOS_DB_DSN"},
		},
		{
			name: "collects invalid fields",
			cfg:  Config{SessionTTL: -time.Second},
			wantErrs: []string{
				"ANTI_DDOS_CONTROL_ADDR",
				"ANTI_DDOS_SESSION_TTL",
				"ANTI_DDOS_XDP_OBJECT",
				"ANTI_DDOS_AGENT_STALE_AFTER",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate(tt.requireDB)
			if len(tt.wantErrs) == 0 {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() error = nil")
			}
			for _, want := range tt.wantErrs {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Validate() error = %v, want containing %q", err, want)
				}
			}
		})
	}
}

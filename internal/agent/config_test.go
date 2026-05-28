package agent

import "testing"

func TestLoadConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("ANTI_DDOS_WAN_IFACE", "veth-test")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.WANIface != "veth-test" {
		t.Fatalf("unexpected iface %q", cfg.WANIface)
	}
	if cfg.XDPObject != defaultXDPObject {
		t.Fatalf("unexpected default object %q", cfg.XDPObject)
	}
	if cfg.XDPMode != "native" {
		t.Fatalf("unexpected xdp mode %q", cfg.XDPMode)
	}
	if cfg.AllowGenericFallback {
		t.Fatal("generic fallback should default to false")
	}
	if cfg.LinkPinPath() == cfg.ProgramPinPath() {
		t.Fatal("link and program pins must be distinct")
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := Config{XDPObject: "obj.o", XDPMode: "native", MetricsAddr: "127.0.0.1:0", BPFPinDir: "/tmp/pins", SnapshotPath: "/tmp/snapshot.json"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing iface validation error")
	}

	cfg.WANIface = "eth0"
	cfg.XDPMode = "bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected bad mode validation error")
	}
}

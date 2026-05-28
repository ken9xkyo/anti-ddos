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
	if cfg.BootstrapPolicyPath != "" {
		t.Fatalf("unexpected bootstrap policy path %q", cfg.BootstrapPolicyPath)
	}
	if cfg.PolicyMemoryBudgetBytes != 0 {
		t.Fatalf("unexpected policy memory budget %d", cfg.PolicyMemoryBudgetBytes)
	}
	if cfg.ControlURL != "" {
		t.Fatalf("unexpected control URL %q", cfg.ControlURL)
	}
	if cfg.AgentStatePath != defaultAgentState {
		t.Fatalf("unexpected agent state path %q", cfg.AgentStatePath)
	}
	if cfg.LinkPinPath() == cfg.ProgramPinPath() {
		t.Fatal("link and program pins must be distinct")
	}
}

func TestLoadConfigFromEnvPolicyOptions(t *testing.T) {
	t.Setenv("ANTI_DDOS_WAN_IFACE", "veth-test")
	t.Setenv("ANTI_DDOS_BOOTSTRAP_POLICY_PATH", "/tmp/policy.json")
	t.Setenv("ANTI_DDOS_POLICY_MEMORY_BUDGET_BYTES", "4096")
	t.Setenv("ANTI_DDOS_CONTROL_URL", "http://127.0.0.1:8080/")
	t.Setenv("ANTI_DDOS_AGENT_TOKEN", "shared")
	t.Setenv("ANTI_DDOS_AGENT_STATE_PATH", "/tmp/control-state.json")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.BootstrapPolicyPath != "/tmp/policy.json" {
		t.Fatalf("unexpected bootstrap policy path %q", cfg.BootstrapPolicyPath)
	}
	if cfg.PolicyMemoryBudgetBytes != 4096 {
		t.Fatalf("unexpected policy memory budget %d", cfg.PolicyMemoryBudgetBytes)
	}
	if cfg.ControlURL != "http://127.0.0.1:8080" || cfg.AgentToken != "shared" || cfg.AgentStatePath != "/tmp/control-state.json" {
		t.Fatalf("unexpected control sync config: %#v", cfg)
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

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultXDPObject    = "build/bpf/xdp_data_plane.bpf.o"
	defaultXDPMode      = "native"
	defaultMetricsAddr  = "127.0.0.1:9091"
	defaultBPFPinDir    = "/sys/fs/bpf/anti-ddos"
	defaultSnapshotPath = "/var/lib/anti-ddos/agent/last-valid-snapshot.json"
	defaultAgentState   = "/var/lib/anti-ddos/agent/control-state.json"
)

type Config struct {
	WANIface                string
	XDPObject               string
	XDPMode                 string
	AllowGenericFallback    bool
	MetricsAddr             string
	BPFPinDir               string
	SnapshotPath            string
	BootstrapPolicyPath     string
	PolicyMemoryBudgetBytes uint64
	SafeDetachOnExit        bool
	ControlURL              string
	AgentToken              string
	AgentStatePath          string
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		WANIface:                os.Getenv("ANTI_DDOS_WAN_IFACE"),
		XDPObject:               envOrDefault("ANTI_DDOS_XDP_OBJECT", defaultXDPObject),
		XDPMode:                 strings.ToLower(envOrDefault("ANTI_DDOS_XDP_MODE", defaultXDPMode)),
		AllowGenericFallback:    parseBoolEnv("ANTI_DDOS_XDP_ALLOW_GENERIC_FALLBACK", false),
		MetricsAddr:             envOrDefault("ANTI_DDOS_METRICS_ADDR", defaultMetricsAddr),
		BPFPinDir:               envOrDefault("ANTI_DDOS_BPF_PIN_DIR", defaultBPFPinDir),
		SnapshotPath:            envOrDefault("ANTI_DDOS_SNAPSHOT_PATH", defaultSnapshotPath),
		BootstrapPolicyPath:     strings.TrimSpace(os.Getenv("ANTI_DDOS_BOOTSTRAP_POLICY_PATH")),
		PolicyMemoryBudgetBytes: parseUint64Env("ANTI_DDOS_POLICY_MEMORY_BUDGET_BYTES", 0),
		SafeDetachOnExit:        parseBoolEnv("ANTI_DDOS_SAFE_DETACH_ON_EXIT", false),
		ControlURL:              strings.TrimRight(strings.TrimSpace(os.Getenv("ANTI_DDOS_CONTROL_URL")), "/"),
		AgentToken:              strings.TrimSpace(os.Getenv("ANTI_DDOS_AGENT_TOKEN")),
		AgentStatePath:          envOrDefault("ANTI_DDOS_AGENT_STATE_PATH", defaultAgentState),
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.WANIface) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_WAN_IFACE is required"))
	}
	if strings.TrimSpace(c.XDPObject) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_XDP_OBJECT is required"))
	}
	switch c.XDPMode {
	case "native", "generic":
	default:
		errs = append(errs, fmt.Errorf("ANTI_DDOS_XDP_MODE must be native or generic, got %q", c.XDPMode))
	}
	if strings.TrimSpace(c.MetricsAddr) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_METRICS_ADDR is required"))
	}
	if strings.TrimSpace(c.BPFPinDir) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_BPF_PIN_DIR is required"))
	}
	if strings.TrimSpace(c.SnapshotPath) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_SNAPSHOT_PATH is required"))
	}
	if strings.TrimSpace(c.ControlURL) != "" && strings.TrimSpace(c.AgentStatePath) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_AGENT_STATE_PATH is required when ANTI_DDOS_CONTROL_URL is set"))
	}

	return errors.Join(errs...)
}

func (c Config) MapPinDir() string {
	return filepath.Join(c.BPFPinDir, "maps")
}

func (c Config) LinkPinDir() string {
	return filepath.Join(c.BPFPinDir, "links")
}

func (c Config) ProgramPinDir() string {
	return filepath.Join(c.BPFPinDir, "programs")
}

func (c Config) MetadataDir() string {
	return filepath.Join(filepath.Dir(c.SnapshotPath), "metadata")
}

func (c Config) LinkPinPath() string {
	return filepath.Join(c.LinkPinDir(), "xdp_"+sanitizeFileName(c.WANIface))
}

func (c Config) ProgramPinPath() string {
	return filepath.Join(c.ProgramPinDir(), "xdp_entry")
}

func (c Config) MetadataPath() string {
	return filepath.Join(c.MetadataDir(), "xdp_"+sanitizeFileName(c.WANIface)+".json")
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseBoolEnv(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseUint64Env(key string, fallback uint64) uint64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func sanitizeFileName(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", "\t", "_", "\n", "_")
	clean := replacer.Replace(value)
	if clean == "" {
		return "unknown"
	}
	return clean
}

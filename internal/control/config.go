package control

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultControlAddr = "127.0.0.1:8080"
	defaultSessionTTL  = 12 * time.Hour
	defaultXDPObject   = "build/bpf/xdp_data_plane.bpf.o"
)

type Config struct {
	Addr             string
	DBDSN            string
	SessionTTL       time.Duration
	XDPObject        string
	AgentSharedToken string
}

func LoadConfigFromEnv() Config {
	return Config{
		Addr:             envOrDefault("ANTI_DDOS_CONTROL_ADDR", defaultControlAddr),
		DBDSN:            strings.TrimSpace(os.Getenv("ANTI_DDOS_DB_DSN")),
		SessionTTL:       parseDurationEnv("ANTI_DDOS_SESSION_TTL", defaultSessionTTL),
		XDPObject:        envOrDefault("ANTI_DDOS_XDP_OBJECT", defaultXDPObject),
		AgentSharedToken: strings.TrimSpace(os.Getenv("ANTI_DDOS_AGENT_SHARED_TOKEN")),
	}
}

func (c Config) Validate(requireDB bool) error {
	var errs []error
	if strings.TrimSpace(c.Addr) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_CONTROL_ADDR is required"))
	}
	if requireDB && strings.TrimSpace(c.DBDSN) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_DB_DSN is required"))
	}
	if c.SessionTTL <= 0 {
		errs = append(errs, fmt.Errorf("ANTI_DDOS_SESSION_TTL must be positive, got %s", c.SessionTTL))
	}
	if strings.TrimSpace(c.XDPObject) == "" {
		errs = append(errs, errors.New("ANTI_DDOS_XDP_OBJECT is required"))
	}
	return errors.Join(errs...)
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type controlClient struct {
	baseURL string
	token   string
	client  *http.Client
}

type controlState struct {
	AgentID string `json:"agent_id"`
}

type controlAgentInterface struct {
	Name    string `json:"name"`
	Ifindex uint32 `json:"ifindex,omitempty"`
	MAC     string `json:"mac,omitempty"`
	Role    string `json:"role,omitempty"`
}

type controlRegisterRequest struct {
	Hostname      string                  `json:"hostname"`
	Interfaces    []controlAgentInterface `json:"interfaces,omitempty"`
	KernelVersion string                  `json:"kernel_version,omitempty"`
	UbuntuVersion string                  `json:"ubuntu_version,omitempty"`
	XDPMode       string                  `json:"xdp_mode,omitempty"`
	DevmapSupport bool                    `json:"devmap_support"`
	AgentVersion  string                  `json:"agent_version,omitempty"`
}

type controlRegisterResponse struct {
	AgentID              string `json:"agent_id"`
	DesiredPolicyVersion uint32 `json:"desired_policy_version"`
}

type controlHeartbeatRequest struct {
	Status              string `json:"status"`
	ActivePolicyVersion uint32 `json:"active_policy_version"`
	XDPMode             string `json:"xdp_mode,omitempty"`
}

type controlHeartbeatResponse struct {
	DesiredPolicyVersion uint32 `json:"desired_policy_version"`
}

type controlSnapshotResponse struct {
	Snapshot PolicySnapshot `json:"snapshot"`
}

func RunControlSync(ctx context.Context, cfg Config, runtime *Runtime, metrics *Metrics, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	client := controlClient{
		baseURL: strings.TrimRight(cfg.ControlURL, "/"),
		token:   cfg.AgentToken,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
	state, _ := loadControlState(cfg.AgentStatePath)
	if state.AgentID == "" {
		resp, err := client.register(ctx, controlRegisterRequest{
			Hostname:      hostname(),
			Interfaces:    []controlAgentInterface{interfaceMetadata(cfg.WANIface)},
			KernelVersion: fileTrimmed("/proc/sys/kernel/osrelease"),
			UbuntuVersion: ubuntuVersion(),
			XDPMode:       cfg.XDPMode,
			DevmapSupport: true,
			AgentVersion:  "phase05",
		})
		if err != nil {
			logger.Warn("control register failed", "error", RedactString(err.Error()))
		} else {
			state.AgentID = resp.AgentID
			if err := saveControlState(cfg.AgentStatePath, state); err != nil {
				logger.Warn("persist control state failed", "error", RedactString(err.Error()))
			}
		}
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if state.AgentID == "" {
				continue
			}
			active := runtime.Snapshot.PolicyVersion
			heartbeat, err := client.heartbeat(ctx, state.AgentID, controlHeartbeatRequest{
				Status:              "online",
				ActivePolicyVersion: active,
				XDPMode:             cfg.XDPMode,
			})
			if err != nil {
				logger.Warn("control heartbeat failed", "error", RedactString(err.Error()))
				continue
			}
			if heartbeat.DesiredPolicyVersion <= active {
				continue
			}
			snapshot, ok, err := client.fetchSnapshot(ctx, state.AgentID, active)
			if err != nil {
				logger.Warn("control snapshot fetch failed", "error", RedactString(err.Error()))
				continue
			}
			if !ok {
				continue
			}
			result, applyErr := ApplyPolicySnapshot(runtime, snapshot, PolicyApplyOptions{
				SnapshotPath:      cfg.SnapshotPath,
				ObjectChecksum:    runtime.ObjectChecksum,
				MemoryBudgetBytes: cfg.PolicyMemoryBudgetBytes,
				Metrics:           metrics,
				Now:               time.Now(),
				CapacityOverrides: nil,
			})
			if err := client.ack(ctx, state.AgentID, result); err != nil {
				logger.Warn("control apply ack failed", "error", RedactString(err.Error()))
			}
			if applyErr != nil {
				logger.Warn("control snapshot apply failed", "version", snapshot.Version, "error", RedactString(applyErr.Error()))
			}
		}
	}
}

func (c controlClient) register(ctx context.Context, req controlRegisterRequest) (controlRegisterResponse, error) {
	var resp controlRegisterResponse
	return resp, c.doJSON(ctx, http.MethodPost, "/v1/agents/register", req, &resp)
}

func (c controlClient) heartbeat(ctx context.Context, agentID string, req controlHeartbeatRequest) (controlHeartbeatResponse, error) {
	var resp controlHeartbeatResponse
	return resp, c.doJSON(ctx, http.MethodPost, "/v1/agents/"+agentID+"/heartbeat", req, &resp)
}

func (c controlClient) fetchSnapshot(ctx context.Context, agentID string, active uint32) (PolicySnapshot, bool, error) {
	url := fmt.Sprintf("%s/v1/agents/%s/snapshot?active_version=%d", c.baseURL, agentID, active)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PolicySnapshot{}, false, err
	}
	c.authorize(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return PolicySnapshot{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return PolicySnapshot{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return PolicySnapshot{}, false, fmt.Errorf("control status %d: %s", resp.StatusCode, RedactString(string(body)))
	}
	var out controlSnapshotResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return PolicySnapshot{}, false, err
	}
	return out.Snapshot, true, nil
}

func (c controlClient) ack(ctx context.Context, agentID string, result PolicyApplyResult) error {
	payload := map[string]any{
		"policy_version": result.Version,
		"status":         result.Status,
		"error_stage":    result.ErrorStage,
		"error_reason":   result.ErrorReason,
		"map_stats":      result.MapStats,
		"devmap_stats":   result.DevmapStats,
	}
	return c.doJSON(ctx, http.MethodPost, "/v1/agents/"+agentID+"/apply", payload, nil)
}

func (c controlClient) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.authorize(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control status %d: %s", resp.StatusCode, RedactString(string(raw)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c controlClient) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func loadControlState(path string) (controlState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return controlState{}, err
	}
	var state controlState
	if err := json.Unmarshal(raw, &state); err != nil {
		return controlState{}, err
	}
	return state, nil
}

func saveControlState(path string, state controlState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unknown"
	}
	return name
}

func interfaceMetadata(name string) controlAgentInterface {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return controlAgentInterface{Name: name}
	}
	return controlAgentInterface{
		Name:    iface.Name,
		Ifindex: uint32(iface.Index),
		MAC:     iface.HardwareAddr.String(),
		Role:    "wan",
	}
}

func fileTrimmed(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func ubuntuVersion() string {
	raw := fileTrimmed("/etc/os-release")
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

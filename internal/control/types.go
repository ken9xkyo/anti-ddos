package control

import (
	"encoding/json"
	"time"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"

	StatusActive  = "active"
	StatusRevoked = "revoked"

	ActionPass      = 0
	ActionDrop      = 1
	ActionRateLimit = 2
	ActionObserve   = 3
	ActionSample    = 4
	ActionRedirect  = 6

	PolicyScopeGlobal  = 0
	PolicyScopeService = 1

	NeighborResolved = 1
)

type User struct {
	ID                  string     `json:"id"`
	Username            string     `json:"username"`
	Role                string     `json:"role"`
	Status              string     `json:"status"`
	ForcePasswordChange bool       `json:"force_password_change"`
	CreatedAt           time.Time  `json:"created_at"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
}

type Session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      User      `json:"user"`
}

type ServiceInput struct {
	Reason                   string   `json:"reason"`
	Name                     string   `json:"name"`
	Description              string   `json:"description,omitempty"`
	BackendCIDR              string   `json:"backend_cidr"`
	Protocol                 string   `json:"protocol"`
	AllowedPorts             []uint16 `json:"allowed_ports"`
	OutputInterface          string   `json:"output_interface"`
	Owner                    string   `json:"owner"`
	Criticality              string   `json:"criticality"`
	ProtectionMode           string   `json:"protection_mode"`
	Enabled                  *bool    `json:"enabled,omitempty"`
	Priority                 uint32   `json:"priority,omitempty"`
	Tags                     []string `json:"tags,omitempty"`
	ResolvedIfindex          uint32   `json:"resolved_ifindex,omitempty"`
	ResolvedNextHopMAC       string   `json:"resolved_next_hop_mac,omitempty"`
	ResolvedSourceMAC        string   `json:"resolved_src_mac,omitempty"`
	NeighborResolutionStatus string   `json:"neighbor_resolution_status,omitempty"`
}

type Service struct {
	ID                       string    `json:"id"`
	EBPFID                   uint32    `json:"ebpf_id"`
	Name                     string    `json:"name"`
	Description              string    `json:"description,omitempty"`
	BackendCIDR              string    `json:"backend_cidr"`
	Protocol                 string    `json:"protocol"`
	AllowedPorts             []uint16  `json:"allowed_ports"`
	OutputInterface          string    `json:"output_interface"`
	Owner                    string    `json:"owner"`
	Criticality              string    `json:"criticality"`
	ProtectionMode           string    `json:"protection_mode"`
	Enabled                  bool      `json:"enabled"`
	Priority                 uint32    `json:"priority"`
	Tags                     []string  `json:"tags,omitempty"`
	SyncStatus               string    `json:"sync_status"`
	ResolvedIfindex          uint32    `json:"resolved_ifindex,omitempty"`
	ResolvedNextHopMAC       string    `json:"resolved_next_hop_mac,omitempty"`
	ResolvedSourceMAC        string    `json:"resolved_src_mac,omitempty"`
	NeighborResolutionStatus string    `json:"neighbor_resolution_status"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type ForwardingPolicyInput struct {
	Reason          string `json:"reason"`
	ServiceID       string `json:"service_id"`
	MatchProtocol   string `json:"match_protocol"`
	MatchDstPort    uint16 `json:"match_dst_port"`
	BackendTarget   string `json:"backend_target"`
	OutputInterface string `json:"output_interface"`
	ResolvedIfindex uint32 `json:"resolved_ifindex,omitempty"`
	ResolvedDstMAC  string `json:"resolved_dst_mac,omitempty"`
	ResolvedSrcMAC  string `json:"resolved_src_mac,omitempty"`
	DevmapKey       uint32 `json:"devmap_key,omitempty"`
	Action          string `json:"action"`
	Priority        uint32 `json:"priority,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty"`
	Owner           string `json:"owner"`
}

type ForwardingPolicy struct {
	ID              string    `json:"id"`
	EBPFID          uint32    `json:"ebpf_id"`
	ServiceID       string    `json:"service_id"`
	MatchProtocol   string    `json:"match_protocol"`
	MatchDstPort    uint16    `json:"match_dst_port"`
	BackendTarget   string    `json:"backend_target"`
	OutputInterface string    `json:"output_interface"`
	ResolvedIfindex uint32    `json:"resolved_ifindex,omitempty"`
	ResolvedDstMAC  string    `json:"resolved_dst_mac,omitempty"`
	ResolvedSrcMAC  string    `json:"resolved_src_mac,omitempty"`
	DevmapKey       uint32    `json:"devmap_key"`
	Action          string    `json:"action"`
	Priority        uint32    `json:"priority"`
	Enabled         bool      `json:"enabled"`
	Owner           string    `json:"owner"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type WhitelistInput struct {
	Reason    string    `json:"reason"`
	CIDR      string    `json:"cidr"`
	Scope     string    `json:"scope"`
	ServiceID string    `json:"service_id,omitempty"`
	Label     string    `json:"label,omitempty"`
	Owner     string    `json:"owner"`
	Priority  uint32    `json:"priority,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Enabled   *bool     `json:"enabled,omitempty"`
}

type WhitelistEntry struct {
	ID        string     `json:"id"`
	EBPFID    uint32     `json:"ebpf_id"`
	CIDR      string     `json:"cidr"`
	Scope     string     `json:"scope"`
	ServiceID string     `json:"service_id,omitempty"`
	Label     string     `json:"label,omitempty"`
	Reason    string     `json:"reason"`
	Owner     string     `json:"owner"`
	Priority  uint32     `json:"priority"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type RuleInput struct {
	Reason       string          `json:"reason"`
	ServiceID    string          `json:"service_id,omitempty"`
	Name         string          `json:"name"`
	Priority     uint32          `json:"priority,omitempty"`
	MatchExpr    json.RawMessage `json:"match_expr,omitempty"`
	Action       string          `json:"action"`
	Mode         string          `json:"mode"`
	ThresholdPPS uint32          `json:"threshold_pps,omitempty"`
	ThresholdBPS uint32          `json:"threshold_bps,omitempty"`
	ThresholdCPS uint32          `json:"threshold_cps,omitempty"`
	BurstPackets uint32          `json:"burst_packets,omitempty"`
	BurstBytes   uint32          `json:"burst_bytes,omitempty"`
	SampleDenom  uint32          `json:"sample_denom,omitempty"`
	TTLSeconds   uint32          `json:"ttl_seconds,omitempty"`
	ExpiresAt    time.Time       `json:"expires_at,omitempty"`
	Evidence     json.RawMessage `json:"evidence,omitempty"`
	Confidence   float64         `json:"confidence,omitempty"`
	Enabled      *bool           `json:"enabled,omitempty"`
	Owner        string          `json:"owner"`
}

type Rule struct {
	ID           string          `json:"id"`
	EBPFID       uint32          `json:"ebpf_id"`
	ServiceID    string          `json:"service_id,omitempty"`
	Name         string          `json:"name"`
	Priority     uint32          `json:"priority"`
	MatchExpr    json.RawMessage `json:"match_expr,omitempty"`
	Action       string          `json:"action"`
	Mode         string          `json:"mode"`
	ThresholdPPS uint32          `json:"threshold_pps,omitempty"`
	ThresholdBPS uint32          `json:"threshold_bps,omitempty"`
	ThresholdCPS uint32          `json:"threshold_cps,omitempty"`
	BurstPackets uint32          `json:"burst_packets,omitempty"`
	BurstBytes   uint32          `json:"burst_bytes,omitempty"`
	SampleDenom  uint32          `json:"sample_denom,omitempty"`
	TTLSeconds   uint32          `json:"ttl_seconds,omitempty"`
	ExpiresAt    *time.Time      `json:"expires_at,omitempty"`
	Evidence     json.RawMessage `json:"evidence,omitempty"`
	Confidence   float64         `json:"confidence,omitempty"`
	Enabled      bool            `json:"enabled"`
	Owner        string          `json:"owner"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type BlacklistInput struct {
	Reason    string    `json:"reason"`
	CIDR      string    `json:"cidr"`
	Score     uint32    `json:"score,omitempty"`
	Action    string    `json:"action"`
	Source    string    `json:"source"`
	RuleID    string    `json:"rule_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Enabled   *bool     `json:"enabled,omitempty"`
}

type BlacklistEntry struct {
	ID        string     `json:"id"`
	EBPFID    uint32     `json:"ebpf_id"`
	CIDR      string     `json:"cidr"`
	Score     uint32     `json:"score,omitempty"`
	Action    string     `json:"action"`
	Source    string     `json:"source"`
	RuleID    string     `json:"rule_id,omitempty"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type FeedSourceInput struct {
	Reason                string          `json:"reason"`
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	URL                   string          `json:"url,omitempty"`
	CredentialRef         string          `json:"credential_ref,omitempty"`
	RequiredForProduction bool            `json:"required_for_production,omitempty"`
	Enabled               *bool           `json:"enabled,omitempty"`
	IntervalSeconds       uint32          `json:"interval_seconds,omitempty"`
	LicenseNote           string          `json:"license_note,omitempty"`
	QuotaMetadata         json.RawMessage `json:"quota_metadata,omitempty"`
	Status                string          `json:"status,omitempty"`
}

type FeedSource struct {
	ID                    string          `json:"id"`
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	URL                   string          `json:"url,omitempty"`
	CredentialRef         string          `json:"credential_ref,omitempty"`
	RequiredForProduction bool            `json:"required_for_production"`
	Enabled               bool            `json:"enabled"`
	IntervalSeconds       uint32          `json:"interval_seconds"`
	LicenseNote           string          `json:"license_note,omitempty"`
	QuotaMetadata         json.RawMessage `json:"quota_metadata,omitempty"`
	Status                string          `json:"status"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

type AuditEvent struct {
	ID            string          `json:"id"`
	CreatedAt     time.Time       `json:"created_at"`
	ActorID       string          `json:"actor_id,omitempty"`
	ActorUsername string          `json:"actor_username,omitempty"`
	Action        string          `json:"action"`
	EntityType    string          `json:"entity_type"`
	EntityID      string          `json:"entity_id"`
	Before        json.RawMessage `json:"before,omitempty"`
	After         json.RawMessage `json:"after,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
}

type SnapshotMetadata struct {
	Version        uint32          `json:"version"`
	Checksum       string          `json:"checksum"`
	ObjectChecksum string          `json:"object_checksum"`
	RollbackFrom   *uint32         `json:"rollback_from,omitempty"`
	CreatedBy      string          `json:"created_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	Snapshot       json.RawMessage `json:"snapshot,omitempty"`
}

type AgentInterface struct {
	Name         string `json:"name"`
	Ifindex      uint32 `json:"ifindex,omitempty"`
	MAC          string `json:"mac,omitempty"`
	Role         string `json:"role,omitempty"`
	LinkSpeedBPS uint64 `json:"link_speed_bps,omitempty"`
}

type AgentRegisterRequest struct {
	Hostname      string           `json:"hostname"`
	Interfaces    []AgentInterface `json:"interfaces,omitempty"`
	KernelVersion string           `json:"kernel_version,omitempty"`
	UbuntuVersion string           `json:"ubuntu_version,omitempty"`
	XDPMode       string           `json:"xdp_mode,omitempty"`
	DevmapSupport bool             `json:"devmap_support"`
	AgentVersion  string           `json:"agent_version,omitempty"`
}

type AgentRegisterResponse struct {
	AgentID              string `json:"agent_id"`
	DesiredPolicyVersion uint32 `json:"desired_policy_version"`
}

type AgentHeartbeatRequest struct {
	Status              string          `json:"status"`
	ActivePolicyVersion uint32          `json:"active_policy_version"`
	XDPMode             string          `json:"xdp_mode,omitempty"`
	UptimeSeconds       uint64          `json:"uptime_seconds,omitempty"`
	MapUtilization      json.RawMessage `json:"map_utilization,omitempty"`
}

type AgentHeartbeatResponse struct {
	DesiredPolicyVersion uint32 `json:"desired_policy_version"`
}

type AgentApplyRequest struct {
	PolicyVersion uint32          `json:"policy_version"`
	Status        string          `json:"status"`
	ErrorStage    string          `json:"error_stage,omitempty"`
	ErrorReason   string          `json:"error_reason,omitempty"`
	MapStats      json.RawMessage `json:"map_stats,omitempty"`
	DevmapStats   json.RawMessage `json:"devmap_stats,omitempty"`
}

type SecurityEventBatch struct {
	Events []SecurityEventInput `json:"events"`
}

type SecurityEventInput struct {
	EventTime     time.Time       `json:"event_time,omitempty"`
	MonoTSNS      uint64          `json:"mono_ts_ns,omitempty"`
	PolicyVersion uint32          `json:"policy_version,omitempty"`
	SrcIP         string          `json:"src_ip"`
	DstIP         string          `json:"dst_ip"`
	SrcPort       uint16          `json:"src_port,omitempty"`
	DstPort       uint16          `json:"dst_port,omitempty"`
	Protocol      uint8           `json:"protocol,omitempty"`
	TCPFlags      uint8           `json:"tcp_flags,omitempty"`
	Action        uint8           `json:"action,omitempty"`
	Reason        uint8           `json:"reason,omitempty"`
	ServiceID     uint32          `json:"service_id,omitempty"`
	RuleID        uint32          `json:"rule_id,omitempty"`
	PktLen        uint32          `json:"pkt_len,omitempty"`
	SampleRate    uint32          `json:"sample_rate,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

type SecurityEvent struct {
	ID            string          `json:"id"`
	ReceivedAt    time.Time       `json:"received_at"`
	EventTime     time.Time       `json:"event_time"`
	AgentID       string          `json:"agent_id,omitempty"`
	MonoTSNS      uint64          `json:"mono_ts_ns,omitempty"`
	PolicyVersion uint32          `json:"policy_version,omitempty"`
	SrcIP         string          `json:"src_ip"`
	SrcPrefix24   string          `json:"src_prefix24"`
	DstIP         string          `json:"dst_ip"`
	SrcPort       uint16          `json:"src_port,omitempty"`
	DstPort       uint16          `json:"dst_port,omitempty"`
	Protocol      uint8           `json:"protocol,omitempty"`
	TCPFlags      uint8           `json:"tcp_flags,omitempty"`
	Action        uint8           `json:"action,omitempty"`
	Reason        uint8           `json:"reason,omitempty"`
	ServiceID     uint32          `json:"service_id,omitempty"`
	RuleID        uint32          `json:"rule_id,omitempty"`
	PktLen        uint32          `json:"pkt_len,omitempty"`
	SampleRate    uint32          `json:"sample_rate,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

type SecurityEventIngestResult struct {
	Accepted int `json:"accepted"`
}

type SecurityEventSummary struct {
	WindowSeconds int                `json:"window_seconds"`
	Total         uint64             `json:"total"`
	TopSources    []SecurityEventTop `json:"top_sources"`
	TopPorts      []SecurityEventTop `json:"top_ports"`
	ByDecision    []SecurityEventTop `json:"by_decision"`
}

type SecurityEventTop struct {
	Key     string `json:"key"`
	Count   uint64 `json:"count"`
	Packets uint64 `json:"packets,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty"`
}

type DashboardOverview struct {
	GeneratedAt       time.Time              `json:"generated_at"`
	Prometheus        PrometheusStatus       `json:"prometheus"`
	Traffic           DashboardTraffic       `json:"traffic"`
	DecisionRates     map[string]float64     `json:"decision_rates"`
	SecurityEvents    SecurityEventSummary   `json:"security_events"`
	AgentSummary      DashboardAgentSummary  `json:"agents"`
	SnapshotVersion   uint32                 `json:"snapshot_version"`
	LatestApplyStatus []DashboardApplyStatus `json:"latest_apply_status"`
}

type PrometheusStatus struct {
	Configured bool   `json:"configured"`
	Healthy    bool   `json:"healthy"`
	Error      string `json:"error,omitempty"`
}

type DashboardTraffic struct {
	PPS float64 `json:"pps"`
	BPS float64 `json:"bps"`
	CPS float64 `json:"cps"`
}

type DashboardAgentSummary struct {
	Total int `json:"total"`
	Stale int `json:"stale"`
}

type DashboardApplyStatus struct {
	AgentID       string    `json:"agent_id"`
	Hostname      string    `json:"hostname"`
	PolicyVersion uint32    `json:"policy_version"`
	Status        string    `json:"status"`
	ErrorStage    string    `json:"error_stage,omitempty"`
	ErrorReason   string    `json:"error_reason,omitempty"`
	ReportedAt    time.Time `json:"reported_at"`
}

type DashboardAgent struct {
	ID                  string                `json:"id"`
	Hostname            string                `json:"hostname"`
	Status              string                `json:"status"`
	XDPMode             string                `json:"xdp_mode"`
	DevmapSupport       bool                  `json:"devmap_support"`
	ActivePolicyVersion uint32                `json:"active_policy_version"`
	LastSeenAt          *time.Time            `json:"last_seen_at,omitempty"`
	Stale               bool                  `json:"stale"`
	MapUtilization      json.RawMessage       `json:"map_utilization,omitempty"`
	Interfaces          []AgentInterface      `json:"interfaces,omitempty"`
	LatestApply         *DashboardApplyStatus `json:"latest_apply,omitempty"`
}

type DashboardService struct {
	Service
	Counters    map[string]float64 `json:"counters,omitempty"`
	ApplyStatus string             `json:"apply_status,omitempty"`
}

type DashboardRule struct {
	Rule
	TTLRemainingSeconds int64              `json:"ttl_remaining_seconds,omitempty"`
	Counters            map[string]float64 `json:"counters,omitempty"`
}

type RollbackRequest struct {
	Reason        string `json:"reason"`
	TargetVersion uint32 `json:"target_version"`
}

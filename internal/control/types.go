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

type UserUpdateInput struct {
	Reason              string `json:"reason"`
	Role                string `json:"role,omitempty"`
	Status              string `json:"status,omitempty"`
	ForcePasswordChange *bool  `json:"force_password_change,omitempty"`
}

type PasswordResetInput struct {
	Reason              string `json:"reason"`
	Password            string `json:"password"`
	ForcePasswordChange *bool  `json:"force_password_change,omitempty"`
}

type OwnPasswordInput struct {
	Reason          string `json:"reason"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
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
	Dimension    string          `json:"dimension,omitempty"`
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
	Dimension    string          `json:"dimension,omitempty"`
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
	LastSuccessAt         *time.Time      `json:"last_success_at,omitempty"`
	LastErrorAt           *time.Time      `json:"last_error_at,omitempty"`
	LastError             string          `json:"last_error,omitempty"`
	NextRunAt             *time.Time      `json:"next_run_at,omitempty"`
	ActiveEntries         uint32          `json:"active_entries"`
	ConflictCount         uint32          `json:"conflict_count"`
	ParseErrorCount       uint32          `json:"parse_error_count"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

type FeedRun struct {
	ID              string     `json:"id"`
	SourceID        string     `json:"source_id"`
	SourceName      string     `json:"source_name,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	Status          string     `json:"status"`
	ItemsFetched    uint32     `json:"items_fetched"`
	ItemsValid      uint32     `json:"items_valid"`
	ParseErrors     uint32     `json:"parse_errors"`
	Error           string     `json:"error,omitempty"`
	SnapshotVersion uint32     `json:"snapshot_version,omitempty"`
}

type FeedConflict struct {
	ID             string    `json:"id"`
	SourceID       string    `json:"source_id"`
	SourceName     string    `json:"source_name,omitempty"`
	ReputationID   string    `json:"reputation_id"`
	WhitelistID    string    `json:"whitelist_id"`
	ReputationCIDR string    `json:"reputation_cidr"`
	WhitelistCIDR  string    `json:"whitelist_cidr"`
	Status         string    `json:"status"`
	DetectedAt     time.Time `json:"detected_at"`
}

type TelegramConfigInput struct {
	Reason      string `json:"reason"`
	BotTokenRef string `json:"bot_token_ref"`
	ChatID      string `json:"chat_id"`
	ParseMode   string `json:"parse_mode,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

type TelegramConfig struct {
	BotTokenRef     string    `json:"bot_token_ref"`
	BotTokenPresent bool      `json:"bot_token_present"`
	ChatID          string    `json:"chat_id"`
	ParseMode       string    `json:"parse_mode,omitempty"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type AlertInput struct {
	Severity          string          `json:"severity"`
	Type              string          `json:"type"`
	DedupeKey         string          `json:"dedupe_key"`
	ServiceID         string          `json:"service_id,omitempty"`
	AffectedService   string          `json:"affected_service,omitempty"`
	Vector            string          `json:"vector,omitempty"`
	Evidence          json.RawMessage `json:"evidence,omitempty"`
	RecommendedAction string          `json:"recommended_action,omitempty"`
}

type Alert struct {
	ID                string          `json:"id"`
	Severity          string          `json:"severity"`
	Type              string          `json:"type"`
	DedupeKey         string          `json:"dedupe_key"`
	ServiceID         string          `json:"service_id,omitempty"`
	AffectedService   string          `json:"affected_service,omitempty"`
	Vector            string          `json:"vector,omitempty"`
	Evidence          json.RawMessage `json:"evidence,omitempty"`
	RecommendedAction string          `json:"recommended_action,omitempty"`
	Status            string          `json:"status"`
	CreatedBy         string          `json:"created_by,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	ResolvedAt        *time.Time      `json:"resolved_at,omitempty"`
	Deliveries        []AlertDelivery `json:"deliveries,omitempty"`
}

type AlertDelivery struct {
	ID        string          `json:"id"`
	AlertID   string          `json:"alert_id"`
	Channel   string          `json:"channel"`
	Status    string          `json:"status"`
	Attempt   uint32          `json:"attempt"`
	Error     string          `json:"error,omitempty"`
	Response  json.RawMessage `json:"response,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	SentAt    *time.Time      `json:"sent_at,omitempty"`
}

type ISPEscalationInput struct {
	Reason          string          `json:"reason"`
	ServiceID       string          `json:"service_id,omitempty"`
	Target          string          `json:"target,omitempty"`
	Vector          string          `json:"vector,omitempty"`
	StartTime       time.Time       `json:"start_time,omitempty"`
	PeakBPS         float64         `json:"peak_bps,omitempty"`
	PeakPPS         float64         `json:"peak_pps,omitempty"`
	PacketLossRatio float64         `json:"packet_loss_ratio,omitempty"`
	RouteFailure    string          `json:"route_failure,omitempty"`
	Evidence        json.RawMessage `json:"evidence,omitempty"`
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

type SnapshotDiffValue struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Changed bool   `json:"changed"`
}

type SnapshotDiffItem struct {
	Key  string          `json:"key"`
	Item json.RawMessage `json:"item"`
}

type SnapshotDiffChange struct {
	Key    string          `json:"key"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

type SnapshotCollectionDiff struct {
	Added     []SnapshotDiffItem   `json:"added"`
	Removed   []SnapshotDiffItem   `json:"removed"`
	Changed   []SnapshotDiffChange `json:"changed"`
	Unchanged uint32               `json:"unchanged"`
}

type SnapshotDiff struct {
	FromVersion    uint32                 `json:"from_version"`
	ToVersion      uint32                 `json:"to_version"`
	ObjectChecksum SnapshotDiffValue      `json:"object_checksum"`
	Runtime        *SnapshotDiffChange    `json:"runtime,omitempty"`
	Services       SnapshotCollectionDiff `json:"services"`
	WhitelistV4    SnapshotCollectionDiff `json:"whitelist_v4"`
	BlacklistV4    SnapshotCollectionDiff `json:"blacklist_v4"`
	Rules          SnapshotCollectionDiff `json:"rules"`
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
	Status              string           `json:"status"`
	ActivePolicyVersion uint32           `json:"active_policy_version"`
	XDPMode             string           `json:"xdp_mode,omitempty"`
	UptimeSeconds       uint64           `json:"uptime_seconds,omitempty"`
	MapUtilization      json.RawMessage  `json:"map_utilization,omitempty"`
	Interfaces          []AgentInterface `json:"interfaces,omitempty"`
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

type BaselineProfileInput struct {
	Reason       string          `json:"reason"`
	ServiceID    string          `json:"service_id"`
	Interface    string          `json:"interface"`
	Protocol     string          `json:"protocol"`
	Port         uint16          `json:"port,omitempty"`
	Window       string          `json:"window"`
	ExpectedPPS  float64         `json:"expected_pps"`
	ExpectedBPS  float64         `json:"expected_bps"`
	ExpectedCPS  float64         `json:"expected_cps"`
	HistoryHours uint32          `json:"history_hours"`
	Confidence   float64         `json:"confidence"`
	Evidence     json.RawMessage `json:"evidence,omitempty"`
}

type BaselineProfile struct {
	ID            string          `json:"id"`
	ServiceID     string          `json:"service_id"`
	ServiceEBPFID uint32          `json:"service_ebpf_id,omitempty"`
	ServiceName   string          `json:"service_name,omitempty"`
	Interface     string          `json:"interface"`
	Protocol      string          `json:"protocol"`
	Port          uint16          `json:"port,omitempty"`
	Window        string          `json:"window"`
	ExpectedPPS   float64         `json:"expected_pps"`
	ExpectedBPS   float64         `json:"expected_bps"`
	ExpectedCPS   float64         `json:"expected_cps"`
	HistoryHours  uint32          `json:"history_hours"`
	Confidence    float64         `json:"confidence"`
	Approved      bool            `json:"approved"`
	Status        string          `json:"status"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	ApprovedAt    *time.Time      `json:"approved_at,omitempty"`
}

type AnomalyEvaluation struct {
	ID                 string          `json:"id"`
	ServiceID          string          `json:"service_id,omitempty"`
	ServiceEBPFID      uint32          `json:"service_ebpf_id,omitempty"`
	ServiceName        string          `json:"service_name,omitempty"`
	BaselineID         string          `json:"baseline_id,omitempty"`
	EvaluatedAt        time.Time       `json:"evaluated_at"`
	Window             string          `json:"window"`
	PPS                float64         `json:"pps"`
	BPS                float64         `json:"bps"`
	CPS                float64         `json:"cps"`
	DropRatio          float64         `json:"drop_ratio"`
	Score              float64         `json:"score"`
	Confidence         float64         `json:"confidence"`
	Signals            []string        `json:"signals,omitempty"`
	Recommendation     string          `json:"recommendation"`
	RecommendedAction  string          `json:"recommended_action"`
	ProposedTTLSeconds uint32          `json:"proposed_ttl_seconds,omitempty"`
	ProposedRuleID     string          `json:"proposed_rule_id,omitempty"`
	AutoEnforced       bool            `json:"auto_enforced"`
	Status             string          `json:"status"`
	Reason             string          `json:"reason,omitempty"`
	Source             string          `json:"source,omitempty"`
	Evidence           json.RawMessage `json:"evidence,omitempty"`
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

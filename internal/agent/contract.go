package agent

const (
	actionPass       = 0
	actionDrop       = 1
	actionRateLimit  = 2
	actionObserve    = 3
	actionSample     = 4
	actionNotForward = 5
	actionRedirect   = 6

	reasonNone               = 0
	reasonBlacklist          = 3
	reasonNotAllowedService  = 4
	reasonMapError           = 7
	reasonRedirectError      = 8
	reasonNeighborUnresolved = 9

	l4ICMP = 1
	l4TCP  = 6
	l4UDP  = 17

	policyScopeGlobal  = 0
	policyScopeService = 1

	neighborUnresolved = 0
	neighborResolved   = 1

	maxEventSampleDenom = 1000000
)

type RuntimeConfigValue struct {
	ActiveSlot        uint32
	PolicyVersion     uint32
	MalformedPolicy   uint32
	SampleDenom       uint32
	UpdatedAtUnixNano uint64
}

type LPMV4Key struct {
	PrefixLen uint32
	Addr      uint32
}

type CIDRPolicyValue struct {
	EntryID         uint32
	Priority        uint32
	Action          uint32
	SourceType      uint32
	Scope           uint32
	ServiceID       uint32
	Score           uint32
	RuleID          uint32
	ExpiresAtUnixNS uint64
}

type ServiceKey struct {
	DstV4   uint32
	DstPort uint16
	Proto   uint8
	Pad     uint8
}

type ServiceValue struct {
	ServiceID          uint32
	ForwardingPolicyID uint32
	Action             uint32
	Priority           uint32
	DefaultRuleID      uint32
	OutputIfindex      uint32
	DevmapKey          uint32
	NeighborStatus     uint32
	DstMAC             [6]byte
	SrcMAC             [6]byte
	Pad                uint16
	TailPad            uint16
}

type RuleValue struct {
	RuleID          uint32
	Priority        uint32
	Action          uint32
	Mode            uint32
	ServiceID       uint32
	ThresholdPPS    uint32
	ThresholdBPS    uint32
	ThresholdCPS    uint32
	BurstPackets    uint32
	BurstBytes      uint32
	SampleDenom     uint32
	Pad             uint32
	ExpiresAtUnixNS uint64
}

type CounterKey struct {
	Reason    uint32
	RuleID    uint32
	ServiceID uint32
	Proto     uint8
	Action    uint8
	Pad       uint16
}

type CounterValue struct {
	Packets uint64
	Bytes   uint64
}

type EventRecord struct {
	TsMonoNS      uint64
	PolicyVersion uint32
	SrcV4         uint32
	DstV4         uint32
	SrcPort       uint16
	DstPort       uint16
	Proto         uint8
	TCPFlags      uint8
	Action        uint8
	Reason        uint8
	ServiceID     uint32
	RuleID        uint32
	PktLen        uint32
}

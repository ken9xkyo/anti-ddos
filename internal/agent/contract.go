package agent

const (
	actionDrop = 1

	reasonMapError = 7
)

type RuntimeConfigValue struct {
	ActiveSlot        uint32
	PolicyVersion     uint32
	MalformedPolicy   uint32
	SampleDenom       uint32
	UpdatedAtUnixNano uint64
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

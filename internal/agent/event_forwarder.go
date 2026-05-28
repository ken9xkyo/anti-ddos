package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	defaultEventQueueSize = 4096
	defaultEventBatchSize = 100
	defaultEventFlush     = time.Second
)

type controlSecurityEventBatch struct {
	Events []controlSecurityEvent `json:"events"`
}

type controlSecurityEvent struct {
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

type SecurityEventForwarder struct {
	client     controlClient
	statePath  string
	queue      chan controlSecurityEvent
	batchSize  int
	flushEvery time.Duration
	sampleRate uint32
	metrics    *Metrics
	logger     *slog.Logger
}

func NewSecurityEventForwarder(cfg Config, sampleRate uint32, metrics *Metrics, logger *slog.Logger) *SecurityEventForwarder {
	if sampleRate == 0 {
		sampleRate = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SecurityEventForwarder{
		client: controlClient{
			baseURL: cfg.ControlURL,
			token:   cfg.AgentToken,
			client:  &http.Client{Timeout: 10 * time.Second},
		},
		statePath:  cfg.AgentStatePath,
		queue:      make(chan controlSecurityEvent, defaultEventQueueSize),
		batchSize:  defaultEventBatchSize,
		flushEvery: defaultEventFlush,
		sampleRate: sampleRate,
		metrics:    metrics,
		logger:     logger,
	}
}

func (f *SecurityEventForwarder) Enqueue(record EventRecord) {
	event := controlEventFromRecord(record, time.Now().UTC(), f.sampleRate)
	select {
	case f.queue <- event:
	default:
		if f.metrics != nil {
			f.metrics.IncControlEventDrop("queue_full")
		}
	}
}

func (f *SecurityEventForwarder) Run(ctx context.Context) {
	ticker := time.NewTicker(f.flushEvery)
	defer ticker.Stop()
	batch := make([]controlSecurityEvent, 0, f.batchSize)
	for {
		select {
		case <-ctx.Done():
			f.flush(context.Background(), batch)
			return
		case event := <-f.queue:
			batch = append(batch, event)
			if len(batch) >= f.batchSize {
				f.flush(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				f.flush(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

func (f *SecurityEventForwarder) flush(ctx context.Context, batch []controlSecurityEvent) {
	if len(batch) == 0 {
		return
	}
	state, err := loadControlState(f.statePath)
	if err != nil || state.AgentID == "" {
		if f.metrics != nil {
			for range batch {
				f.metrics.IncControlEventDrop("unregistered")
			}
		}
		return
	}
	if err := f.client.postEvents(ctx, state.AgentID, batch); err != nil {
		if f.metrics != nil {
			f.metrics.IncControlEventForwardError()
			for range batch {
				f.metrics.IncControlEventDrop("post_failed")
			}
		}
		if f.logger != nil {
			f.logger.Warn("control event forwarding failed", "error", RedactString(err.Error()))
		}
		return
	}
	if f.metrics != nil {
		f.metrics.AddControlEventsForwarded(len(batch))
	}
}

func (c controlClient) postEvents(ctx context.Context, agentID string, events []controlSecurityEvent) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/agents/"+agentID+"/events", controlSecurityEventBatch{Events: events}, nil)
}

func controlEventFromRecord(record EventRecord, eventTime time.Time, sampleRate uint32) controlSecurityEvent {
	return controlSecurityEvent{
		EventTime:     eventTime,
		MonoTSNS:      record.TsMonoNS,
		PolicyVersion: record.PolicyVersion,
		SrcIP:         ipv4String(record.SrcV4),
		DstIP:         ipv4String(record.DstV4),
		SrcPort:       record.SrcPort,
		DstPort:       record.DstPort,
		Protocol:      record.Proto,
		TCPFlags:      record.TCPFlags,
		Action:        record.Action,
		Reason:        record.Reason,
		ServiceID:     record.ServiceID,
		RuleID:        record.RuleID,
		PktLen:        record.PktLen,
		SampleRate:    sampleRate,
	}
}

func ipv4String(value uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

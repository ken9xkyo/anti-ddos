// Package events consumes the BPF ringbuf and dispatches structured records.
package events

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// Event mirrors struct event in bpf/common.h.
type Event struct {
	TSJiffies   uint64
	SaddrHi     uint32
	Saddr       uint32
	SaddrMid1   uint32
	SaddrMid2   uint32
	Sport       uint16
	Dport       uint16
	Proto       uint8
	Action      uint8 // 0=pass 1=redirect 2=drop
	Reason      uint8
	V6          uint8
	Bytes       uint32
}

// Handler is called for every event decoded from the ringbuf.
type Handler func(Event)

// Reader pumps the ringbuf until the context is cancelled.
type Reader struct {
	m   *ebpf.Map
	log *zap.Logger
	h   Handler
}

// New wires a reader over the pinned events ringbuf map.
func New(m *ebpf.Map, log *zap.Logger, h Handler) *Reader {
	if log == nil {
		log = zap.NewNop()
	}
	return &Reader{m: m, log: log, h: h}
}

// Run blocks until ctx is cancelled or the ringbuf is closed.
func (r *Reader) Run(ctx context.Context) error {
	rd, err := ringbuf.NewReader(r.m)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Close on cancel.
	go func() { <-ctx.Done(); _ = rd.Close() }()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		if len(rec.RawSample) < 40 {
			r.log.Warn("short ringbuf record", zap.Int("len", len(rec.RawSample)))
			continue
		}
		ev := decode(rec.RawSample)
		if r.h != nil {
			r.h(ev)
		}
	}
}

func decode(b []byte) Event {
	le := binary.LittleEndian
	var e Event
	e.TSJiffies = le.Uint64(b[0:8])
	e.SaddrHi = le.Uint32(b[8:12])
	e.Saddr = le.Uint32(b[12:16])
	e.SaddrMid1 = le.Uint32(b[16:20])
	e.SaddrMid2 = le.Uint32(b[20:24])
	e.Sport = le.Uint16(b[24:26])
	e.Dport = le.Uint16(b[26:28])
	e.Proto = b[28]
	e.Action = b[29]
	e.Reason = b[30]
	e.V6 = b[31]
	e.Bytes = le.Uint32(b[32:36])
	return e
}

// SrcIP returns the parsed source IP of the event. The BPF-side fields hold
// addresses in network byte order; the on-wire layout is preserved after
// decoding via little-endian, so we just write the u32s back out little-endian
// to reconstruct the original NBO byte sequence.
func (e Event) SrcIP() netip.Addr {
	if e.V6 != 0 {
		var raw [16]byte
		putRawBE(raw[0:4], e.SaddrHi)
		putRawBE(raw[4:8], e.Saddr)
		putRawBE(raw[8:12], e.SaddrMid1)
		putRawBE(raw[12:16], e.SaddrMid2)
		return netip.AddrFrom16(raw)
	}
	var raw [4]byte
	putRawBE(raw[:], e.Saddr)
	return netip.AddrFrom4(raw)
}

func putRawBE(dst []byte, v uint32) {
	// v was decoded LE from NBO bytes; writing LE restores the NBO sequence.
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

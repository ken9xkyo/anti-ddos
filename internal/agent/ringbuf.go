package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func ConsumeRingbuf(ctx context.Context, events *ebpf.Map, metrics *Metrics, logger *slog.Logger) error {
	if events == nil {
		return nil
	}
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return err
	}
	defer reader.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		reader.SetDeadline(time.Now().Add(500 * time.Millisecond))
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrClosed) {
				continue
			}
			if metrics != nil {
				metrics.IncRingbufError()
			}
			if logger != nil {
				logger.Warn("ringbuf consume error", "error", RedactString(err.Error()))
			}
			continue
		}

		var event EventRecord
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			if metrics != nil {
				metrics.IncRingbufError()
			}
			continue
		}
		if metrics != nil {
			metrics.IncRingbufEvent()
		}
	}
}

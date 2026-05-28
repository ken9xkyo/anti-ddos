package agent

import "testing"

func TestSumCounterValues(t *testing.T) {
	got := SumCounterValues([]CounterValue{
		{Packets: 1, Bytes: 64},
		{Packets: 2, Bytes: 128},
	})
	if got.Packets != 3 || got.Bytes != 192 {
		t.Fatalf("unexpected sum: %#v", got)
	}
}

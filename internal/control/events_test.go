package control

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeSecurityEventDefaults(t *testing.T) {
	event, err := normalizeSecurityEvent(SecurityEventInput{
		SrcIP:    "198.51.100.10",
		DstIP:    "203.0.113.10",
		SrcPort:  12345,
		DstPort:  443,
		Protocol: 6,
		Action:   uint8(ActionDrop),
		Reason:   5,
		PktLen:   60,
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if event.SrcPrefix24 != "198.51.100.0/24" || event.SampleRate != 10 || string(event.Metadata) != "{}" {
		t.Fatalf("normalized event = %#v", event)
	}
	if event.EventTime.IsZero() || event.EventTime.Location() != time.UTC {
		t.Fatalf("event time not defaulted to UTC: %#v", event.EventTime)
	}
}

func TestNormalizeSecurityEventRejectsNonIPv4(t *testing.T) {
	tests := []struct {
		name  string
		input SecurityEventInput
		want  string
	}{
		{name: "bad source", input: SecurityEventInput{SrcIP: "2001:db8::1", DstIP: "203.0.113.10"}, want: "src_ip"},
		{name: "bad destination", input: SecurityEventInput{SrcIP: "198.51.100.10", DstIP: "2001:db8::1"}, want: "dst_ip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalizeSecurityEvent(tt.input, 1)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("normalizeSecurityEvent() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseSecurityEventQuery(t *testing.T) {
	query, err := parseSecurityEventQuery(map[string][]string{
		"since":      {"2026-06-01T00:00:00Z"},
		"until":      {"2026-06-01T01:00:00Z"},
		"service_id": {"40"},
		"rule_id":    {"400"},
		"action":     {"1"},
		"reason":     {"5"},
		"src":        {"198.51.100.0/24"},
		"limit":      {"50"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if query.ServiceID != 40 || query.RuleID != 400 || query.Action != 1 || query.Reason != 5 || query.Src != "198.51.100.0/24" || query.Limit != 50 {
		t.Fatalf("query parsed incorrectly: %#v", query)
	}
	where, args, err := securityEventWhere(query)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "service_id") || !strings.Contains(where, "src_ip <<=") || len(args) != 7 {
		t.Fatalf("where=%q args=%#v", where, args)
	}
}

func TestParseSecurityEventQueryRejectsInvalidValues(t *testing.T) {
	if _, err := parseSecurityEventQuery(map[string][]string{"since": {"bad-time"}}); err == nil {
		t.Fatal("expected invalid since to fail")
	}
	if _, _, err := securityEventWhere(SecurityEventQuery{Src: "not-an-ip"}); err == nil {
		t.Fatal("expected invalid source filter to fail")
	}
}

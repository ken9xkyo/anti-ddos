package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelegramClientSendMessageClassifiesResponses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		retryable bool
		wantErr   bool
	}{
		{name: "success", status: http.StatusOK, body: `{"ok":true}`},
		{name: "rate limit", status: http.StatusTooManyRequests, body: `{"ok":false}`, retryable: true, wantErr: true},
		{name: "server error", status: http.StatusBadGateway, body: `bad gateway`, retryable: true, wantErr: true},
		{name: "malformed", status: http.StatusOK, body: `not-json`, retryable: true, wantErr: true},
		{name: "auth failure", status: http.StatusUnauthorized, body: `{"ok":false}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			result, err := NewTelegramClient(server.URL, server.Client()).SendMessage(context.Background(), "token", "chat", "", "hello")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if result.Retryable != tt.retryable {
				t.Fatalf("retryable=%v want=%v", result.Retryable, tt.retryable)
			}
			if !json.Valid(defaultJSON(result.Response)) {
				t.Fatalf("response must be valid json: %s", result.Response)
			}
		})
	}
}

func TestAlertHelpers(t *testing.T) {
	input := AlertInput{Severity: "CRITICAL", Type: "isp_escalation_needed", DedupeKey: "k"}
	if err := validateAlertInput(input); err != nil {
		t.Fatal(err)
	}
	msg := renderAlertMessage(Alert{
		Severity:          "critical",
		Type:              "isp_escalation_needed",
		DedupeKey:         "k",
		AffectedService:   "api",
		Vector:            "udp_flood",
		RecommendedAction: "manual escalation",
		Evidence:          json.RawMessage(`{"peak_bps":1000}`),
	}, "")
	for _, want := range []string{"CRITICAL", "isp_escalation_needed", "api", "udp_flood", "manual escalation"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q missing %q", msg, want)
		}
	}
	if got := trimTelegramMessage(strings.Repeat("x", maxTelegramMessageBytes+100)); len(got) > maxTelegramMessageBytes {
		t.Fatalf("telegram trim failed len=%d", len(got))
	}
	store := &Store{alertRetryBase: time.Millisecond}
	if got := store.alertRetryDelay(3); got != 4*time.Millisecond {
		t.Fatalf("backoff=%s", got)
	}
}

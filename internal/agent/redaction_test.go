package agent

import (
	"strings"
	"testing"
)

func TestRedactKeyValue(t *testing.T) {
	if got := RedactKeyValue("ANTI_DDOS_DB_DSN_SECRET_REF", "postgres://user:pass@example/db"); got != redactedValue {
		t.Fatalf("secret key was not redacted: %q", got)
	}

	got := RedactKeyValue("url", "https://example.test/feed?api_key=abc123&safe=yes")
	if strings.Contains(got, "abc123") {
		t.Fatalf("query secret was not redacted: %q", got)
	}
	if !strings.Contains(got, "safe=yes") {
		t.Fatalf("non-secret query value should remain visible: %q", got)
	}
}

func TestRedactedEnvSnapshotSortsKeys(t *testing.T) {
	got := RedactedEnvSnapshot(map[string]string{
		"B": "safe",
		"A": "123456:abcdefghijklmnopqrstuvwxyz",
	})
	if len(got) != 2 || !strings.HasPrefix(got[0], "A=") {
		t.Fatalf("env snapshot not sorted: %#v", got)
	}
	if strings.Contains(got[0], "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("telegram-shaped token was not redacted: %#v", got)
	}
}

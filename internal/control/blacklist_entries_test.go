package control

import (
	"strings"
	"testing"
)

func TestBlacklistEntriesCTEUsesReputationTimestampColumns(t *testing.T) {
	sql := blacklistEntriesCTE()
	if strings.Contains(sql, "re.created_at") {
		t.Fatal("blacklist entries CTE references reputation_entries.created_at, which does not exist")
	}
	if !strings.Contains(sql, "re.first_seen_at AS created_at") {
		t.Fatal("blacklist entries CTE should expose feed row created_at from reputation_entries.first_seen_at")
	}
	if !strings.Contains(sql, "re.last_seen_at AS updated_at") {
		t.Fatal("blacklist entries CTE should expose feed row updated_at from reputation_entries.last_seen_at")
	}
}

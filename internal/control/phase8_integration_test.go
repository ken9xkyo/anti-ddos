package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

func TestPhase08ThreatFeedSyncIntegration(t *testing.T) {
	dsn := os.Getenv("ANTI_DDOS_CONTROL_TEST_DSN")
	if dsn == "" {
		t.Skip("ANTI_DDOS_CONTROL_TEST_DSN is not set")
	}
	ctx := context.Background()
	pool, err := OpenPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("idempotent migration run: %v", err)
	}

	failFeed := false
	feedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failFeed {
			http.Error(w, "feed unavailable", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{"cidr": "198.51.100.0/25", "score": 95, "action": "drop", "ttl_seconds": 3600, "reason": "fixture"},
				{"cidr": "198.51.100.128/25", "score": 95, "action": "drop", "ttl_seconds": 3600, "reason": "fixture"},
				{"cidr": "203.0.113.0/25", "score": 80, "action": "drop", "ttl_seconds": 3600, "reason": "merge"},
				{"cidr": "203.0.113.128/25", "score": 80, "action": "drop", "ttl_seconds": 3600, "reason": "merge"},
				{"cidr": "2001:db8::/32", "score": 80, "action": "drop"},
			},
		})
	}))
	defer feedServer.Close()

	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret"}
	store := NewStore(pool, cfg, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	if _, err := store.CreateUser(ctx, adminActor, "viewer", "viewer password phrase", RoleViewer, "create viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(ctx, adminActor, "operator", "operator password phrase", RoleOperator, "create operator"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	viewerToken := login(t, server.URL, "viewer", "viewer password phrase")
	operatorToken := login(t, server.URL, "operator", "operator password phrase")

	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/whitelist", adminToken, WhitelistInput{
		Reason: "trusted customer source",
		CIDR:   "198.51.100.10/32",
		Scope:  "global",
		Owner:  "sre",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("create whitelist status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources", adminToken, FeedSourceInput{
		Reason:                "configure internal feed",
		Name:                  "internal-fixture",
		Type:                  "internal_json",
		URL:                   feedServer.URL,
		RequiredForProduction: true,
		Enabled:               boolPtr(true),
		IntervalSeconds:       3600,
		LicenseNote:           "fixture",
		QuotaMetadata:         json.RawMessage(`{"ttl_seconds":3600}`),
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("create feed source status=%d body=%s", resp.Code, resp.Body.String())
	}
	var source FeedSource
	if err := json.Unmarshal(resp.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}

	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/feed-sources/"+source.ID, operatorToken, FeedSourceInput{
		Reason:          "operator cannot update credential",
		Name:            source.Name,
		Type:            source.Type,
		URL:             source.URL,
		CredentialRef:   "env://SHOULD_NOT_BE_ALLOWED",
		Enabled:         boolPtr(true),
		IntervalSeconds: 3600,
	})
	if resp.Code != http.StatusBadRequest && resp.Code != http.StatusForbidden {
		t.Fatalf("operator credential update should fail status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources/"+source.ID+"/sync", viewerToken, map[string]string{"reason": "viewer should not sync"})
	if resp.Code != http.StatusForbidden && resp.Code != http.StatusBadRequest {
		t.Fatalf("viewer sync should fail status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources/"+source.ID+"/sync", adminToken, map[string]string{"reason": "manual feed sync"})
	if resp.Code != http.StatusOK {
		t.Fatalf("sync feed status=%d body=%s", resp.Code, resp.Body.String())
	}
	var run FeedRun
	if err := json.Unmarshal(resp.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.ItemsFetched != 5 || run.ParseErrors != 1 || run.ItemsValid != 3 {
		t.Fatalf("unexpected run stats: %#v", run)
	}

	conflicts, err := store.ListFeedConflicts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 || conflicts[0].ReputationCIDR != "198.51.100.0/25" {
		t.Fatalf("expected whitelist conflict report, got %#v", conflicts)
	}
	source, err = store.GetFeedSource(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if source.ActiveEntries != 2 || source.ConflictCount != 1 || source.Status != feedStatusHealthy {
		t.Fatalf("source status not updated: %#v", source)
	}
	assertLatestSnapshotBlacklist(t, store, ctx, []string{"198.51.100.128/25", "203.0.113.0/24"}, []string{"198.51.100.0/25"})

	beforeVersion, err := store.LatestPolicyVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failFeed = true
	if _, err := store.SyncFeedSource(ctx, source.ID, adminActor, "failure retention check"); err == nil {
		t.Fatal("expected feed sync failure")
	}
	afterVersion, err := store.LatestPolicyVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterVersion != beforeVersion {
		t.Fatalf("failed feed should not rebuild snapshot before=%d after=%d", beforeVersion, afterVersion)
	}
	source, err = store.GetFeedSource(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if source.Status != feedStatusError || !strings.Contains(source.LastError, "status 500") {
		t.Fatalf("failure status not recorded safely: %#v", source)
	}
	assertLatestSnapshotBlacklist(t, store, ctx, []string{"198.51.100.128/25", "203.0.113.0/24"}, []string{"198.51.100.0/25"})
}

func assertLatestSnapshotBlacklist(t *testing.T, store *Store, ctx context.Context, want, absent []string) {
	t.Helper()
	snapshots, err := store.ListSnapshots(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) == 0 {
		t.Fatal("no snapshots found")
	}
	var snapshot agent.PolicySnapshot
	if err := json.Unmarshal(snapshots[0].Snapshot, &snapshot); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range snapshot.BlacklistV4 {
		seen[entry.CIDR] = true
	}
	for _, cidr := range want {
		if !seen[cidr] {
			t.Fatalf("snapshot blacklist missing %s: %#v", cidr, snapshot.BlacklistV4)
		}
	}
	for _, cidr := range absent {
		if seen[cidr] {
			t.Fatalf("snapshot blacklist should suppress %s: %#v", cidr, snapshot.BlacklistV4)
		}
	}
}

func boolPtr(value bool) *bool {
	return &value
}

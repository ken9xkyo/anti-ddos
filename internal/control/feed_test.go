package control

import (
	"net/netip"
	"testing"
	"time"
)

func TestFeedParsersNormalizeAndKeepValidEntries(t *testing.T) {
	source := FeedSource{Name: "spamhaus", Type: "spamhaus_drop", QuotaMetadata: []byte(`{"ttl_seconds":3600}`)}
	parsed := parseFeedPayload(source, []byte("203.0.113.0/24 ; test range\nbad-entry\n2001:db8::/32\n198.51.100.7\n"), time.Now())
	if parsed.Fetched != 4 {
		t.Fatalf("fetched=%d", parsed.Fetched)
	}
	if parsed.ParseErrors != 2 {
		t.Fatalf("parse errors=%d", parsed.ParseErrors)
	}
	if len(parsed.Entries) != 2 {
		t.Fatalf("valid entries=%d %#v", len(parsed.Entries), parsed.Entries)
	}
	if parsed.Entries[1].CIDR.String() != "198.51.100.7/32" {
		t.Fatalf("host IP was not normalized to /32: %#v", parsed.Entries[1])
	}
}

func TestInternalJSONFeedParser(t *testing.T) {
	source := FeedSource{Name: "internal", Type: "internal_json"}
	body := []byte(`{"entries":[
		{"cidr":"198.51.100.0/25","score":88,"action":"drop","ttl_seconds":600,"reason":"partner"},
		{"ip":"198.51.100.10","score":90,"action":"drop"},
		{"cidr":"2001:db8::/32","score":90,"action":"drop"}
	]}`)
	parsed := parseFeedPayload(source, body, time.Now())
	if parsed.ParseErrors != 1 || len(parsed.Entries) != 2 {
		t.Fatalf("parsed=%#v", parsed)
	}
	if parsed.Entries[0].TTLSeconds != 600 {
		t.Fatalf("ttl not preserved: %#v", parsed.Entries[0])
	}
}

func TestFeedAggregationOnlyMergesSafeSiblings(t *testing.T) {
	entries := []normalizedFeedEntry{
		{CIDR: mustPrefix(t, "198.51.100.0/25"), Score: 90, Action: "drop", TTLSeconds: 3600},
		{CIDR: mustPrefix(t, "198.51.100.128/25"), Score: 90, Action: "drop", TTLSeconds: 3600},
		{CIDR: mustPrefix(t, "203.0.113.0/25"), Score: 90, Action: "drop", TTLSeconds: 3600},
		{CIDR: mustPrefix(t, "203.0.113.128/25"), Score: 80, Action: "drop", TTLSeconds: 3600},
	}
	aggregated := aggregateFeedEntries(entries, nil)
	if len(aggregated) != 3 {
		t.Fatalf("expected one safe merge only, got %#v", aggregated)
	}
	if aggregated[0].CIDR.String() != "198.51.100.0/24" {
		t.Fatalf("safe siblings did not merge: %#v", aggregated)
	}
}

func TestFeedAggregationDoesNotBroadenAcrossWhitelist(t *testing.T) {
	entries := []normalizedFeedEntry{
		{CIDR: mustPrefix(t, "198.51.100.0/25"), Score: 90, Action: "drop", TTLSeconds: 3600},
		{CIDR: mustPrefix(t, "198.51.100.128/25"), Score: 90, Action: "drop", TTLSeconds: 3600},
	}
	whitelist := []feedWhitelist{{ID: "w1", Prefix: mustPrefix(t, "198.51.100.10/32")}}
	aggregated := aggregateFeedEntries(entries, whitelist)
	if len(aggregated) != 2 {
		t.Fatalf("whitelist should block broad merge, got %#v", aggregated)
	}
}

func TestCredentialRefResolution(t *testing.T) {
	t.Setenv("ANTI_DDOS_SECRET_ABUSEIPDB_KEY", "fake-key")
	value, status := resolveCredentialRef("secret://anti-ddos/abuseipdb-key")
	if status != "present" || value != "fake-key" {
		t.Fatalf("secret ref resolution failed value=%q status=%q", value, status)
	}
	_, status = resolveCredentialRef("env://MISSING_PHASE8_SECRET")
	if status != "missing" {
		t.Fatalf("missing env status=%q", status)
	}
}

func mustPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

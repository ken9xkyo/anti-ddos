package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestParseWhitelistEntryQuery(t *testing.T) {
	query, err := parseWhitelistEntryQuery(url.Values{
		"q":          {" trusted "},
		"scope":      {" SERVICE "},
		"service_id": {"svc-1"},
		"state":      {" Enabled "},
		"expiry":     {" Valid "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if query.Search != "trusted" || query.Scope != "service" || query.ServiceID != "svc-1" || query.State != "enabled" || query.Expiry != "valid" {
		t.Fatalf("query parsed incorrectly: %#v", query)
	}

	defaults, err := parseWhitelistEntryQuery(url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Scope != "all" || defaults.State != "all" || defaults.Expiry != "all" {
		t.Fatalf("defaults parsed incorrectly: %#v", defaults)
	}
}

func TestParseWhitelistEntryQueryRejectsInvalidEnums(t *testing.T) {
	tests := []url.Values{
		{"scope": {"tenant"}},
		{"state": {"archived"}},
		{"expiry": {"soon"}},
	}
	for _, values := range tests {
		if _, err := parseWhitelistEntryQuery(values); err == nil {
			t.Fatalf("expected error for %#v", values)
		}
	}
}

func TestWhitelistListFiltersIntegration(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret"}
	store := NewStore(pool, cfg, nil)
	if _, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()
	token := login(t, server.URL, "admin", "correct horse battery staple")

	service := createWhitelistFilterService(t, server.URL, token, "api-https", "203.0.113.10/32")
	otherService := createWhitelistFilterService(t, server.URL, token, "admin-ssh", "203.0.113.20/32")
	createWhitelistFilterEntry(t, server.URL, token, WhitelistInput{
		Reason: "allow trusted monitor",
		CIDR:   "198.51.100.10/32",
		Scope:  "global",
		Label:  "trusted-host",
		Owner:  "soc",
	})
	createWhitelistFilterEntry(t, server.URL, token, WhitelistInput{
		Reason:    "allow api customer",
		CIDR:      "198.51.100.20/32",
		Scope:     "service",
		ServiceID: service.ID,
		Label:     "api-customer",
		Owner:     "noc",
	})
	createWhitelistFilterEntry(t, server.URL, token, WhitelistInput{
		Reason:  "legacy partner disabled",
		CIDR:    "203.0.113.50/32",
		Scope:   "global",
		Label:   "legacy-partner",
		Owner:   "soc",
		Enabled: boolPtr(false),
	})
	createWhitelistFilterEntry(t, server.URL, token, WhitelistInput{
		Reason:    "expired customer window",
		CIDR:      "198.51.100.30/32",
		Scope:     "service",
		ServiceID: service.ID,
		Label:     "expired-api-customer",
		Owner:     "noc",
		ExpiresAt: time.Now().Add(-time.Hour).UTC(),
	})
	createWhitelistFilterEntry(t, server.URL, token, WhitelistInput{
		Reason:    "allow ssh admin",
		CIDR:      "198.51.100.40/32",
		Scope:     "service",
		ServiceID: otherService.ID,
		Label:     "ssh-admin",
		Owner:     "sre",
	})

	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{name: "default returns all history", want: []string{"198.51.100.10/32", "198.51.100.20/32", "198.51.100.30/32", "198.51.100.40/32", "203.0.113.50/32"}},
		{name: "text searches label", query: "q=api-customer", want: []string{"198.51.100.20/32", "198.51.100.30/32"}},
		{name: "text searches service name", query: "q=api-https", want: []string{"198.51.100.20/32", "198.51.100.30/32"}},
		{name: "scope global", query: "scope=global", want: []string{"198.51.100.10/32", "203.0.113.50/32"}},
		{name: "scope service", query: "scope=service", want: []string{"198.51.100.20/32", "198.51.100.30/32", "198.51.100.40/32"}},
		{name: "state disabled", query: "state=disabled", want: []string{"203.0.113.50/32"}},
		{name: "expiry expired", query: "expiry=expired", want: []string{"198.51.100.30/32"}},
		{name: "expiry valid", query: "expiry=valid", want: []string{"198.51.100.10/32", "198.51.100.20/32", "198.51.100.40/32", "203.0.113.50/32"}},
		{name: "effective service includes global and scoped", query: "service_id=" + url.QueryEscape(service.ID), want: []string{"198.51.100.10/32", "198.51.100.20/32", "198.51.100.30/32", "203.0.113.50/32"}},
		{name: "service scope narrows service filter", query: "scope=service&service_id=" + url.QueryEscape(service.ID), want: []string{"198.51.100.20/32", "198.51.100.30/32"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := whitelistFilterCIDRs(t, getWhitelistFilterEntries(t, server.URL, token, tt.query))
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("cidrs=%v want=%v", got, tt.want)
			}
		})
	}

	resp := authedJSON(t, http.MethodGet, server.URL+"/v1/whitelist?scope=bad", token, nil)
	requireHTTPStatus(t, resp, http.StatusBadRequest)
	requireBodyContains(t, resp, "scope must be all, global, or service")
}

func createWhitelistFilterService(t *testing.T, baseURL, token, name, backendCIDR string) Service {
	t.Helper()
	resp := authedJSON(t, http.MethodPost, baseURL+"/v1/services", token, ServiceInput{
		Reason:                   "create filter test service",
		Name:                     name,
		BackendCIDR:              backendCIDR,
		Protocol:                 "tcp",
		AllowedPorts:             []uint16{443},
		OutputInterface:          "backend0",
		Owner:                    "sre",
		Criticality:              "high",
		ProtectionMode:           "enforce",
		ResolvedIfindex:          7,
		ResolvedNextHopMAC:       "02:00:00:00:00:02",
		ResolvedSourceMAC:        "02:00:00:00:00:01",
		NeighborResolutionStatus: "resolved",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var service Service
	decodeTestBody(t, resp, &service)
	return service
}

func createWhitelistFilterEntry(t *testing.T, baseURL, token string, input WhitelistInput) WhitelistEntry {
	t.Helper()
	resp := authedJSON(t, http.MethodPost, baseURL+"/v1/whitelist", token, input)
	requireHTTPStatus(t, resp, http.StatusOK)
	var entry WhitelistEntry
	decodeTestBody(t, resp, &entry)
	return entry
}

func getWhitelistFilterEntries(t *testing.T, baseURL, token, rawQuery string) []WhitelistEntry {
	t.Helper()
	url := baseURL + "/v1/whitelist"
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	resp := authedJSON(t, http.MethodGet, url, token, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	var entries []WhitelistEntry
	if err := json.Unmarshal(resp.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode whitelist entries: %v", err)
	}
	return entries
}

func whitelistFilterCIDRs(t *testing.T, entries []WhitelistEntry) []string {
	t.Helper()
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.CIDR)
	}
	sort.Strings(out)
	return out
}

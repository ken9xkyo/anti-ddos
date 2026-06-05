package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMultiTenantRBACUpdate(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret"}
	store := NewStore(pool, cfg, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	if _, err := store.CreateUser(ctx, adminActor, "operator", "operator password phrase", RoleOperator, "create operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(ctx, adminActor, "peer-operator", "peer operator password phrase", RoleOperator, "create peer operator"); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()

	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	operatorToken := login(t, server.URL, "operator", "operator password phrase")

	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/users", operatorToken, map[string]string{
		"reason":   "operator creates viewer",
		"username": "analyst",
		"password": "viewer temporary phrase",
		"role":     RoleViewer,
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var analyst User
	decodeTestBody(t, resp, &analyst)
	if analyst.Role != RoleViewer {
		t.Fatalf("operator-created user role=%q", analyst.Role)
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users", operatorToken, map[string]string{
		"reason":   "operator should not create operator",
		"username": "blocked-operator",
		"password": "blocked password phrase",
		"role":     RoleOperator,
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	var members []User
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/users", adminToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	decodeTestBody(t, resp, &members)
	var peerOperator User
	for _, user := range members {
		if user.Username == "peer-operator" {
			peerOperator = user
			break
		}
	}
	if peerOperator.ID == "" {
		t.Fatal("peer operator not found")
	}
	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/users/"+peerOperator.ID, operatorToken, UserUpdateInput{
		Reason: "operator should not demote peer operator",
		Role:   RoleViewer,
		Status: StatusActive,
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users/"+analyst.ID+"/password-reset", operatorToken, PasswordResetInput{
		Reason:   "operator resets viewer",
		Password: "viewer replacement phrase",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	analystToken := login(t, server.URL, "analyst", "viewer replacement phrase")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users/"+analyst.ID+"/sessions/revoke", operatorToken, map[string]string{"reason": "operator revokes viewer sessions"})
	requireHTTPStatus(t, resp, http.StatusOK)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/me", analystToken, nil)
	requireHTTPStatus(t, resp, http.StatusUnauthorized)

	deleteReq, err := http.NewRequest(http.MethodDelete, server.URL+"/v1/users/"+analyst.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	deleteReq.Header.Set("Authorization", "Bearer "+operatorToken)
	deleteReq.Header.Set("X-Audit-Reason", "operator revokes viewer membership")
	resp = doTestHTTP(t, deleteReq)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"status":"revoked"`)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users", operatorToken, map[string]string{
		"reason":   "operator reactivates viewer",
		"username": "analyst",
		"password": "unused reactivation phrase",
		"role":     RoleViewer,
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"status":"active"`)

	rawTelegramToken := "123456:abcdefghijklmnopqrstuvwxyzABCDEF"
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", operatorToken, TelegramConfigInput{
		Reason:      "operator configures tenant telegram",
		BotTokenRef: rawTelegramToken,
		ChatID:      "1234",
		ParseMode:   "HTML",
		Enabled:     boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	if strings.Contains(resp.Body.String(), rawTelegramToken) || !strings.Contains(resp.Body.String(), telegramTokenMask) {
		t.Fatalf("telegram response masking failed: %s", resp.Body.String())
	}

	rawFeedCredential := "raw-feed-key"
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources", adminToken, FeedSourceInput{
		Reason:        "admin creates credentialed feed",
		Name:          "credentialed-feed",
		Type:          "internal_json",
		URL:           "https://feeds.example.test/drop.json",
		CredentialRef: stringPtr(rawFeedCredential),
		Enabled:       boolPtr(false),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, feedCredentialMask)
	var feed FeedSource
	decodeTestBody(t, resp, &feed)

	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/feed-sources/"+feed.ID, operatorToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	if strings.Contains(resp.Body.String(), "credential_ref") || strings.Contains(resp.Body.String(), rawFeedCredential) || strings.Contains(resp.Body.String(), feedCredentialMask) {
		t.Fatalf("operator feed response exposed credential state: %s", resp.Body.String())
	}
	nextCredential := "new-feed-key"
	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/feed-sources/"+feed.ID, operatorToken, FeedSourceInput{
		Reason:        "operator should not change feed credential",
		Name:          feed.Name,
		Type:          feed.Type,
		URL:           feed.URL,
		CredentialRef: stringPtr(nextCredential),
		Enabled:       boolPtr(false),
		Status:        feed.Status,
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	viewerToken := login(t, server.URL, "analyst", "viewer replacement phrase")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users", viewerToken, map[string]string{
		"reason":   "viewer should not create user",
		"username": "viewer-created",
		"password": "viewer created password phrase",
		"role":     RoleViewer,
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", viewerToken, TelegramConfigInput{
		Reason:      "viewer should not configure telegram",
		BotTokenRef: rawTelegramToken,
		ChatID:      "1234",
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/feed-sources", viewerToken, FeedSourceInput{
		Reason: "viewer should not create feed",
		Name:   "viewer-feed",
		Type:   "internal_json",
		URL:    "https://feeds.example.test/viewer.json",
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	platformToken := login(t, server.URL, "admin", "correct horse battery staple")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/tenants", platformToken, TenantInput{
		Slug: "customer-a",
		Name: "Customer A",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	var tenant Tenant
	decodeTestBody(t, resp, &tenant)
	resp = authedJSON(t, http.MethodPatch, server.URL+"/v1/tenants/"+tenant.ID, platformToken, TenantInput{Name: "Customer A Production", Status: StatusActive})
	requireHTTPStatus(t, resp, http.StatusOK)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/tenants?include_revoked=true", platformToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, "Customer A Production")
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/tenants/switch", platformToken, TenantSwitchInput{TenantID: tenant.ID})
	requireHTTPStatus(t, resp, http.StatusOK)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users", platformToken, map[string]string{
		"reason":   "platform admin creates tenant operator",
		"username": "customer-a-operator",
		"password": "customer operator password phrase",
		"role":     RoleOperator,
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, `"role":"operator"`)

	audits, err := store.ListAuditEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if strings.Contains(string(audit.Before), rawTelegramToken) || strings.Contains(string(audit.After), rawTelegramToken) ||
			strings.Contains(string(audit.Before), rawFeedCredential) || strings.Contains(string(audit.After), rawFeedCredential) {
			t.Fatalf("secret leaked in audit: %#v", audit)
		}
	}
}

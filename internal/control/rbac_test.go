package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdminUserRBACNoTenant(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	cfg := Config{Addr: "127.0.0.1:0", DBDSN: dsn, SessionTTL: time.Hour, XDPObject: "missing-ok.o", AgentSharedToken: "agent-secret"}
	store := NewStore(pool, cfg, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	user, err := store.CreateUser(ctx, adminActor, "user", "user password phrase", RoleUser, "create user")
	if err != nil {
		t.Fatal(err)
	}
	ownerCtx := contextWithOwner(ctx, user.ID)

	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()

	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	userToken := login(t, server.URL, "user", "user password phrase")

	resp := authedJSON(t, http.MethodPost, server.URL+"/v1/users", userToken, map[string]string{
		"reason":   "user should not create accounts",
		"username": "blocked",
		"password": "blocked password phrase",
		"role":     RoleUser,
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	rawTelegramToken := "123456:abcdefghijklmnopqrstuvwxyzABCDEF"
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", userToken, TelegramConfigInput{
		Reason:      "user configures own telegram",
		BotTokenRef: rawTelegramToken,
		ChatID:      "1234",
		ParseMode:   "HTML",
		Enabled:     boolPtr(true),
	})
	requireHTTPStatus(t, resp, http.StatusOK)
	if strings.Contains(resp.Body.String(), rawTelegramToken) || !strings.Contains(resp.Body.String(), telegramTokenMask) {
		t.Fatalf("telegram response masking failed: %s", resp.Body.String())
	}

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/admin/view-user", adminToken, AdminViewUserInput{UserID: user.ID})
	requireHTTPStatus(t, resp, http.StatusOK)
	var viewSession Session
	decodeTestBody(t, resp, &viewSession)
	if !viewSession.User.ReadOnly || viewSession.User.ViewingUser == nil || viewSession.User.ViewingUser.Username != "user" {
		t.Fatalf("unexpected view-user session: %#v", viewSession.User)
	}

	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/telegram/config", viewSession.Token, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	requireBodyContains(t, resp, telegramTokenMask)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/telegram/config", viewSession.Token, TelegramConfigInput{
		Reason:      "admin read-only should not mutate",
		BotTokenRef: rawTelegramToken,
		ChatID:      "9999",
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/tenants", adminToken, map[string]string{"slug": "customer-a"})
	requireHTTPStatus(t, resp, http.StatusNotFound)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/feed-sources", adminToken, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/feed-sources", userToken, nil)
	requireHTTPStatus(t, resp, http.StatusForbidden)
	resp = authedJSON(t, http.MethodGet, server.URL+"/v1/feed-sources", viewSession.Token, nil)
	requireHTTPStatus(t, resp, http.StatusForbidden)

	audits, err := store.ListAuditEvents(ownerCtx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range audits {
		if strings.Contains(string(audit.Before), rawTelegramToken) || strings.Contains(string(audit.After), rawTelegramToken) {
			t.Fatalf("secret leaked in audit: %#v", audit)
		}
	}
}

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func resetControlTestDB(t *testing.T) (context.Context, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("ANTI_DDOS_CONTROL_TEST_DSN")
	if dsn == "" {
		t.Skip("ANTI_DDOS_CONTROL_TEST_DSN is not set")
	}
	ctx := context.Background()
	pool, err := OpenPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("idempotent migration run: %v", err)
	}
	return ctx, pool, dsn
}

func login(t *testing.T, baseURL, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(baseURL+"/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var session Session
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	return session.Token
}

type testHTTPResponse struct {
	Code int
	Body bytes.Buffer
}

func authedJSON(t *testing.T, method, url, token string, body any) *testHTTPResponse {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return doTestHTTP(t, req)
}

func agentJSON(t *testing.T, method, url, token string, body any) *testHTTPResponse {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return doTestHTTP(t, req)
}

func doTestHTTP(t *testing.T, req *http.Request) *testHTTPResponse {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out testHTTPResponse
	out.Code = resp.StatusCode
	_, _ = io.Copy(&out.Body, resp.Body)
	return &out
}

func boolPtr(value bool) *bool {
	return &value
}

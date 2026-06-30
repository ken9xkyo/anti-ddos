package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAllocatedCIDRIntegration(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)

	cfg := Config{
		Addr:             "127.0.0.1:0",
		DBDSN:            dsn,
		SessionTTL:       time.Hour,
		XDPObject:        "missing-ok.o",
		AgentSharedToken: "agent-secret",
		AgentStaleAfter:  time.Minute,
		EventSampleDenom: 10,
	}
	store := NewStore(pool, cfg, nil)

	// Create admin and users
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}

	user1, err := store.CreateUser(ctx, adminActor, "user1", "user1 password phrase", RoleUser, "create user1")
	if err != nil {
		t.Fatal(err)
	}
	user1Actor := &Actor{User: user1}

	user2, err := store.CreateUser(ctx, adminActor, "user2", "user2 password phrase", RoleUser, "create user2")
	if err != nil {
		t.Fatal(err)
	}

	// Set up HTTP test server
	server := httptest.NewServer(NewServer(store, cfg, nil))
	defer server.Close()

	adminToken := login(t, server.URL, "admin", "correct horse battery staple")
	user1Token := login(t, server.URL, "user1", "user1 password phrase")
	user2Token := login(t, server.URL, "user2", "user2 password phrase")

	// 1. Initially, user1 should have no allocated CIDRs
	cidrs, err := store.ListUserAllocatedCIDRs(ctx, user1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrs) != 0 {
		t.Fatalf("expected 0 allocated CIDRs, got %d", len(cidrs))
	}

	// 2. Admin allocates 10.10.0.0/16 to user1
	alloc1, err := store.CreateAllocatedCIDR(ctx, adminActor, user1.ID, AllocatedCIDRInput{
		Reason: "allow local space",
		CIDR:   "10.10.0.0/16",
	}, "test allocation")
	if err != nil {
		t.Fatal(err)
	}
	if alloc1.CIDR != "10.10.0.0/16" {
		t.Fatalf("expected 10.10.0.0/16, got %s", alloc1.CIDR)
	}

	// 3. Try to allocate overlapping CIDR to user2 -> should fail
	_, err = store.CreateAllocatedCIDR(ctx, adminActor, user2.ID, AllocatedCIDRInput{
		Reason: "allow local overlap",
		CIDR:   "10.10.1.0/24",
	}, "test allocation overlap")
	if err == nil {
		t.Fatal("expected overlap error, got none")
	}

	// 4. Try to allocate overlapping CIDR to user1 -> should succeed (same user can have overlaps)
	alloc2, err := store.CreateAllocatedCIDR(ctx, adminActor, user1.ID, AllocatedCIDRInput{
		Reason: "nested space for same user",
		CIDR:   "10.10.2.0/24",
	}, "test nested allocation")
	if err != nil {
		t.Fatal(err)
	}
	if alloc2.CIDR != "10.10.2.0/24" {
		t.Fatalf("expected 10.10.2.0/24, got %s", alloc2.CIDR)
	}

	// 5. User1 attempts to create service with backend_cidr outside allocation -> should fail
	_, err = store.CreateService(ctx, user1Actor, ServiceInput{
		Name:            "service-fail",
		BackendCIDR:     "192.168.1.5/32",
		Protocol:        "tcp",
		AllowedPorts:    []uint16{80},
		OutputInterface: "backend0",
		Owner:           "user1",
		Criticality:     "low",
		ProtectionMode:  "observe",
	}, "create service outside bounds")
	if err == nil {
		t.Fatal("expected validation error for out-of-bounds service CIDR, got none")
	}

	// 6. User1 creates service inside allocated CIDR (10.10.5.5/32) -> should succeed
	svc, err := store.CreateService(ctx, user1Actor, ServiceInput{
		Name:            "service-ok",
		BackendCIDR:     "10.10.5.5/32",
		Protocol:        "tcp",
		AllowedPorts:    []uint16{80},
		OutputInterface: "backend0",
		Owner:           "user1",
		Criticality:     "low",
		ProtectionMode:  "observe",
	}, "create service inside bounds")
	if err != nil {
		t.Fatal(err)
	}

	// 7. Try to delete user1's CIDR allocation (10.10.0.0/16) while the service is using it -> should be blocked
	err = store.DeleteAllocatedCIDR(ctx, adminActor, user1.ID, alloc1.ID, "delete used allocation")
	if err == nil {
		t.Fatal("expected deletion to be blocked, got none")
	}

	// 8. Delete the service, then try to delete the allocation -> should succeed
	_, err = store.DeleteService(ctx, user1Actor, svc.ID, "cleanup service")
	if err != nil {
		t.Fatal(err)
	}
	err = store.DeleteAllocatedCIDR(ctx, adminActor, user1.ID, alloc1.ID, "delete unused allocation")
	if err != nil {
		t.Fatal(err)
	}

	// 9. API REST endpoints tests
	// - GET /v1/me/allocated-cidrs for user1
	resp := authedJSON(t, http.MethodGet, server.URL+"/v1/me/allocated-cidrs", user1Token, nil)
	requireHTTPStatus(t, resp, http.StatusOK)
	var meAllocations []AllocatedCIDR
	decodeTestBody(t, resp, &meAllocations)
	// alloc2 remains
	if len(meAllocations) != 1 {
		t.Fatalf("expected 1 me allocation, got %d", len(meAllocations))
	}

	// - POST /v1/users/{userId}/allocated-cidrs (non-admin) -> 403 Forbidden
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users/"+user1.ID+"/allocated-cidrs", user2Token, AllocatedCIDRInput{
		CIDR: "172.16.0.0/12",
	})
	requireHTTPStatus(t, resp, http.StatusForbidden)

	// - POST /v1/users/{userId}/allocated-cidrs (admin) -> 200 OK (returned as result)
	resp = authedJSON(t, http.MethodPost, server.URL+"/v1/users/"+user2.ID+"/allocated-cidrs", adminToken, AllocatedCIDRInput{
		Reason: "user2 space",
		CIDR:   "172.16.0.0/12",
	})
	requireHTTPStatus(t, resp, http.StatusOK)
}

func TestExistingServicesMigrationAutoAllocate(t *testing.T) {
	// Let's verify that the Version 12 database migration automatically creates
	// allocations for preexisting active services.
	ctx := context.Background()
	dsn := os.Getenv("ANTI_DDOS_CONTROL_TEST_DSN")
	if dsn == "" {
		t.Skip("ANTI_DDOS_CONTROL_TEST_DSN is not set")
	}
	pool, err := OpenPool(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// Reset DB up to migration 11
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	for _, m := range Migrations {
		if m.Version >= 12 {
			continue
		}
		if _, err := pool.Exec(ctx, m.SQL); err != nil {
			t.Fatalf("migration %d failed: %v", m.Version, err)
		}
		if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, name text)`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version, name) VALUES ($1, $2)`, m.Version, m.Name); err != nil {
			t.Fatal(err)
		}
	}

	// Bootstrap users and insert a preexisting service at the DB level
	adminID := "00000000-0000-0000-0000-000000000001"
	userID := "00000000-0000-0000-0000-000000000002"
	_, _ = pool.Exec(ctx, `INSERT INTO app_users(id, username, password_hash, role, status) VALUES ($1, 'admin', 'hash', 'admin', 'active')`, adminID)
	_, _ = pool.Exec(ctx, `INSERT INTO app_users(id, username, password_hash, role, status) VALUES ($1, 'user', 'hash', 'user', 'active')`, userID)

	serviceID := "00000000-0000-0000-0000-000000000003"
	_, err = pool.Exec(ctx, `INSERT INTO backend_services(id, owner_user_id, name, backend_cidr, protocol, output_interface, owner, criticality, protection_mode)
VALUES ($1, $2, 'preexisting-service', '192.168.50.0/24', 'tcp', 'eth0', 'user', 'high', 'enforce')`, serviceID, userID)
	if err != nil {
		t.Fatal(err)
	}

	// Apply migration 12
	m12 := Migrations[11] // 12 is at index 11
	if m12.Version != 12 {
		t.Fatalf("expected version 12, got index 11 version %d", m12.Version)
	}
	if _, err := pool.Exec(ctx, m12.SQL); err != nil {
		t.Fatalf("migration 12 failed: %v", err)
	}

	// Check if allocation was auto-created for userID
	var cidrStr string
	err = pool.QueryRow(ctx, `SELECT cidr::text FROM allocated_cidrs WHERE user_id=$1`, userID).Scan(&cidrStr)
	if err != nil {
		t.Fatal(err)
	}
	if cidrStr != "192.168.50.0/24" {
		t.Fatalf("expected 192.168.50.0/24, got %s", cidrStr)
	}
}

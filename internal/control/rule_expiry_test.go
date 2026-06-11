package control

import (
	"testing"
	"time"
)

func TestExpireTTLRulesDisablesExpiredManualRules(t *testing.T) {
	ctx, pool, dsn := resetControlTestDB(t)
	cfg := Config{
		Addr:             "127.0.0.1:0",
		DBDSN:            dsn,
		SessionTTL:       time.Hour,
		XDPObject:        "missing-ok.o",
		AgentSharedToken: "agent-secret",
		AgentStaleAfter:  time.Minute,
	}
	store := NewStore(pool, cfg, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	owner, err := store.CreateUser(ctx, adminActor, "user", "user password phrase", RoleUser, "create user")
	if err != nil {
		t.Fatal(err)
	}
	ownerActor := &Actor{User: owner}
	ownerCtx := contextWithOwner(ctx, owner.ID)

	service, err := store.CreateService(ownerCtx, ownerActor, ServiceInput{
		Reason:                   "publish service",
		Name:                     "api-https",
		BackendCIDR:              "203.0.113.10/32",
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
	}, "publish service")
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.CreateRule(ownerCtx, ownerActor, RuleInput{
		Reason:       "manual ttl rule",
		ServiceID:    service.ID,
		Name:         "manual-ttl-rule",
		Priority:     1000,
		Action:       "observe",
		Mode:         "observe",
		Dimension:    "source_service",
		TTLSeconds:   900,
		BurstPackets: 1,
		Owner:        "sre",
	}, "manual ttl rule")
	if err != nil {
		t.Fatal(err)
	}
	if rule.ExpiresAt == nil {
		t.Fatalf("manual ttl rule did not derive expires_at: %#v", rule)
	}

	var snapshotBefore uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotBefore); err != nil {
		t.Fatal(err)
	}
	var auditBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='expire_rule'`).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE rules SET expires_at=now() - interval '1 second' WHERE id::text = $1`, rule.ID); err != nil {
		t.Fatal(err)
	}
	expired, err := store.ExpireTTLRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if expired != 1 {
		t.Fatalf("expected expired manual rule to be disabled, got %d", expired)
	}
	var snapshotAfter uint32
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM policy_snapshots`).Scan(&snapshotAfter); err != nil {
		t.Fatal(err)
	}
	if snapshotAfter <= snapshotBefore {
		t.Fatalf("ttl expiry did not create a new snapshot: before=%d after=%d", snapshotBefore, snapshotAfter)
	}
	var auditAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='expire_rule'`).Scan(&auditAfter); err != nil {
		t.Fatal(err)
	}
	if auditAfter < auditBefore+1 {
		t.Fatalf("ttl expiry audit missing: before=%d after=%d", auditBefore, auditAfter)
	}
	rules, err := store.ListRules(ownerCtx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range rules {
		if item.ID == rule.ID && item.Enabled {
			t.Fatalf("expired rule still enabled: %#v", item)
		}
	}
}

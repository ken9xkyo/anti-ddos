package control

import (
	"strings"
	"testing"
	"time"
)

func TestUserDefaultOutputInterface(t *testing.T) {
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

	// Create admin
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}

	// 1. Create a user without default output interface
	userNoIface, err := store.CreateUser(ctx, adminActor, "noiface", "passwordphrase123", RoleUser, "create user no iface")
	if err != nil {
		t.Fatal(err)
	}
	userNoIfaceActor := &Actor{User: userNoIface}

	// 2. Allocate CIDR to userNoIface so service validation passes
	_, err = store.CreateAllocatedCIDR(ctx, adminActor, userNoIface.ID, AllocatedCIDRInput{
		Reason: "allow local space",
		CIDR:   "10.10.0.0/16",
	}, "test allocation")
	if err != nil {
		t.Fatal(err)
	}

	// 3. User attempts to create a service -> should fail because no default interface is set
	_, err = store.CreateService(ctx, userNoIfaceActor, ServiceInput{
		Name:           "svc1",
		BackendCIDR:    "10.10.1.1/32",
		Protocol:       "tcp",
		AllowedPorts:   []uint16{80},
		Owner:          "noiface",
		ProtectionMode: "observe",
	}, "create svc without default output interface")
	if err == nil || !strings.Contains(err.Error(), "default output interface not assigned by administrator") {
		t.Fatalf("expected error containing 'default output interface not assigned', got: %v", err)
	}

	// 4. Update user with a default output interface
	defaultIface := "backend0"
	updatedUser, err := store.UpdateUser(ctx, adminActor, userNoIface.ID, UserUpdateInput{
		Reason:                 "assign default output interface",
		DefaultOutputInterface: &defaultIface,
	}, "assign interface")
	if err != nil {
		t.Fatal(err)
	}
	if updatedUser.DefaultOutputInterface != defaultIface {
		t.Fatalf("expected default output interface %q, got %q", defaultIface, updatedUser.DefaultOutputInterface)
	}
	userNoIfaceActor.User = updatedUser

	// 5. User creates service -> should succeed and default to "backend0"
	svc, err := store.CreateService(ctx, userNoIfaceActor, ServiceInput{
		Name:           "svc1",
		BackendCIDR:    "10.10.1.1/32",
		Protocol:       "tcp",
		AllowedPorts:   []uint16{80},
		Owner:          "noiface",
		ProtectionMode: "observe",
	}, "create svc with default output interface")
	if err != nil {
		t.Fatal(err)
	}
	if svc.OutputInterface != defaultIface {
		t.Fatalf("expected output interface %q, got %q", defaultIface, svc.OutputInterface)
	}

	// 6. User updates service trying to change the output interface -> it should ignore/preserve original
	anotherIface := "backend1"
	updatedSvc, err := store.UpdateService(ctx, userNoIfaceActor, svc.ID, ServiceInput{
		Name:            "svc1-updated",
		BackendCIDR:     "10.10.1.1/32",
		Protocol:        "tcp",
		AllowedPorts:    []uint16{80},
		OutputInterface: anotherIface, // try to change it
		Owner:           "noiface",
		ProtectionMode:  "observe",
	}, "update service attempt to change interface")
	if err != nil {
		t.Fatal(err)
	}
	if updatedSvc.OutputInterface != defaultIface {
		t.Fatalf("expected output interface to remain %q, but it changed to %q", defaultIface, updatedSvc.OutputInterface)
	}

	// 7. Register an agent and interfaces for this user to test auto-calculation
	agentRegisterReq := AgentRegisterRequest{
		Hostname: "test-agent-host",
		Interfaces: []AgentInterface{
			{
				Name:         "backend0",
				Ifindex:      42,
				MAC:          "02:00:00:00:00:42",
				Role:         "wan",
				LinkSpeedBPS: 1000000000,
			},
		},
	}
	_, err = store.RegisterAgentForOwner(ctx, userNoIface.ID, agentRegisterReq)
	if err != nil {
		t.Fatal(err)
	}

	// 8. Create a new service under this user. It should auto-calculate ResolvedIfindex and ResolvedSourceMAC from the registered interface.
	svc2, err := store.CreateService(ctx, userNoIfaceActor, ServiceInput{
		Name:           "svc2",
		BackendCIDR:    "10.10.2.2/32",
		Protocol:       "tcp",
		AllowedPorts:   []uint16{80},
		Owner:          "noiface",
		ProtectionMode: "observe",
	}, "create svc2 to verify auto-calculation")
	if err != nil {
		t.Fatal(err)
	}
	if svc2.ResolvedIfindex != 42 {
		t.Fatalf("expected ResolvedIfindex to be auto-calculated as 42, got %d", svc2.ResolvedIfindex)
	}
	if svc2.ResolvedSourceMAC != "02:00:00:00:00:42" {
		t.Fatalf("expected ResolvedSourceMAC to be auto-calculated as 02:00:00:00:00:42, got %q", svc2.ResolvedSourceMAC)
	}
}

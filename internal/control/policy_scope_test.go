package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyScopeEffectiveReadAndSnapshotPrecedence(t *testing.T) {
	ctx, pool, _ := resetControlTestDB(t)
	objectPath := filepath.Join(t.TempDir(), "xdp.o")
	if err := os.WriteFile(objectPath, []byte("test object"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool, Config{XDPObject: objectPath}, nil)
	admin, err := store.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	adminActor := &Actor{User: admin}
	adminCtx := contextWithOwner(ctx, admin.ID)
	user, err := store.CreateUser(ctx, adminActor, "alice", "user password phrase", RoleUser, "create user")
	if err != nil {
		t.Fatal(err)
	}
	userActor := &Actor{User: user}
	userCtx := contextWithOwner(ctx, user.ID)

	adminEntry, err := store.CreateWhitelistEntry(adminCtx, adminActor, WhitelistInput{
		Reason:    "admin allow monitor",
		CIDR:      "198.51.100.10/32",
		ScopeType: ScopeTypeAdminGlobal,
		Label:     "admin-monitor",
		Priority:  100,
		Owner:     "client owner ignored",
	}, "admin allow monitor")
	if err != nil {
		t.Fatal(err)
	}
	if adminEntry.ScopeType != ScopeTypeAdminGlobal || adminEntry.Owner != "admin" {
		t.Fatalf("admin entry owner/scope = %#v", adminEntry)
	}

	userEntry, err := store.CreateWhitelistEntry(userCtx, userActor, WhitelistInput{
		Reason:    "user allow monitor",
		CIDR:      "198.51.100.10/32",
		ScopeType: ScopeTypeUserGlobal,
		Label:     "user-monitor",
		Priority:  100,
		Owner:     "client owner ignored",
	}, "user allow monitor")
	if err != nil {
		t.Fatal(err)
	}
	if userEntry.ScopeType != ScopeTypeUserGlobal || userEntry.Owner != "alice" {
		t.Fatalf("user entry owner/scope = %#v", userEntry)
	}

	userEntries, err := store.ListWhitelistEntries(userCtx, userActor, WhitelistEntryQuery{ScopeType: "all", Scope: "all"})
	if err != nil {
		t.Fatal(err)
	}
	var sawAdminReadOnly, sawUserEditable bool
	for _, entry := range userEntries {
		switch entry.ID {
		case adminEntry.ID:
			sawAdminReadOnly = !entry.Editable
		case userEntry.ID:
			sawUserEditable = entry.Editable
		}
	}
	if !sawAdminReadOnly || !sawUserEditable {
		t.Fatalf("effective user entries editable flags = %#v", userEntries)
	}

	adminEntries, err := store.ListWhitelistEntries(adminCtx, adminActor, WhitelistEntryQuery{ScopeType: "all", Scope: "all"})
	if err != nil {
		t.Fatal(err)
	}
	if len(adminEntries) != 1 || adminEntries[0].ID != adminEntry.ID || !adminEntries[0].Editable {
		t.Fatalf("admin entries = %#v, want editable admin-global only", adminEntries)
	}

	updatedAdmin, err := store.UpdateWhitelistEntry(adminCtx, adminActor, adminEntry.ID, WhitelistInput{
		Reason:    "update admin allow monitor",
		CIDR:      "198.51.100.10/32",
		ScopeType: ScopeTypeAdminGlobal,
		Label:     "admin-monitor-updated",
		Priority:  10,
		Enabled:   boolPtr(true),
		Owner:     "attempted owner change",
	}, "update admin allow monitor")
	if err != nil {
		t.Fatal(err)
	}
	if updatedAdmin.Owner != "admin" {
		t.Fatalf("admin-global update changed owner: %#v", updatedAdmin)
	}
	if _, err := store.UpdateWhitelistEntry(userCtx, userActor, adminEntry.ID, WhitelistInput{
		Reason:    "attempt user update admin-global",
		CIDR:      "198.51.100.10/32",
		ScopeType: ScopeTypeAdminGlobal,
		Priority:  10,
		Enabled:   boolPtr(true),
	}, "attempt user update admin-global"); err == nil {
		t.Fatal("user update of admin-global whitelist succeeded")
	}

	snapshot, err := store.FetchSnapshot(userCtx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.WhitelistV4) != 1 {
		t.Fatalf("snapshot whitelist = %#v, want deduped user-global entry", snapshot.WhitelistV4)
	}
	if snapshot.WhitelistV4[0].EntryID != userEntry.EBPFID {
		t.Fatalf("snapshot whitelist = %#v, want user-global entry id %d", snapshot.WhitelistV4, userEntry.EBPFID)
	}
}

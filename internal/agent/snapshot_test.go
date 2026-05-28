package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadLastValidSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	snapshot := DefaultSnapshot("abc123")
	snapshot.PolicyVersion = 42

	if err := SaveLastValidSnapshot(path, snapshot); err != nil {
		t.Fatalf("SaveLastValidSnapshot() error = %v", err)
	}

	loaded, err := LoadLastValidSnapshot(path)
	if err != nil {
		t.Fatalf("LoadLastValidSnapshot() error = %v", err)
	}
	if loaded.PolicyVersion != 42 {
		t.Fatalf("unexpected policy version %d", loaded.PolicyVersion)
	}
	if loaded.Checksum == "" {
		t.Fatal("checksum was not persisted")
	}
}

func TestSnapshotRejectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	snapshot := DefaultSnapshot("abc123")
	if err := SaveLastValidSnapshot(path, snapshot); err != nil {
		t.Fatalf("SaveLastValidSnapshot() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"policy_version": 1`, `"policy_version": 2`, 1))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadLastValidSnapshot(path); err == nil {
		t.Fatal("expected tampered snapshot to fail")
	}
}

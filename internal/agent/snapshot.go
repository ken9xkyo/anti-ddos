package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type LastValidSnapshot struct {
	SchemaVersion int    `json:"schema_version"`
	Checksum      string `json:"checksum"`

	ObjectChecksum string `json:"object_checksum"`
	ActiveSlot     uint32 `json:"active_slot"`
	PolicyVersion  uint32 `json:"policy_version"`
	SampleDenom    uint32 `json:"sample_denom"`
	SavedAtUnixNS  int64  `json:"saved_at_unix_ns"`
}

func DefaultSnapshot(objectChecksum string) LastValidSnapshot {
	return LastValidSnapshot{
		SchemaVersion:  1,
		ObjectChecksum: objectChecksum,
		ActiveSlot:     0,
		PolicyVersion:  1,
		SampleDenom:    1,
		SavedAtUnixNS:  time.Now().UnixNano(),
	}
}

func LoadLastValidSnapshot(path string) (LastValidSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LastValidSnapshot{}, err
	}

	var snapshot LastValidSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return LastValidSnapshot{}, err
	}
	if err := snapshot.Verify(); err != nil {
		return LastValidSnapshot{}, err
	}
	return snapshot, nil
}

func SaveLastValidSnapshot(path string, snapshot LastValidSnapshot) error {
	snapshot.Checksum = ""
	snapshot.Checksum = snapshot.ComputeChecksum()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s LastValidSnapshot) Verify() error {
	if s.SchemaVersion != 1 {
		return fmt.Errorf("unsupported snapshot schema_version %d", s.SchemaVersion)
	}
	if s.PolicyVersion == 0 {
		return errors.New("snapshot policy_version must be non-zero")
	}
	if s.Checksum == "" {
		return errors.New("snapshot checksum is required")
	}
	if expected := s.ComputeChecksum(); expected != s.Checksum {
		return fmt.Errorf("snapshot checksum mismatch: expected %s got %s", expected, s.Checksum)
	}
	return nil
}

func (s LastValidSnapshot) ComputeChecksum() string {
	s.Checksum = ""
	raw, _ := json.Marshal(s)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s LastValidSnapshot) RuntimeConfig(now time.Time) RuntimeConfigValue {
	return RuntimeConfigValue{
		ActiveSlot:        s.ActiveSlot,
		PolicyVersion:     s.PolicyVersion,
		MalformedPolicy:   actionDrop,
		SampleDenom:       s.SampleDenom,
		UpdatedAtUnixNano: uint64(now.UnixNano()),
	}
}

func FileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

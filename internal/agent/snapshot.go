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

	ObjectChecksum string          `json:"object_checksum"`
	ActiveSlot     uint32          `json:"active_slot"`
	PolicyVersion  uint32          `json:"policy_version"`
	SampleDenom    uint32          `json:"sample_denom"`
	SavedAtUnixNS  int64           `json:"saved_at_unix_ns"`
	Policy         *PolicySnapshot `json:"policy,omitempty"`
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
		policy, policyErr := DecodePolicySnapshot(raw)
		if policyErr == nil {
			if _, verifyErr := VerifyPolicySnapshot(policy, PolicySnapshotVerifyOptions{}); verifyErr == nil {
				lastValid := LastValidFromPolicySnapshot(policy, 0, policy.ObjectChecksum, time.Now())
				lastValid.Checksum = lastValid.ComputeChecksum()
				return lastValid, nil
			}
		}
		return LastValidSnapshot{}, err
	}
	return snapshot, nil
}

func SaveLastValidSnapshot(path string, snapshot LastValidSnapshot) error {
	if snapshot.Policy != nil {
		if snapshot.Policy.Checksum == "" {
			policy, err := SignPolicySnapshot(*snapshot.Policy)
			if err != nil {
				return err
			}
			snapshot.Policy = &policy
		} else {
			checksum := snapshot.Policy.Checksum
			policy := normalizePolicySnapshot(*snapshot.Policy)
			policy.Checksum = checksum
			snapshot.Policy = &policy
		}
	}
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
	if s.ActiveSlot > 1 {
		return fmt.Errorf("snapshot active_slot must be 0 or 1, got %d", s.ActiveSlot)
	}
	if s.Checksum == "" {
		return errors.New("snapshot checksum is required")
	}
	if expected := s.ComputeChecksum(); expected != s.Checksum {
		return fmt.Errorf("snapshot checksum mismatch: expected %s got %s", expected, s.Checksum)
	}
	if s.Policy != nil {
		if s.Policy.Version != s.PolicyVersion {
			return fmt.Errorf("snapshot policy version mismatch: wrapper %d policy %d", s.PolicyVersion, s.Policy.Version)
		}
		if _, err := VerifyPolicySnapshot(*s.Policy, PolicySnapshotVerifyOptions{ObjectChecksum: s.ObjectChecksum}); err != nil {
			return fmt.Errorf("embedded policy snapshot: %w", err)
		}
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
	malformedPolicy := uint32(actionDrop)
	if s.Policy != nil && s.Policy.Runtime.MalformedPolicy != 0 {
		malformedPolicy = s.Policy.Runtime.MalformedPolicy
	}
	return RuntimeConfigValue{
		ActiveSlot:        s.ActiveSlot,
		PolicyVersion:     s.PolicyVersion,
		MalformedPolicy:   malformedPolicy,
		SampleDenom:       s.SampleDenom,
		UpdatedAtUnixNano: uint64(now.UnixNano()),
	}
}

func LastValidFromPolicySnapshot(policy PolicySnapshot, activeSlot uint32, objectChecksum string, now time.Time) LastValidSnapshot {
	checksum := policy.Checksum
	policy = normalizePolicySnapshot(policy)
	policy.Checksum = checksum
	if objectChecksum == "" {
		objectChecksum = policy.ObjectChecksum
	}
	return LastValidSnapshot{
		SchemaVersion:  1,
		ObjectChecksum: objectChecksum,
		ActiveSlot:     activeSlot,
		PolicyVersion:  policy.Version,
		SampleDenom:    policy.Runtime.SampleDenom,
		SavedAtUnixNS:  now.UnixNano(),
		Policy:         &policy,
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

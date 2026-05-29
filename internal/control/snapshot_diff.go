package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

func (s *Store) GetSnapshotMetadata(ctx context.Context, version uint32, includeSnapshot bool) (SnapshotMetadata, error) {
	if version == 0 {
		return SnapshotMetadata{}, errors.New("snapshot version is required")
	}
	row := s.pool.QueryRow(ctx, `SELECT version, checksum, object_checksum, snapshot, rollback_from, COALESCE(created_by::text, ''), created_at
FROM policy_snapshots WHERE version=$1`, version)
	return scanSnapshot(row, includeSnapshot)
}

func (s *Store) DiffSnapshots(ctx context.Context, fromVersion, toVersion uint32) (SnapshotDiff, error) {
	if fromVersion == 0 || toVersion == 0 {
		return SnapshotDiff{}, errors.New("from and to snapshot versions are required")
	}
	fromRaw, err := snapshotRaw(ctx, s.pool, fromVersion)
	if err != nil {
		return SnapshotDiff{}, err
	}
	toRaw, err := snapshotRaw(ctx, s.pool, toVersion)
	if err != nil {
		return SnapshotDiff{}, err
	}
	var from, to agent.PolicySnapshot
	if err := json.Unmarshal(fromRaw, &from); err != nil {
		return SnapshotDiff{}, fmt.Errorf("decode from snapshot %d: %w", fromVersion, err)
	}
	if err := json.Unmarshal(toRaw, &to); err != nil {
		return SnapshotDiff{}, fmt.Errorf("decode to snapshot %d: %w", toVersion, err)
	}
	diff := SnapshotDiff{
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		ObjectChecksum: SnapshotDiffValue{
			From:    from.ObjectChecksum,
			To:      to.ObjectChecksum,
			Changed: from.ObjectChecksum != to.ObjectChecksum,
		},
		Services:    collectionDiff(from.Services, to.Services, func(item agent.PolicyService) string { return strconv.FormatUint(uint64(item.ServiceID), 10) }),
		WhitelistV4: collectionDiff(from.WhitelistV4, to.WhitelistV4, cidrEntryKey),
		BlacklistV4: collectionDiff(from.BlacklistV4, to.BlacklistV4, cidrEntryKey),
		Rules:       collectionDiff(from.Rules, to.Rules, func(item agent.PolicyRule) string { return strconv.FormatUint(uint64(item.RuleID), 10) }),
	}
	if !jsonEqual(from.Runtime, to.Runtime) {
		diff.Runtime = &SnapshotDiffChange{
			Key:    "runtime",
			Before: marshalSnapshotValue(from.Runtime),
			After:  marshalSnapshotValue(to.Runtime),
		}
	}
	return diff, nil
}

func cidrEntryKey(item agent.PolicyCIDREntry) string {
	return strconv.FormatUint(uint64(item.EntryID), 10)
}

func collectionDiff[T any](from, to []T, keyFn func(T) string) SnapshotCollectionDiff {
	fromByKey := make(map[string]T, len(from))
	toByKey := make(map[string]T, len(to))
	keys := make(map[string]struct{}, len(from)+len(to))
	for _, item := range from {
		key := keyFn(item)
		fromByKey[key] = item
		keys[key] = struct{}{}
	}
	for _, item := range to {
		key := keyFn(item)
		toByKey[key] = item
		keys[key] = struct{}{}
	}

	out := SnapshotCollectionDiff{
		Added:   []SnapshotDiffItem{},
		Removed: []SnapshotDiffItem{},
		Changed: []SnapshotDiffChange{},
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		before, hadBefore := fromByKey[key]
		after, hasAfter := toByKey[key]
		switch {
		case !hadBefore && hasAfter:
			out.Added = append(out.Added, SnapshotDiffItem{Key: key, Item: marshalSnapshotValue(after)})
		case hadBefore && !hasAfter:
			out.Removed = append(out.Removed, SnapshotDiffItem{Key: key, Item: marshalSnapshotValue(before)})
		case hadBefore && hasAfter && !jsonEqual(before, after):
			out.Changed = append(out.Changed, SnapshotDiffChange{Key: key, Before: marshalSnapshotValue(before), After: marshalSnapshotValue(after)})
		case hadBefore && hasAfter:
			out.Unchanged++
		}
	}
	return out
}

func jsonEqual(left, right any) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}

func marshalSnapshotValue(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage("{}")
	}
	return raw
}

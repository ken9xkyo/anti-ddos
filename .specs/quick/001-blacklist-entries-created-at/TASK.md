# Quick Task 001: Blacklist Entries Created At

**Date:** 2026-06-12
**Status:** Done

## Description

Fix `/v1/blacklist/entries` failing on feed-origin rows because the combined SQL query referenced `reputation_entries.created_at`, a column that does not exist.

## Files Changed

- `internal/control/policy_store.go` - map feed row `created_at` from `reputation_entries.first_seen_at`.
- `internal/control/blacklist_entries_test.go` - guard the combined blacklist CTE against the missing feed timestamp column.
- `.notebook/admin-console-vnext.md` - record the blacklist/feed timestamp schema gotcha.

## Verification

- [x] `go test ./internal/control`
- [x] `go test ./...`
- [x] `scripts/lab/threat-feed-postgres-test.sh`
- [x] Rebuilt and restarted local `control-api` container.

## Commit

`fix(control): use feed first_seen_at in blacklist entries`

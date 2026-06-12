# Quick Task 001 Summary

Fixed the combined blacklist entries query by using `reputation_entries.first_seen_at` for feed row `created_at`.

Verification passed:
- `go test ./internal/control`
- `go test ./...`
- `scripts/lab/threat-feed-postgres-test.sh`

Local runtime:
- Rebuilt `anti-ddos/control-api:local`.
- Recreated `anti-ddos-control-api-1`; service is healthy.

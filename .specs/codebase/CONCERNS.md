# Codebase Concerns

**Analysis Date:** 2026-07-01

## Tech Debt

**Duplicated Config Helpers:**

- Issue: `envOrDefault()` and `parseUint64Env()` are identically implemented in both `internal/agent/config.go` and `internal/control/config.go`
- Files: `internal/agent/config.go:121-127`, `internal/control/config.go:66-72` (envOrDefault), `internal/agent/config.go:141-151`, `internal/control/config.go:88-98` (parseUint64Env)
- Why: The two packages were developed independently and both needed env parsing
- Impact: Bug fixes or behavioral changes must be applied in two places
- Fix approach: Extract a shared `internal/config` or `internal/env` package with common helpers

**Monolithic Control Server:**

- Issue: `internal/control/server.go` is 1,208 lines containing all HTTP handlers, routing, auth middleware, and helper functions in a single file
- Files: `internal/control/server.go`
- Why: Organic growth from MVP scope
- Impact: Hard to navigate and maintain; all API changes touch this single file
- Fix approach: Split handlers into domain-specific files (e.g., `handler_services.go`, `handler_auth.go`, `handler_agents.go`)

**Monolithic Policy Store:**

- Issue: `internal/control/policy_store.go` is 70,061 bytes — the largest file in the project
- Files: `internal/control/policy_store.go`
- Why: All policy-related CRUD operations accumulated in one file
- Impact: Difficult to navigate; merge conflicts likely when multiple features touch policy
- Fix approach: Split by domain (services, rules, whitelist, blacklist, UDP blocks)

**Large Migrations File:**

- Issue: `internal/control/migrations.go` is 59,103 bytes (1,238 lines) containing all SQL migrations as Go string literals
- Files: `internal/control/migrations.go`
- Why: Inline SQL approach avoids external migration files/tools
- Impact: File will grow linearly with schema changes; no easy way to run individual migrations
- Fix approach: Consider migration file-per-version approach or SQL file embedding via `go:embed`

## Security Considerations

**Session Token in Cookie Without Secure Flag:**

- Risk: Session cookie `anti_ddos_session` is set with `HttpOnly` and `SameSite=Strict` but without the `Secure` flag
- Files: `internal/control/server.go:136-143`
- Current mitigation: Lab deployment binds to `127.0.0.1` by default; system is documented as not terminating TLS
- Recommendations: Add `Secure: true` when deploying behind TLS termination; document this requirement clearly

**Agent Shared Token:**

- Risk: All agents share a single `ANTI_DDOS_AGENT_SHARED_TOKEN` for Control API authentication — if leaked, all agents are compromised
- Files: `internal/control/config.go:38`, `.env.example:25`
- Current mitigation: Token is required for control sync; agent registration also requires owner identification
- Recommendations: Consider per-agent token generation at registration time for production deployments

## Fragile Areas

**BPF/Go Contract Synchronization:**

- Files: `include/anti_ddos/bpf_contract.h`, `internal/agent/contract.go`
- Why fragile: C struct definitions and Go struct mirrors must be kept in exact byte-level sync manually. No automated verification of struct layout compatibility.
- Common failures: Adding a field to the C struct without updating the Go mirror (or vice versa) causes silent data corruption in BPF map operations
- Safe modification: Always update both files together. Run `make bpf-test` + `make go-test` after any contract change
- Test coverage: `internal/agent/contracts_bpf_test.go` validates some struct sizes but not all fields

**A/B Map Slot Swap:**

- Files: `bpf/xdp_data_plane.bpf.c`, `internal/agent/policy_apply.go`
- Why fragile: The inactive slot must be fully populated before the atomic swap. Partial population during swap causes packet misclassification
- Common failures: Map population errors leaving stale data in the "new" slot
- Safe modification: Always populate the full inactive slot, never modify the active slot directly. Verify with `policy_snapshot_test.go`
- Test coverage: Extensive tests in `internal/agent/policy_snapshot_test.go` (27K bytes)

## Test Coverage Gaps

**No Coverage Measurement:**

- What's not tested: Overall coverage percentage is unknown — no coverage tooling configured
- Risk: Unknown blind spots in critical paths
- Priority: Medium
- Difficulty to test: Low — `go test -cover ./...` and Vitest `--coverage` can be added easily

**Integration Test DB Isolation:**

- What's not tested: PostgreSQL integration tests use `DROP SCHEMA public CASCADE` for cleanup — entire schema is destroyed between test suites
- Risk: Tests cannot run in parallel against the same database; real production data would be destroyed if test DSN accidentally points to production
- Priority: Medium
- Difficulty to test: Tests already gate on `ANTI_DDOS_CONTROL_TEST_DSN` env var (skips if unset). Shell scripts use ephemeral containers.

**XDP Packet Path Testing:**

- What's not tested: No automated packet-level tests that verify actual XDP packet classification (drop/pass/redirect verdicts with crafted packets)
- Risk: Regression in BPF C logic may not be caught until lab or production testing
- Priority: High
- Difficulty to test: Requires BPF_PROG_TEST_RUN or XDP testing framework (e.g., xdp-tools test framework). The current `xdp_fixture_test.c` only validates map/program existence, not packet processing logic.

---

_Concerns audit: 2026-07-01_
_Update as issues are fixed or new ones discovered_

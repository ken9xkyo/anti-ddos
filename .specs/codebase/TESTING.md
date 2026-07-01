# Testing Infrastructure

## Test Frameworks

**Unit/Integration (Go):** stdlib `testing` package (no third-party test framework)
**Unit (Frontend):** Vitest 2.1.8 + @testing-library/react 16.1.0 + @testing-library/jest-dom 6.6.3 + jsdom 25.0.1
**BPF Fixture:** Custom C test harness compiled with gcc + libbpf (loads BPF object, validates maps/programs)
**Integration (PostgreSQL):** Shell scripts launching ephemeral Docker PostgreSQL containers
**E2E:** Python (Playwright-based, `scripts/e2e/`)
**Coverage:** Not configured explicitly

## Test Organization

**Location:**
- Go tests: collocated with source (`internal/agent/*_test.go`, `internal/control/*_test.go`)
- Frontend tests: collocated with source (`web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`)
- BPF fixture test: `tests/xdp/xdp_fixture_test.c`
- Integration test scripts: `scripts/lab/*.sh`
- E2E tests: `scripts/e2e/`, `tests/automation_test/admin-dashboard/`

**Naming:**
- Go: `<file>_test.go` in same package (white-box testing)
- Frontend: `<file>.test.tsx` / `<file>.test.ts`

**Structure:**
- Go tests use `testing.T` with `t.Helper()`, `t.Fatal()`, `t.Skip()` patterns
- No testify or assertion libraries — raw stdlib assertions
- Test helpers centralized in `internal/control/test_helpers_test.go`

## Testing Patterns

### Unit Tests (Go)

**Approach:** White-box, same-package tests
**Location:** `internal/agent/*_test.go`, `internal/control/*_test.go`
- Config validation tests (`config_test.go`)
- Snapshot signing/parsing tests (`policy_snapshot_test.go`, 27K bytes — extensive)
- Metrics tests (`metrics_test.go`)
- Event forwarder tests (`event_forwarder_test.go`)
- BPF contract validation tests (`contracts_bpf_test.go`)
- Redaction tests (`redaction_test.go`)
- Counter tests (`counters_test.go`)

### Integration Tests (PostgreSQL)

**Approach:** Shell scripts spin up ephemeral PostgreSQL Docker containers, run `go test` with `ANTI_DDOS_CONTROL_TEST_DSN` pointing to the container. Tests can also self-provision via `t.Skip()` when env var is unset.
**Location:** `scripts/lab/*.sh`
**Pattern in Go:** `resetControlTestDB(t)` helper drops/recreates public schema, runs migrations (including idempotency check), returns pool.

Test suites:
- `control-core-postgres-test`: Core control store operations
- `observability-postgres-test`: Observability handlers
- `threat-feed-postgres-test`: Threat feed ingestion
- `alerting-postgres-test`: Alert evaluation and delivery
- `dashboard-postgres-test`: Dashboard API endpoints

### BPF Fixture Tests

**Approach:** C test binary loads compiled BPF object, validates map existence, structure, program sections
**Location:** `tests/xdp/xdp_fixture_test.c` (compiled to `build/tests/xdp_fixture_test`)
**Run:** `make bpf-test`

### Frontend Unit Tests

**Approach:** Vitest with React Testing Library, jsdom environment
**Location:** `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`
**Run:** `npm --prefix web/dashboard test -- --run`

### E2E Tests

**Approach:** Python/Playwright for services dashboard flows
**Location:** `scripts/e2e/`
**Run:** `make services-ui-e2e`

### XDP/VETH Lab Tests

**Approach:** Shell scripts creating VETH pairs, running agent lifecycle and DEVMAP forwarding tests
**Location:** `scripts/lab/agent-lifecycle-veth-test.sh`, `scripts/lab/devmap-forwarding-veth-test.sh`
**Run:** `make agent-lifecycle-veth-test`, `make devmap-forwarding-veth-test`

## Test Execution

**Commands:**
```bash
make test              # Fast gate: BPF fixture + Go tests + UI tests + UI build
make test-all          # Full gate: test + lint + go-race + integration tests
make go-test           # go test ./...
make go-vet            # go vet ./...
make go-race           # go test -race ./...
make ui-test           # Vitest run
make bpf-test          # BPF fixture test
make integration-test  # All PostgreSQL integration tests
make control-postgres-test          # All control PG tests combined
make control-core-postgres-test     # Core only
make observability-postgres-test    # Observability only
make threat-feed-postgres-test      # Feed only
make alerting-postgres-test         # Alerting only
make dashboard-postgres-test        # Dashboard only
make admin-dashboard-test           # lint + race + integration + UI tests + UI build
make agent-lifecycle-veth-test      # Agent VETH lifecycle test
make devmap-forwarding-veth-test    # DEVMAP forwarding VETH test
make services-ui-e2e                # Playwright E2E
```

## Coverage Targets

**Current:** Not measured explicitly
**Goals:** Not documented
**Enforcement:** Not automated

## Test Coverage Matrix

| Code Layer | Required Test Type | Location Pattern | Run Command |
|---|---|---|---|
| BPF data plane | Fixture (C) | `tests/xdp/xdp_fixture_test.c` | `make bpf-test` |
| Agent (internal/agent) | Unit (Go) | `internal/agent/*_test.go` | `make go-test` |
| Control core | Unit + Integration (PG) | `internal/control/*_test.go` | `make go-test` / `make control-core-postgres-test` |
| Control observability | Integration (PG) | `internal/control/observability_handlers_test.go` | `make observability-postgres-test` |
| Control feed | Integration (PG) | `internal/control/feed_test.go` | `make threat-feed-postgres-test` |
| Control alerting | Integration (PG) | `internal/control/alert_test.go` | `make alerting-postgres-test` |
| Control dashboard | Integration (PG) | `internal/control/admin_dashboard_integration_test.go` | `make dashboard-postgres-test` |
| Admin Dashboard UI | Unit (Vitest) | `web/dashboard/src/*.test.{ts,tsx}` | `make ui-test` |
| Services E2E | E2E (Playwright) | `scripts/e2e/` | `make services-ui-e2e` |
| Agent lifecycle | Lab (VETH) | `scripts/lab/agent-lifecycle-veth-test.sh` | `make agent-lifecycle-veth-test` |
| DEVMAP forwarding | Lab (VETH) | `scripts/lab/devmap-forwarding-veth-test.sh` | `make devmap-forwarding-veth-test` |

## Parallelism Assessment

| Test Type | Parallel-Safe? | Isolation Model | Evidence |
|---|---|---|---|
| Go unit tests | Yes | No shared state | Pure function tests, struct method tests |
| Go PG integration | No | Schema-level cleanup | `DROP SCHEMA public CASCADE` in `resetControlTestDB()` |
| BPF fixture | Yes | Read-only BPF object inspection | No mutable state |
| Vitest frontend | Yes | jsdom isolation | Separate DOM per test, mock fetch |
| VETH lab tests | No | System-level (VETH pairs, XDP attach) | Requires root, modifies kernel state |

## Gate Check Commands

| Gate Level | When to Use | Command |
|---|---|---|
| Quick | After pure Go/UI changes | `make go-test ui-test` |
| BPF | After BPF C changes | `make bpf-test` |
| Standard | After any backend change | `make test` |
| Full | Before merge / after RBAC changes | `make test-all` |
| Build | Validate everything compiles | `make build` |

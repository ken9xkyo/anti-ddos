# Testing Infrastructure

## Test Frameworks

* **eBPF Data Plane (C):** Custom user-space C harness (`tests/xdp/xdp_fixture_test.c`) that loads the compiled BPF object using `libbpf` and executes mock packets via the BPF kernel test runner API (`bpf_prog_test_run_opts`).
* **Backend Services (Go):** Standard library Go `testing` framework.
* **Frontend UI (TypeScript):** Vitest v2.1.8 with `@testing-library/react` and `jsdom` for React component unit testing.
* **E2E Automation (Python/Playwright):** Python-based Playwright E2E suite (`tests/automation_test/admin-dashboard`) running automated user flows against a live ephemeral environment.

---

## Test Organization

* **eBPF Tests:** Contained in `tests/xdp/`.
* **Go Unit & Integration Tests:** Co-located next to the implementation files under `internal/agent/` and `internal/control/` with a `_test.go` suffix.
* **Go Database Integration Tests:** Contained inside `internal/control/` (e.g., `admin_dashboard_integration_test.go`, `alert_test.go`, `server_test.go`). These tests invoke `resetControlTestDB(t)` to clear and populate a PostgreSQL database container.
* **UI Component Tests:** Co-located in the `web/dashboard/src/` folder with `.test.tsx` or `.test.ts` extensions.
* **Dashboard E2E Tests:** Contained in `tests/automation_test/admin-dashboard/`.

---

## Test Coverage Matrix

| Code Layer | Required Test Type | Location Pattern | Run Command |
| :--- | :--- | :--- | :--- |
| **eBPF Data Plane** | C Kernel Test Run | `tests/xdp/xdp_fixture_test.c` | `make bpf-test` |
| **Node Agent** | Go Unit Testing | `internal/agent/*_test.go` | `make go-test` |
| **Control Core** | Go Database Integration | `internal/control/*_test.go` | `make integration-test` |
| **Admin Dashboard UI** | Vitest React Testing | `web/dashboard/src/**/*.test.tsx` | `make ui-test` |
| **Live UI & API E2E** | Playwright E2E | `tests/automation_test/admin-dashboard/` | `.venv-e2e/bin/python tests/automation_test/admin-dashboard/run_admin_dashboard.py` |

---

## Parallelism Assessment

| Test Type | Parallel-Safe? | Isolation Model | Evidence |
| :--- | :--- | :--- | :--- |
| **BPF Tests** | Yes | Execution context isolated by kernel namespace per process run. | Running `make bpf-test` spawns a single test process using a temporary BPF object load. |
| **Go Unit Tests** | Yes | Isolated in-memory tests with no database dependency. | No global state sharing; run standard `go test ./...` in parallel safely. |
| **Go DB Integration Tests** | **No** | Share database schema via `ANTI_DDOS_CONTROL_TEST_DSN`. | Tests do not call `t.Parallel()`. Calling `resetControlTestDB` drops public schema cascading, which would break concurrent tests. |
| **Vitest UI Tests** | Yes | Vitest runs worker threads and mock browser environment (jsdom) isolation. | Vitest defaults to parallel file execution. |
| **Playwright E2E Tests** | **No** | Ephemeral docker-compose postgres DB initialized sequentially. | Run script spins up services on free local ports and executes tests sequentially. |

---

## Gate Check Commands

Use the following commands to check build health before submitting changes:

| Gate Level | When to Use | Command | Description |
| :--- | :--- | :--- | :--- |
| **Quick** | Local task check after minor change | `make test` | Runs BPF test, Go unit tests, UI unit tests, and compiles UI assets. |
| **Full** | Pre-commit / Pre-PR | `make test-all` | Runs `test` + Go linter + Go race detector + Postgres integration tests. |
| **Build** | Check clean compilation | `make build` | Builds BPF object, Go binaries, and builds frontend production assets. |

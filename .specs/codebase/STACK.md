# Tech Stack

**Analyzed:** 2026-06-30

## Core

- **Framework:** None (standard library `net/http` for API server)
- **Language:** Go 1.22.2 (Backend), TypeScript 5.7.2 (Frontend), C (eBPF Data Plane), Python 3 (E2E Tests)
- **Runtime:** Linux Kernel with eBPF (XDP), Node.js (build-time UI)
- **Package manager:** Go Modules (`go.mod`), npm (`package.json`)

## Frontend

- **UI Framework:** React 18.3.1
- **Styling:** MUI (Material-UI) v9.0.1, Emotion (@emotion/react v11.14.0, @emotion/styled v11.14.1)
- **State Management:** React local state, Context API
- **Form Handling:** Standard controlled React components
- **Component Libraries:** `@mui/x-charts` v9.3.0, `@mui/x-data-grid` v9.3.0, `lucide-react` v0.468.0

## Backend

- **API Style:** REST API over HTTP using standard Go `http.ServeMux`
- **Database:** PostgreSQL (requires v16+; defaults to `postgres:16.9-alpine3.22` in Compose)
- **Database Driver:** `github.com/jackc/pgx/v5` and `pgxpool` for connection pooling
- **Authentication:** Token-based session authentication with bcrypt password hashing (`golang.org/x/crypto/bcrypt`)

## Testing

- **Unit:** Go standard `testing` package (Backend), Vitest v2.1.8 (Frontend)
- **Integration:** Go `testing` package targeting temporary test containers (driven by `scripts/lab/lib/control_postgres.sh`)
- **E2E:** Python Playwright E2E suite (`tests/automation_test/admin-dashboard`) and custom shell/python scripts (`scripts/lab/` and `scripts/e2e/`)

## External Services

- **Observability:** Prometheus v3.5.2 (metrics scraping & alerting metrics), Grafana v12.4.3 (dashboard visualization)
- **Alerting:** Telegram Bot API (webhook messages to groups/channels)
- **Threat Feeds:** AbuseIPDB API and general JSON feeds for dynamic IP blacklists

## Development Tools

- **Compilers:** `clang` (target `bpf` for compiler optimization), `gcc` (local test fixtures compilation)
- **eBPF Tools:** `bpftool` (BTF dump generation of `vmlinux.h` and link inspection)
- **Orchestration:** Docker, Docker Compose
- **Linter:** `go vet`, `golangci-lint` (optional/run if present)

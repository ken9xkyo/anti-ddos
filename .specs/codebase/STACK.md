# Tech Stack

**Analyzed:** 2026-07-01

## Core

- Language: Go 1.22.2 (backend + agent)
- Language: C (eBPF/XDP data plane)
- Language: TypeScript (admin dashboard)
- Package Manager: Go modules, npm
- Build System: GNU Make (comprehensive Makefile with ~60 targets)
- Runtime: Linux kernel (eBPF/XDP requires kernel 5.x+, targeting Ubuntu 24.04)

## Data Plane (eBPF/XDP)

- BPF Compiler: Clang (target bpf, `-O2 -Wall -Werror`)
- BPF Framework: libbpf (CO-RE via vmlinux.h generated at build time)
- Go BPF Library: cilium/ebpf v0.17.3
- Kernel Helpers: bpf_helpers.h, bpf_endian.h
- Shared Contract: `include/anti_ddos/bpf_contract.h` (structs & enums shared between C and Go)

## Backend (Go)

- API Style: REST (stdlib `net/http` + `http.ServeMux`, no router library)
- Database: PostgreSQL 16.9 via `jackc/pgx/v5` (pgxpool connection pool, raw SQL)
- Authentication: bcrypt password hashing (`golang.org/x/crypto`), session tokens, RBAC (admin/user)
- Metrics: Prometheus client_golang v1.22.0
- Networking: vishvananda/netlink v1.3.1 (interface management for XDP)

## Frontend

- UI Framework: React 18.3.1
- Component Library: MUI (Material UI) v9.0.1
- Charts: @mui/x-charts v9.3.0
- Data Grid: @mui/x-data-grid v9.3.0
- Styling: Emotion (@emotion/react, @emotion/styled) + vanilla CSS
- Icons: lucide-react 0.468.0
- Build Tool: Vite 5.4.11
- TypeScript: 5.7.2

## Testing

- Unit (Go): `go test` (stdlib testing package)
- Unit (Frontend): Vitest 2.1.8 + @testing-library/react 16.1.0 + jsdom 25.0.1
- BPF Fixture Tests: Custom C test harness compiled with gcc + libbpf
- Integration: PostgreSQL integration tests via shell scripts launching ephemeral containers
- E2E: Python (Playwright-based services dashboard E2E via `scripts/e2e/`)
- Lint: `go vet` + optional `golangci-lint`

## External Services

- Database: PostgreSQL 16.9 (Alpine)
- Monitoring: Prometheus v3.5.2 + Grafana 12.4.3
- Notifications: Telegram Bot API (alerting)
- Container Runtime: Docker Compose (bridge networking, health checks)

## Development Tools

- Containerization: Docker Compose (multi-service lab stack)
- BPF Tooling: bpftool (BTF dump, program inspection)
- CI/Lab Scripts: Shell scripts in `scripts/lab/`
- Node Runtime: Node.js 22.22.1 (Alpine, for dashboard build)
- Web Server: Nginx 1.30.1 (Alpine, serves dashboard static assets)

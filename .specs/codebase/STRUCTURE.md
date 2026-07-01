# Project Structure

**Root:** `/root/anti-ddos`

## Directory Tree

```
anti-ddos/
├── bpf/                            # eBPF/XDP C source programs
│   ├── xdp_data_plane.bpf.c       # Main XDP packet processing (~1000 LOC)
│   └── xdp_pass.bpf.c             # Minimal pass-through for output NICs
├── include/
│   └── anti_ddos/
│       └── bpf_contract.h          # Shared C/Go ABI contract (structs, enums, limits)
├── cmd/                            # Binary entrypoints (thin main.go files)
│   ├── agent/main.go               # Node Agent binary
│   ├── control-api/main.go         # Control API server (migrate|serve|print-migrations)
│   ├── control-admin/main.go       # CLI admin tool (bootstrap)
│   └── policygen/main.go           # Offline policy snapshot generator
├── internal/                       # Private Go packages
│   ├── agent/                      # Node Agent logic (25 files, 14 source + 11 test)
│   └── control/                    # Control Plane logic (42 files, 22 source + 20 test)
├── web/
│   └── dashboard/                  # React/TypeScript admin SPA
│       ├── src/
│       │   ├── views/              # 12 page-level view components
│       │   ├── App.tsx             # Root component with routing
│       │   ├── DashboardShell.tsx  # Layout shell with navigation
│       │   ├── api.ts              # API client layer
│       │   ├── types.ts            # TypeScript type definitions
│       │   └── styles.css          # Global styles
│       ├── package.json
│       └── vite.config.ts
├── deploy/
│   ├── docker/                     # Dockerfiles + nginx config
│   │   ├── control-api.Dockerfile
│   │   ├── admin-dashboard.Dockerfile
│   │   └── admin-dashboard.nginx.conf
│   ├── prometheus/                 # Prometheus scrape/recording rules
│   └── grafana/                    # Dashboard JSON + provisioning
├── scripts/
│   └── lab/                        # Integration test shell scripts
│       ├── agent-lifecycle-veth-test.sh
│       ├── devmap-forwarding-veth-test.sh
│       ├── control-postgres-test.sh
│       ├── control-core-postgres-test.sh
│       ├── observability-postgres-test.sh
│       ├── threat-feed-postgres-test.sh
│       ├── alerting-postgres-test.sh
│       ├── dashboard-postgres-test.sh
│       └── lib/                    # Shared test helpers
├── tests/
│   ├── xdp/
│   │   └── xdp_fixture_test.c     # BPF fixture test in C
│   └── automation_test/
│       └── admin-dashboard/        # E2E automation tests
├── build/                          # Build output directory
│   ├── bpf/                        # Compiled BPF objects + vmlinux.h
│   ├── agent/                      # Agent binary + logs + PID
│   └── tests/                      # Compiled test binaries
├── docker-compose.yml              # Full lab stack (5 services)
├── Makefile                        # ~578 lines, comprehensive build system
├── go.mod / go.sum                 # Go module dependencies
├── .env.example                    # Environment template
└── README.md                       # Operational documentation (Vietnamese)
```

## Module Organization

### Data Plane (BPF)
**Purpose:** Kernel-space packet classification, filtering, rate limiting, forwarding
**Location:** `bpf/`, `include/anti_ddos/`
**Key files:** `xdp_data_plane.bpf.c` (main program), `bpf_contract.h` (shared ABI)

### Node Agent
**Purpose:** BPF loader, policy manager, metrics collector, control sync
**Location:** `internal/agent/`, `cmd/agent/`
**Key files:** `agent.go` (orchestrator), `loader.go` (BPF load/attach), `policy_apply.go` (map population), `policy_snapshot.go` (snapshot parsing/signing), `control_client.go` (control API sync), `metrics.go` (Prometheus)

### Control Plane
**Purpose:** REST API, RBAC, policy CRUD, snapshots, audit, alerting, feed ingestion
**Location:** `internal/control/`, `cmd/control-api/`, `cmd/control-admin/`
**Key files:** `server.go` (HTTP routing, 1208 LOC), `store.go` (DB layer), `policy_store.go` (policy CRUD, 70K bytes), `types.go` (domain types), `migrations.go` (59K bytes, sequential SQL), `feed.go` (threat feed), `alert.go` (alerting), `snapshot.go` (snapshot builder)

### Admin Dashboard
**Purpose:** Web UI for operations management
**Location:** `web/dashboard/`
**Key files:** `App.tsx` (routing), `DashboardShell.tsx` (layout), `api.ts` (API client), `views/*.tsx` (12 view pages)

### Policy Generator
**Purpose:** Offline CLI tool for generating signed policy snapshots
**Location:** `cmd/policygen/`
**Key files:** `main.go` (single file, uses agent package)

## Where Things Live

**Packet Processing:**
- Classification logic: `bpf/xdp_data_plane.bpf.c`
- Shared contract: `include/anti_ddos/bpf_contract.h`
- Go mirror types: `internal/agent/contract.go`

**Policy Management:**
- API endpoints: `internal/control/server.go`
- DB CRUD: `internal/control/policy_store.go`
- Snapshot build: `internal/control/snapshot.go`
- Agent apply: `internal/agent/policy_apply.go`

**Configuration:**
- Agent: `internal/agent/config.go` (env vars → Config struct)
- Control: `internal/control/config.go` (env vars → Config struct)
- Docker: `docker-compose.yml` + `.env.example`

**Observability:**
- Agent metrics: `internal/agent/metrics.go`
- Control metrics: `internal/control/metrics.go`
- Prometheus config: `deploy/prometheus/`
- Grafana dashboard: `deploy/grafana/`

## Special Directories

**`build/`:**
**Purpose:** All compiled outputs (BPF objects, Go binaries, test binaries). Created by Make targets. Cleaned by `make clean`.

**`scripts/lab/`:**
**Purpose:** Shell-based integration test harnesses. Each test script sets up ephemeral PostgreSQL or VETH pairs, runs tests, and tears down.

**`.specs/`:**
**Purpose:** Project specifications and codebase analysis documents (this brownfield mapping).

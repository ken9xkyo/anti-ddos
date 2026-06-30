# Project Structure

**Root:** `/root/anti-ddos`

## Directory Tree

```
├── .specs/                    # System design, roadmap, and codebase specifications
├── bpf/                       # C source code for the eBPF data plane
│   ├── xdp_data_plane.bpf.c   # Main packet parser, whitelist/blacklist/rate limits
│   └── xdp_pass.bpf.c         # Redirect/pass-through program for devmap queues
├── cmd/                       # Entry points for compiling binaries
│   ├── agent/                 # Main entry for the Node Agent daemon
│   ├── control-admin/         # CLI tool for bootstrapping and user operations
│   ├── control-api/           # REST API server for dashboard/agent coordination
│   └── policygen/             # CLI rules/policy template generator
├── deploy/                    # Config files for orchestration and instrumentation
│   ├── grafana/               # Dashboards and data source provisioning configs
│   ├── prometheus/            # Metric scraping rules and recording rules
│   └── docker/                # Dockerfiles for Control API & Dashboard
├── include/                   # Shared C header references
│   └── anti_ddos/             # Directory for data-plane contract headers
│       └── bpf_contract.h     # Shared struct layouts and limits between C & Go
├── internal/                  # Private Go internal packages
│   ├── agent/                 # Agent logic (BPF loading, metrics, policy processing)
│   └── control/               # Control Plane logic (DB CRUD, server routing, feeds, alerts)
├── scripts/                   # Dev tools, automation, and virtual network lab scripts
│   ├── e2e/                   # E2E pipeline scripts (services forwarding verification)
│   └── lab/                   # Isolated integration and performance lab tests
├── tests/                     # Integration and regression test suites
│   ├── automation_test/       # Playwright-Python browser E2E test suite
│   └── xdp/                   # XDP unit fixture test in C
└── web/                       # Frontend application sources
    └── dashboard/             # Vite + React + MUI admin console codebase
```

---

## Where Things Live

**eBPF Data Plane & Parsers:**
* Located in `bpf/` and `include/anti_ddos/`.
* Key contracts (like map capacities and struct layouts) are shared via `bpf_contract.h`.

**Node Agent Daemon:**
* Entry point is `cmd/agent/main.go`.
* Business logic for map loading and synchronization is in `internal/agent/`.

**Control Plane Server & API:**
* Entry point is `cmd/control-api/main.go`.
* Database CRUD, user tables, configurations, alerts, and migrations are under `internal/control/`.

**Admin Web Dashboard:**
* The React SPA source code is located in `web/dashboard/src/`.
* Vite config is at `web/dashboard/vite.config.ts`.
* HTML entrypoint is `web/dashboard/index.html`.

**Integration and Automation Tests:**
* Backend integrations are tested using runners inside `scripts/lab/` (orchestrated by Go's testing tool).
* Full UI E2E browser tests are in `tests/automation_test/admin-dashboard/`.

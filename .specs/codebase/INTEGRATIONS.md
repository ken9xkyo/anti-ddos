# External Integrations

## Database

**Service:** PostgreSQL 16.9
**Purpose:** Persistent storage for all control plane data (users, sessions, services, rules, whitelist, blacklist, agents, snapshots, audit, events, feeds, alerts)
**Implementation:** `internal/control/store.go` — `pgxpool.Pool` with max 8 connections
**Configuration:** `ANTI_DDOS_DB_DSN` environment variable (PostgreSQL connection string)
**Authentication:** PostgreSQL user/password via DSN
**Migrations:** Sequential SQL migrations in `internal/control/migrations.go` (1238 lines, idempotent)

## Monitoring — Prometheus

**Service:** Prometheus v3.5.2
**Purpose:** Scrape and store metrics from Control API and Node Agent
**Implementation:** 
- Control API exposes `/metrics` on `:8080` — `internal/control/metrics.go`
- Node Agent exposes `/metrics` on `:9091` — `internal/agent/metrics.go`
- Both use `prometheus/client_golang` registry
**Configuration:** 
- Scrape config: `deploy/prometheus/compose-prometheus.yml`
- Recording rules: `deploy/prometheus/anti-ddos-recording-rules.yml`
- Agent scraped via `host.docker.internal:9091`
**Key metrics:** Drop counters by action/reason/protocol, forwarding counters, agent up status, XDP mode, BPF map stats, HTTP request latency

## Monitoring — Grafana

**Service:** Grafana 12.4.3
**Purpose:** Operational dashboards and visualization
**Implementation:** Pre-provisioned dashboards and datasource
**Configuration:**
- Dashboard JSON: `deploy/grafana/anti-ddos-p1-dashboard.json`
- Provisioning: `deploy/grafana/provisioning/`
- Auto-provisioned Prometheus datasource
**Authentication:** Admin user/password via env vars (`GRAFANA_ADMIN_USER`, `GRAFANA_ADMIN_PASSWORD`)

## Monitoring — Control API → Prometheus Client

**Service:** Prometheus Query API (reverse direction — Control API queries Prometheus)
**Purpose:** Dashboard overview fetches real-time metrics (traffic rates, top talkers) from Prometheus
**Implementation:** `internal/control/prometheus.go` — `PrometheusClient` with HTTP client
**Configuration:** `ANTI_DDOS_PROMETHEUS_URL` environment variable
**Key queries:** Agent metrics, drop rate, forwarding rate

## Notifications — Telegram

**Service:** Telegram Bot API
**Purpose:** Alert delivery for DDoS events (ISP escalation, threshold breaches)
**Implementation:** `internal/control/alert.go`, Telegram client in Store
**Configuration:** 
- `ANTI_DDOS_TELEGRAM_API_URL` (default: `https://api.telegram.org`)
- Bot token and chat ID stored per-user in DB via `/v1/telegram/config`
**Authentication:** Bot token per user

## Threat Feed Ingestion

**Service:** External HTTP feeds (CIDR blocklists)
**Purpose:** Automated blacklist population from threat intelligence sources
**Implementation:** `internal/control/feed.go` (30K bytes) — `FeedSource` with HTTP client
**Configuration:** Feed sources managed via `/v1/feed-sources` API
**Key features:** Scheduled sync, conflict detection, entry deduplication, feed run history

## BPF/Kernel Interface

**Service:** Linux kernel BPF subsystem
**Purpose:** Data plane attachment, map management, program loading
**Implementation:** `internal/agent/loader.go` — uses `cilium/ebpf` Go library
**Configuration:** 
- BPF pin directory: `ANTI_DDOS_BPF_PIN_DIR` (default: `/sys/fs/bpf/anti-ddos`)
- XDP mode: `ANTI_DDOS_XDP_MODE` (native or generic)
**Key operations:** `LoadAndAttach()`, BPF link pinning, map pinning, XDP_REDIRECT via DEVMAP

## Netlink (Network Interface Management)

**Service:** Linux netlink
**Purpose:** Interface discovery, ifindex resolution, neighbor (ARP) resolution for forwarding
**Implementation:** `internal/agent/forwarding_resolver.go` — uses `vishvananda/netlink`
**Configuration:** `ANTI_DDOS_WAN_IFACE`, `ANTI_DDOS_OUTPUT_IFACES` environment variables
**Key operations:** Interface lookup, MAC address resolution, neighbor table queries

## Background Jobs

**Queue system:** No external queue — goroutine-based schedulers
**Location:** `internal/control/scheduler.go`, `internal/agent/agent.go`
**Jobs:**
- **Agent metrics collection:** 1-second ticker in Agent.Run()
- **Ringbuf event consumption:** Goroutine consuming BPF ring buffer
- **Security event forwarding:** Goroutine batching + forwarding events to Control API
- **Control sync:** Goroutine polling Control API for snapshot updates
- **Control schedulers:** `StartBackgroundSchedulers()` for feed sync, alert evaluation, session cleanup

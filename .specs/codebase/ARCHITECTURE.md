# Architecture

**Pattern:** Multi-plane monorepo — eBPF/XDP data plane + Go control plane + React management dashboard

## High-Level Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Management Plane                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Grafana      │  │  Prometheus  │  │  Admin Dashboard (React) │  │
│  │  :3000        │  │  :9090       │  │  :8088 (nginx→SPA)       │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────────┘  │
│         │ scrape          │ scrape               │ REST API         │
├─────────┴─────────────────┴──────────────────────┴──────────────────┤
│                      Control Plane                                   │
│  ┌─────────────────────────────────────────────┐                    │
│  │  Control API (Go, :8080)                     │                    │
│  │  ├─ REST endpoints /v1/*                     │                    │
│  │  ├─ Session auth (bcrypt + token)            │                    │
│  │  ├─ RBAC (admin / user)                      │                    │
│  │  ├─ Policy store, snapshot, rollback         │                    │
│  │  ├─ Threat feed ingestion                    │                    │
│  │  ├─ Alerting (Telegram)                      │                    │
│  │  └─ Audit trail                              │                    │
│  └──────────┬──────────────────────────┘                            │
│             │ SQL                                                    │
│  ┌──────────▼───────────────────────┐                               │
│  │  PostgreSQL 16 (:5432)            │                               │
│  └──────────────────────────────────┘                               │
├──────────────────────────────────────────────────────────────────────┤
│                       Node Plane                                     │
│  ┌──────────────────────────────────────────┐                       │
│  │  Node Agent (Go, host process)            │                       │
│  │  ├─ Load/attach/rollback XDP              │                       │
│  │  ├─ Policy snapshot sync (control client) │                       │
│  │  ├─ eBPF map management (A/B slot swap)   │                       │
│  │  ├─ Ringbuf event consumption             │                       │
│  │  ├─ Prometheus metrics (:9091)            │                       │
│  │  └─ BPF pin management                   │                       │
│  └──────────┬───────────────────────┘                               │
│             │ eBPF maps, link pins                                   │
├─────────────┴────────────────────────────────────────────────────────┤
│               Data Plane (XDP/eBPF, kernel space)                    │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  xdp_entry (xdp_data_plane.bpf.c, ~1000 LOC)        │           │
│  │  ├─ Parse: Ethernet → VLAN → IPv4 → L4              │           │
│  │  ├─ Check: whitelist/blacklist (LPM trie, A/B maps)  │           │
│  │  ├─ Check: service allowlist (dst_v4:port:proto)     │           │
│  │  ├─ Rate limit: token bucket (per-source, subnet,    │           │
│  │  │   service, source-service, PPS/BPS/CPS)           │           │
│  │  ├─ Forward: L2 MAC rewrite + DEVMAP XDP_REDIRECT    │           │
│  │  ├─ UDP amplification source port blocking            │           │
│  │  ├─ Fragment / malformed / bogon drop                 │           │
│  │  ├─ Per-key drop counters (percpu hash)               │           │
│  │  └─ Sampled event ringbuf                             │           │
│  └──────────────────────────────────────────────────────┘           │
│               Forwarding Plane                                       │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  L2 MAC rewrite → DEVMAP → XDP_REDIRECT              │           │
│  │  WAN NIC (xdp_entry) → output NIC(s) (xdp_pass)     │           │
│  └──────────────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────────────┘
```

## Identified Patterns

### A/B Map Slot Pattern
**Location:** `bpf/xdp_data_plane.bpf.c`, `internal/agent/policy_apply.go`
**Purpose:** Zero-downtime policy updates on live data plane
**Implementation:** Each policy map (whitelist, blacklist, service-specific) exists in duplicate `_a`/`_b` variants. The agent populates the inactive slot, then atomically swaps `runtime_config.active_slot`. The XDP program reads `active_slot` to select which set of maps to use.
**Example:** `whitelist_v4_a`/`whitelist_v4_b`, `blacklist_v4_a`/`blacklist_v4_b`

### Policy Snapshot Pattern
**Location:** `internal/agent/policy_snapshot.go`, `internal/control/snapshot.go`
**Purpose:** Declarative, versioned, signed policy state with rollback
**Implementation:** The control plane builds a complete policy snapshot (services, rules, whitelist, blacklist, forwarding) as a single JSON document with schema version, feature flags, and HMAC signature. The agent validates the snapshot signature and object checksum before applying.
**Example:** `agent.PolicySnapshot` struct, `agent.SignPolicySnapshot()`

### Owner-Scoped Data Isolation
**Location:** `internal/control/owner.go`, `internal/control/store.go`
**Purpose:** Multi-user data isolation without tenancy or RLS
**Implementation:** All business data (services, rules, whitelist, blacklist) is tagged with `owner_user_id`. Every query filters by the actor's resolved owner ID. Admin can view-as-user via `/v1/admin/view-user` endpoint (read-only mode).
**Example:** `resolveOwner()`, `Actor.ViewOwnerUserID`

### Env-Driven Configuration
**Location:** `internal/agent/config.go`, `internal/control/config.go`
**Purpose:** All configuration via environment variables with defaults
**Implementation:** `LoadConfigFromEnv()` pattern in both agent and control packages. Uses `envOrDefault()`, `parseBoolEnv()`, `parseDurationEnv()` helper functions. Validated with `errors.Join()` for multi-error reporting.

### HTTP Handler Pattern (stdlib)
**Location:** `internal/control/server.go`
**Purpose:** REST API without external router dependency
**Implementation:** `http.ServeMux` with `HandleFunc`. Manual method dispatch inside handlers. Path-based routing with `strings.HasPrefix`/`TrimPrefix` for sub-resources. Shared helpers: `writeJSON()`, `writeError()`, `decodeJSON()`, `requireActor()`, `requireAdmin()`.
**Example:** `handleServices()`, `handleServiceByID()`

## Data Flow

### Packet Processing (Data Plane → Forwarding)

1. Packet arrives on WAN NIC
2. XDP program `xdp_entry` parses Ethernet/VLAN/IPv4/L4 headers
3. Bogon/fragment/malformed check → DROP if malformed
4. Source IP checked against global + service-scoped blacklist (LPM trie)
5. Service lookup by (dst_v4, dst_port, proto) → service_id
6. Whitelist check (global + service-scoped, LPM trie)
7. UDP amplification source port block check
8. Rate limiting rules evaluated (token bucket per dimension)
9. Clean traffic: L2 MAC rewrite (dst_mac, src_mac) → DEVMAP → XDP_REDIRECT
10. Drop counters and sampled events emitted to BPF maps

### Policy Sync (Control → Agent → Data Plane)

1. User configures services/rules/whitelist/blacklist via Control API
2. Control API builds signed policy snapshot
3. Agent polls `/v1/agents/{id}/snapshot` from Control API
4. Agent validates snapshot signature + object checksum
5. Agent populates inactive A/B map slot via `PolicyApply()`
6. Agent atomically swaps `runtime_config.active_slot`
7. Agent persists last valid snapshot to disk for crash recovery

## Code Organization

**Approach:** Layer-based with plane separation

**Module boundaries:**
- `bpf/` — eBPF/XDP C programs (kernel-space data plane)
- `include/anti_ddos/` — Shared C header contract between BPF and Go
- `internal/agent/` — Node Agent Go package (BPF loader, policy apply, metrics, control sync)
- `internal/control/` — Control Plane Go package (server, store, migrations, types, feed, alert)
- `cmd/` — Four binary entrypoints (agent, control-api, control-admin, policygen)
- `web/dashboard/` — React/TypeScript admin SPA
- `deploy/` — Docker, Prometheus, Grafana configs
- `scripts/lab/` — Integration test scripts
- `tests/` — BPF fixture tests (C) and automation tests

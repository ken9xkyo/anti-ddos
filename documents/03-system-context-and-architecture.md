# System Context And Architecture

## System Context

Sơ đồ: [diagrams/system-context.mmd](diagrams/system-context.mmd)

Hệ thống nằm giữa Internet/WAN traffic và protected backend services. Data plane xử lý packet trên scrubbing host. Control plane và management plane cung cấp cấu hình, audit, dashboard và observability. Network/SRE là stakeholder bắt buộc vì hệ thống cần interface roles, service inventory và forwarding metadata đúng.

## Container Architecture

Sơ đồ: [diagrams/container-architecture.mmd](diagrams/container-architecture.mmd)

| Container/Component | Runtime | Trách nhiệm |
|---|---|---|
| `xdp_entry` | eBPF program attach vào WAN interface | Parse packet, enforce policy, redirect/drop/pass |
| eBPF maps | bpffs pinned maps | Policy A/B slots, runtime config, devmap, counters, ringbuf |
| Node Agent | Host Go process | Load/attach XDP, pin, apply snapshot, expose metrics, forward events |
| Control API | Go HTTP server | REST API, migrations, scheduler, snapshots, RBAC, audit, alerts |
| PostgreSQL | Compose service hoặc external DB | Source of truth và tenant isolation |
| Admin Dashboard | React/Vite build served by Nginx | Operator UI |
| Prometheus | Compose service | Scrape Agent/Control metrics và phục vụ dashboard data |
| Grafana | Compose service | Prebuilt operational dashboards |
| `control-admin` | CLI trong control image | Bootstrap admin đầu tiên |
| `policygen` | CLI local | Sinh signed policy snapshot cho lab/manual testing |

## Plane Boundaries

### Data Plane

- Không gọi network hoặc DB.
- Chỉ đọc eBPF maps và packet data.
- Mọi quyết định packet phải bounded, verifier-friendly, no dynamic allocation.
- Fail closed khi runtime config invalid, malformed packet, fragment, service missing, unresolved neighbor hoặc redirect error.

### Node Plane

- Là cầu nối giữa Control API và eBPF maps.
- Có quyền attach XDP và pin bpffs, nên phải chạy trên host, không nằm trong compose stack mặc định.
- Khi Control URL được cấu hình, Agent register, heartbeat, fetch snapshot, apply và ack.
- Khi Control URL rỗng, Agent vẫn có thể load snapshot local/bootstrap.

### Control Plane

- Source of truth cho tenant, service, policy, feed, event, snapshot, audit, alert.
- Chạy migrations khi `control-api serve` hoặc `control-api migrate`.
- Có background schedulers: anomaly evaluation 10s, rule expiry 30s, feed scheduler 30s.
- Không attach XDP trực tiếp.

### Management Plane

- Dashboard gọi Control API qua HTTP JSON.
- Prometheus scrape Agent `/metrics` và Control API `/metrics`.
- Grafana dùng Prometheus.
- Telegram alerting thông qua Control API; API/UI phải mask token hoặc token ref và không hiển thị raw secret.

## Key Runtime Flows

| Flow | Mô tả | Tài liệu chi tiết |
|---|---|---|
| Packet decision | WAN packet vào XDP, match service/list/rule, redirect/drop/pass | [04-data-plane-ebpf-xdp.md](04-data-plane-ebpf-xdp.md) |
| Policy lifecycle | Control build snapshot, Agent verify/apply A/B maps | [08-policy-snapshot-and-enforcement.md](08-policy-snapshot-and-enforcement.md) |
| Agent-Control sync | Register, heartbeat, snapshot fetch, apply ack, event forwarding | [05-node-agent.md](05-node-agent.md) |
| Dashboard operations | UI navigation, RBAC, API mapping | [09-admin-dashboard.md](09-admin-dashboard.md) |
| Tenant isolation | Active tenant, transaction GUC, RLS | [11-security-rbac-and-secrets.md](11-security-rbac-and-secrets.md) |

## Public Interfaces

| Interface | Producer | Consumer |
|---|---|---|
| HTTP `/v1/*` | Control API | Dashboard, Agent, operators |
| Agent `/metrics`, `/healthz` | Node Agent | Prometheus, health checks |
| Control `/metrics`, `/healthz` | Control API | Prometheus, compose health checks |
| Policy snapshot JSON | Control API / policygen | Agent |
| eBPF ABI maps/structs | BPF contract header | Agent loader/apply code |
| PostgreSQL schema | Control migrations | Control store methods |

## Source Alignment

- Architecture docs hiện có: `docs/System-Architecture-Design.md`, `docs/High-Level-Design.md`
- Runtime entrypoints: `cmd/agent/main.go`, `cmd/control-api/main.go`, `cmd/control-admin/main.go`, `cmd/policygen/main.go`
- Control routes: `internal/control/server.go`
- Agent lifecycle: `internal/agent/agent.go`, `internal/agent/loader.go`
- Deploy topology: `docker-compose.yml`, `deploy/docker/*.Dockerfile`

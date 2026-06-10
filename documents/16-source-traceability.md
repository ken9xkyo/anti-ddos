# Source Traceability

## Quy Ước

Ma trận này chỉ ra nơi cần đọc source khi team mới muốn clone hoặc verify một subsystem. Với target SaaS RBAC, role names trong `documents/` là canonical product-facing spec. Source hiện tại vẫn là implementation anchor cho endpoint, migration, eBPF ABI, Agent behavior, dashboard flow và tests.

Nếu tài liệu target RBAC và source hiện tại khác nhau về tên role, không expose tên role implementation-only ra sản phẩm mới; dùng source để hiểu nơi cần thay đổi khi implement. Nếu tài liệu low-level và source khác nhau về ABI/endpoint/migration hiện hữu, verify source trước khi build contract tương thích.

## Target SaaS RBAC Traceability

| Target concept | Tài liệu chính | Source anchor hiện tại |
|---|---|---|
| Tenant = Customer Account | [11-security-rbac-and-secrets.md](11-security-rbac-and-secrets.md), [07-database-schema-and-migrations.md](07-database-schema-and-migrations.md) | `internal/control/tenant.go`, `internal/control/tenant_store.go` |
| Platform roles | [11-security-rbac-and-secrets.md](11-security-rbac-and-secrets.md) | `internal/control/types.go`, `internal/control/store.go` |
| Tenant roles | [11-security-rbac-and-secrets.md](11-security-rbac-and-secrets.md), [09-admin-dashboard.md](09-admin-dashboard.md) | `internal/control/types.go`, `internal/control/rbac_test.go` |
| Active tenant session | [06-control-plane-api.md](06-control-plane-api.md), [11-security-rbac-and-secrets.md](11-security-rbac-and-secrets.md) | `internal/control/tenant.go`, `internal/control/store.go` |
| Tenant-scoped DB/RLS | [07-database-schema-and-migrations.md](07-database-schema-and-migrations.md) | `internal/control/migrations.go`, `internal/control/tenant.go` |
| Agent tenant binding | [05-node-agent.md](05-node-agent.md), [06-control-plane-api.md](06-control-plane-api.md) | `internal/control/agent_store.go`, `internal/agent/control_client.go` |
| Audit and support/break-glass | [10-observability-alerting-and-audit.md](10-observability-alerting-and-audit.md), [11-security-rbac-and-secrets.md](11-security-rbac-and-secrets.md) | `internal/control/store.go`, `internal/control/alert.go` |

## Runtime Entrypoints

| Artifact | Source | Tài liệu liên quan |
|---|---|---|
| Host Agent | `cmd/agent/main.go` | [05-node-agent.md](05-node-agent.md) |
| Control API | `cmd/control-api/main.go` | [06-control-plane-api.md](06-control-plane-api.md) |
| Control Admin CLI | `cmd/control-admin/main.go` | [12-deployment-and-operations.md](12-deployment-and-operations.md) |
| Policy generator | `cmd/policygen/main.go` | [08-policy-snapshot-and-enforcement.md](08-policy-snapshot-and-enforcement.md) |
| Dashboard | `web/dashboard/src/main.tsx`, `web/dashboard/src/App.tsx` | [09-admin-dashboard.md](09-admin-dashboard.md) |

## Data Plane

| Concern | Source |
|---|---|
| ABI constants, struct layout | `include/anti_ddos/bpf_contract.h` |
| Main XDP maps and hot path | `bpf/xdp_data_plane.bpf.c` |
| Pass-through output XDP helper | `bpf/xdp_pass.bpf.c` |
| BPF object expectation | `internal/agent/contracts_bpf.go` |
| XDP fixture test | `tests/xdp/xdp_fixture_test.c` |

## Agent

| Concern | Source |
|---|---|
| Env config and defaults | `internal/agent/config.go` |
| Load/attach/pin metadata | `internal/agent/loader.go` |
| Last-valid snapshot | `internal/agent/snapshot.go` |
| Policy snapshot schema/verify | `internal/agent/policy_snapshot.go` |
| Policy A/B apply | `internal/agent/policy_apply.go` |
| Control sync | `internal/agent/control_client.go` |
| Event forwarding | `internal/agent/event_forwarder.go` |
| Ringbuf consume | `internal/agent/ringbuf.go` |
| Metrics/counters | `internal/agent/metrics.go`, `internal/agent/counters.go` |
| Forwarding resolution | `internal/agent/forwarding_resolver.go` |

## Control Plane

| Concern | Source |
|---|---|
| Config/env | `internal/control/config.go` |
| Routes and middleware | `internal/control/server.go` |
| API DTOs/constants | `internal/control/types.go` |
| DB pool/store/auth/audit | `internal/control/store.go` |
| Migrations | `internal/control/migrations.go` |
| Tenant/RLS helpers | `internal/control/tenant.go`, `internal/control/tenant_store.go` |
| Policy CRUD | `internal/control/policy_store.go` |
| Snapshot build/diff | `internal/control/snapshot.go`, `internal/control/snapshot_diff.go` |
| Agent store/protocol | `internal/control/agent_store.go` |
| Events/dashboard handlers | `internal/control/events.go`, `internal/control/observability_handlers.go`, `internal/control/dashboard.go` |
| Anomaly/baseline | `internal/control/anomaly.go`, `internal/control/anomaly_handlers.go` |
| Feeds/reputation | `internal/control/feed.go` |
| Alerts/Telegram | `internal/control/alert.go`, `internal/control/alert_handlers.go` |
| Metrics/Prometheus client | `internal/control/metrics.go`, `internal/control/prometheus.go` |

## Dashboard

| Concern | Source |
|---|---|
| Shell/login/polling | `web/dashboard/src/App.tsx`, `web/dashboard/src/DashboardShell.tsx` |
| Navigation | `web/dashboard/src/navigation.ts` |
| API client | `web/dashboard/src/api.ts` |
| DTOs | `web/dashboard/src/types.ts` |
| Theme/styles | `web/dashboard/src/muiTheme.ts`, `web/dashboard/src/styles.css` |
| Shared admin UI | `web/dashboard/src/adminUi.tsx`, `web/dashboard/src/components.tsx` |
| Views | `web/dashboard/src/views/*.tsx` |
| Tests | `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts` |

## Deployment And Tests

| Concern | Source |
|---|---|
| Build/test/deploy commands | `Makefile` |
| Compose topology | `docker-compose.yml` |
| Env template | `.env.example` |
| Dockerfiles | `deploy/docker/control-api.Dockerfile`, `deploy/docker/admin-dashboard.Dockerfile` |
| Prometheus | `deploy/prometheus/compose-prometheus.yml`, `deploy/prometheus/anti-ddos-recording-rules.yml` |
| Grafana dashboard | `deploy/grafana/anti-ddos-p1-dashboard.json` |
| Lab scripts | `scripts/lab/*.sh` |
| E2E script | `scripts/e2e/phase4_services_forwarding.py` |

## Existing Documentation Inputs

| Existing doc | Vai trò |
|---|---|
| `README.md` | Quickstart, safety, high-level description |
| `docs/High-Level-Design.md` | Prior HLD context |
| `docs/Low-Level-Design.md` | Prior LLD context |
| `docs/System-Architecture-Design.md` | Prior architecture |
| `docs/Control-Api.md` | Prior API reference |
| `docs/Admin-Dashboard-v2.md` | Prior dashboard spec |
| `docs/guide/*.md` | Per-page user guide |
| `.specs/project/STATE.md` | Decisions, blockers, host facts |
| `.notebook/*.md` | Investigation notes and gotchas |

## Gap Watchlist

| Gap | Current status |
|---|---|
| Production service inventory | Missing, Network/SRE dependency |
| Formal WAN/output interface assignment | Missing, do not attach production NIC |
| 10/40 Gbps benchmark | Not available |
| IPv6 datapath | Out of scope |
| Auto-enforce anomaly | Disabled by design, alert-only |
| Production secret manager integration | Only ref conventions documented in current source |
| Target SaaS RBAC implementation | Documents define target taxonomy; source anchors show where implementation must align |

## Source Alignment

Tài liệu này được tổng hợp từ repo root, bao gồm `README.md`, `docs/`, `.specs/project/STATE.md`, `.notebook/`, `bpf/`, `cmd/`, `internal/`, `web/dashboard/`, `deploy/`, `Makefile` và `docker-compose.yml`.

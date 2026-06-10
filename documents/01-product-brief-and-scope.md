# Product Brief And Scope

## Problem Statement

Các service backend public-facing có thể bị DDoS L3/L4 trước khi request tới application layer. Nếu xử lý muộn trong user space hoặc sau khi packet đã đi qua kernel networking stack, host dễ mất CPU, queue, conntrack hoặc bandwidth trước khi kịp lọc. Hệ thống cần một scrubbing gateway đặt trước backend để drop/rate-limit/redirect traffic ngay tại XDP layer, đồng thời vẫn có control plane đủ an toàn cho vận hành nhiều tenant.

## Target Users

| Persona | Jobs To Be Done | Nhu cầu chính |
|---|---|---|
| Network/SRE | Đưa service inventory, xác nhận WAN/output interface, xử lý sự cố forwarding | Cần mapping rõ giữa service, output interface, next-hop MAC, rollback |
| Security Operator | Tạo rule, whitelist, blacklist, feed, UDP port block, xem incident/event | Cần UI nhanh, audit đầy đủ, quyền mutation có kiểm soát |
| Tenant Admin | Quản lý user, service và policy trong tenant | Cần tách dữ liệu giữa tenant, không nhìn nhầm tenant khác |
| Viewer/Analyst | Quan sát dashboard, investigation, audit, snapshot | Cần read-only data an toàn và dễ truy vấn |
| Platform Admin | Quản lý tenant và bootstrap hệ thống | Cần quyền cross-tenant có kiểm soát và audit |
| Implementation Team | Clone lại hệ thống tương tự | Cần contract, schema, flow, test gate, runbook và source traceability |

## Value Proposition

- Drop/rate-limit traffic độc hại sớm ở XDP để giảm tải host.
- Chỉ cho phép traffic tới protected service đã khai báo, fail closed nếu chưa có policy.
- Tách rõ control plane và data plane bằng policy snapshot versioned, signed bằng checksum.
- Hỗ trợ vận hành tenant-scoped với RBAC, audit, Prometheus/Grafana và dashboard.
- Cho phép triển khai lab an toàn bằng Docker Compose và VETH tests trước khi đụng NIC thật.

## In Scope

- IPv4 L3/L4 packet parsing cho TCP, UDP, ICMP.
- Service allowlist theo destination IPv4, protocol, port.
- Whitelist global/service, blacklist manual/feed, UDP source-port block.
- Rate limit token bucket theo `source`, `subnet`, `service`, `source_service`.
- L2 MAC rewrite và redirect qua `BPF_MAP_TYPE_DEVMAP`.
- Agent load/attach XDP, pin maps/program/link, collect counters, consume ringbuf, sync Control API.
- Control API REST `/v1/*`, PostgreSQL migrations v1-v8, tenant RBAC, audit, snapshots.
- Admin Dashboard React/Vite với các màn hình Operation, Configuration, Threat Intelligence, Setting.
- Prometheus metrics, Grafana dashboard, security events, anomaly alert-only, Telegram alerting.
- Docker Compose lab stack cho PostgreSQL, Control API, Admin Dashboard, Prometheus, Grafana.

## Out Of Scope

- TLS termination, HTTP reverse proxy, WAF, L7/DPI.
- IPv6 enforcement trong active policy.
- Multi-node control orchestration nâng cao ngoài agent heartbeat/apply state hiện tại.
- Auto-discovery production service inventory.
- Auto-enforce anomaly mitigation.
- Production benchmarking 10/40 Gbps, vì kết quả hiện chưa có trong repo state.

## Business Constraints

- Không ghi secret thật trong config mẫu, log, audit hoặc docs.
- Không attach XDP vào NIC thật nếu chưa có phê duyệt vận hành.
- Backend service inventory và vai trò WAN/LAN/output interface phải do Network/SRE xác nhận.
- PostgreSQL và Prometheus command-line binaries có thể thiếu trên lab host, nhưng Docker Compose cung cấp runtime services.

## Success Metrics

| Mục tiêu | Cách đo |
|---|---|
| Data plane fail closed đúng | Packet không match service bị `REASON_NOT_ALLOWED_SERVICE` |
| Policy rollout an toàn | Snapshot lỗi không flip active slot; apply ack ghi `failed` kèm stage |
| Tenant isolation đúng | Non-platform user chỉ thấy dữ liệu tenant active; RLS bật trên bảng tenant-scoped |
| Dashboard vận hành được | Viewer read-only, Operator/Admin mutation đúng quyền, platform-only Tenants ẩn với non-platform |
| Rebuild khả thi | Team mới dựng được BPF, Agent, Control API, Dashboard, DB schema và test gates từ tài liệu |

## Source Alignment

- Business context: `README.md`, `docs/High-Level-Design.md`
- Scope/decision: `.specs/project/STATE.md`
- Roles/RBAC: `internal/control/types.go`, `internal/control/tenant.go`, `internal/control/tenant_store.go`
- Dashboard personas: `docs/Admin-Dashboard-v2.md`, `web/dashboard/src/navigation.ts`

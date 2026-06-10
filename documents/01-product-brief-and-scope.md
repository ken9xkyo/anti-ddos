# Product Brief And Scope

## Problem Statement

Các service backend public-facing có thể bị DDoS L3/L4 trước khi request tới application layer. Nếu xử lý muộn trong user space hoặc sau khi packet đã đi qua kernel networking stack, host dễ mất CPU, queue, conntrack hoặc bandwidth trước khi kịp lọc. Hệ thống cần một scrubbing gateway đặt trước backend để drop/rate-limit/redirect traffic ngay tại XDP layer.

Target product là multitenant SaaS: một platform vận hành nhiều Customer Account. Mỗi Customer Account là một `Tenant` độc lập về users, protected services, policies, agents, snapshots, audit và observability. Khách hàng cần tự vận hành anti-DDoS trong tenant của họ, còn platform team cần provision, support và audit mà không phá customer boundary.

## Target Users

| Persona | Jobs To Be Done | Nhu cầu chính |
|---|---|---|
| `platform_owner` | Sở hữu vận hành SaaS và policy bảo mật platform | Cần quyền quản trị cao nhất, break-glass policy, audit và tenant lifecycle control |
| `platform_admin` | Provision/suspend tenant, bootstrap control plane, hỗ trợ vận hành platform | Cần console platform có audit và không nhầm với tenant membership |
| `platform_support` | Hỗ trợ khách hàng theo ticket | Cần access time-bound vào tenant cụ thể, reason-required và audited |
| `platform_auditor` | Review platform operations và support access | Cần read-only platform audit, export và traceability |
| `tenant_owner` | Sở hữu Customer Account | Cần quản lý membership, settings, offboarding request và quyền cuối trong tenant |
| `tenant_admin` | Quản lý vận hành tenant thường ngày | Cần quản lý members, services, policies, integrations, alerts và audit tenant |
| `security_operator` | Điều hành security controls | Cần tạo/sửa rules, whitelist, blacklist, UDP blocks, feeds, snapshots và incidents |
| `network_operator` | Điều hành network/forwarding | Cần quản lý protected services, forwarding metadata, agents và interface state |
| `viewer` | Quan sát trạng thái vận hành | Cần read-only dashboard an toàn |
| `auditor` | Kiểm tra audit/compliance tenant | Cần read-only audit, change history và alert history |
| Network/SRE | Xác nhận service inventory và interface roles | Cần mapping rõ giữa service, output interface, next-hop MAC và rollback |
| Implementation Team | Clone lại hệ thống tương tự | Cần contract, schema, flow, test gate, runbook và source traceability |

## Value Proposition

- Drop/rate-limit traffic độc hại sớm ở XDP để giảm tải host.
- Chỉ cho phép traffic tới protected service đã khai báo, fail closed nếu chưa có policy.
- Tách rõ control plane và data plane bằng policy snapshot versioned, signed bằng checksum.
- Cho phép nhiều Customer Account dùng chung platform nhưng không nhìn hoặc thao tác dữ liệu của nhau.
- Áp dụng least privilege giữa `security_operator` và `network_operator`.
- Cho phép platform support can thiệp theo ticket/time window mà vẫn có audit đầy đủ.
- Cho phép triển khai lab an toàn bằng Docker Compose và VETH tests trước khi đụng NIC thật.

## In Scope

- IPv4 L3/L4 packet parsing cho TCP, UDP, ICMP.
- Service allowlist theo destination IPv4, protocol, port.
- Whitelist global/service, blacklist manual/feed, UDP source-port block.
- Rate limit token bucket theo `source`, `subnet`, `service`, `source_service`.
- L2 MAC rewrite và redirect qua `BPF_MAP_TYPE_DEVMAP`.
- Agent load/attach XDP, pin maps/program/link, collect counters, consume ringbuf, sync Control API.
- Control API REST `/v1/*`, PostgreSQL migrations v1-v8-equivalent, tenant-scoped data model, audit và snapshots.
- SaaS RBAC target với platform roles và tenant roles canonical.
- Tenant lifecycle: `provisioned`, `active`, `suspended`, `offboarding`, `revoked`.
- Membership lifecycle: `invited`, `active`, `suspended`, `revoked`.
- Admin Dashboard React/Vite với tenant switcher, tenant member management, platform tenant console và role-aware actions.
- Prometheus metrics, Grafana dashboard, security events, anomaly alert-only, Telegram alerting.
- Docker Compose lab stack cho PostgreSQL, Control API, Admin Dashboard, Prometheus, Grafana.

## Out Of Scope

- TLS termination, HTTP reverse proxy, WAF, L7/DPI.
- IPv6 enforcement trong active policy.
- Multi-node control orchestration nâng cao ngoài agent heartbeat/apply state hiện tại.
- Auto-discovery production service inventory.
- Auto-enforce anomaly mitigation.
- Billing, subscription plans, commercial entitlements, feature packages và quota thương mại.
- Production benchmarking 10/40 Gbps, vì kết quả hiện chưa có trong repo state.

## Business Constraints

- Không ghi secret thật trong config mẫu, log, audit hoặc docs.
- Không attach XDP vào NIC thật nếu chưa có phê duyệt vận hành.
- Backend service inventory và vai trò WAN/LAN/output interface phải do Network/SRE xác nhận.
- Tenant là customer boundary bắt buộc; mọi operational resource mặc định tenant-scoped.
- Platform support/break-glass phải có reason, TTL và audit.
- PostgreSQL và Prometheus command-line binaries có thể thiếu trên lab host, nhưng Docker Compose cung cấp runtime services.

## Success Metrics

| Mục tiêu | Cách đo |
|---|---|
| Data plane fail closed đúng | Packet không match service bị `REASON_NOT_ALLOWED_SERVICE` |
| Policy rollout an toàn | Snapshot lỗi không flip active slot; apply ack ghi `failed` kèm stage |
| Tenant isolation đúng | User không thấy dữ liệu ngoài active Customer Account; RLS hoặc isolation guard bật trên bảng tenant-scoped |
| Role split đúng | `security_operator` không đổi forwarding, `network_operator` không đổi enforcement rules, `viewer`/`auditor` read-only |
| Platform support đúng | Mọi support access có tenant, reason, TTL và audit event |
| Dashboard SaaS vận hành được | Tenant switcher, member management, platform tenant console và action visibility đúng role |
| Rebuild khả thi | Team mới dựng được BPF, Agent, Control API, Dashboard, DB schema và test gates từ tài liệu |

## Source Alignment

- Business context: `README.md`, `docs/High-Level-Design.md`
- Scope/decision: `.specs/project/STATE.md`
- Current RBAC/source anchors: `internal/control/types.go`, `internal/control/tenant.go`, `internal/control/tenant_store.go`
- Dashboard personas/navigation: `docs/Admin-Dashboard-v2.md`, `web/dashboard/src/navigation.ts`

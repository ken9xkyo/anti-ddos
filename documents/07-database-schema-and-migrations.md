# Database Schema And Migrations

Sơ đồ ERD: [diagrams/database-erd.mmd](diagrams/database-erd.mmd)

## Mục Tiêu

PostgreSQL là source of truth của control plane. Target schema dùng shared database/shared schema với tenant isolation theo `tenant_id` trên mọi operational resource. PostgreSQL Row Level Security hoặc isolation guard tương đương là lớp defense-in-depth bên cạnh auth/RBAC ở application layer.

Trong target SaaS, `Tenant` là Customer Account. `TenantMembership` là nguồn effective tenant role. Platform access tách khỏi membership và không được dùng để bỏ qua audit.

## Target Data Model Concepts

| Concept | Mô tả target |
|---|---|
| `Tenant` | Customer Account; có lifecycle `provisioned`, `active`, `suspended`, `offboarding`, `revoked` |
| `TenantMembership` | Quan hệ user-tenant; có role tenant canonical và lifecycle `invited`, `active`, `suspended`, `revoked` |
| `PlatformUser` | User có platform role như `platform_owner`, `platform_admin`, `platform_support`, `platform_auditor`; tách khỏi tenant membership |
| `Session` | Token/session của user; luôn có `active_tenant_id` khi gọi tenant-scoped endpoint |
| `AuditEvent` | Bản ghi mutation/access/export; có actor, tenant target nếu có, platform context nếu có, reason và before/after redacted JSON |
| `SupportGrant` | Target concept cho platform support/break-glass access; tenant-specific, actor-specific, reason-required, TTL-bound |

All operational resources are tenant-scoped by default: agents, interfaces, services, forwarding policies, rules, whitelist, blacklist, UDP blocks, feeds, snapshots, apply status, events, alerts, Telegram config, baselines, anomalies and tenant audit.

## Migration Inventory

| Version | Name | Nội dung chính |
|---:|---|---|
| 1 | `phase05_control_core` | Users, sessions, agents, services, forwarding policies, rules, whitelist, manual blacklist, feed sources, policy snapshots, apply status, audit |
| 2 | `phase06_observability_events` | `security_events` và indexes |
| 3 | `phase07_baseline_anomaly_auto_enforce` | Rule dimension, `baseline_profiles`, `anomaly_evaluations` |
| 4 | `phase08_threat_feed_sync` | Feed status columns, `feed_runs`, `reputation_entries`, `feed_conflicts` |
| 5 | `phase09_telegram_isp_runbook` | `telegram_configs`, `alert_policies`, `alerts`, `alert_deliveries` |
| 6 | `udp_source_port_blocks` | UDP source port block table và disabled seed entries |
| 7 | `multi_tenant_rbac` | Tenants, memberships, `tenant_id` columns, indexes, RLS policies |
| 8 | `operator_single_tenant` | Current-source compatibility guard; target SaaS rebuild nên thay bằng membership lifecycle và support-grant checks |

## Core Tables

| Domain | Tables |
|---|---|
| Identity/RBAC | `app_users`, `user_sessions`, `tenants`, `tenant_memberships`; target adds/normalizes platform role and support grant concepts |
| Agent/Fleet | `agents`, `agent_interfaces`, `policy_apply_status` |
| Protected services | `backend_services`, `forwarding_policies` |
| Policy objects | `rules`, `whitelist_entries`, `manual_blacklist_entries`, `udp_source_port_blocks` |
| Threat intelligence | `feed_sources`, `feed_runs`, `reputation_entries`, `feed_conflicts` |
| Snapshots | `policy_snapshots` |
| Observability | `security_events`, `baseline_profiles`, `anomaly_evaluations` |
| Alerting | `telegram_configs`, `alert_policies`, `alerts`, `alert_deliveries` |
| Audit | `audit_events`, `audit_events_default` partition |
| Migration tracking | `schema_migrations` |

## Tenant Isolation

Migration v7-equivalent target behavior:

- Tạo tenant default/lab nếu cần bootstrap, nhưng production tenant phải được provision như Customer Account.
- Tách platform roles khỏi tenant memberships.
- Thêm `active_tenant_id` cho sessions.
- Tạo `tenant_memberships` với role/status canonical.
- Thêm `tenant_id` vào mọi bảng nghiệp vụ.
- Backfill dữ liệu legacy vào tenant bootstrap khi migrate từ single-tenant.
- Set `tenant_id NOT NULL`.
- Chuyển unique constraint sang tenant-scoped với index như `(tenant_id, hostname)`, `(tenant_id, name)`, `(tenant_id, port)`.
- Enable và force RLS trên bảng tenant-scoped.
- Policy RLS cho phép row khi `tenant_id = current_setting('anti_ddos.tenant_id')::uuid` hoặc platform workflow đã set platform context hợp lệ.

Application phải dùng:

- Tenant transaction cho thao tác tenant-scoped.
- Platform transaction cho tenant lifecycle, platform audit và support-grant workflows.
- Agent tenant context khi register, heartbeat, snapshot, apply ack và event ingest.

## Important Keys And Constraints

| Table | Constraint đáng chú ý |
|---|---|
| `policy_snapshots` | Primary key `(tenant_id, version)` sau migration v7-equivalent |
| `agents` | Unique `(tenant_id, hostname)` |
| `backend_services` | Unique `(tenant_id, name)` |
| `feed_sources` | Unique `(tenant_id, name)` |
| `udp_source_port_blocks` | Unique `(tenant_id, port)` |
| `forwarding_policies` | Unique enabled `(service_id, match_protocol, match_dst_port)` |
| `tenant_memberships` | Unique `(tenant_id, user_id)`; only one active role per user per tenant |
| `audit_events` | Must include tenant target for tenant-scoped events and platform context for platform events |
| Target `support_grants` | Unique active grant by `(tenant_id, platform_user_id, reason_ref)` with expiry |

## Rebuild Notes

- Migration runner phải tạo `schema_migrations` và apply migrations tăng dần, unique version.
- `RunMigrations` chạy trong transaction từng migration.
- Sau migrate, `control-api migrate/serve` gọi cleanup để giữ anomaly alert-only semantics.
- Audit events partitioned by `created_at`; default partition phải tồn tại.
- Dữ liệu legacy trước multi-tenant phải được backfill vào tenant bootstrap.
- Target SaaS rebuild nên model lifecycle/status rõ ràng cho tenant và membership thay vì chỉ dùng boolean access.
- Không thêm billing, commercial entitlement, subscription plan hoặc quota thương mại vào RBAC schema pass này.

## Source Alignment

- SQL migrations: `internal/control/migrations.go`
- Migration tests: `internal/control/migrations_test.go`
- Store and transactions: `internal/control/store.go`, `internal/control/tenant.go`
- Tenant store/source anchors: `internal/control/tenant_store.go`
- RBAC tests/source anchors: `internal/control/rbac_test.go`

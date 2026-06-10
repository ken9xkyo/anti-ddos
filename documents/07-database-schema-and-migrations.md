# Database Schema And Migrations

Sơ đồ ERD: [diagrams/database-erd.mmd](diagrams/database-erd.mmd)

## Mục Tiêu

PostgreSQL là source of truth của control plane. Schema dùng shared database/shared schema, mỗi bảng nghiệp vụ có `tenant_id` sau migration multi-tenant. PostgreSQL Row Level Security là lớp defense-in-depth bên cạnh auth/RBAC ở application layer.

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
| 8 | `operator_single_tenant` | Guard non-platform operator không có nhiều active tenant memberships |

## Core Tables

| Domain | Tables |
|---|---|
| Identity/RBAC | `app_users`, `user_sessions`, `tenants`, `tenant_memberships` |
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

Migration v7:

- Tạo tenant `default` nếu chưa có.
- Thêm `platform_role` cho `app_users`.
- Thêm `active_tenant_id` cho `user_sessions`.
- Tạo `tenant_memberships`.
- Thêm `tenant_id` vào bảng nghiệp vụ.
- Backfill dữ liệu cũ vào tenant `default`.
- Set `tenant_id NOT NULL`.
- Chuyển unique constraint sang tenant-scoped với index như `(tenant_id, hostname)`, `(tenant_id, name)`, `(tenant_id, port)`.
- Enable và force RLS trên bảng tenant-scoped.
- Policy RLS cho phép row khi `tenant_id = current_setting('anti_ddos.tenant_id')::uuid` hoặc `anti_ddos.platform=true`.

Application phải dùng:

- `beginContextTenantTx` cho thao tác tenant-scoped.
- `beginPlatformTx` cho platform admin operations.
- `contextWithTenant` khi cần ép tenant cho Agent hoặc audit.

## Important Keys And Constraints

| Table | Constraint đáng chú ý |
|---|---|
| `policy_snapshots` | Primary key `(tenant_id, version)` sau migration v7 |
| `agents` | Unique `(tenant_id, hostname)` |
| `backend_services` | Unique `(tenant_id, name)` |
| `feed_sources` | Unique `(tenant_id, name)` |
| `udp_source_port_blocks` | Unique `(tenant_id, port)` |
| `forwarding_policies` | Unique enabled `(service_id, match_protocol, match_dst_port)` |
| `tenant_memberships` | Unique `(tenant_id, user_id)` |

## Rebuild Notes

- Migration runner phải tạo `schema_migrations` và apply migrations tăng dần, unique version.
- `RunMigrations` chạy trong transaction từng migration.
- Sau migrate, `control-api migrate/serve` gọi `DisableLegacyAutoEnforceRules` để giữ anomaly alert-only semantics.
- Audit events partitioned by `created_at`; default partition phải tồn tại.
- Dữ liệu legacy trước multi-tenant phải được backfill vào tenant `default`.

## Source Alignment

- SQL migrations: `internal/control/migrations.go`
- Migration tests: `internal/control/migrations_test.go`
- Store and transactions: `internal/control/store.go`, `internal/control/tenant.go`
- Tenant store: `internal/control/tenant_store.go`
- RBAC tests: `internal/control/rbac_test.go`

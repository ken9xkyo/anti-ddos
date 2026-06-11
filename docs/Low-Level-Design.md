# Low-Level Design

Trang thai: cap nhat theo RBAC `admin`/`user` khong con tenant ngay 2026-06-11.

## Backend modules

- `internal/control/store.go`: auth/session, actor construction, account lifecycle.
- `internal/control/owner.go`: owner context, owner transactions, role guards.
- `internal/control/admin_view.go`: `POST /v1/admin/view-user` read-only session context.
- `internal/control/policy_store.go`: owner-scoped services, rules, whitelist, manual blacklist, UDP ports.
- `internal/control/snapshot.go`: owner-scoped snapshot build/diff/rollback.
- `internal/control/agent_store.go`: agent register with owner headers and owner resolution by `agent_id`.
- `internal/control/migrations.go`: destructive tenant removal and `owner_user_id` migration.

## Authorization rules

- `RoleAdmin = "admin"`, `RoleUser = "user"`.
- `user` may read/mutate config only when `owner_user_id = actor.ID`.
- `admin` may mutate accounts only.
- `admin` view-user may read target user's config but `requireConfigMutation` returns `403`.
- `/v1/tenants*` routes are retired.

## Schema rules

Operational tables use `owner_user_id` foreign key to `app_users`.

Removed from current schema after migration:

- `tenants`
- `tenant_memberships`
- `user_sessions.active_tenant_id`
- `app_users.platform_role`
- tenant RLS policy based on `anti_ddos.tenant_id`

Operational data from the old tenant model is truncated by migration instead of migrated.

## Agent ownership

Agent register requires one owner identity header:

- `X-Owner-User-ID`
- `X-Owner-Username`

Heartbeat, snapshot, apply and event ingestion resolve owner from stored `agent_id`.

## Frontend rules

- `canMutate = user.role === "user" && !user.read_only`.
- `Accounts` is admin-only.
- `View config` calls `/v1/admin/view-user` and reloads dashboard read-only.
- `Tenants` and `Reputation` are not rendered.

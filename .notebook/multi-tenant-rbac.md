# Multi-Tenant RBAC

Date: 2026-06-05
Tags: auth, tenant, rls, agents, dashboard
Type: flow

## Summary

Control API uses global `app_users` identities plus per-tenant `tenant_memberships`. `app_users.role` remains a legacy source/migration field; effective authorization comes from the active tenant membership. `platform_admin` is stored in `app_users.platform_role` and can manage tenants/switch into tenants.

Current RBAC contract:

- `viewer`: tenant-scoped read-only.
- `operator`: operational policy/config/snapshot mutations, full tenant Telegram config, non-secret feed operations, and viewer lifecycle management in its single active tenant only. Non-platform operator identities cannot have any other active tenant membership.
- `admin`: full tenant member management plus feed credential access in the active tenant.
- `platform_admin`: tenant CRUD plus effective `admin` when switched into any active tenant.

## Pointers

- Tenant/RLS transaction helpers: `internal/control/tenant.go`
- Tenant CRUD/switch/access resolution: `internal/control/tenant_store.go`
- Auth/session active tenant resolution: `internal/control/store.go:BootstrapAdmin`, `AuthenticateForTenant`, `AuthenticateToken`
- Viewer lifecycle permission helpers: `internal/control/tenant.go`
- Admin console user lifecycle methods: `internal/control/store.go:CreateUser`, `internal/control/admin_console.go`
- Shared-schema migration and RLS policies: `internal/control/migrations.go` migrations `multi_tenant_rbac` and `operator_single_tenant`
- Agent tenant binding: `internal/control/server.go:handleAgentRegister`, `internal/control/agent_store.go`
- Dashboard tenant switcher and tenant management: `web/dashboard/src/DashboardShell.tsx`, `web/dashboard/src/views/TenantsView.tsx`, `web/dashboard/src/App.tsx`

## Gotchas

- RLS tables require a transaction with `anti_ddos.tenant_id` set. Background jobs either iterate active tenants or resolve tenant from resource parent before mutating tenant data.
- Snapshot versions are per tenant via `policy_snapshots(tenant_id, version)`. Any system mutation that rebuilds snapshots must run in a tenant tx, not a platform tx.
- Agent registration requires `X-Tenant-ID` or `X-Tenant-Slug`; subsequent agent subroutes resolve tenant from `agent_id`.
- `GET /v1/tenants` remains active-tenant access for session/topbar. Platform admin tenant management uses `include_revoked=true` to list all tenant statuses without enabling switch into revoked tenants.
- `operator_single_tenant` fails fast if existing data has a non-platform active operator with multiple active memberships, then installs a trigger on `tenant_memberships` to block direct SQL violations.
- Feed credentials are Admin-only. Operator/Viewer feed responses omit `credential_ref`; Admin responses mask it as `***`.

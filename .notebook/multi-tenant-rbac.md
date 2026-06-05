# Multi-Tenant RBAC

Date: 2026-06-04
Tags: auth, tenant, rls, agents, dashboard
Type: flow

## Summary

Control API uses global `app_users` identities plus per-tenant `tenant_memberships`. `app_users.role` remains a legacy source/migration field; effective authorization comes from the active tenant membership. `platform_admin` is stored in `app_users.platform_role` and can manage tenants/switch into tenants.

## Pointers

- Tenant/RLS transaction helpers: `internal/control/tenant.go`
- Tenant CRUD/switch/access resolution: `internal/control/tenant_store.go`
- Auth/session active tenant resolution: `internal/control/store.go:BootstrapAdmin`, `AuthenticateForTenant`, `AuthenticateToken`
- Shared-schema migration and RLS policies: `internal/control/migrations.go` migration `multi_tenant_rbac`
- Agent tenant binding: `internal/control/server.go:handleAgentRegister`, `internal/control/agent_store.go`
- Dashboard tenant switcher: `web/dashboard/src/DashboardShell.tsx`, `web/dashboard/src/App.tsx`

## Gotchas

- RLS tables require a transaction with `anti_ddos.tenant_id` set. Background jobs either iterate active tenants or resolve tenant from resource parent before mutating tenant data.
- Snapshot versions are per tenant via `policy_snapshots(tenant_id, version)`. Any system mutation that rebuilds snapshots must run in a tenant tx, not a platform tx.
- Agent registration requires `X-Tenant-ID` or `X-Tenant-Slug`; subsequent agent subroutes resolve tenant from `agent_id`.

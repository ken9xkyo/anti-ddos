# Low-Level Design

## Backend Modules

- `internal/control/server.go`: HTTP route table, auth middleware, request decoding and endpoint handlers.
- `internal/control/store.go`: users, sessions, bootstrap, audit helpers and shared store dependencies.
- `internal/control/owner.go`: owner context, owner-scoped transactions and role guards.
- `internal/control/admin_view.go`: `POST /v1/admin/view-user` read-only admin context.
- `internal/control/policy_store.go`: services, forwarding policies, whitelist, rules, manual blacklist, UDP source-port blocks and validation.
- `internal/control/snapshot.go`: owner policy snapshot build, signing, content diff, rollback and agent fetch.
- `internal/control/feed.go`: admin-only global feed source CRUD/sync, reputation rows, conflicts and snapshot rebuild for active users.
- `internal/control/alert.go`: Telegram config, alert creation/delivery, ISP escalation payloads.
- `internal/control/agent_store.go`: owner-bound agent register, heartbeat, snapshot apply and event ingest storage.
- `internal/control/migrations.go`: ordered SQL migrations and current owner-user schema.

## Authorization Rules

- `RoleAdmin = "admin"` and `RoleUser = "user"`.
- `requireAdmin` gates account lifecycle and normal admin-only operations.
- `requireGlobalFeedAdmin` requires `admin` plus a normal non-read-only session.
- `requireConfigMutation` requires `role=user` and `actorOwnerUserID(actor) == actor.ID`.
- Admin view-user sessions set `ViewingUser` and `ReadOnly`; they can read owner-scoped data but cannot mutate config.
- Agent endpoints use the configured shared token and resolve owner from register headers or stored `agent_id`.

## Schema Rules

Operational tables use `owner_user_id` and are queried with:

```sql
owner_user_id = NULLIF(current_setting('anti_ddos.owner_user_id', true), '')::uuid
```

Owner-scoped transactions set `anti_ddos.owner_user_id` at transaction start. Unscoped transactions clear it for account/global-feed management.

Global feed tables are the exception:

- `feed_sources.owner_user_id = NULL`
- `feed_runs.owner_user_id = NULL`
- `reputation_entries.owner_user_id = NULL`
- `feed_conflicts.owner_user_id` remains the owner of the conflicting whitelist entry

`policy_snapshots` and `telegram_configs` use composite primary keys with `owner_user_id`. Owner-level uniqueness is used for agents, services, UDP source-port blocks and alert policies.

## Policy Snapshot Contract

- Snapshot schema is `policy_snapshot_v1` in `internal/agent/policy_snapshot.go`.
- Feature flags include `policy_snapshot_v1`, `ipv4`, `ab_policy_maps`, `tx_devmap`, and `udp_src_port_block` when UDP source-port entries are active.
- Checksums are computed over canonical JSON excluding the mutable checksum field.
- Control verifies snapshots with `AllowUnresolvedServices=true`; the Agent resolves forwarding metadata before applying maps.
- Applying a snapshot populates inactive A/B maps, updates `tx_devmap`, then flips `runtime_config.active_slot`.

## Datapath Rules

Detailed datapath documentation: [XDP-Data-Plane.md](XDP-Data-Plane.md).

- Non-IPv4 traffic passes.
- Malformed IPv4 and fragments are dropped.
- IPv4 traffic must match a service allowlist entry before threat checks.
- Whitelist takes precedence over blacklist and UDP source-port blocks.
- UDP source-port blocks drop matching non-whitelisted UDP packets with reason `REASON_UDP_AMP_SOURCE_PORT`.
- Resolved services are MAC-rewritten and redirected through `tx_devmap`; unresolved forwarding drops fail closed.

## Frontend Rules

- `canMutate = user.role === "user" && !user.read_only`.
- `Accounts` navigation is visible to admins.
- `Reputation` navigation is visible only to normal admin sessions.
- `View config` calls `/v1/admin/view-user` and reloads dashboard data in read-only context.
- Dashboard polling loads feed endpoints only for normal admin sessions.

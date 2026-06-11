# High-Level Design

Trang thai: cap nhat theo RBAC `admin`/`user` khong con tenant ngay 2026-06-11.

Anti-DDoS Scrubbing Gateway gom Data Plane XDP/eBPF, Node Agent, Control API, PostgreSQL va Admin Dashboard. Control Plane quan ly policy snapshot va operational config theo owner user.

## Actors

| Actor | Muc tieu | Quyen |
|---|---|---|
| `user` | Van hanh config Anti-DDoS cua chinh minh | Read/mutate owner-scoped services, rules, whitelist, manual blacklist, UDP ports, snapshots, baselines/anomalies, agents/events/alerts va Telegram |
| `admin` | Quan ly tai khoan va ho tro user | User lifecycle mutations; read-only view config cua tung user qua Accounts |

## Architecture

- Data Plane: XDP/eBPF drop/rate-limit/redirect va counters/events.
- Node Agent: attach/rollback XDP, sync snapshot, forward sampled events, expose metrics.
- Control API: auth/session, owner-scoped config APIs, account admin APIs, agent APIs.
- PostgreSQL: identity/session tables va operational tables co `owner_user_id`.
- Dashboard: React/Vite ops console khong tenant switcher, khong Reputation/Threat Feed user-facing.

## Data Isolation

Operational records belong to one `owner_user_id`. Request handling sets owner context from actor:

- `user`: owner is actor ID.
- `admin` view-user: owner is target user ID and session is read-only.
- `admin` account management: unscoped account lifecycle only.

Tenant tables, tenant memberships, `active_tenant_id`, tenant RLS and `platform_role` are removed by destructive migration. Old operational data is not migrated.

## Policy Flow

1. User mutates owner config with reason.
2. Store validates role/owner and writes audit.
3. Control builds owner policy snapshot.
4. Agent registered to that owner fetches newer snapshot and applies XDP map updates.
5. Agent reports apply status and security events back to owner context.

## Safety

- Admin read-only config context cannot mutate operational config.
- Manual blacklist and UDP source-port blocks are owner-scoped and audited.
- Telegram token is write-only/masked.
- Threat Feed/Reputation is not user-facing in this scope.

# High-Level Design

Anti-DDoS Scrubbing Gateway protects L3/L4 services with an XDP/eBPF data plane on a scrubbing host. The management stack provides a Control API, PostgreSQL state, an Admin Dashboard, Prometheus/Grafana observability and a host Node Agent that applies signed policy snapshots.

The current system is IPv4-focused, owner-scoped by `owner_user_id`, and exposes two public user roles: `admin` and `user`. It does not terminate TLS, proxy HTTP, inspect L7 payloads or replace a WAF.

## Actors

| Actor | Goal | Permissions |
|---|---|---|
| `user` | Operate Anti-DDoS configuration for their own account | Read/mutate owner-scoped services, rules, whitelist, manual blacklist, UDP ports, snapshots, agents/events/alerts and Telegram config |
| `admin` | Manage accounts and global threat feeds; assist users | Mutate account lifecycle, manage global feed sources/runs/conflicts, and open read-only dashboard context for a user |
| Node Agent | Apply dataplane policy for one owner account | Register with owner identity, fetch snapshots, apply eBPF maps, report heartbeat/apply status/events |

## Architecture

- Data Plane: `xdp_entry` parses Ethernet/IPv4/L4 traffic, applies service allowlist, whitelist, blacklist, UDP source-port blocks and rule decisions, then counts and samples events.
- Forwarding Plane: valid service traffic is L2-rewritten and redirected through `tx_devmap`; unresolved forwarding metadata fails closed.
- Node Plane: the Go Agent attaches XDP, maintains pinned maps, resolves forwarding metadata, persists last-valid snapshots, exposes `/metrics` and forwards sampled events.
- Control Plane: Go HTTP API handles auth/session, owner isolation, account admin, policy CRUD, snapshot build/diff/rollback, global feeds, alerts and agent APIs.
- Management Plane: React/Vite dashboard, Prometheus and Grafana provide operations UI, polling views, metrics and investigation workflows.

## Data Isolation

Operational records are keyed by `owner_user_id`.

- A `user` request uses the actor's own user ID as owner context.
- An `admin` normal session is unscoped for account/global-feed administration.
- An `admin` view-user session sets owner context to the target user and marks the session read-only.

Current sessions, API payloads and dashboard navigation use owner-user context only.

## Policy Flow

1. A user mutates owner-scoped config with an audit reason.
2. Store guards validate role, owner context and input.
3. Control rebuilds a signed `PolicySnapshot` for that owner when effective content changes.
4. An owner-bound Agent reports heartbeat and desired policy version.
5. The Agent fetches a newer snapshot, verifies checksum/object compatibility, resolves forwarding metadata and fills the inactive A/B map slot.
6. The Agent flips `runtime_config.active_slot`, persists the last-valid snapshot and reports apply status.

## Safety

- Operational mutations require `role=user` in the user's own owner context.
- Admin view-user sessions can read target config but config mutations return `403`.
- Global active reputation from admin-managed feeds is unioned into every active user's snapshot; feed-origin blacklist rows are read-only in user views.
- Telegram bot tokens and feed credentials are write-only/masked in API responses and audit payloads.
- Compose starts the management/control stack only. Host Agent execution and XDP attachment require explicit interface selection.

# System Architecture Design

## Context

Anti-DDoS Scrubbing Gateway protects backend services by enforcing L3/L4 policy at XDP on a scrubbing host. Users manage policy through the Admin Dashboard and Control API. A host Node Agent owns XDP lifecycle and applies policy snapshots to eBPF maps.

## Components

| Component | Tech | Responsibility |
|---|---|---|
| Admin Dashboard | React, Vite, Nginx | Operations UI for account management, user-owned config, incidents, events, snapshots and feed management |
| Control API | Go HTTP JSON API | Auth, RBAC, owner isolation, policy CRUD, snapshots, agent API, alerts, metrics |
| PostgreSQL | PostgreSQL | Users, sessions, owner-scoped operational data, snapshots, events, alerts and audit |
| Node Agent | Go host process | Attach XDP, register with owner identity, sync/apply snapshots, resolve forwarding metadata, expose metrics |
| XDP Data Plane | eBPF maps/programs | Parse packets, enforce policy, emit counters/events and redirect clean traffic |
| Prometheus/Grafana | Compose services | Scrape metrics and render operations dashboards |

## RBAC And Ownership

- `user`: reads and mutates operational config where `owner_user_id` is the actor ID.
- `admin`: manages accounts and global feeds.
- `admin` view-user session: reads target user config with `read_only=true`; config mutation guards return `403`.
- Agent registration requires `X-Owner-User-ID` or `X-Owner-Username`; later heartbeat/snapshot/apply/events resolve owner from stored `agent_id`.

Current sessions, API payloads and dashboard navigation are owner-user based.

## Data Model

Core identity/session:

- `app_users`: `role` is `admin` or `user`; `status` is `active` or `revoked`.
- `user_sessions`: bearer/cookie sessions with optional `view_owner_user_id` for admin read-only context.

Owner-scoped operational tables include agents, interfaces, services, forwarding policies, rules, whitelist, manual blacklist, UDP source-port blocks, policy snapshots, apply status, security events, Telegram config, alerts, alert deliveries and audit events.

Global feed tables use `owner_user_id = NULL` for `feed_sources`, `feed_runs` and `reputation_entries`. `feed_conflicts.owner_user_id` points at the user whose whitelist conflicts with a global reputation entry.

## Runtime Flow

1. User logs in with `username` and `password`.
2. Control API builds actor and owner context from the active session.
3. User changes policy config; Control writes audit and rebuilds snapshot for the owner.
4. Agent registered for that owner polls heartbeat, fetches newer snapshot and applies it.
5. XDP enforces the active map slot and records counters/events.
6. Dashboard polls owner-scoped read APIs plus Prometheus-backed overview data.

## API Boundaries

- User/session API: `/v1/auth/*`, `/v1/me`, `/v1/users*`, `/v1/admin/view-user`.
- Policy API: `/v1/services*`, `/v1/forwarding-policies`, `/v1/whitelist*`, `/v1/rules*`, `/v1/blacklist*`, `/v1/udp-source-port-blocks*`.
- Global feed API: `/v1/feed-sources*`, `/v1/feed-runs`, `/v1/feed-conflicts`.
- Observability/API views: `/v1/dashboard/*`, `/v1/security-events*`, `/v1/audit`, `/v1/alerts*`, `/v1/telegram/*`.
- Agent API: `/v1/agents/register`, `/v1/agents/{id}/heartbeat`, `/v1/agents/{id}/snapshot`, `/v1/agents/{id}/apply`, `/v1/agents/{id}/events`.

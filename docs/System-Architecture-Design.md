# System Architecture Design

Trang thai: cap nhat theo RBAC `admin`/`user` khong con tenant ngay 2026-06-11.

## Context

Anti-DDoS Scrubbing Gateway bao ve L3/L4 services bang XDP/eBPF tren host scrubbing. Control Plane va Dashboard quan ly config owner-scoped; Node Agent sync snapshot va apply vao eBPF maps.

## Components

| Component | Tech | Responsibility |
|---|---|---|
| Admin Dashboard | React/Vite | Ops UI cho user config va admin account management |
| Control API | Go HTTP | Auth, RBAC, owner isolation, policy APIs, agent APIs |
| PostgreSQL | PostgreSQL | Identity/session, owner-scoped operational data, snapshots, audit |
| Node Agent | Go | Register owner agent, sync/apply snapshots, forward events |
| XDP Data Plane | eBPF | Packet filtering, counters, sampled events, redirect |
| Prometheus/Grafana | Observability | Metrics and dashboards |

## RBAC

- `user`: owns and mutates operational config.
- `admin`: manages accounts and can view a user's config read-only.

No tenant switcher, tenant memberships, `platform_role`, `operator`, `viewer`, `X-Tenant-*` headers, or tenant RLS are part of the current architecture.

## Data model

Core identity/session:

- `app_users`
- `user_sessions` with optional `view_owner_user_id`

Operational tables use `owner_user_id`, including agents, services, forwarding policies, rules, whitelist, manual blacklist, UDP ports, snapshots, apply status, events, baselines, anomalies, Telegram config, alerts and audit.

## Runtime flow

1. User logs in.
2. Control API sets owner context from actor or admin view-user session.
3. User mutates owner config with reason.
4. Snapshot is rebuilt for that owner.
5. Agent registered to the owner fetches and applies snapshot.
6. Agent reports apply status/events; dashboard reads owner-scoped data.

## Retired surfaces

- `/v1/tenants*`
- Tenant switcher and Tenants page
- `operator`/`viewer` role model

Threat Feed/Reputation is restored as admin-only global feed management and is not tenant/user-owned.

# Control Plane API

## Mục Tiêu

Control API là HTTP boundary chính của hệ thống. Nó phục vụ Dashboard, Agent, tenant users, platform users và automation. API quản lý auth/session, tenant/RBAC, policy objects, snapshots, observability, alerts và Agent protocol. Source of truth là PostgreSQL.

Target API mô tả một multitenant SaaS application: `Tenant` là Customer Account, `TenantMembership` là nguồn effective tenant role, platform access tách khỏi tenant membership và mọi tenant-scoped resource phải được truy vấn trong tenant context.

## Entrypoint And Runtime

`cmd/control-api/main.go` hỗ trợ:

| Command | Hành vi |
|---|---|
| `control-api serve` | Validate DB config, open pool, run migrations, disable legacy auto-enforce rules, start schedulers, serve HTTP |
| `control-api migrate` | Run migrations và cleanup legacy auto-enforce rules |
| `control-api print-migrations` | In SQL migrations text |

Default listen addr là `127.0.0.1:8080`.

## Environment Contract

| Env | Default | Mục đích |
|---|---|---|
| `ANTI_DDOS_CONTROL_ADDR` | `127.0.0.1:8080` | HTTP bind address |
| `ANTI_DDOS_DB_DSN` | empty | PostgreSQL DSN, required khi serve/migrate |
| `ANTI_DDOS_SESSION_TTL` | `12h` | Session TTL |
| `ANTI_DDOS_XDP_OBJECT` | `build/bpf/xdp_data_plane.bpf.o` | Object checksum khi build snapshot |
| `ANTI_DDOS_AGENT_SHARED_TOKEN` | empty | Bearer token cho Agent API |
| `ANTI_DDOS_PROMETHEUS_URL` | empty | Prometheus base URL |
| `ANTI_DDOS_AGENT_STALE_AFTER` | `30s` | Agent stale threshold |
| `ANTI_DDOS_EVENT_SAMPLE_DENOM` | `1` | Default sample rate metadata cho event ingest |
| `ANTI_DDOS_TELEGRAM_API_URL` | `https://api.telegram.org` | Telegram API base |

## Target SaaS API Semantics

- Auth returns `active_tenant`, `memberships[]`, `effective_role` for active tenant and platform role metadata if applicable.
- Session must have an active tenant for tenant-scoped endpoints.
- `Tenant` represents a Customer Account, not an internal namespace.
- Tenant management is platform-only: `platform_owner` and `platform_admin` provision/update/suspend; revoke requires `platform_owner`.
- Tenant membership management is controlled by `tenant_owner` and `tenant_admin` inside the tenant.
- Operational policy changes require role-specific permissions: security resources require `security_operator`, `tenant_admin` or `tenant_owner`; network resources require `network_operator`, `tenant_admin` or `tenant_owner`.
- Platform support access must be time-bound, reason-required, tenant-specific and audited.
- Audit endpoints expose tenant audit to `auditor`, `tenant_admin`, `tenant_owner` and platform audit to `platform_auditor`, `platform_admin`, `platform_owner`.
- Agent registration is always tenant-bound; later Agent calls resolve tenant from registered agent identity.
- Tenant-scoped resources are never queried outside tenant context. Platform transactions are reserved for tenant lifecycle, platform audit and explicit support workflows.

## Auth And Common Behavior

- Dashboard/user API dùng Bearer token hoặc cookie token qua `bearerTokenOrCookie`.
- Agent API dùng Bearer token khớp `ANTI_DDOS_AGENT_SHARED_TOKEN`.
- Tenant context được lấy từ session active tenant với user API, hoặc từ tenant identifier khi Agent register.
- Mutating endpoints nhận `reason` trong body hoặc `X-Audit-Reason`; support/break-glass mutation bắt buộc có reason/ticket.
- JSON errors trả `{ "error": "..." }`.

## Endpoint Catalog

| Endpoint | Methods | Consumer | Target authorization semantics |
|---|---|---|---|
| `/healthz` | GET | Health check | Public/internal health, no tenant data |
| `/metrics` | GET | Prometheus | Platform/ops network policy; no tenant secret |
| `/v1/auth/login` | POST | Dashboard | Returns active tenant, memberships and effective role |
| `/v1/auth/logout` | POST | Dashboard | Revoke token hiện tại |
| `/v1/me` | GET intended | Dashboard | Actor, platform roles, active tenant, memberships |
| `/v1/me/password` | POST | Dashboard | Current user only |
| `/v1/tenants` | GET, POST | Dashboard/platform | Platform console; POST by `platform_owner`/`platform_admin` |
| `/v1/tenants/{id}` | PATCH | Dashboard/platform | Platform tenant lifecycle/update; revoke by `platform_owner` |
| `/v1/tenants/switch` | POST | Dashboard | Switch to tenant with active membership or active support grant |
| `/v1/users` | GET, POST | Dashboard | Tenant member/user management by `tenant_owner`/`tenant_admin` |
| `/v1/users/{id}` | PATCH, DELETE | Dashboard | Tenant membership update/revoke by `tenant_owner`/`tenant_admin`; owner safeguards required |
| `/v1/users/{id}/password-reset` | POST | Dashboard | `tenant_owner`/`tenant_admin` or platform account recovery workflow |
| `/v1/users/{id}/sessions/revoke` | POST | Dashboard | `tenant_owner`/`tenant_admin` for tenant sessions; platform roles for platform sessions |
| `/v1/services` | GET, POST | Dashboard | Read all tenant roles; mutate by `network_operator`, `tenant_admin`, `tenant_owner` |
| `/v1/services/{id}` | PUT, DELETE | Dashboard | Network permission required |
| `/v1/forwarding-policies` | GET, POST | Dashboard/API | Network permission required for mutation |
| `/v1/whitelist` | GET, POST | Dashboard | Security permission required for mutation |
| `/v1/whitelist/{id}` | PATCH, DELETE | Dashboard | Security permission required |
| `/v1/rules` | GET, POST | Dashboard | Security permission required for mutation |
| `/v1/rules/{id}` | PATCH, DELETE | Dashboard | Security permission required |
| `/v1/blacklist` | GET, POST | Dashboard | Security permission required for mutation |
| `/v1/blacklist/entries` | GET | Dashboard | Tenant read access |
| `/v1/blacklist/{id}` | PATCH, DELETE | Dashboard | Security permission required |
| `/v1/udp-source-port-blocks` | GET, POST | Dashboard | Security permission required for mutation |
| `/v1/udp-source-port-blocks/{id}` | PATCH, DELETE | Dashboard | Security permission required |
| `/v1/feed-sources` | GET, POST | Dashboard | Security permission; secret ref changes require `tenant_owner`/`tenant_admin` |
| `/v1/feed-sources/{id}` | GET, PATCH, DELETE | Dashboard | Security permission; credential ref redacted and audited |
| `/v1/feed-sources/{id}/sync` | POST | Dashboard | Security permission |
| `/v1/feed-runs` | GET | Dashboard | Tenant read access |
| `/v1/feed-conflicts` | GET | Dashboard | Tenant read access |
| `/v1/telegram/config` | GET, POST | Dashboard | `tenant_owner`/`tenant_admin` for secret ref config; `security_operator` may test/use if granted |
| `/v1/telegram/test` | POST | Dashboard | `tenant_owner`, `tenant_admin` or `security_operator` with integration permission |
| `/v1/alerts` | GET, POST | Dashboard/API | Read tenant roles; lifecycle mutation by `security_operator`, `tenant_admin`, `tenant_owner` |
| `/v1/alerts/{id}/deliveries` | GET | Dashboard | Tenant read access; auditor can read |
| `/v1/alerts/evaluate-isp-escalation` | POST | Dashboard | Security permission, may query Prometheus |
| `/v1/snapshots` | GET | Dashboard | Tenant read access, `include_snapshot` query |
| `/v1/snapshots/{version}` | GET | Dashboard | Tenant read access |
| `/v1/snapshots/diff` | GET | Dashboard | Tenant read access |
| `/v1/snapshots/build` | POST | Dashboard | Security permission or `tenant_admin`/`tenant_owner` |
| `/v1/snapshots/rollback` | POST | Dashboard | Security permission or `tenant_admin`/`tenant_owner`, reason required |
| `/v1/audit` | GET | Dashboard | Tenant audit for `auditor`, `tenant_admin`, `tenant_owner`; platform audit for `platform_auditor`, `platform_admin`, `platform_owner` |
| `/v1/security-events` | GET | Dashboard | Tenant read access |
| `/v1/security-events/summary` | GET | Dashboard | Tenant read access |
| `/v1/security-events/investigate` | GET | Dashboard | Tenant read access |
| `/v1/baselines` | GET, POST | Dashboard | Security permission for mutation |
| `/v1/baselines/{id}/approve` | POST | Dashboard | Security permission |
| `/v1/baselines/{id}/recalibrate` | POST | Dashboard | Security permission |
| `/v1/anomalies` | GET | Dashboard | Tenant read access |
| `/v1/anomalies/evaluate` | POST | Dashboard | Security permission; alert-only evaluation |
| `/v1/dashboard/overview` | GET | Dashboard | Tenant read access |
| `/v1/dashboard/agents` | GET | Dashboard | Tenant read access; network operator sees operational controls |
| `/v1/dashboard/services` | GET | Dashboard | Tenant read access |
| `/v1/dashboard/rules` | GET | Dashboard | Tenant read access |
| `/v1/agents/register` | POST | Agent | Shared token plus tenant identifier; creates tenant-bound agent |
| `/v1/agents/{id}/heartbeat` | POST | Agent | Resolve tenant from agent ID |
| `/v1/agents/{id}/snapshot` | GET | Agent | Resolve tenant from agent ID; 204 when no newer snapshot |
| `/v1/agents/{id}/apply` | POST | Agent | Tenant-bound apply ack |
| `/v1/agents/{id}/events` | POST | Agent | Tenant-bound security event batch |

## Scheduler Contract

| Scheduler | Interval | Behavior |
|---|---:|---|
| Anomaly evaluation | 10s | Runs `EvaluateAnomalies`, alert-only, tenant-aware |
| Rule expiry | 30s | Expires TTL rules in tenant context |
| Feed sync | 30s | Sync due feeds per tenant, credential refs redacted |

## Rebuild Notes

- Keep route names aligned with endpoint catalog for metrics cardinality.
- Keep Agent endpoints separate from user auth; Agent uses shared token and tenant resolution by register header/agent ID.
- Implement authorization as resource-specific permission checks, not one generic mutation flag.
- Do not expose old implementation role names as public API role names in a target SaaS rebuild.
- Any platform transaction touching tenant data must require reason and insert audit.

## Source Alignment

- Entrypoint/config: `cmd/control-api/main.go`, `internal/control/config.go`
- Routes/methods: `internal/control/server.go`, `internal/control/alert_handlers.go`, `internal/control/anomaly_handlers.go`, `internal/control/observability_handlers.go`
- API types/source anchors: `internal/control/types.go`
- Tenant helpers/source anchors: `internal/control/tenant.go`, `internal/control/tenant_store.go`
- Dashboard client usage: `web/dashboard/src/api.ts`

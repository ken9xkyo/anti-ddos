# Control Plane API

## Mục Tiêu

Control API là HTTP boundary chính của hệ thống. Nó phục vụ Dashboard, Agent, operators và automation. API quản lý auth/session, tenant/RBAC, policy objects, snapshots, observability, alerts và Agent protocol. Source of truth là PostgreSQL.

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

## Auth And Common Behavior

- Dashboard/user API dùng Bearer token hoặc cookie token qua `bearerTokenOrCookie`.
- Agent API dùng Bearer token khớp `ANTI_DDOS_AGENT_SHARED_TOKEN`.
- Tenant context được lấy từ session active tenant với user API, hoặc từ `X-Tenant-ID`/`X-Tenant-Slug` khi Agent register.
- Mutating endpoints thường nhận `reason` trong body hoặc `X-Audit-Reason`.
- JSON errors trả `{ "error": "..." }`.

## Endpoint Catalog

| Endpoint | Methods | Consumer | Ghi chú |
|---|---|---|---|
| `/healthz` | GET | Health check | Plain text `ok` |
| `/metrics` | GET | Prometheus | Refresh control metrics trước khi serve |
| `/v1/auth/login` | POST | Dashboard | Optional `tenant_slug`; trả token/session |
| `/v1/auth/logout` | POST | Dashboard | Revoke token hiện tại |
| `/v1/me` | GET intended | Dashboard | Handler hiện trả actor sau auth, không có method guard riêng |
| `/v1/me/password` | POST | Dashboard | Đổi password user hiện tại |
| `/v1/tenants` | GET, POST | Dashboard | POST platform_admin only |
| `/v1/tenants/{id}` | PATCH | Dashboard | platform_admin only |
| `/v1/tenants/switch` | POST | Dashboard | Đổi active tenant/session |
| `/v1/users` | GET, POST | Dashboard | Tenant-scoped users |
| `/v1/users/{id}` | PATCH, DELETE | Dashboard | Update/revoke user |
| `/v1/users/{id}/password-reset` | POST | Dashboard | Reset password |
| `/v1/users/{id}/sessions/revoke` | POST | Dashboard | Revoke sessions |
| `/v1/services` | GET, POST | Dashboard | Protected services |
| `/v1/services/{id}` | PUT, DELETE | Dashboard | Update/delete service |
| `/v1/forwarding-policies` | GET, POST | Dashboard/API | Explicit forwarding policy |
| `/v1/whitelist` | GET, POST | Dashboard | Query filters supported |
| `/v1/whitelist/{id}` | PATCH, DELETE | Dashboard | Disable via DELETE |
| `/v1/rules` | GET, POST | Dashboard | Mitigation rules |
| `/v1/rules/{id}` | PATCH, DELETE | Dashboard | Disable via DELETE |
| `/v1/blacklist` | GET, POST | Dashboard | Manual blacklist |
| `/v1/blacklist/entries` | GET | Dashboard | Combined manual/feed page |
| `/v1/blacklist/{id}` | PATCH, DELETE | Dashboard | Disable manual entry |
| `/v1/udp-source-port-blocks` | GET, POST | Dashboard | UDP reflection port controls |
| `/v1/udp-source-port-blocks/{id}` | PATCH, DELETE | Dashboard | Disable via DELETE |
| `/v1/feed-sources` | GET, POST | Dashboard | Feed config |
| `/v1/feed-sources/{id}` | GET, PATCH, DELETE | Dashboard | Credential changes require admin rules |
| `/v1/feed-sources/{id}/sync` | POST | Dashboard | Manual sync |
| `/v1/feed-runs` | GET | Dashboard | Feed run history |
| `/v1/feed-conflicts` | GET | Dashboard | Feed vs whitelist conflicts |
| `/v1/telegram/config` | GET, POST | Dashboard | Token ref masked |
| `/v1/telegram/test` | POST | Dashboard | Operator/Admin |
| `/v1/alerts` | GET, POST | Dashboard/API | Alert lifecycle |
| `/v1/alerts/{id}/deliveries` | GET | Dashboard | Delivery history |
| `/v1/alerts/evaluate-isp-escalation` | POST | Dashboard | Operator/Admin, may query Prometheus |
| `/v1/snapshots` | GET | Dashboard | `include_snapshot` query |
| `/v1/snapshots/{version}` | GET | Dashboard | Snapshot metadata/body |
| `/v1/snapshots/diff` | GET | Dashboard | `from`, `to` required |
| `/v1/snapshots/build` | POST | Dashboard | Operator/Admin |
| `/v1/snapshots/rollback` | POST | Dashboard | Operator/Admin |
| `/v1/audit` | GET | Dashboard | `limit` query |
| `/v1/security-events` | GET | Dashboard | Event query |
| `/v1/security-events/summary` | GET | Dashboard | Top sources/ports/decisions |
| `/v1/security-events/investigate` | GET | Dashboard | Target investigation |
| `/v1/baselines` | GET, POST | Dashboard | Baseline profile |
| `/v1/baselines/{id}/approve` | POST | Dashboard | Approve baseline |
| `/v1/baselines/{id}/recalibrate` | POST | Dashboard | Recalibrate |
| `/v1/anomalies` | GET | Dashboard | List evaluations |
| `/v1/anomalies/evaluate` | POST | Dashboard | Alert-only evaluation |
| `/v1/dashboard/overview` | GET | Dashboard | Aggregated landing data |
| `/v1/dashboard/agents` | GET | Dashboard | Agent list |
| `/v1/dashboard/services` | GET | Dashboard | Service list |
| `/v1/dashboard/rules` | GET | Dashboard | Rule list |
| `/v1/agents/register` | POST | Agent | Requires agent token and tenant header |
| `/v1/agents/{id}/heartbeat` | POST | Agent | Resolve tenant from agent ID |
| `/v1/agents/{id}/snapshot` | GET | Agent | 204 when no newer snapshot |
| `/v1/agents/{id}/apply` | POST | Agent | Apply ack |
| `/v1/agents/{id}/events` | POST | Agent | Security event batch |

## Scheduler Contract

| Scheduler | Interval | Behavior |
|---|---:|---|
| Anomaly evaluation | 10s | Runs `EvaluateAnomalies`, alert-only |
| Rule expiry | 30s | Expires TTL rules |
| Feed sync | 30s | Sync due feeds |

## Rebuild Notes

- Use `net/http.ServeMux` pattern with route handlers if cloning closely.
- Keep `routeName` mapping aligned with all endpoints for metrics cardinality.
- Keep Agent endpoints separate from user auth; Agent uses shared token and tenant resolution by register header/agent ID.
- Keep `requireOperator` semantics: admin/operator can mutate operational resources; viewer read-only.

## Source Alignment

- Entrypoint/config: `cmd/control-api/main.go`, `internal/control/config.go`
- Routes/methods: `internal/control/server.go`, `internal/control/alert_handlers.go`, `internal/control/anomaly_handlers.go`, `internal/control/observability_handlers.go`
- API types: `internal/control/types.go`
- Dashboard client usage: `web/dashboard/src/api.ts`

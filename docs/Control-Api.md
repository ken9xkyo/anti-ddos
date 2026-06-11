# Control API

Trang thai: tai lieu mo ta Control Plane HTTP API hien co trong working tree ngay 2026-06-11.

Control API la JSON API dung cho dashboard/admin console, agent control loop va cac workflow van hanh Anti-DDoS. Tat ca endpoint nghiep vu nam duoi `/v1`, tru `/healthz` va `/metrics`.

## 1. Conventions

- JSON request/response, `Content-Type: application/json` cho response.
- Timestamp dung RFC3339.
- JSON decoder reject unknown fields. Field sai ten se tra `400`.
- Thanh cong mac dinh tra `200`.
- Loi tra object dang:

```json
{"error":"reason is required"}
```

- Auth user dung `Authorization: Bearer <session_token>` hoac cookie `anti_ddos_session`.
- Auth agent dung `Authorization: Bearer <agent_shared_token>` neu `AgentSharedToken` duoc cau hinh. Neu token nay rong, agent endpoints khong bi chan boi shared token.
- User session khong con tenant. Operational data duoc co lap bang owner context `owner_user_id`: user thay/mutate data cua chinh minh; admin view-user chi doc data cua target user.
- Mutation reason lay tu body `reason` truoc, fallback sang header `X-Audit-Reason`.
- Nhieu store error duoc map thanh `400`; loi role co text `role required` duoc map thanh `403`.
- `POST /v1/agents/{id}/snapshot` khong ton tai; agent fetch snapshot bang `GET`.

## 2. RBAC admin/user

| Role | Mo ta |
|---|---|
| `user` | Doc va mutation config van hanh cua chinh minh: services, rules, whitelist, manual blacklist, UDP ports, snapshots, baselines/anomalies, agents/events/alerts va Telegram |
| `admin` | Quan ly account lifecycle va mo read-only config context cua tung user qua `/v1/admin/view-user` |

Mutation policy:

- Account mutations: `admin` only.
- Operational config mutations: `user` only and only for `owner_user_id = actor.ID`.
- Admin view-user context: read-only, operational mutations return `403`.
- Telegram config: `user` only for own owner context; response luon masked as `*****`.
- Threat Feed/Reputation endpoints are retired from user-facing API in this scope.

## 3. Common data enums

| Field | Values |
|---|---|
| `role` | `admin`, `user` |
| user `status` | `active`, `revoked` |
| packet/action constants | `0` pass, `1` drop, `2` rate_limit, `3` observe, `4` sample, `6` redirect |
| policy scope constants | `0` global, `1` service |
| neighbor status | `1` resolved |

## 4. Health and metrics

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/healthz` | None | `{"ok":true}` |
| GET | `/metrics` | None | Prometheus metrics when enabled; `503` JSON error when disabled |

## 5. Auth and current user

### POST `/v1/auth/login`

Public login endpoint.

Request:

```json
{
  "username": "user",
  "password": "password phrase"
}
```

Only `username` and `password` are accepted by the current session model.

Response `Session`:

```json
{
  "token": "session-token",
  "expires_at": "2026-05-29T12:00:00Z",
  "user": {
    "id": "uuid",
    "username": "user",
    "role": "user",
    "status": "active",
    "force_password_change": false,
    "created_at": "2026-05-29T12:00:00Z"
  }
}
```

Side effect: sets `anti_ddos_session` HttpOnly cookie.

### POST `/v1/auth/logout`

Authenticated by bearer or cookie if present. Revokes token when token exists.

Response:

```json
{"ok":true}
```

### GET `/v1/me`

Authenticated. Returns current `User`.

### POST `/v1/me/password`

Authenticated. Changes own password, clears `force_password_change`, revokes other active sessions.

Request `OwnPasswordInput`:

```json
{
  "reason": "rotate own password",
  "current_password": "current password phrase",
  "new_password": "new password phrase"
}
```

Password minimum length is 12 characters.

## 6. RBAC context

Tenant endpoints are retired. `/v1/tenants*` returns `404` and new sessions do not expose `active_tenant`, `tenants` or `platform_role`.

Admin read-only user config context:

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| POST | `/v1/admin/view-user` | `{"user_id":"uuid"}` | `Session` | Admin opens read-only dashboard context for target user config |

The returned `User` includes `viewing_user` and `read_only=true`.

## 7. Users

Authenticated read. `admin` has full account lifecycle mutation. `user` cannot manage accounts.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/users` | none | `User[]` | List accounts |
| POST | `/v1/users` | `{username,password,role,reason}` | `User` | Create account |
| PATCH | `/v1/users/{id}` | `UserUpdateInput` | `User` | Update role/status/force_password_change |
| DELETE | `/v1/users/{id}` | reason via header | `User` | Revoke account |
| POST | `/v1/users/{id}/password-reset` | `PasswordResetInput` | `User` | Reset password and revoke sessions |
| POST | `/v1/users/{id}/sessions/revoke` | optional `{reason}` | `User` | Revoke sessions |

`UserUpdateInput`:

```json
{
  "reason": "update access",
  "role": "user",
  "status": "active",
  "force_password_change": true
}
```

Safety:

- Backend prevents revoking/downgrading the last active admin.
- Non-admin account mutation requests return `403`.
- Admin operational config mutation in view-user context returns `403`.
- Raw password is never included in returned user or audit before/after payload.

## 8. Services

Authenticated read. `user` mutates own config; `admin` view-user context is read-only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/services` | none | `Service[]` | List protected services |
| POST | `/v1/services` | `ServiceInput` | `Service` | Create service and rebuild snapshot |
| PUT | `/v1/services/{id}` | `ServiceInput` | `Service` | Replace/update service and rebuild snapshot |
| DELETE | `/v1/services/{id}` | reason via header | `Service` | Existing service delete/disable flow |

`ServiceInput` fields:

- `reason`
- `name`, `description`
- `backend_cidr`
- `protocol`
- `allowed_ports`
- `output_interface`
- `owner`
- `criticality`
- `protection_mode`
- `enabled`
- `priority`
- `tags`
- `resolved_ifindex`
- `resolved_next_hop_mac`
- `resolved_src_mac`
- `neighbor_resolution_status`

Dashboard vNext policy: next-hop MAC is not manually configured in the dashboard. The Agent resolves/configures next-hop MAC during forwarding metadata resolution.

## 9. Forwarding policies

Authenticated read. `user` mutates own config; `admin` view-user context is read-only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/forwarding-policies` | none | `ForwardingPolicy[]` | List forwarding policies |
| POST | `/v1/forwarding-policies` | `ForwardingPolicyInput` | `ForwardingPolicy` | Create forwarding policy |

`ForwardingPolicyInput` key fields:

- `reason`
- `service_id`
- `match_protocol`
- `match_dst_port`
- `backend_target`
- `output_interface`
- `resolved_ifindex`
- `resolved_dst_mac`
- `resolved_src_mac`
- `devmap_key`
- `action`
- `priority`
- `enabled`
- `owner`

## 10. Whitelist

Authenticated read. `user` mutates own config; `admin` view-user context is read-only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/whitelist` | none | `WhitelistEntry[]` | List entries |
| POST | `/v1/whitelist` | `WhitelistInput` | `WhitelistEntry` | Create entry and rebuild snapshot |
| PATCH | `/v1/whitelist/{id}` | `WhitelistInput` | `WhitelistEntry` | Update entry and rebuild snapshot |
| DELETE | `/v1/whitelist/{id}` | reason via header | `WhitelistEntry` | Soft-disable entry and rebuild snapshot |

`WhitelistInput`:

```json
{
  "reason": "allow customer monitor",
  "cidr": "203.0.113.10/32",
  "scope": "global",
  "service_id": "",
  "label": "customer-monitor",
  "owner": "sre",
  "priority": 100,
  "expires_at": "2026-06-01T00:00:00Z",
  "enabled": true
}
```

## 11. Rules

Authenticated read. `user` mutates own config; `admin` view-user context is read-only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/rules` | none | `Rule[]` | List rules |
| POST | `/v1/rules` | `RuleInput` | `Rule` | Create rule and rebuild snapshot |
| PATCH | `/v1/rules/{id}` | `RuleInput` | `Rule` | Update rule and rebuild snapshot |
| DELETE | `/v1/rules/{id}` | reason via header | `Rule` | Soft-disable rule and rebuild snapshot |

`RuleInput` key fields:

- `reason`
- `service_id`
- `name`
- `priority`
- `match_expr`
- `action`
- `mode`
- `threshold_pps`
- `threshold_bps`
- `threshold_cps`
- `dimension`
- `burst_packets`
- `burst_bytes`
- `sample_denom`
- `ttl_seconds`
- `expires_at`
- `evidence`
- `confidence`
- `enabled`
- `owner`

If `ttl_seconds` is set and `expires_at` is omitted, backend derives expiry from current time.

## 12. Blacklist

Authenticated read. `user` mutates own config; `admin` view-user context is read-only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/blacklist` | none | `BlacklistEntry[]` | List manual blacklist entries |
| GET | `/v1/blacklist/entries` | none | `BlacklistEntriesPage` | List paginated manual blacklist rows |
| POST | `/v1/blacklist` | `BlacklistInput` | `BlacklistEntry` | Create entry |
| PATCH | `/v1/blacklist/{id}` | `BlacklistInput` | `BlacklistEntry` | Update entry |
| DELETE | `/v1/blacklist/{id}` | reason via header | `BlacklistEntry` | Soft-disable entry |

Optional list filters:

- `q`: search CIDR, source, reason, rule UUID or rule name.
- `source`: exact source filter, case-insensitive.
- `origin`: optional legacy compatibility value `all` or `manual` on `/v1/blacklist/entries`.
- `state`: `all`, `enabled`, `disabled`.
- `expiry`: `all`, `valid`, `expired`, `none`.
- `page`: zero-based page on `/v1/blacklist/entries`; default `0`.
- `page_size`: page size on `/v1/blacklist/entries`; default `25`, max `100`.

`BlacklistEntriesPage`:

```json
{
  "items": [
    {
      "id": "uuid",
      "ebpf_id": 31,
      "cidr": "203.0.113.8/32",
      "score": 100,
      "action": "drop",
      "source": "manual",
      "source_name": "",
      "reason": "manual evidence",
      "enabled": true,
      "status": "enabled",
      "origin": "manual",
      "editable": true,
      "created_at": "2026-06-01T00:00:00Z",
      "updated_at": "2026-06-01T00:00:00Z"
    }
  ],
  "total": 1,
  "page": 0,
  "page_size": 25
}
```

Threat feed/reputation rows are not exposed through this endpoint in the current user-facing API.

`BlacklistInput`:

```json
{
  "reason": "manual abuse block",
  "cidr": "198.51.100.0/24",
  "score": 80,
  "action": "drop",
  "source": "manual",
  "rule_id": "",
  "expires_at": "2026-06-01T00:00:00Z",
  "enabled": true
}
```

Manual blacklist action must be `drop`. Create/update/disable rebuild policy snapshots.

## 13. UDP Source Port Blocks

Authenticated read. `user` mutates own config; `admin` view-user context is read-only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/udp-source-port-blocks?q=&state=&expiry=` | query | `UDPSourcePortBlock[]` | List owner UDP source-port block entries |
| POST | `/v1/udp-source-port-blocks` | `UDPSourcePortBlockInput` | `UDPSourcePortBlock` | Create entry and rebuild snapshot |
| PATCH | `/v1/udp-source-port-blocks/{id}` | `UDPSourcePortBlockInput` | `UDPSourcePortBlock` | Update entry and rebuild snapshot |
| DELETE | `/v1/udp-source-port-blocks/{id}` | `X-Audit-Reason` | `UDPSourcePortBlock` | Soft-disable entry and rebuild snapshot |

Optional list filters:

- `q`: search port, label, reason or owner.
- `state`: `all`, `enabled`, `disabled`.
- `expiry`: `all`, `valid`, `expired`, `none`.

`UDPSourcePortBlockInput`:

```json
{
  "reason": "block NTP reflection source port",
  "port": 123,
  "label": "ntp",
  "owner": "sre",
  "expires_at": "2026-06-10T00:00:00Z",
  "enabled": true
}
```

`UDPSourcePortBlock`:

```json
{
  "id": "uuid",
  "ebpf_id": 42,
  "port": 123,
  "label": "ntp",
  "reason": "block NTP reflection source port",
  "owner": "sre",
  "enabled": true,
  "expires_at": "2026-06-10T00:00:00Z",
  "created_at": "2026-06-03T00:00:00Z",
  "updated_at": "2026-06-03T00:00:00Z"
}
```

The migration seeds disabled entries for common UDP reflection/amplification source ports: `0`, `19`, `53`, `69`, `111`, `123`, `137`, `161`, `162`, `389`, `427`, `520`, `1194`, `1900`, `3702`, `5353`, `10001`, `11211`, `20800`, `27005`.

Only enabled and non-expired entries are included in owner policy snapshots as `udp_source_port_blocks`. Snapshot feature flag `udp_src_port_block` is present only when active entries exist. Datapath semantics apply inside the owner snapshot: after a protected service match and whitelist precedence, non-whitelisted UDP packets with a matching source port are dropped with reason `11`. Whitelisted sources bypass this check; packets outside the service allowlist keep the existing `REASON_NOT_ALLOWED_SERVICE` behavior.

## 14. Feeds and reputation

Threat Feed/Reputation is not user-facing in the current admin/user RBAC scope. The dashboard does not call feed endpoints, and `/v1/feed-sources`, `/v1/feed-runs` and `/v1/feed-conflicts` are retired from the public Control API.

## 15. Telegram and alerts

Authenticated read. `user` mutates own Telegram/alert config; `admin` view-user context is read-only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/telegram/config` | none | `TelegramConfig` | Get Telegram config |
| POST | `/v1/telegram/config` | `TelegramConfigInput` | `TelegramConfig` | Upsert owner Telegram config |
| POST | `/v1/telegram/test` | optional `{reason}` | `Alert` | Create test alert |
| GET | `/v1/alerts?limit=N` | none | `Alert[]` | List alerts |
| POST | `/v1/alerts` | `AlertInput` | `Alert` | Create alert |
| GET | `/v1/alerts/{id}/deliveries` | none | `AlertDelivery[]` | List alert deliveries |
| POST | `/v1/alerts/evaluate-isp-escalation` | `ISPEscalationInput` | `Alert` | Evaluate manual ISP escalation |

`TelegramConfigInput`:

```json
{
  "reason": "configure telegram",
  "bot_token_ref": "123456:telegram-bot-token",
  "chat_id": "123456",
  "parse_mode": "MarkdownV2",
  "enabled": true
}
```

`bot_token_ref` is a write-only Telegram bot token value that a `user` can set for their own owner context. Responses return `bot_token_ref: "*****"` when a token is configured; sending `"*****"` or an empty value keeps the existing token.

`AlertInput` key fields:

- `severity`
- `type`
- `dedupe_key`
- `service_id`
- `affected_service`
- `vector`
- `evidence`
- `recommended_action`

ISP escalation does not perform automatic BGP/RTBH/FlowSpec. It creates/evaluates alert/runbook payload for manual escalation.

## 16. Snapshots

Authenticated read. `user` can build/rollback own snapshots; `admin` view-user context is read-only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/snapshots?include_snapshot=true|false` | query | `SnapshotMetadata[]` | List snapshots; raw snapshot included only when true |
| GET | `/v1/snapshots/{version}?include_snapshot=true|false` | query | `SnapshotMetadata` | Get one snapshot; raw snapshot included unless `false` |
| GET | `/v1/snapshots/diff?from=1&to=2` | query | `SnapshotDiff` | Semantic diff |
| POST | `/v1/snapshots/build` | `{reason}` | `SnapshotMetadata` or `{"status":"unchanged"}` | Rebuild active snapshot |
| POST | `/v1/snapshots/rollback` | `RollbackRequest` | `SnapshotMetadata` | Create rollback snapshot from target version |

`RollbackRequest`:

```json
{
  "reason": "rollback bad policy",
  "target_version": 7
}
```

`SnapshotDiff` groups changes by:

- `services`
- `whitelist_v4`
- `blacklist_v4`
- `udp_source_port_blocks`
- `rules`
- `runtime`
- `object_checksum`

## 17. Audit

Authenticated.

| Method | Path | Query | Response |
|---|---|---|---|
| GET | `/v1/audit?limit=N` | `limit` optional | `AuditEvent[]` |

Audit event fields:

- `id`
- `created_at`
- `actor_id`
- `actor_username`
- `action`
- `entity_type`
- `entity_id`
- `before`
- `after`
- `reason`
- `request_id`

Sensitive policy: raw passwords, Telegram bot tokens and credential values must not be stored in audit payloads.

## 18. Security events and investigation

Authenticated user endpoints.

| Method | Path | Query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/security-events` | event query | `SecurityEvent[]` | List sampled events |
| GET | `/v1/security-events/summary` | event query | `SecurityEventSummary` | Aggregate summary, default last 5 minutes if no time range |
| GET | `/v1/security-events/investigate` | `target`, `limit` | `{target, events}` | Investigate source/prefix/service target |

Event query parameters:

- `since` RFC3339
- `until` RFC3339
- `service_id`
- `rule_id`
- `action`
- `reason`
- `src`
- `limit`

Agent event ingest is documented in section 21.

## 19. Baselines and anomalies

Authenticated read. `user` can mutate own baselines and evaluate anomalies; `admin` view-user context is read-only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/baselines` | none | `BaselineProfile[]` | List baseline profiles |
| POST | `/v1/baselines` | `BaselineProfileInput` | `BaselineProfile` | Create baseline |
| POST | `/v1/baselines/{id}/approve` | `{reason}` | `BaselineProfile` | Approve baseline |
| POST | `/v1/baselines/{id}/recalibrate` | `BaselineProfileInput` | `BaselineProfile` | Recalibrate baseline |
| GET | `/v1/anomalies?limit=N` | query | `AnomalyEvaluation[]` | List anomalies |
| POST | `/v1/anomalies/evaluate` | `{reason}` | `AnomalyEvaluation[]` | Evaluate anomalies and create alert-only operational signals; it does not create mitigation rules |

`AnomalyEvaluation` keeps legacy compatibility fields such as `auto_enforced`, `proposed_rule_id` and `proposed_ttl_seconds`. New evaluations set `auto_enforced=false` and leave proposed rule fields empty; users create any `rate_limit` rule manually through `Rules`.

`BaselineProfileInput` key fields:

- `reason`
- `service_id`
- `interface`
- `protocol`
- `port`
- `window`
- `expected_pps`
- `expected_bps`
- `expected_cps`
- `history_hours`
- `confidence`
- `evidence`

## 20. Dashboard read API

Authenticated. These endpoints are optimized for dashboard polling and view models. Dashboard overview uses owner-scoped control-plane data.

| Method | Path | Response |
|---|---|---|
| GET | `/v1/dashboard/overview` | `DashboardOverview` |
| GET | `/v1/dashboard/agents` | `DashboardAgent[]` |
| GET | `/v1/dashboard/services` | `DashboardService[]` |
| GET | `/v1/dashboard/rules` | `DashboardRule[]` |

Dashboard overview includes:

- `generated_at`
- `prometheus`
- `traffic`
- `decision_rates`
- `security_events`
- `agents`
- `snapshot_version`
- `latest_apply_status`

## 21. Agent control API

Agent endpoints use the agent shared bearer token, not user sessions.
`POST /v1/agents/register` also requires `X-Owner-User-ID` or `X-Owner-Username`. Heartbeat, snapshot, apply and event ingestion resolve owner from `agent_id` after registration.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| POST | `/v1/agents/register` | `AgentRegisterRequest` + owner header | `AgentRegisterResponse` | Register or refresh agent identity for owner user |
| POST | `/v1/agents/{id}/heartbeat` | `AgentHeartbeatRequest` | `AgentHeartbeatResponse` | Report status/interfaces/map utilization |
| GET | `/v1/agents/{id}/snapshot?active_version=N` | query | `{"snapshot": ...}` or `204` | Fetch desired snapshot when newer than active |
| POST | `/v1/agents/{id}/apply` | `AgentApplyRequest` | `{"ok":true}` | Report apply result |
| POST | `/v1/agents/{id}/events` | `SecurityEventBatch` | `SecurityEventIngestResult` | Ingest sampled XDP/security events |

`AgentRegisterRequest` key fields:

- `hostname`
- `interfaces`
- `kernel_version`
- `ubuntu_version`
- `xdp_mode`
- `devmap_support`
- `agent_version`

`AgentHeartbeatRequest` key fields:

- `status`
- `active_policy_version`
- `xdp_mode`
- `uptime_seconds`
- `map_utilization`
- `interfaces`

`AgentApplyRequest` key fields:

- `policy_version`
- `status`
- `error_stage`
- `error_reason`
- `map_stats`
- `devmap_stats`

`SecurityEventBatch`:

```json
{
  "events": [
    {
      "event_time": "2026-05-29T12:00:00Z",
      "policy_version": 7,
      "src_ip": "198.51.100.10",
      "dst_ip": "203.0.113.10",
      "dst_port": 443,
      "protocol": 6,
      "action": 1,
      "reason": 4,
      "service_id": 1,
      "rule_id": 10,
      "pkt_len": 64,
      "sample_rate": 10,
      "metadata": {}
    }
  ]
}
```

Batch limit: max 1000 events.

## 22. Endpoint summary

| Domain | Endpoints |
|---|---|
| Health | `GET /healthz`, `GET /metrics` |
| Auth | `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/me`, `POST /v1/me/password` |
| Users | `GET/POST /v1/users`, `PATCH/DELETE /v1/users/{id}`, `POST /v1/users/{id}/password-reset`, `POST /v1/users/{id}/sessions/revoke` |
| Policy | `GET/POST /v1/services`, `PUT/DELETE /v1/services/{id}`, `GET/POST /v1/forwarding-policies`, `GET/POST /v1/whitelist`, `PATCH/DELETE /v1/whitelist/{id}`, `GET/POST /v1/rules`, `PATCH/DELETE /v1/rules/{id}`, `GET/POST /v1/blacklist`, `PATCH/DELETE /v1/blacklist/{id}`, `GET/POST /v1/udp-source-port-blocks`, `PATCH/DELETE /v1/udp-source-port-blocks/{id}` |
| Alerts | `GET/POST /v1/alerts`, `GET /v1/alerts/{id}/deliveries`, `POST /v1/alerts/evaluate-isp-escalation`, `GET/POST /v1/telegram/config`, `POST /v1/telegram/test` |
| Snapshots | `GET /v1/snapshots`, `GET /v1/snapshots/{version}`, `GET /v1/snapshots/diff`, `POST /v1/snapshots/build`, `POST /v1/snapshots/rollback` |
| Observability | `GET /v1/audit`, `GET /v1/security-events`, `GET /v1/security-events/summary`, `GET /v1/security-events/investigate`, `GET/POST /v1/baselines`, `POST /v1/baselines/{id}/approve`, `POST /v1/baselines/{id}/recalibrate`, `GET /v1/anomalies`, `POST /v1/anomalies/evaluate`, `GET /v1/dashboard/overview`, `GET /v1/dashboard/agents`, `GET /v1/dashboard/services`, `GET /v1/dashboard/rules` |
| Agents | `POST /v1/agents/register`, `POST /v1/agents/{id}/heartbeat`, `GET /v1/agents/{id}/snapshot`, `POST /v1/agents/{id}/apply`, `POST /v1/agents/{id}/events` |

## 23. Verification guidance

When changing Control API behavior, update this document and run relevant gates:

- Backend route/store changes: `go test ./...`
- Race-sensitive auth/session/snapshot changes: `go test -race ./...`
- Static checks: `go vet ./...`
- Dashboard contract changes: `npm --prefix web/dashboard test -- --run`
- UI/API shape changes: `npm --prefix web/dashboard run build`

Also update `docs/Admin-Dashboard-v2.md` when the dashboard-visible contract changes.

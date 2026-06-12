# Control API

Control API is the JSON HTTP API used by the Admin Dashboard, admin console, host Agent control loop and operations workflows. Business endpoints live under `/v1`; `/healthz` and `/metrics` are outside that prefix.

## 1. Conventions

- Requests and responses use JSON unless an endpoint states otherwise.
- Responses set `Content-Type: application/json`.
- Timestamps are RFC3339.
- Request JSON decoders reject unknown fields.
- Success usually returns `200`.
- Errors return JSON:

```json
{"error":"reason is required"}
```

- User auth accepts `Authorization: Bearer <session_token>` or cookie `anti_ddos_session`.
- Agent auth accepts `Authorization: Bearer <agent_shared_token>` when `ANTI_DDOS_AGENT_SHARED_TOKEN` is configured.
- User operational data is isolated by owner context: a user sees their own data; admin view-user sessions read the target user's data.
- Mutation reason is read from body `reason` first, then from `X-Audit-Reason`.
- Validation errors map to `400`; missing rows map to `404`; role/authorization errors map to `403`.
- Agent fetches policy by `GET /v1/agents/{id}/snapshot?active_version=N`.

## 2. Roles And Ownership

| Role | API behavior |
|---|---|
| `user` | Reads and mutates owner-scoped operational config. |
| `admin` | Manages accounts and global feed sources; can open read-only user config context. |

Mutation policy:

- Account mutations: `admin` only.
- Global feed mutations/sync: normal `admin` session only.
- Operational config mutations: `user` only, and only in the user's own owner context.
- Admin view-user context: read-only; operational mutations return `403`.
- Telegram config: mutable only by `user` owner context; token values are masked in responses.

## 3. Common Data Values

| Field | Values |
|---|---|
| `role` | `admin`, `user` |
| user `status` | `active`, `revoked` |
| packet/action constants | `0` pass, `1` drop, `2` rate_limit, `3` observe, `4` sample, `6` redirect |
| policy scope constants | `0` global, `1` service |
| neighbor status | `1` resolved |

## 4. Health And Metrics

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/healthz` | None | `{"ok":true}` |
| GET | `/metrics` | None | Prometheus metrics when enabled; JSON `503` when disabled |

## 5. Auth And Current User

### POST `/v1/auth/login`

Request:

```json
{
  "username": "user",
  "password": "password phrase"
}
```

Response `Session`:

```json
{
  "token": "session-token",
  "expires_at": "2026-06-12T12:00:00Z",
  "user": {
    "id": "uuid",
    "username": "user",
    "role": "user",
    "status": "active",
    "force_password_change": false,
    "created_at": "2026-06-12T12:00:00Z"
  }
}
```

Side effect: sets HttpOnly cookie `anti_ddos_session`.

### POST `/v1/auth/logout`

Authenticated by bearer or cookie if present. Revokes the matching session token.

Response:

```json
{"ok":true}
```

### GET `/v1/me`

Authenticated. Returns current `User`.

### POST `/v1/me/password`

Authenticated. Changes own password, clears `force_password_change`, and revokes other active sessions.

Request `OwnPasswordInput`:

```json
{
  "reason": "rotate own password",
  "current_password": "current password phrase",
  "new_password": "new password phrase"
}
```

Password minimum length is 12 characters.

## 6. Admin View Context

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| POST | `/v1/admin/view-user` | `{"user_id":"uuid"}` | `Session` | Admin opens read-only dashboard context for an active user |

Returned `User` includes:

```json
{
  "viewing_user": {"id": "uuid", "username": "user"},
  "read_only": true
}
```

## 7. Users

Authenticated read. `admin` has account lifecycle mutation.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/users` | none | `User[]` | List accounts |
| POST | `/v1/users` | `{username,password,role,reason}` | `User` | Create account |
| PATCH | `/v1/users/{id}` | `UserUpdateInput` | `User` | Update role/status/password-change flag |
| DELETE | `/v1/users/{id}` | reason via header | `User` | Revoke account |
| POST | `/v1/users/{id}/password-reset` | `PasswordResetInput` | `User` | Reset password and revoke sessions |
| POST | `/v1/users/{id}/sessions/revoke` | optional `{reason}` | `User` | Revoke sessions |

Safety:

- Backend prevents revoking or downgrading the last active admin.
- Non-admin account mutation requests return `403`.
- Raw passwords are not returned or stored in audit before/after payloads.

## 8. Services

Authenticated read. `user` mutates own config; admin view-user context reads only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/services` | none | `Service[]` | List protected services |
| POST | `/v1/services` | `ServiceInput` | `Service` | Create service and rebuild snapshot |
| PUT | `/v1/services/{id}` | `ServiceInput` | `Service` | Replace/update service and rebuild snapshot |
| DELETE | `/v1/services/{id}` | reason via header | `Service` | Disable service and rebuild snapshot |

`ServiceInput` key fields:

- `reason`, `name`, `description`
- `backend_cidr`
- `protocol`: `tcp`, `udp`, `icmp`
- `allowed_ports`
- `output_interface`
- `owner`, `criticality`, `protection_mode`
- `enabled`, `priority`, `tags`
- optional resolved forwarding metadata: `resolved_ifindex`, `resolved_next_hop_mac`, `resolved_src_mac`, `neighbor_resolution_status`

TCP/UDP services require non-zero allowed ports. ICMP ports must be `0`. Dashboard service creation defaults to disabled and lets the Agent resolve forwarding metadata when live metadata is not yet available.

## 9. Forwarding Policies

Authenticated read. `user` mutates own config; admin view-user context reads only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/forwarding-policies` | none | `ForwardingPolicy[]` | List policies |
| POST | `/v1/forwarding-policies` | `ForwardingPolicyInput` | `ForwardingPolicy` | Create policy |

`ForwardingPolicyInput` requires `service_id`, `backend_target`, `match_protocol`, `output_interface`, `owner`, and `action="redirect"`. TCP/UDP policies require `match_dst_port`; ICMP requires `0`.

## 10. Whitelist

Authenticated read. `user` mutates own config; admin view-user context reads only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/whitelist?q=&scope=&service_id=&state=&expiry=` | query | `WhitelistEntry[]` | List entries |
| POST | `/v1/whitelist` | `WhitelistInput` | `WhitelistEntry` | Create entry and rebuild snapshot |
| PATCH | `/v1/whitelist/{id}` | `WhitelistInput` | `WhitelistEntry` | Update entry and rebuild snapshot |
| DELETE | `/v1/whitelist/{id}` | reason via header | `WhitelistEntry` | Disable entry and rebuild snapshot |

Filters:

- `q`: CIDR, label, owner, reason or service text.
- `scope`: `all`, `global`, `service`.
- `service_id`: UUID for service-scoped entries.
- `state`: `all`, `enabled`, `disabled`.
- `expiry`: `all`, `valid`, `expired`, `none`.

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
  "expires_at": "2026-06-12T00:00:00Z",
  "enabled": true
}
```

Service-scoped whitelist entries require `service_id`.

## 11. Rules

Authenticated read. `user` mutates own config; admin view-user context reads only.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/rules` | none | `Rule[]` | List rules |
| POST | `/v1/rules` | `RuleInput` | `Rule` | Create rule and rebuild snapshot |
| PATCH | `/v1/rules/{id}` | `RuleInput` | `Rule` | Update rule and rebuild snapshot |
| DELETE | `/v1/rules/{id}` | reason via header | `Rule` | Disable rule and rebuild snapshot |

`RuleInput` supports:

- `reason`, `service_id`, `name`, `priority`
- `match_expr`, `evidence` as JSON objects
- `action`: `observe`, `drop`, `rate_limit`, `sample`
- `mode`: `observe`, `enforce`
- thresholds: `threshold_pps`, `threshold_bps`, `threshold_cps`
- burst and sample controls: `burst_packets`, `burst_bytes`, `sample_denom`
- `dimension`: `source`, `service`, `source_service`
- `ttl_seconds`, `expires_at`, `confidence`, `enabled`, `owner`

If `ttl_seconds` is set and `expires_at` is omitted, backend derives expiry from current time.

## 12. Blacklist

Authenticated read. `user` mutates manual blacklist config; admin view-user context reads only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/blacklist?q=&source=&state=&expiry=` | query | `BlacklistEntry[]` | List manual blacklist entries |
| GET | `/v1/blacklist/entries?q=&source=&origin=&state=&expiry=&page=&page_size=` | query | `BlacklistEntriesPage` | List manual plus feed-origin rows |
| POST | `/v1/blacklist` | `BlacklistInput` | `BlacklistEntry` | Create manual entry and rebuild snapshot |
| PATCH | `/v1/blacklist/{id}` | `BlacklistInput` | `BlacklistEntry` | Update manual entry and rebuild snapshot |
| DELETE | `/v1/blacklist/{id}` | reason via header | `BlacklistEntry` | Disable manual entry and rebuild snapshot |

Filters:

- `q`: CIDR, source, reason, rule UUID or rule name.
- `source`: exact source filter, case-insensitive.
- `origin`: `all`, `manual`, `feed` on `/v1/blacklist/entries`.
- `state`: `all`, `enabled`, `disabled`.
- `expiry`: `all`, `valid`, `expired`, `none`.
- `page`: zero-based page on `/v1/blacklist/entries`; default `0`.
- `page_size`: default `25`, max `100`.

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
      "created_at": "2026-06-12T00:00:00Z",
      "updated_at": "2026-06-12T00:00:00Z"
    }
  ],
  "total": 1,
  "page": 0,
  "page_size": 25
}
```

Feed-origin rows are generated from global active reputation and have `editable=false`. Manual blacklist mutations accept only `action="drop"`.

## 13. UDP Source Port Blocks

Authenticated read. `user` mutates own config; admin view-user context reads only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/udp-source-port-blocks?q=&state=&expiry=` | query | `UDPSourcePortBlock[]` | List source-port blocks |
| POST | `/v1/udp-source-port-blocks` | `UDPSourcePortBlockInput` | `UDPSourcePortBlock` | Create entry and rebuild snapshot |
| PATCH | `/v1/udp-source-port-blocks/{id}` | `UDPSourcePortBlockInput` | `UDPSourcePortBlock` | Update entry and rebuild snapshot |
| DELETE | `/v1/udp-source-port-blocks/{id}` | `X-Audit-Reason` | `UDPSourcePortBlock` | Disable entry and rebuild snapshot |

Filters:

- `q`: port, label, reason or owner.
- `state`: `all`, `enabled`, `disabled`.
- `expiry`: `all`, `valid`, `expired`, `none`.

`UDPSourcePortBlockInput`:

```json
{
  "reason": "block NTP reflection source port",
  "port": 123,
  "label": "ntp",
  "owner": "sre",
  "expires_at": "2026-06-12T00:00:00Z",
  "enabled": true
}
```

New user owners are seeded with disabled entries for common reflection/amplification source ports. Enabled, non-expired entries are included in owner snapshots as `udp_source_port_blocks`; whitelist bypasses this datapath check.

## 14. Feeds And Reputation

Threat Feed/Reputation endpoints require normal `admin` session.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/feed-sources` | none | `FeedSource[]` | List global feed sources |
| POST | `/v1/feed-sources` | `FeedSourceInput` | `FeedSource` | Create global feed source |
| GET | `/v1/feed-sources/{id}` | none | `FeedSource` | Get global feed source |
| PATCH | `/v1/feed-sources/{id}` | `FeedSourceInput` | `FeedSource` | Update global feed source |
| DELETE | `/v1/feed-sources/{id}` | `X-Audit-Reason` | `FeedSource` | Disable source and rebuild active user snapshots |
| POST | `/v1/feed-sources/{id}/sync` | optional `{reason}` | `FeedRun` | Sync source, refresh reputation and rebuild active user snapshots |
| GET | `/v1/feed-runs?limit=N` | query | `FeedRun[]` | Recent global feed sync runs |
| GET | `/v1/feed-conflicts` | none | `FeedConflict[]` | Active conflicts between global reputation and user whitelists |

`FeedSourceInput`:

```json
{
  "reason": "create feed",
  "name": "abuseipdb",
  "type": "abuseipdb",
  "url": "https://example.test/feed",
  "credential_ref": "env://ABUSEIPDB_KEY",
  "required_for_production": true,
  "enabled": true,
  "interval_seconds": 3600,
  "license_note": "commercial",
  "quota_metadata": {"ttl_seconds": 3600},
  "status": "placeholder"
}
```

Credential behavior:

- Responses and audit payloads mask credentials as `***`.
- PATCH with `credential_ref: "***"` keeps the stored credential.
- PATCH with `credential_ref: ""` clears the stored credential.

Active global reputation rows with `action="drop"` are unioned into every active user's policy snapshot.

## 15. Telegram And Alerts

Authenticated read. `user` mutates own Telegram/alert config; admin view-user context reads only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/telegram/config` | none | `TelegramConfig` | Get Telegram config |
| POST | `/v1/telegram/config` | `TelegramConfigInput` | `TelegramConfig` | Upsert owner Telegram config |
| POST | `/v1/telegram/test` | optional `{reason}` | `Alert` | Create test alert |
| GET | `/v1/alerts?limit=N` | query | `Alert[]` | List alerts |
| POST | `/v1/alerts` | `AlertInput` | `Alert` | Create alert |
| GET | `/v1/alerts/{id}/deliveries` | none | `AlertDelivery[]` | List alert deliveries |
| POST | `/v1/alerts/evaluate-isp-escalation` | `ISPEscalationInput` | `Alert` | Evaluate manual ISP escalation |

`TelegramConfigInput` requires `chat_id`; `parse_mode` can be empty, `HTML`, `MarkdownV2`, or `Markdown`. `bot_token_ref` is write-only; responses use `*****` when a token is configured.

`AlertInput` requires `severity`, `type` and `dedupe_key`. Severity is `info`, `warning`, or `critical`.

ISP escalation creates/evaluates alert/runbook payloads. It does not perform automatic BGP/RTBH/FlowSpec changes.

## 16. Snapshots

Authenticated read. `user` can build/rollback own snapshots; admin view-user context reads only.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/snapshots?include_snapshot=true|false` | query | `SnapshotMetadata[]` | List snapshots; raw snapshot included only when true |
| GET | `/v1/snapshots/{version}?include_snapshot=true|false` | query | `SnapshotMetadata` | Get one snapshot; raw snapshot included unless `false` |
| GET | `/v1/snapshots/diff?from=1&to=2` | query | `SnapshotDiff` | Semantic diff |
| POST | `/v1/snapshots/build` | `{reason}` | `SnapshotMetadata` or `{"status":"unchanged"}` | Rebuild active snapshot |
| POST | `/v1/snapshots/rollback` | `RollbackRequest` | `SnapshotMetadata` | Create rollback snapshot from target version |

`SnapshotDiff` groups changes by `services`, `whitelist_v4`, `blacklist_v4`, `udp_source_port_blocks`, `rules`, `runtime`, and `object_checksum`.

## 17. Audit

Authenticated.

| Method | Path | Query | Response |
|---|---|---|
| GET | `/v1/audit?limit=N` | `limit` optional | `AuditEvent[]` |

Audit payloads must not include raw passwords, Telegram bot tokens or feed credential values.

## 18. Security Events And Investigation

Authenticated owner-context read endpoints.

| Method | Path | Query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/security-events` | event query | `SecurityEvent[]` | List sampled events |
| GET | `/v1/security-events/summary` | event query | `SecurityEventSummary` | Aggregate summary; default window is last five minutes when no range is supplied |
| GET | `/v1/security-events/investigate` | `target`, `limit` | `{target, events}` | Investigate source/prefix/service target |

Event query parameters: `since`, `until`, `service_id`, `rule_id`, `action`, `reason`, `src`, `limit`.

## 19. Dashboard Read API

Authenticated owner-context read endpoints optimized for dashboard polling.

| Method | Path | Response |
|---|---|---|
| GET | `/v1/dashboard/overview` | `DashboardOverview` |
| GET | `/v1/dashboard/agents` | `DashboardAgent[]` |
| GET | `/v1/dashboard/services` | `DashboardService[]` |
| GET | `/v1/dashboard/rules` | `DashboardRule[]` |

Overview includes generated time, Prometheus status, traffic, decision rates, security event summary, agent summary, snapshot version and latest apply status.

## 20. Agent Control API

Agent endpoints use the agent shared bearer token. Register requires `X-Owner-User-ID` or `X-Owner-Username`; later calls resolve owner from `agent_id`.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| POST | `/v1/agents/register` | `AgentRegisterRequest` + owner header | `AgentRegisterResponse` | Register or refresh agent identity for owner user |
| POST | `/v1/agents/{id}/heartbeat` | `AgentHeartbeatRequest` | `AgentHeartbeatResponse` | Report status/interfaces/map utilization |
| GET | `/v1/agents/{id}/snapshot?active_version=N` | query | `{"snapshot": ...}` or `204` | Fetch desired snapshot when newer than active |
| POST | `/v1/agents/{id}/apply` | `AgentApplyRequest` | `{"ok":true}` | Report apply result |
| POST | `/v1/agents/{id}/events` | `SecurityEventBatch` | `SecurityEventIngestResult` | Ingest sampled XDP/security events |

`AgentRegisterRequest` key fields: `hostname`, `interfaces`, `kernel_version`, `ubuntu_version`, `xdp_mode`, `devmap_support`, `agent_version`.

`AgentHeartbeatRequest` key fields: `status`, `active_policy_version`, `xdp_mode`, `uptime_seconds`, `map_utilization`, `interfaces`.

`AgentApplyRequest` key fields: `policy_version`, `status`, `error_stage`, `error_reason`, `map_stats`, `devmap_stats`.

`SecurityEventBatch` accepts up to 1000 events.

## 21. Endpoint Summary

| Domain | Endpoints |
|---|---|
| Health | `GET /healthz`, `GET /metrics` |
| Auth | `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/me`, `POST /v1/me/password` |
| Users | `GET/POST /v1/users`, `PATCH/DELETE /v1/users/{id}`, `POST /v1/users/{id}/password-reset`, `POST /v1/users/{id}/sessions/revoke`, `POST /v1/admin/view-user` |
| Policy | `GET/POST /v1/services`, `PUT/DELETE /v1/services/{id}`, `GET/POST /v1/forwarding-policies`, `GET/POST /v1/whitelist`, `PATCH/DELETE /v1/whitelist/{id}`, `GET/POST /v1/rules`, `PATCH/DELETE /v1/rules/{id}`, `GET/POST /v1/blacklist`, `GET /v1/blacklist/entries`, `PATCH/DELETE /v1/blacklist/{id}`, `GET/POST /v1/udp-source-port-blocks`, `PATCH/DELETE /v1/udp-source-port-blocks/{id}` |
| Reputation | `GET/POST /v1/feed-sources`, `GET/PATCH/DELETE /v1/feed-sources/{id}`, `POST /v1/feed-sources/{id}/sync`, `GET /v1/feed-runs`, `GET /v1/feed-conflicts` |
| Alerts | `GET/POST /v1/alerts`, `GET /v1/alerts/{id}/deliveries`, `POST /v1/alerts/evaluate-isp-escalation`, `GET/POST /v1/telegram/config`, `POST /v1/telegram/test` |
| Snapshots | `GET /v1/snapshots`, `GET /v1/snapshots/{version}`, `GET /v1/snapshots/diff`, `POST /v1/snapshots/build`, `POST /v1/snapshots/rollback` |
| Observability | `GET /v1/audit`, `GET /v1/security-events`, `GET /v1/security-events/summary`, `GET /v1/security-events/investigate`, `GET /v1/dashboard/overview`, `GET /v1/dashboard/agents`, `GET /v1/dashboard/services`, `GET /v1/dashboard/rules` |
| Agents | `POST /v1/agents/register`, `POST /v1/agents/{id}/heartbeat`, `GET /v1/agents/{id}/snapshot`, `POST /v1/agents/{id}/apply`, `POST /v1/agents/{id}/events` |

## 22. Verification Guidance

When changing Control API behavior, update this document and run relevant gates:

- Backend route/store changes: `go test ./...`
- Race-sensitive auth/session/snapshot changes: `go test -race ./...`
- Static checks: `go vet ./...`
- Dashboard contract changes: `npm --prefix web/dashboard test -- --run`
- UI/API shape changes: `npm --prefix web/dashboard run build`

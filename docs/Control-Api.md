# Control API

Trang thai: tai lieu mo ta Control Plane HTTP API hien co trong working tree ngay 2026-05-29.

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
- Mutation reason lay tu body `reason` truoc, fallback sang header `X-Audit-Reason`.
- Nhieu store error duoc map thanh `400`; loi role co text `role required` duoc map thanh `403`.
- `POST /v1/agents/{id}/snapshot` khong ton tai; agent fetch snapshot bang `GET`.

## 2. Roles

| Role | Mo ta |
|---|---|
| `viewer` | Doc dashboard, policy, events, alerts, feeds, snapshots |
| `operator` | Bao gom viewer; duoc thao tac operational mutations |
| `admin` | Bao gom operator; duoc quan tri users va secret references |

Mutation policy:

- User mutations: Admin only. `GET /v1/users` is authenticated read in the current server.
- Service, forwarding policy, whitelist, rules, blacklist, feed, snapshot, baseline/anomaly operational actions: Operator/Admin.
- Telegram config: Operator/Admin, nhung thay doi `bot_token_ref` can Admin.
- Feed `credential_ref`: Admin only khi create/update.
- Viewer khong nen thay mutation control tren UI, nhung backend van la enforcement chinh.

## 3. Common data enums

| Field | Values |
|---|---|
| `role` | `admin`, `operator`, `viewer` |
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
  "username": "operator",
  "password": "password phrase"
}
```

Response `Session`:

```json
{
  "token": "session-token",
  "expires_at": "2026-05-29T12:00:00Z",
  "user": {
    "id": "uuid",
    "username": "operator",
    "role": "operator",
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

## 6. Users

Authenticated read, Admin mutation.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/users` | none | `User[]` | List local users |
| POST | `/v1/users` | `{username,password,role,reason}` | `User` | Create active user |
| PATCH | `/v1/users/{id}` | `UserUpdateInput` | `User` | Update role/status/force_password_change |
| DELETE | `/v1/users/{id}` | reason via header | `User` | Legacy revoke user route; sets status `revoked` |
| POST | `/v1/users/{id}/password-reset` | `PasswordResetInput` | `User` | Reset password and revoke active sessions |
| POST | `/v1/users/{id}/sessions/revoke` | optional `{reason}` | `User` | Revoke active sessions |

`UserUpdateInput`:

```json
{
  "reason": "update access",
  "role": "operator",
  "status": "active",
  "force_password_change": true
}
```

Safety:

- Backend prevents revoking/downgrading the last active admin.
- Raw password is never included in returned user or audit before/after payload.

## 7. Services

Authenticated read, Operator/Admin mutation.

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

## 8. Forwarding policies

Authenticated read, Operator/Admin mutation.

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

## 9. Whitelist

Authenticated read, Operator/Admin mutation.

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

## 10. Rules

Authenticated read, Operator/Admin mutation.

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

## 11. Blacklist

Authenticated read, Operator/Admin mutation.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/blacklist` | none | `BlacklistEntry[]` | List blacklist entries |
| POST | `/v1/blacklist` | `BlacklistInput` | `BlacklistEntry` | Create entry |

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

No PATCH/DELETE blacklist route exists in the current server.

## 12. Feeds and reputation

Authenticated read, Operator/Admin mutation. `credential_ref` create/update requires Admin.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/feed-sources` | none | `FeedSource[]` | List feed sources |
| POST | `/v1/feed-sources` | `FeedSourceInput` | `FeedSource` | Create feed source |
| GET | `/v1/feed-sources/{id}` | none | `FeedSource` | Get one feed source |
| PATCH | `/v1/feed-sources/{id}` | `FeedSourceInput` | `FeedSource` | Update feed source |
| DELETE | `/v1/feed-sources/{id}` | reason via header | `FeedSource` | Soft-disable feed source |
| POST | `/v1/feed-sources/{id}/sync` | optional `{reason}` | `FeedRun` | Run manual sync; provide reason when sync may change snapshot |
| GET | `/v1/feed-runs?limit=N` | none | `FeedRun[]` | List feed sync runs |
| GET | `/v1/feed-conflicts` | none | `FeedConflict[]` | List whitelist/reputation conflicts |

`FeedSourceInput` key fields:

- `reason`
- `name`
- `type`
- `url`
- `credential_ref`
- `required_for_production`
- `enabled`
- `interval_seconds`
- `license_note`
- `quota_metadata`
- `status`

Soft-disable can rebuild snapshot when active feed state changes.

## 13. Telegram and alerts

Authenticated read. Operational alert actions require Operator/Admin through store checks.

| Method | Path | Body | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/telegram/config` | none | `TelegramConfig` | Get Telegram config |
| POST | `/v1/telegram/config` | `TelegramConfigInput` | `TelegramConfig` | Upsert config; token ref changes require Admin |
| POST | `/v1/telegram/test` | optional `{reason}` | `Alert` | Create test alert |
| GET | `/v1/alerts?limit=N` | none | `Alert[]` | List alerts |
| POST | `/v1/alerts` | `AlertInput` | `Alert` | Create alert |
| GET | `/v1/alerts/{id}/deliveries` | none | `AlertDelivery[]` | List alert deliveries |
| POST | `/v1/alerts/evaluate-isp-escalation` | `ISPEscalationInput` | `Alert` | Evaluate manual ISP escalation |

`TelegramConfigInput`:

```json
{
  "reason": "configure telegram",
  "bot_token_ref": "env://TELEGRAM_TOKEN",
  "chat_id": "123456",
  "parse_mode": "MarkdownV2",
  "enabled": true
}
```

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

## 14. Snapshots

Authenticated read, Operator/Admin mutation for build/rollback.

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
- `rules`
- `runtime`
- `object_checksum`

## 15. Audit

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

Sensitive policy: raw passwords and credential values must not be stored in audit payloads.

## 16. Security events and investigation

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

Agent event ingest is documented in section 19.

## 17. Baselines and anomalies

Authenticated read. Baseline mutation and anomaly evaluate require Operator/Admin through store checks.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| GET | `/v1/baselines` | none | `BaselineProfile[]` | List baseline profiles |
| POST | `/v1/baselines` | `BaselineProfileInput` | `BaselineProfile` | Create baseline |
| POST | `/v1/baselines/{id}/approve` | `{reason}` | `BaselineProfile` | Approve baseline |
| POST | `/v1/baselines/{id}/recalibrate` | `BaselineProfileInput` | `BaselineProfile` | Recalibrate baseline |
| GET | `/v1/anomalies?limit=N` | query | `AnomalyEvaluation[]` | List anomalies |
| POST | `/v1/anomalies/evaluate` | `{reason}` | `AnomalyEvaluation[]` | Evaluate anomalies; reason is required when auto-enforcement creates a rule |

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

## 18. Dashboard read API

Authenticated. These endpoints are optimized for dashboard polling and view models.

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

## 19. Agent control API

Agent endpoints use the agent shared bearer token, not user sessions.

| Method | Path | Body/query | Response | Semantics |
|---|---|---|---|---|
| POST | `/v1/agents/register` | `AgentRegisterRequest` | `AgentRegisterResponse` | Register or refresh agent identity |
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

## 20. Endpoint summary

| Domain | Endpoints |
|---|---|
| Health | `GET /healthz`, `GET /metrics` |
| Auth | `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/me`, `POST /v1/me/password` |
| Users | `GET/POST /v1/users`, `PATCH/DELETE /v1/users/{id}`, `POST /v1/users/{id}/password-reset`, `POST /v1/users/{id}/sessions/revoke` |
| Policy | `GET/POST /v1/services`, `PUT/DELETE /v1/services/{id}`, `GET/POST /v1/forwarding-policies`, `GET/POST /v1/whitelist`, `PATCH/DELETE /v1/whitelist/{id}`, `GET/POST /v1/rules`, `PATCH/DELETE /v1/rules/{id}`, `GET/POST /v1/blacklist` |
| Feeds | `GET/POST /v1/feed-sources`, `GET/PATCH/DELETE /v1/feed-sources/{id}`, `POST /v1/feed-sources/{id}/sync`, `GET /v1/feed-runs`, `GET /v1/feed-conflicts` |
| Alerts | `GET/POST /v1/alerts`, `GET /v1/alerts/{id}/deliveries`, `POST /v1/alerts/evaluate-isp-escalation`, `GET/POST /v1/telegram/config`, `POST /v1/telegram/test` |
| Snapshots | `GET /v1/snapshots`, `GET /v1/snapshots/{version}`, `GET /v1/snapshots/diff`, `POST /v1/snapshots/build`, `POST /v1/snapshots/rollback` |
| Observability | `GET /v1/audit`, `GET /v1/security-events`, `GET /v1/security-events/summary`, `GET /v1/security-events/investigate`, `GET/POST /v1/baselines`, `POST /v1/baselines/{id}/approve`, `POST /v1/baselines/{id}/recalibrate`, `GET /v1/anomalies`, `POST /v1/anomalies/evaluate`, `GET /v1/dashboard/overview`, `GET /v1/dashboard/agents`, `GET /v1/dashboard/services`, `GET /v1/dashboard/rules` |
| Agents | `POST /v1/agents/register`, `POST /v1/agents/{id}/heartbeat`, `GET /v1/agents/{id}/snapshot`, `POST /v1/agents/{id}/apply`, `POST /v1/agents/{id}/events` |

## 21. Verification guidance

When changing Control API behavior, update this document and run relevant gates:

- Backend route/store changes: `go test ./...`
- Race-sensitive auth/session/snapshot changes: `go test -race ./...`
- Static checks: `go vet ./...`
- Dashboard contract changes: `npm --prefix web/dashboard test -- --run`
- UI/API shape changes: `npm --prefix web/dashboard run build`

Also update `docs/Admin-Dashboard-v2.md` when the dashboard-visible contract changes.

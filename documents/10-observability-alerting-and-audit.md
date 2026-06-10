# Observability, Alerting And Audit

Sơ đồ: [diagrams/observability-flow.mmd](diagrams/observability-flow.mmd)

## Metrics Surfaces

| Surface | Endpoint | Producer | Consumer |
|---|---|---|---|
| Agent metrics | `GET /metrics` on Agent addr | Node Agent | Prometheus |
| Agent health | `GET /healthz` on Agent addr | Node Agent | Ops/health check |
| Control metrics | `GET /metrics` on Control API | Control API | Prometheus |
| Control health | `GET /healthz` | Control API | Compose/ops |

Prometheus compose config scrapes:

- `control-api:8080/metrics`
- `host.docker.internal:9091/metrics` for host Agent

## Agent Metrics Inputs

Agent derives metrics from:

- `drop_counters` eBPF map.
- Runtime snapshot version and object checksum.
- Map stats for utilization.
- Forwarding counters based on current snapshot services.
- Ringbuf event forwarder status.

## Control Metrics

Control API exposes:

| Metric family | Mục đích |
|---|---|
| `anti_ddos_control_http_requests_total` | HTTP requests by method/route/status class |
| `anti_ddos_control_http_request_duration_seconds` | API latency |
| `anti_ddos_control_db_up` | PostgreSQL reachability |
| `anti_ddos_control_policy_snapshot_version` | Latest snapshot version |
| `anti_ddos_control_policy_apply_status` | Apply status counts |
| `anti_ddos_control_agents` | Agents by status/XDP mode |
| `anti_ddos_control_agent_stale` | Agent stale state |
| `anti_ddos_control_security_events_ingested_total` | Accepted sampled events |
| `anti_ddos_control_security_events_rejected_total` | Event rejects |
| `anti_ddos_control_prometheus_queries_total` | Prometheus query attempts |
| Feed/alert metrics | Sync success/errors, active entries/conflicts, alerts sent/failed |

## Security Events

XDP writes sampled `event_record` into ringbuf. Agent converts event fields to Control API JSON and batches them to `/v1/agents/{id}/events`.

Control API:

- Rejects missing agent ID.
- Accepts empty batch as no-op.
- Rejects batch size > 1000.
- Normalizes source prefix `/24`.
- Stores tenant-scoped rows in `security_events`.
- Provides list, summary and investigate endpoints.

## Prometheus Recording Rules

`deploy/prometheus/anti-ddos-recording-rules.yml` defines service-level rates:

- `anti_ddos:service_pps:rate1m`, `rate5m`
- `anti_ddos:service_bps:rate1m`, `rate5m`
- `anti_ddos:service_syn_cps:rate1m`, `rate5m`
- `anti_ddos:service_drop_ratio:rate5m`
- `anti_ddos:service_protocol_mix:rate5m`
- `anti_ddos:service_*:peak5m`

Control anomaly evaluation queries Prometheus when configured. Missing Prometheus config is handled cleanly and dashboard reports unconfigured.

## Alerts And Telegram

Alerting domain includes:

- `telegram_configs`: bot token ref, chat ID, parse mode, enabled.
- `alert_policies`: policy by type/severity/channel.
- `alerts`: alert lifecycle and dedupe.
- `alert_deliveries`: delivery attempts/status/error/response.

Telegram token handling:

- Stored/configured as reference or raw value depending current implementation path, but API/UI mask sensitive output.
- Operators/Admin can configure Telegram for tenant; feed credential visibility/mutation has stricter admin rules.

Alert types include test alerts and ISP escalation. ISP escalation endpoint may query Prometheus for peak PPS/BPS when request omits those fields.

## Audit

Mutations call `insertAudit` with actor, entity type/id, before/after JSON and reason. `audit_events` is partitioned by `created_at` with default partition. Redaction runs before storing audit JSON so secrets do not appear in audit entries.

## Source Alignment

- Agent metrics/events: `internal/agent/metrics.go`, `internal/agent/counters.go`, `internal/agent/ringbuf.go`, `internal/agent/event_forwarder.go`
- Control metrics: `internal/control/metrics.go`
- Events store: `internal/control/events.go`, `internal/control/observability_handlers.go`
- Alerts: `internal/control/alert.go`, `internal/control/alert_handlers.go`
- Audit/redaction: `internal/control/store.go`, `internal/agent/redaction.go`
- Prometheus config: `deploy/prometheus/compose-prometheus.yml`, `deploy/prometheus/anti-ddos-recording-rules.yml`

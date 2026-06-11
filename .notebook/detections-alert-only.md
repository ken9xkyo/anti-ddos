# Detections Removed
> flow | detection, alerts, dashboard

Last updated: 2026-06-11

The Detections dashboard feature for baselines and anomaly evaluations has been removed from active code. Shared alerting remains under `Incidents` and still powers Telegram test alerts, ISP runbook alerts, feed failure alerts and agent/apply failure alerts.

Key pointers:

- `web/dashboard/src/navigation.ts` no longer defines a `detection` tab.
- `web/dashboard/src/api.ts` dashboard polling no longer calls `/v1/baselines` or `/v1/anomalies`.
- `internal/control/server.go` no longer registers baseline/anomaly endpoints.
- `internal/control/scheduler.go` starts rule expiry and feed schedulers only.

Compatibility:

- Historical migrations still create `baseline_profiles` and `anomaly_evaluations`; this change intentionally does not drop existing data.
- Use `Incidents` for alert triage and `Rules` for manual mitigation changes.

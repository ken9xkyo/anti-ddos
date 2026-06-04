# Detections Are Alert-Only
> flow | detection, baseline, anomaly, rules

Last updated: 2026-06-04

Detection anomaly evaluation is alert-only. Baselines are used for monitoring thresholds, confidence context and alert generation; they do not create `rate_limit` rules.

Key pointers:

- `internal/control/anomaly.go:evaluateServiceAnomaly()` scores Prometheus signals, records `anomaly_evaluations`, and creates `anomaly` alerts for `alert_only` results.
- `internal/control/anomaly_cleanup.go:DisableLegacyAutoEnforceRules()` disables enabled legacy rules with owner `system:auto-enforce` or evidence `auto_enforce=true`, audits each rule, and rebuilds the policy snapshot.
- `cmd/control-api/main.go` runs legacy cleanup after migrations for both `migrate` and `serve`.
- `web/dashboard/src/views/DetectionView.tsx` renders `Anomalies / Alerts`; mitigation CRUD remains in `Rules`.

Compatibility:

- `AnomalyEvaluation.auto_enforced`, `proposed_rule_id` and `proposed_ttl_seconds` remain in the API for historical data and client compatibility.
- New evaluations set `auto_enforced=false` and leave proposed rule fields empty.

# Roadmap

## P1 MVP Phases

| Phase | Status | Purpose | Primary dependency |
|---|---|---|---|
| 00 - Foundation Lab Readiness | Ready for Phase 01 with gaps carried | Confirm lab host, topology inputs, toolchain, config conventions, benchmark matrix | None |
| 01 - XDP Data Plane Skeleton | Done | Build verifier-safe XDP parser, shared structs, maps, counters, event stub | Phase 00 |
| 02 - Agent Lifecycle | Done | Load, attach, rollback, pinned maps, metrics, last-valid snapshot | Phase 01 |
| 03 - Policy Snapshot Map Sync | Done | Validate and atomically apply immutable policy snapshots to eBPF maps | Phase 01, 02 |
| 04 - DEVMAP Forwarding and Service Allowlist | Done | L2 rewrite, DEVMAP redirect, route/neighbor resolution, fail-closed forwarding | Phase 01, 02, 03 |
| 05 - Control Plane Core | Planned | API, PostgreSQL, RBAC, audit, protected service registry, rollback | Phase 03, 04 |
| 06 - Observability Dashboard | Planned | Prometheus, sampled events, realtime dashboard, Grafana | Phase 02, 05 |
| 07 - Rate Limit Baseline Auto-Enforce | Planned | Baselines, anomaly scoring, token bucket rules, TTL auto-enforce | Phase 03, 05, 06 |
| 08 - Threat Feed Sync | Planned | Spamhaus, Team Cymru, AbuseIPDB, internal feed sync and aggregation | Phase 05, 06 |
| 09 - Telegram ISP Runbook | Planned | Telegram alert delivery, dedupe/retry, manual ISP escalation evidence | Phase 05, 06, 07, 08 |
| 10 - Hardening Benchmark UAT | Planned | Hardening, retention, benchmark report, UAT, runbooks, final acceptance | All prior phases |

## Carried Readiness Gaps

- Protected backend service inventory is still missing and remains a blocker before production service policy rollout in Phase 05.
- WAN/LAN/output interface roles are still not formally assigned; no XDP attach should target a production NIC yet.
- PostgreSQL and Prometheus binaries are still missing on the lab target.
- Native XDP attach capability and throughput benchmarks on real NICs have not been run.
- Phase 02 verification attached XDP only to temporary VETH lab interfaces and intentionally did not attach to production/lab NICs.
- Phase 04 verification used only temporary VETH namespaces and mock/bootstrap service policy; no production/lab NIC was attached.

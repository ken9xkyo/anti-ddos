# Roadmap

## P1 MVP Phases

| Phase | Status | Purpose | Primary dependency |
|---|---|---|---|
| 00 - Foundation Lab Readiness | In progress | Confirm lab host, topology inputs, toolchain, config conventions, benchmark matrix | None |
| 01 - XDP Data Plane Skeleton | Planned | Build verifier-safe XDP parser, shared structs, maps, counters, event stub | Phase 00 |
| 02 - Agent Lifecycle | Planned | Load, attach, rollback, pinned maps, metrics, last-valid snapshot | Phase 01 |
| 03 - Policy Snapshot Map Sync | Planned | Validate and atomically apply immutable policy snapshots to eBPF maps | Phase 01, 02 |
| 04 - DEVMAP Forwarding and Service Allowlist | Planned | L2 rewrite, DEVMAP redirect, route/neighbor resolution, fail-closed forwarding | Phase 01, 02, 03 |
| 05 - Control Plane Core | Planned | API, PostgreSQL, RBAC, audit, protected service registry, rollback | Phase 03, 04 |
| 06 - Observability Dashboard | Planned | Prometheus, sampled events, realtime dashboard, Grafana | Phase 02, 05 |
| 07 - Rate Limit Baseline Auto-Enforce | Planned | Baselines, anomaly scoring, token bucket rules, TTL auto-enforce | Phase 03, 05, 06 |
| 08 - Threat Feed Sync | Planned | Spamhaus, Team Cymru, AbuseIPDB, internal feed sync and aggregation | Phase 05, 06 |
| 09 - Telegram ISP Runbook | Planned | Telegram alert delivery, dedupe/retry, manual ISP escalation evidence | Phase 05, 06, 07, 08 |
| 10 - Hardening Benchmark UAT | Planned | Hardening, retention, benchmark report, UAT, runbooks, final acceptance | All prior phases |

## Current Phase 0 Exit Criteria

- Lab host inventory recorded with kernel, BTF, eBPF toolchain, Go, PostgreSQL, Prometheus, NIC, link, queue, route, and neighbor state.
- Required protected backend service table exists with TODO placeholders and no inferred services.
- Benchmark matrix covers drop path, allowlist miss, blacklist hit, UDP/SYN/ICMP flood, neighbor unresolved, and full DEVMAP redirect path.
- Config and secret baseline defines required env keys and redaction expectations.
- Gaps are explicit before Phase 01 and before any production readiness claim.


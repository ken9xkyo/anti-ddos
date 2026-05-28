# Ke hoach P1 MVP Anti-DDoS eBPF/XDP

Tai lieu nay la index cho bo ke hoach hoan thien P1 MVP theo phase trong thu muc `plans/`. Moi phase co mot file Markdown rieng, ghi ro muc tieu, pham vi, task cu the, muc dich, ket qua ban giao, phu thuoc, tieu chi chap nhan, cach kiem chung, truy vet PRD va rui ro chinh.

## Tong quan

- Pham vi thuc thi: P1 MVP single active scrubbing gateway tren Ubuntu 24.04.
- Data plane: XDP/eBPF verifier-safe, native XDP la muc tieu hieu nang, generic XDP chi la fallback co canh bao.
- Forwarding plane: L2 MAC rewrite + `XDP_REDIRECT` qua `BPF_MAP_TYPE_DEVMAP`; traffic sach chi toi backend/service allowlist.
- Node plane: Node Agent quan ly load/attach/rollback eBPF, policy snapshot, eBPF maps, counters/events va Prometheus metrics.
- Control plane: Control API, PostgreSQL, immutable policy snapshot, RBAC, audit va rollback.
- Management plane: Dashboard van hanh, Prometheus/Grafana va Telegram alerting.
- Ranh gioi MVP: khong L7/DPI, khong HA, khong tu dong BGP/RTBH/FlowSpec.

## Nguon tham chieu

- `docs/PRD-Anti-DDoS.md`
- `docs/System-Architecture-Design.md`
- `docs/HLD.md`
- `docs/LLD.md`

## Thu tu phase

| Phase | File | Muc dich chinh | Phu thuoc |
|---|---|---|---|
| 00 | `phase-00-foundation-lab-readiness.md` | Chot lab, topology, toolchain, benchmark input | Khong |
| 01 | `phase-01-xdp-data-plane-skeleton.md` | XDP skeleton, parser, maps, counters, verifier gate | Phase 00 |
| 02 | `phase-02-agent-lifecycle.md` | Agent load/attach/rollback, pinned maps, metrics, last-valid snapshot | Phase 01 |
| 03 | `phase-03-policy-snapshot-map-sync.md` | Canonical snapshot, checksum, capacity check, A/B map apply | Phase 01, 02 |
| 04 | `phase-04-devmap-forwarding-service-allowlist.md` | Service allowlist, neighbor/MAC resolution, L2 rewrite, DEVMAP redirect | Phase 01, 02, 03 |
| 05 | `phase-05-control-plane-core.md` | API, PostgreSQL, RBAC, audit, rollback, Agent sync | Phase 03, 04 |
| 06 | `phase-06-observability-dashboard.md` | Prometheus, sampled events, dashboard, Grafana | Phase 02, 05 |
| 07 | `phase-07-rate-limit-baseline-auto-enforce.md` | Token bucket, baseline, anomaly, auto-enforce TTL | Phase 03, 05, 06 |
| 08 | `phase-08-threat-feed-sync.md` | Hourly feed sync, dedupe, safe aggregation, whitelist conflicts | Phase 05, 06 |
| 09 | `phase-09-telegram-isp-runbook.md` | Telegram alerts, dedupe/retry, manual ISP escalation | Phase 05, 06, 07, 08 |
| 10 | `phase-10-hardening-benchmark-uat.md` | Hardening, retention, benchmark, UAT, runbooks, final acceptance | Tat ca phase truoc |

## Truy vet tong hop

| PRD | Phase chinh |
|---|---|
| PRD-001 Baseline profiling L3/L4 | Phase 07, 10 |
| PRD-002 Monitor realtime va Prometheus/Grafana | Phase 02, 06, 07, 10 |
| PRD-003 XDP/eBPF packet filtering | Phase 01, 02, 03, 10 |
| PRD-004 Rate limiting va auto-enforce TTL | Phase 07, 10 |
| PRD-005 IP reputation va blacklist aggregation | Phase 08, 10 |
| PRD-006 IP whitelist management | Phase 03, 05, 08, 10 |
| PRD-007 Dashboard quan ly protected backend services va XDP DEVMAP forwarding allowlist | Phase 04, 05, 06, 10 |
| PRD-008 Telegram alerting | Phase 09, 10 |
| PRD-009 Local RBAC, audit log va rollback | Phase 05, 07, 10 |
| PRD-010 Agent/control-plane fail-safe | Phase 02, 03, 05, 10 |
| PRD-011 Manual ISP escalation runbook | Phase 09, 10 |

## Ranh gioi P2/P3

P2/P3 chi duoc ghi nhan nhu future scope trong bo plan nay. Incident workflow nang cao, active-passive HA va upstream automation can design rieng sau khi P1 da co benchmark, UAT va quyen routing/upstream ro rang.


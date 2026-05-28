# Kế hoạch P1 MVP Anti-DDoS eBPF/XDP

Tài liệu này là chỉ mục cho bộ kế hoạch hoàn thiện P1 MVP theo từng phase trong thư mục `plans/`. Mỗi phase có một file Markdown riêng, ghi rõ mục tiêu, phạm vi, task cụ thể, mục đích, kết quả bàn giao, phụ thuộc, tiêu chí chấp nhận, cách kiểm chứng, truy vết PRD và rủi ro chính.

## Tổng quan

- Phạm vi thực thi: P1 MVP với một scrubbing gateway active đơn trên Ubuntu 24.04.
- Data plane: XDP/eBPF verifier-safe, native XDP là mục tiêu hiệu năng, generic XDP chỉ là fallback có cảnh báo.
- Forwarding plane: L2 MAC rewrite + `XDP_REDIRECT` qua `BPF_MAP_TYPE_DEVMAP`; traffic sạch chỉ tới backend/service allowlist.
- Node plane: Node Agent quản lý load/attach/rollback eBPF, policy snapshot, eBPF maps, counters/events và Prometheus metrics.
- Control plane: Control API, PostgreSQL, immutable policy snapshot, RBAC, audit và rollback.
- Management plane: dashboard vận hành, Prometheus/Grafana và Telegram alerting.
- Ranh giới MVP: không L7/DPI, không HA, không tự động BGP/RTBH/FlowSpec.

## Nguồn tham chiếu

- `docs/PRD-Anti-DDoS.md`
- `docs/System-Architecture-Design.md`
- `docs/HLD.md`
- `docs/LLD.md`

## Thứ tự phase

| Phase | File | Mục đích chính | Phụ thuộc |
|---|---|---|---|
| 00 | `phase-00-foundation-lab-readiness.md` | Chốt lab, topology, toolchain, benchmark input | Không |
| 01 | `phase-01-xdp-data-plane-skeleton.md` | XDP skeleton, parser, maps, counters, verifier gate | Phase 00 |
| 02 | `phase-02-agent-lifecycle.md` | Agent load/attach/rollback, pinned maps, metrics, last-valid snapshot | Phase 01 |
| 03 | `phase-03-policy-snapshot-map-sync.md` | Canonical snapshot, checksum, capacity check, A/B map apply | Phase 01, 02 |
| 04 | `phase-04-devmap-forwarding-service-allowlist.md` | Service allowlist, neighbor/MAC resolution, L2 rewrite, DEVMAP redirect | Phase 01, 02, 03 |
| 05 | `phase-05-control-plane-core.md` | API, PostgreSQL, RBAC, audit, rollback, Agent sync | Phase 03, 04 |
| 06 | `phase-06-observability-dashboard.md` | Prometheus, sampled events, dashboard, Grafana | Phase 02, 05 |
| 07 | `phase-07-rate-limit-baseline-auto-enforce.md` | Token bucket, baseline, anomaly, auto-enforce TTL | Phase 03, 05, 06 |
| 08 | `phase-08-threat-feed-sync.md` | Hourly feed sync, dedupe, safe aggregation, whitelist conflicts | Phase 05, 06 |
| 09 | `phase-09-telegram-isp-runbook.md` | Telegram alerts, dedupe/retry, manual ISP escalation | Phase 05, 06, 07, 08 |
| 10 | `phase-10-hardening-benchmark-uat.md` | Hardening, retention, benchmark, UAT, runbooks, final acceptance | Tất cả phase trước |

## Truy vết tổng hợp

| PRD | Phase chính |
|---|---|
| PRD-001 Baseline profiling L3/L4 | Phase 07, 10 |
| PRD-002 Monitor realtime và Prometheus/Grafana | Phase 02, 06, 07, 10 |
| PRD-003 XDP/eBPF packet filtering | Phase 01, 02, 03, 10 |
| PRD-004 Rate limiting và auto-enforce TTL | Phase 07, 10 |
| PRD-005 IP reputation và blacklist aggregation | Phase 08, 10 |
| PRD-006 IP whitelist management | Phase 03, 05, 08, 10 |
| PRD-007 Dashboard quản lý protected backend services và XDP DEVMAP forwarding allowlist | Phase 04, 05, 06, 10 |
| PRD-008 Telegram alerting | Phase 09, 10 |
| PRD-009 Local RBAC, audit log và rollback | Phase 05, 07, 10 |
| PRD-010 Agent/control-plane fail-safe | Phase 02, 03, 05, 10 |
| PRD-011 Runbook manual ISP escalation | Phase 09, 10 |

## Ranh giới P2/P3

P2/P3 chỉ được ghi nhận như future scope trong bộ plan này. Incident workflow nâng cao, active-passive HA và upstream automation cần thiết kế riêng sau khi P1 đã có benchmark, UAT và quyền routing/upstream rõ ràng.

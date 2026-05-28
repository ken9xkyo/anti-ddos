# Phase 10 - Hardening, Benchmark va UAT

## Muc tieu

Hoan thien readiness truoc khi go-live P1: security hardening, retention, failure-mode tests, benchmark native XDP/DEVMAP forwarding, UAT theo PRD-001 den PRD-011 va runbooks van hanh.

## Pham vi

- Hardening API/dashboard/Agent/config/secrets/logging.
- Retention raw events 30 ngay, aggregated metrics 90 ngay, audit log 365 ngay.
- Benchmark native XDP, fallback warning, blacklist/service/rate overhead va full DEVMAP forwarding throughput.
- UAT voi flows: allowed redirect, blacklist, whitelist conflict, service miss, redirect failure, rate limit, feed sync, Telegram, rollback, control plane outage.
- Khong cam ket SLA 10-40 Gbps neu benchmark lab/NIC chua dat va chua duoc chap thuan.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P10-T01 | Security hardening pass | Giam rui ro van hanh va lo secret | Session timeout, password policy baseline, secret redaction, secure config | Phase 05 |
| P10-T02 | Implement retention jobs | Dap ung 30/90/365 ngay | Cleanup/partition jobs cho security_events, metrics retention docs, audit archive/delete | Phase 06 |
| P10-T03 | Failure-mode test suite | Chung minh fail-safe | Tests control plane down, Agent restart, attach fail, map capacity exceeded, feed fail | Phase 02, 03, 08 |
| P10-T04 | Benchmark XDP drop path | Do gioi han data plane | Results native/generic drop pps/bps theo NIC/queue/kernel | Phase 01, 02 |
| P10-T05 | Benchmark DEVMAP forwarding path | Do hieu nang thuc te cua gateway | Results L2 rewrite + `XDP_REDIRECT` throughput, latency, CPU, packet loss | Phase 04 |
| P10-T06 | Benchmark mitigation scenarios | Do overhead khi co policy | Results blacklist LPM, service allowlist, token bucket, ringbuf sampling overhead | Phase 07, 08 |
| P10-T07 | UAT allowed/drop/service flows | Xac nhan packet behavior PRD | Evidence allowed redirect, blacklist, whitelist, service miss, malformed/fragment | Phase 04, 08 |
| P10-T08 | UAT redirect failure flows | Xac nhan fail-closed forwarding | Evidence neighbor unresolved, missing DEVMAP target, output interface down | Phase 04, 09 |
| P10-T09 | UAT observability/alerting | Xac nhan operator workflow | Evidence dashboard freshness, Grafana, Telegram, delivery log, ISP runbook | Phase 06, 09 |
| P10-T10 | UAT rollback/fail-safe | Xac nhan recover nhanh | Evidence rollback <= target khi Agent online, stale status khi API down | Phase 03, 05 |
| P10-T11 | Write operations runbooks | Chuyen giao van hanh | Runbooks attach/detach XDP, rollback, emergency disable, feed failure, ISP escalation | Phase 09 |
| P10-T12 | Final acceptance review | Chot MVP readiness | PRD checklist signed off, known limits, benchmark caveats, go/no-go | P10-T01 to P10-T11 |

## Tieu chi chap nhan

- Secrets khong xuat hien plaintext trong logs, audit diffs, API responses hoac dashboard.
- Retention jobs hoac cau hinh retention dap ung raw/security events 30 ngay, aggregated metrics 90 ngay, audit 365 ngay.
- Failure-mode tests chung minh current policy duoc giu khi Control Plane down va apply loi khong doi active policy.
- Benchmark co ket qua rieng cho native XDP drop-only, XDP plus service allowlist, rate limit va full L2 rewrite + DEVMAP forwarding path.
- UAT cover PRD-001 den PRD-011 voi evidence ro rang.
- Runbooks van hanh co attach/detach XDP, rollback, incident response, emergency disable va ISP escalation.

## Kiem chung

- Secret scan tren logs/test output/API response fixtures.
- Retention dry-run tren partition hoac timestamp cleanup.
- Automated integration suite cho failure modes va packet flows.
- Load test/traffic generator benchmark theo matrix Phase 00.
- Manual UAT voi Network/SRE/SOC/Admin personas.
- Final checklist doi chieu PRD acceptance criteria va LLD validation checklist.

## Truy vet PRD

- PRD-001: baseline profiling va recalibration acceptance.
- PRD-002: dashboard freshness, Prometheus/Grafana metrics.
- PRD-003: XDP filtering, attach fallback, verifier/load failure behavior, DEVMAP redirect behavior.
- PRD-004: rate limiting, auto-enforce TTL, rollback.
- PRD-005: hourly feed sync, dedupe, conflict, failure retention.
- PRD-006: whitelist management, expiry, audit.
- PRD-007: L2 rewrite + XDP DEVMAP forwarding va backend service allowlist.
- PRD-008: Telegram test, dedupe, retry, delivery log.
- PRD-009: RBAC, audit, rollback.
- PRD-010: keep-last-policy, stale status, Agent restart.
- PRD-011: ISP escalation alert va runbook.

## Ghi chu va rui ro

- Neu benchmark khong dat 10 Gbps, ket qua phai ghi ro bottleneck va khong cam ket SLA vuot bang chung do duoc.
- Generic XDP fallback co the dung de functional test nhung khong duoc xem la bang chung hieu nang production.
- Ringbuf sampling va top-source data la approximate; runbook phai noi ro khi dung lam evidence.
- Emergency disable phai can bang giua khoi phuc traffic hop le va rui ro mo cua attack.


# Phase 10 - Hardening, đánh giá hiệu năng và UAT

## Mục tiêu

Hoàn thiện readiness trước khi go-live P1: security hardening, retention, failure-mode tests, benchmark native XDP/DEVMAP forwarding, UAT theo PRD-001 đến PRD-011 và runbooks vận hành.

## Phạm vi

- Hardening API/dashboard/Agent/config/secrets/logging.
- Retention raw events 30 ngày, aggregated metrics 90 ngày, audit log 365 ngày.
- Đánh giá hiệu năng native XDP, fallback warning, blacklist/service/rate overhead và full DEVMAP forwarding throughput.
- UAT với flows: allowed redirect, blacklist, whitelist conflict, service miss, redirect failure, rate limit, feed sync, Telegram, rollback, control plane outage.
- Không cam kết SLA 10-40 Gbps nếu benchmark lab/NIC chưa đạt và chưa được chấp thuận.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P10-T01 | Rà soát security hardening | Giảm rủi ro vận hành và lộ secret | Session timeout, password policy baseline, secret redaction, secure config | Phase 05 |
| P10-T02 | Triển khai retention jobs | Đáp ứng 30/90/365 ngày | Cleanup/partition jobs cho security_events, metrics retention docs, audit archive/delete | Phase 06 |
| P10-T03 | Bộ kiểm thử failure-mode | Chứng minh fail-safe | Tests control plane down, Agent restart, attach fail, map capacity exceeded, feed fail | Phase 02, 03, 08 |
| P10-T04 | Đánh giá hiệu năng XDP drop path | Đo giới hạn data plane | Kết quả native/generic drop pps/bps theo NIC/queue/kernel | Phase 01, 02 |
| P10-T05 | Đánh giá hiệu năng DEVMAP forwarding path | Đo hiệu năng thực tế của gateway | Kết quả L2 rewrite + `XDP_REDIRECT` throughput, latency, CPU, packet loss | Phase 04 |
| P10-T06 | Đánh giá hiệu năng mitigation scenarios | Đo overhead khi có policy | Kết quả blacklist LPM, service allowlist, token bucket, ringbuf sampling overhead | Phase 07, 08 |
| P10-T07 | UAT allowed/drop/service flows | Xác nhận packet behavior PRD | Evidence allowed redirect, blacklist, whitelist, service miss, malformed/fragment | Phase 04, 08 |
| P10-T08 | UAT redirect failure flows | Xác nhận fail-closed forwarding | Evidence neighbor unresolved, missing DEVMAP target, output interface down | Phase 04, 09 |
| P10-T09 | UAT observability/alerting | Xác nhận operator workflow | Evidence dashboard freshness, Grafana, Telegram, delivery log, ISP runbook | Phase 06, 09 |
| P10-T10 | UAT rollback/fail-safe | Xác nhận recover nhanh | Evidence rollback <= target khi Agent online, stale status khi API down | Phase 03, 05 |
| P10-T11 | Viết operations runbooks | Chuyển giao vận hành | Runbooks attach/detach XDP, rollback, emergency disable, feed failure, ISP escalation | Phase 09 |
| P10-T12 | Review nghiệm thu cuối | Chốt MVP readiness | PRD checklist signed off, known limits, benchmark caveats, go/no-go | P10-T01 to P10-T11 |

## Tiêu chí chấp nhận

- Secrets không xuất hiện plaintext trong logs, audit diffs, API responses hoặc dashboard.
- Retention jobs hoặc cấu hình retention đáp ứng raw/security events 30 ngày, aggregated metrics 90 ngày, audit 365 ngày.
- Các kiểm thử failure-mode chứng minh current policy được giữ khi Control Plane down và apply lỗi không đổi active policy.
- Đánh giá hiệu năng có kết quả riêng cho native XDP drop-only, XDP plus service allowlist, rate limit và full L2 rewrite + DEVMAP forwarding path.
- UAT cover PRD-001 đến PRD-011 với evidence rõ ràng.
- Runbooks vận hành có attach/detach XDP, rollback, incident response, emergency disable và ISP escalation.

## Kiểm chứng

- Secret scan trên logs/test output/API response fixtures.
- Retention dry-run trên partition hoặc timestamp cleanup.
- Automated integration suite cho failure modes và packet flows.
- Load test/traffic generator benchmark theo matrix Phase 00.
- Manual UAT với Network/SRE/SOC/Admin personas.
- Checklist cuối đối chiếu PRD acceptance criteria và LLD validation checklist.

## Truy vết PRD

- PRD-001: baseline profiling và recalibration acceptance.
- PRD-002: dashboard freshness, Prometheus/Grafana metrics.
- PRD-003: XDP filtering, attach fallback, verifier/load failure behavior, DEVMAP redirect behavior.
- PRD-004: rate limiting, auto-enforce TTL, rollback.
- PRD-005: hourly feed sync, dedupe, conflict, failure retention.
- PRD-006: whitelist management, expiry, audit.
- PRD-007: L2 rewrite + XDP DEVMAP forwarding và backend service allowlist.
- PRD-008: Telegram test, dedupe, retry, delivery log.
- PRD-009: RBAC, audit, rollback.
- PRD-010: keep-last-policy, stale status, Agent restart.
- PRD-011: ISP escalation alert và runbook.

## Ghi chú và rủi ro

- Nếu benchmark không đạt 10 Gbps, kết quả phải ghi rõ bottleneck và không cam kết SLA vượt bằng chứng đo được.
- Generic XDP fallback có thể dùng để functional test nhưng không được xem là bằng chứng hiệu năng production.
- Ringbuf sampling và top-source data là approximate; runbook phải nói rõ khi dùng làm evidence.
- Emergency disable phải cân bằng giữa khôi phục traffic hợp lệ và rủi ro mở cửa attack.

# Phase 07 - Rate Limit, Baseline và Auto-Enforce

## Mục tiêu

Hoàn thiện mitigation tự động cho P1: token bucket rate limit trong XDP, baseline profiling L3/L4, anomaly evaluator, auto-enforce rule có TTL/evidence và rollback qua Control Plane.

## Phạm vi

- Token bucket theo source/service/rule/protocol trong `rate_state` LRU hash.
- Rate thresholds: pps, bps, cps approximated bằng TCP SYN packets.
- Observe mode chỉ đếm/events, enforce mode drop over-limit.
- Baseline từ Prometheus recording/rates theo service/interface/protocol/port/time window.
- Auto-enforce tạo rule/snapshot thông qua Control Plane, không bypass audit.
- Whitelist conflict phải chặn auto-enforce với source/prefix liên quan.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P07-T01 | Chốt rule map value và selector | XDP biết rule nào áp dụng | `rule_value` fields action/mode/thresholds/burst/TTL metadata | Phase 03 |
| P07-T02 | Triển khai token bucket packet/byte | Drop over-limit theo pps/bps | XDP helper refill/decrement tokens với bounded logic | P07-T01 |
| P07-T03 | Triển khai CPS/SYN bucket | Phát hiện SYN flood | SYN without ACK counter/token logic theo threshold_cps | P07-T02 |
| P07-T04 | Triển khai observe mode counters/events | Thu thập evidence không drop | Observe path update counters và sampled events, return redirect/pass decision unchanged | P07-T02 |
| P07-T05 | Triển khai enforce mode decisions | Mitigation thật sự trong XDP | Drop over-limit với `REASON_RATE_LIMIT` hoặc `REASON_RULE_DROP` | P07-T04 |
| P07-T06 | Thêm baseline profile schema/API | Lưu baseline được approve | `baseline_profiles`, approve/recalibrate endpoints | Phase 05 |
| P07-T07 | Thêm Prometheus recording queries | Tạo input cho anomaly | Rules cho 1m/5m pps,bps,cps, drop ratio, protocol mix | Phase 06 |
| P07-T08 | Triển khai anomaly evaluator | Chuyển metrics thành alert/mitigation candidate | Weighted score, confidence, evidence, affected service | P07-T07 |
| P07-T09 | Triển khai auto-enforce policy gate | Giảm false positive | Gate min confidence, evidence, TTL bounds, whitelist conflict check | P07-T08 |
| P07-T10 | Triển khai TTL expiry scheduler | Rule hết hạn tự disable | Scheduler disables expired rules, audit, new snapshot | P07-T09 |
| P07-T11 | Triển khai kiểm thử rollback lifecycle | Đảm bảo undo nhanh | Kịch bản rollback từ active auto-rule về previous snapshot | P07-T10 |
| P07-T12 | Đưa trạng thái anomaly/rule lên dashboard | Operator thấy rule đang làm gì | API/UI data cho anomaly score, active rule, TTL, affected service | P07-T08 |

## Tiêu chí chấp nhận

- Observe rule không drop packet nhưng tăng counters/events.
- Enforce `rate_limit` drop packet vượt ngưỡng pps/bps/cps và cho packet trong ngưỡng tiếp tục redirect.
- `drop` action drop mọi packet matching rule mà không cần token bucket.
- Baseline chưa đủ 24h history dùng default thresholds và đánh dấu confidence thấp.
- Auto-enforce rule chỉ tạo khi có evidence, confidence đạt ngưỡng, TTL trong bound và không conflict whitelist.
- TTL expiry disable rule, ghi audit và tạo snapshot mới.

## Kiểm chứng

- Packet tests cho token bucket: under limit redirect/pass, over limit drop, refill theo thời gian.
- SYN flood test xác nhận cps threshold kích hoạt với SYN without ACK.
- Observe/enforce integration test qua VETH/namespace.
- Baseline unit tests cho low-confidence default và approved baseline.
- Auto-enforce tests cho confidence thấp, thiếu evidence, whitelist conflict, TTL expiry.
- Rollback test xác nhận apply snapshot rollback trong mục tiêu khi Agent online.

## Truy vết PRD

- PRD-001: baseline profiling L3/L4 và recalibration approval.
- PRD-002: anomaly score, active rule, TTL và affected service visibility.
- PRD-004: rate limiting và auto-enforce TTL.
- PRD-006: whitelist conflict ngăn auto-enforce sai.
- PRD-009: audit và rollback rule.
- PRD-010: snapshot apply và fail-safe khi rollback/TTL update.

## Ghi chú và rủi ro

- XDP không nên có loop phức tạp để select nhiều rule; nếu rule selection lớn, cần priority/default rule strategy hoặc tail-call sau.
- Rate state LRU eviction có thể reset attacker state; burst/mặc định phải conservative.
- CPS trong MVP là SYN rate approximation, không phải established TCP connection count.
- Auto-enforce default nên balanced, ưu tiên TTL ngắn và rollback để giảm false positive.

# Phase 07 - Rate Limit, Baseline va Auto-Enforce

## Muc tieu

Hoan thien mitigation tu dong cho P1: token bucket rate limit trong XDP, baseline profiling L3/L4, anomaly evaluator, auto-enforce rule co TTL/evidence va rollback qua Control Plane.

## Pham vi

- Token bucket theo source/service/rule/protocol trong `rate_state` LRU hash.
- Rate thresholds: pps, bps, cps approximated bang TCP SYN packets.
- Observe mode chi dem/events, enforce mode drop over-limit.
- Baseline tu Prometheus recording/rates theo service/interface/protocol/port/time window.
- Auto-enforce tao rule/snapshot thong qua Control Plane, khong bypass audit.
- Whitelist conflict phai chan auto-enforce voi source/prefix lien quan.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P07-T01 | Finalize rule map value va selector | XDP biet rule nao ap dung | `rule_value` fields action/mode/thresholds/burst/TTL metadata | Phase 03 |
| P07-T02 | Implement token bucket packet/byte | Drop over-limit theo pps/bps | XDP helper refill/decrement tokens voi bounded logic | P07-T01 |
| P07-T03 | Implement CPS/SYN bucket | Phat hien SYN flood | SYN without ACK counter/token logic theo threshold_cps | P07-T02 |
| P07-T04 | Implement observe mode counters/events | Thu thap evidence khong drop | Observe path update counters va sampled events, return redirect/pass decision unchanged | P07-T02 |
| P07-T05 | Implement enforce mode decisions | Mitigation that su trong XDP | Drop over-limit voi `REASON_RATE_LIMIT` hoac `REASON_RULE_DROP` | P07-T04 |
| P07-T06 | Add baseline profile schema/API | Luu baseline duoc approve | `baseline_profiles`, approve/recalibrate endpoints | Phase 05 |
| P07-T07 | Add Prometheus recording queries | Tao input cho anomaly | Rules cho 1m/5m pps,bps,cps, drop ratio, protocol mix | Phase 06 |
| P07-T08 | Implement anomaly evaluator | Chuyen metrics thanh alert/mitigation candidate | Weighted score, confidence, evidence, affected service | P07-T07 |
| P07-T09 | Implement auto-enforce policy gate | Giam false positive | Gate min confidence, evidence, TTL bounds, whitelist conflict check | P07-T08 |
| P07-T10 | Implement TTL expiry scheduler | Rule het han tu disable | Scheduler disables expired rules, audit, new snapshot | P07-T09 |
| P07-T11 | Implement rollback lifecycle test | Dam bao undo nhanh | Test rollback from active auto-rule to previous snapshot | P07-T10 |
| P07-T12 | Surface anomaly/rule state to dashboard | Operator thay rule dang lam gi | API/UI data cho anomaly score, active rule, TTL, affected service | P07-T08 |

## Tieu chi chap nhan

- Observe rule khong drop packet nhung tang counters/events.
- Enforce `rate_limit` drop packet vuot nguong pps/bps/cps va cho packet trong nguong tiep tuc redirect.
- `drop` action drop moi packet matching rule ma khong can token bucket.
- Baseline chua du 24h history dung default thresholds va danh dau confidence thap.
- Auto-enforce rule chi tao khi co evidence, confidence dat nguong, TTL trong bound va khong conflict whitelist.
- TTL expiry disable rule, ghi audit va tao snapshot moi.

## Kiem chung

- Packet tests cho token bucket: under limit redirect/pass, over limit drop, refill theo thoi gian.
- SYN flood test xac nhan cps threshold kich hoat voi SYN without ACK.
- Observe/enforce integration test qua VETH/namespace.
- Baseline unit tests cho low-confidence default va approved baseline.
- Auto-enforce tests cho confidence thap, thieu evidence, whitelist conflict, TTL expiry.
- Rollback test xac nhan apply snapshot rollback trong muc tieu khi Agent online.

## Truy vet PRD

- PRD-001: baseline profiling L3/L4 va recalibration approval.
- PRD-002: anomaly score, active rule, TTL va affected service visibility.
- PRD-004: rate limiting va auto-enforce TTL.
- PRD-006: whitelist conflict ngan auto-enforce sai.
- PRD-009: audit va rollback rule.
- PRD-010: snapshot apply va fail-safe khi rollback/TTL update.

## Ghi chu va rui ro

- XDP khong nen co loop phuc tap de select nhieu rule; neu rule selection lon, can priority/default rule strategy hoac tail-call sau.
- Rate state LRU eviction co the reset attacker state; burst/mac dinh phai conservative.
- CPS trong MVP la SYN rate approximation, khong phai established TCP connection count.
- Auto-enforce default nen balanced, uu tien TTL ngan va rollback de giam false positive.


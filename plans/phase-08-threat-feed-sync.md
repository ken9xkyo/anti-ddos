# Phase 08 - Threat Feed Sync

## Mục tiêu

Đồng bộ IP/CIDR reputation feeds bắt buộc cho P1, normalize/dedupe/aggregate an toàn, tạo conflict report với whitelist và đưa effective blacklist vào policy snapshot mới mỗi 1 giờ hoặc theo interval cấu hình.

## Phạm vi

- Scheduler theo source interval, default 1 giờ.
- Feed source metadata: URL, enabled, interval, license/quota note, secret ref, last status.
- Parser cho Spamhaus DROP, Team Cymru/bogon, AbuseIPDB và internal HTTP JSON.
- Safe CIDR aggregation chỉ merge khi cùng source/action/score/TTL và không có whitelist conflict trong prefix rộng hơn.
- Feed failure giữ last valid source snapshot và alert nếu lỗi kéo dài.
- AbuseIPDB key và feed secrets không log plaintext.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P08-T01 | Triển khai feed source schema/API | Quản lý nguồn reputation | `feed_sources`, CRUD config, secret ref, interval, license note | Phase 05 |
| P08-T02 | Triển khai scheduler và locking | Chạy sync đúng chu kỳ, không overlap | Hourly scheduler, per-source run lock, run status | P08-T01 |
| P08-T03 | Triển khai fetch client timeout/retry | Không treo scheduler khi feed lỗi | HTTP clients với timeout, auth header từ secret ref | P08-T02 |
| P08-T04 | Triển khai Spamhaus DROP parser | Đưa Spamhaus vào blacklist | Parser plain text CIDR, comments, source metadata | P08-T03 |
| P08-T05 | Triển khai Team Cymru/bogon parser | Đưa bogon/invalid source vào blacklist | Parser CIDR/bogon feed, source metadata | P08-T03 |
| P08-T06 | Triển khai AbuseIPDB parser/client | Đưa reputation API vào pipeline | Client/parser theo config quota, score, TTL | P08-T03 |
| P08-T07 | Triển khai internal HTTP JSON parser | Hỗ trợ feed nội bộ | Parser IP/CIDR, score, action, TTL, reason, source metadata | P08-T03 |
| P08-T08 | Triển khai normalize/dedupe | Loại duplicate và invalid entries | CIDR validation IPv4, source metadata, score/action/TTL | P08-T04, P08-T05, P08-T06, P08-T07 |
| P08-T09 | Triển khai safe CIDR aggregation | Giảm map entries không broaden sai | Aggregator chỉ merge khi source/action/score/TTL safe | P08-T08 |
| P08-T10 | Triển khai whitelist conflict report | Giữ whitelist precedence | `feed_conflicts`, suppressed entries, UI/API output | P08-T09 |
| P08-T11 | Tạo effective blacklist snapshot | Đưa reputation vào XDP maps | Snapshot builder include blacklist minus whitelist-suppressed conflicts | P08-T10 |
| P08-T12 | Triển khai feed failure behavior | Không xóa rule đang enforce khi lỗi | Keep last valid, record `feed_runs`, alert candidate | P08-T02 |
| P08-T13 | Thêm feed UI/metrics | Operator thấy last sync/errors/quota | Dashboard feed status và Prometheus feed metrics | Phase 06 |

## Tiêu chí chấp nhận

- Scheduler sync enabled feeds theo interval cấu hình, default 1 giờ.
- Invalid IP/CIDR bị reject có parse error count, không làm fail cả run nếu còn entries hợp lệ.
- Duplicate CIDR được dedupe, adjacent CIDR chỉ aggregate khi safe.
- Entry conflict whitelist không được enforce trong effective blacklist và có conflict report.
- Feed failure giữ last valid snapshot và không xóa blacklist đang enforce nếu chưa có snapshot mới hợp lệ.
- Feed status, items fetched, errors, active entries và conflicts hiện trên metrics/dashboard.

## Kiểm chứng

- Fixture tests cho Spamhaus DROP, Team Cymru/bogon, AbuseIPDB và internal feed.
- Aggregation tests cho merge safe và không merge khi TTL/source/score khác hoặc có whitelist inside.
- Kiểm thử lỗi timeout, invalid auth, malformed payload và partial invalid entries.
- Snapshot diff test xác nhận chỉ build version mới khi effective set thay đổi.
- UI/API test xác nhận conflict report và feed run history.

## Truy vết PRD

- PRD-005: IP reputation và blacklist aggregation mỗi 1 giờ.
- PRD-006: whitelist precedence và conflict report.
- PRD-008: feed failure cảnh báo qua alert pipeline sau Phase 09.
- PRD-009: feed config changes có audit.
- PRD-010: feed failure giữ last valid snapshot.

## Ghi chú và rủi ro

- Feed license/quota/update interval phải được lưu và tôn trọng; không hard-code gọi quá tần suất cho phép.
- CIDR aggregation sai có thể block rộng hơn ý định; nếu uncertain thì giữ prefix hẹp.
- AbuseIPDB có quota/API semantics thay đổi theo account; cần cấu hình timeout và rate limit riêng.
- Feed secrets phải dùng secret ref/encrypted storage, không đưa vào audit diff plaintext.

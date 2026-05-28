# Phase 03 - Policy Snapshot và Map Sync

## Mục tiêu

Thiết kế và triển khai luồng apply immutable policy snapshot vào eBPF maps một cách atomic: validate checksum/version/capacity, populate inactive slot, populate `tx_devmap`, flip `runtime_config`, ack thành công hoặc giữ policy cũ khi lỗi.

## Phạm vi

- Snapshot là canonical JSON có version tăng dần và checksum.
- Agent validate feature flags, TTL, map capacity, memory estimate, DEVMAP target và compatibility với XDP object.
- Policy maps cần atomic replacement dùng A/B double-buffer: whitelist, blacklist, service allowlist, rule config.
- Shared maps như `tx_devmap`, rate state, counters, events không clear tùy tiện; update có validate và rollback theo snapshot.
- Control API đầy đủ nằm ở Phase 05; phase này có local/mock snapshot builder để test map sync.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P03-T01 | Định nghĩa schema snapshot canonical | Làm hợp đồng chung giữa API và Agent | JSON schema cho version, checksum, rules, whitelist, blacklist, services, xdp_config | Phase 02 |
| P03-T02 | Triển khai checksum canonical | Phát hiện snapshot bị sửa/hỏng | Canonical encoder và SHA checksum verifier | P03-T01 |
| P03-T03 | Triển khai version và compatibility checks | Tránh apply snapshot cũ hoặc không support | Validation version monotonic, feature flags, object version | P03-T02 |
| P03-T04 | Triển khai capacity và memory estimator | Tránh map đầy hoặc memory vượt budget | Estimator entries/memory cho LPM, service, rules, runtime, devmap | P03-T01 |
| P03-T05 | Kiểm tra service redirect target input | Chặn snapshot có route/ifindex/MAC không hợp lệ | Kiểm tra output ifindex, devmap key, resolved MAC, neighbor status | P03-T04 |
| P03-T06 | Triển khai inactive-slot clear/populate | Không lộ policy partial trên hot path | Map writer cho whitelist/blacklist/service/rules inactive slot | P03-T05 |
| P03-T07 | Populate `tx_devmap` safely | Đảm bảo redirect target sẵn sàng trước runtime flip | Devmap updater với output ifindex và failure reason | P03-T05 |
| P03-T08 | Triển khai runtime flip | Chuyển policy atomic trong XDP | Update `runtime_config[0]` active slot và policy version | P03-T06, P03-T07 |
| P03-T09 | Triển khai failure rollback cho inactive slot | Lỗi populate không ảnh hưởng active slot | Clear inactive slot, report failure, giữ current policy | P03-T06 |
| P03-T10 | Persist local last-valid snapshot sau apply | Hỗ trợ restart fail-safe | Local snapshot store chỉ ghi sau runtime flip success | P03-T08 |
| P03-T11 | Triển khai apply ack/failure payload | Control Plane biết trạng thái apply | Ack có version, status, map stats, redirect stats, error reason | P03-T09 |
| P03-T12 | Kiểm thử whitelist/blacklist precedence input | Đảm bảo whitelist precedence trước blacklist/rate limit | Snapshot fixture conflict và expected active maps | P03-T06 |

## Tiêu chí chấp nhận

- Snapshot sai checksum, version cũ, unsupported feature, redirect target sai hoặc vượt capacity bị reject trước khi ghi active policy.
- Lỗi khi populate inactive slot hoặc `tx_devmap` không đổi active slot và không đổi packet decision.
- Runtime flip chỉ thực hiện sau khi tất cả inactive policy maps và redirect targets validate/populate thành công.
- Last-valid snapshot chỉ được persist sau apply thành công.
- Apply ack/failure có reason đủ để dashboard/API hiển thị và audit.
- Whitelist precedence được encode trong effective snapshot hoặc XDP decision order đúng thiết kế.

## Kiểm chứng

- Unit test checksum canonical với JSON field order khác nhau nhưng nội dung giống nhau.
- Unit test reject snapshot vượt capacity của `blacklist_lpm`, `service_allowlist`, `rule_config`, `tx_devmap`.
- Integration test populate fail giữa chừng và xác nhận `runtime_config.active_slot` không đổi.
- Integration test missing/invalid devmap target và unresolved neighbor bị reject hoặc apply fail rõ reason.
- Khởi động lại Agent sau apply thành công, xác nhận load local last-valid snapshot và active version đúng.
- Packet test whitelist conflict blacklist: source trong whitelist vẫn bypass blacklist/rate-limit nhưng không bypass service allowlist.

## Truy vết PRD

- PRD-004: rule TTL và rollback lifecycle cần snapshot versioning.
- PRD-005: blacklist effective set apply qua snapshot.
- PRD-006: whitelist precedence và expiry input.
- PRD-007: service allowlist và DEVMAP target apply without restart.
- PRD-009: policy versioning làm nền tảng rollback/audit.
- PRD-010: keep-last-policy fail-safe.

## Ghi chú và rủi ro

- XDP không nên phụ thuộc wall-clock expiry nếu không có time source đáng tin; Control Plane và Agent remove expired entries khi build snapshot.
- Double-buffer clear old slot nên thực hiện sau ack success hoặc async để giảm thời gian apply.
- LPM trie và `rate_state` capacity lớn cần validate locked memory và kernel limits.
- Partial apply strategy duy nhất được chấp nhận trong MVP là reject và giữ policy cũ.

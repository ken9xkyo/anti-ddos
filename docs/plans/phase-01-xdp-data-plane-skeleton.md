# Phase 01 - XDP Data Plane Skeleton

## Mục tiêu

Xây dựng chương trình XDP tối thiểu nhưng verifier-safe: parse Ethernet/IPv4/TCP/UDP/ICMP, khai báo map contracts, đếm pass/drop/redirect, xử lý malformed/fragment theo policy và load được bằng libbpf. Phase này tạo packet path nền tảng cho blacklist, service allowlist, DEVMAP redirect và rate limit.

## Phạm vi

- Viết XDP C/libbpf object với `SEC("xdp") xdp_entry`.
- Định nghĩa shared structs: `packet_meta`, action, reason, runtime config, LPM key, service key/value, rule/rate/counter/event records.
- Khai báo maps đúng LLD: whitelist/blacklist LPM, service allowlist A/B, `tx_devmap`, rate state, rule config, per-CPU counters, ringbuf, runtime config.
- Parser support IPv4 trong MVP; IPv6 chỉ reserve type/schema, chưa enforce.
- Chưa triển khai Agent full lifecycle; load/verifier test có thể dùng harness/toy loader.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P01-T01 | Tạo source layout cho data plane | Tách rõ kernel eBPF code và shared headers | Thư mục data plane, shared headers, build target XDP object | Phase 00 |
| P01-T02 | Định nghĩa enum action/reason/protocol | Đảm bảo counters/events thống nhất với API sau này | Header có `ACTION_*`, `REASON_*`, `L4_*` theo LLD | P01-T01 |
| P01-T03 | Định nghĩa `packet_meta` zero-initialized | Tránh verifier lỗi uninitialized stack | Struct compact có src/dst, ports, proto, flags, action, reason | P01-T02 |
| P01-T04 | Khai báo maps với max entries mặc định | Có contract kernel/userspace rõ ràng | Map definitions cho runtime, LPM, service, `tx_devmap`, rules, rate, counters, events | P01-T02 |
| P01-T05 | Triển khai Ethernet và IPv4 parser bounds-check | Đọc header an toàn trước `data_end` | Function parse L2/L3 trả ok/malformed/fragment | P01-T03 |
| P01-T06 | Triển khai TCP/UDP/ICMP parser bounds-check | Lấy dst port, src port, SYN flags an toàn | Function parse L4, handle fragments/unknown protocol | P01-T05 |
| P01-T07 | Triển khai malformed và fragment default drop | Fail-closed khi không đủ header match service | Logic `REASON_MALFORMED`, `REASON_FRAGMENT`, counter và `XDP_DROP` | P01-T06 |
| P01-T08 | Triển khai counter update per-CPU | Giảm contention trên hot path | Helper count packets/bytes theo reason/action/proto/service/rule | P01-T04 |
| P01-T09 | Triển khai sampled ringbuf event stub | Đặt nền cho sampled security events | `maybe_sample` có ringbuf reserve/submit và dropped-event counter | P01-T08 |
| P01-T10 | Thêm safe runtime-config missing behavior | Tránh chạy với policy không hợp lệ | Thiếu `runtime_config` thì count `REASON_MAP_ERROR` và `XDP_DROP` | P01-T08 |
| P01-T11 | Thiết lập build và verifier log gate | Bắt lỗi verifier sớm | Lệnh build, verbose verifier output, xlated dump nếu cần | P01-T10 |
| P01-T12 | Packet unit tests bằng fixture | Chống regression parser | Tests malformed Ethernet/IP, TCP/UDP/ICMP, fragments, unknown protocol | P01-T11 |

## Tiến độ thực hiện

Ngày cập nhật: 2026-05-28

Evidence chính: `make phase1-verify` PASS; report ở `reports/phase-01-xdp-data-plane-skeleton.md`; verifier log ở `build/bpf/verifier.log`. Phase này chỉ build/load/test-run bằng libbpf, không attach XDP vào interface thật hoặc veth.

| ID | Status | Evidence |
|---|---|---|
| P01-T01 | Done | Tạo layout `bpf/`, `include/anti_ddos/`, `tests/phase01/`, root `Makefile`. |
| P01-T02 | Done | `include/anti_ddos/bpf_contract.h` định nghĩa `ACTION_*`, `REASON_*`, `L4_*`. |
| P01-T03 | Done | `packet_meta` trong shared contract và XDP entry dùng zero-initialized stack struct. |
| P01-T04 | Done | BPF maps khai báo đủ runtime, LPM A/B, service A/B, `tx_devmap`, rate, rules, counters, events, `prog_array`; harness validate type/max_entries. |
| P01-T05 | Done | Parser Ethernet/IPv4 bounds-check trước khi đọc header và drop malformed. |
| P01-T06 | Done | Parser TCP/UDP/ICMP bounds-check, lấy ports/flags khi header đủ, unknown protocol không đọc L4. |
| P01-T07 | Done | Malformed và fragment default `XDP_DROP` với `REASON_MALFORMED`/`REASON_FRAGMENT`. |
| P01-T08 | Done | `drop_counters` per-CPU hash cập nhật packets/bytes theo reason/action/proto/service/rule. |
| P01-T09 | Done | `maybe_sample` ringbuf reserve/submit theo `sample_denom`; reserve failure chỉ tăng counter sample error. |
| P01-T10 | Done | `runtime_config[0]` chưa initialized (`policy_version == 0`) fail-closed `XDP_DROP` + `REASON_MAP_ERROR`. |
| P01-T11 | Done | `make phase1-build`, `make phase1-test`, `make phase1-verify`; verifier log captured. |
| P01-T12 | Done | Fixtures pass: missing runtime config, truncated Ethernet payload, malformed IPv4/IHL, IPv4 fragment, TCP SYN, UDP, ICMP, unknown IPv4 protocol, non-IPv4 pass. |

## Tiêu chí chấp nhận

- XDP object build được bằng clang target BPF và load được trong lab.
- Mọi packet pointer access đều có bounds check trước khi đọc.
- Tất cả stack structs được zero-init; không có verifier lỗi uninitialized stack.
- Nếu `runtime_config` thiếu, XDP fail-closed bằng `XDP_DROP` với counter `REASON_MAP_ERROR`.
- Malformed và fragment packet bị drop mặc định và tăng counter riêng.
- Ringbuf failure chỉ tăng dropped-event counter, không thay đổi packet decision.

## Kiểm chứng

- Biên dịch XDP object với debug symbols và BTF.
- Load object với verbose verifier log; không có `invalid mem access`, `R0 !read_ok`, `unreachable insn`.
- Chạy lại fixture malformed và valid packets qua XDP test harness hoặc network namespace.
- Kiểm tra maps bằng `bpftool map` để xác nhận type và max entries đúng contract.
- Kiểm tra program bằng `bpftool prog dump xlated` nếu cần để xác nhận không có loop không bounded.

## Truy vết PRD

- PRD-002: tạo counters và ringbuf làm nguồn metrics/events.
- PRD-003: XDP/eBPF packet filtering, malformed handling, verifier-safe data plane.
- PRD-007: đặt nền `service_allowlist` và `tx_devmap` maps cho forwarding policy.
- PRD-010: fail-safe khi runtime config/policy không hợp lệ.

## Ghi chú và rủi ro

- Không đưa logic phức tạp vào XDP skeleton nếu làm tăng rủi ro verifier; rate limit và feed policy nằm ở phase sau.
- LPM trie và per-CPU maps cần ước lượng memory trước khi load capacity lớn.
- Fragment handling giữ rõ: MVP drop default, không reassembly.
- Top-source exact accounting không nằm trong XDP hot path; dùng sampled events và counters để tránh cardinality/memory cao.

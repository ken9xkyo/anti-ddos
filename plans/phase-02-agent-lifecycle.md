# Phase 02 - Agent Lifecycle

## Mục tiêu

Xây dựng Node Agent để quản lý lifecycle data plane: load/attach native XDP, fallback có cảnh báo, pin maps, rollback program, đọc counters/events, expose `/metrics` và giữ last-valid snapshot khi Control Plane không sẵn sàng.

## Phạm vi

- Agent là process chạy trên scrubbing node Ubuntu 24.04.
- Quản lý eBPF object C/libbpf thông qua libbpf binding hoặc wrapper phù hợp.
- Attach vào WAN interface, ưu tiên native XDP; generic fallback chỉ khi policy cho phép.
- Pin maps/program metadata để hỗ trợ restart, debug và rollback.
- Đọc per-CPU counters, ringbuf events, map utilization và expose Prometheus metrics tối thiểu.
- Chưa cần Control Plane API đầy đủ; có local/mock snapshot để test restart và fail-safe.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P02-T01 | Tạo Agent service skeleton | Có runtime quản lý XDP riêng biệt | Binary agent, config loader, ghi log có cấu trúc, signal handling | Phase 01 |
| P02-T02 | Load eBPF object và discover maps | Kết nối userspace với data plane | Loader load object, lấy program/map handles, validate object version | P02-T01 |
| P02-T03 | Attach native XDP vào WAN interface | Đặt filtering ở ingress sớm nhất | Attach flow native mode với status metric | P02-T02 |
| P02-T04 | Triển khai fallback generic theo config | Vẫn có chế độ chạy khi native fail | Fallback logic, performance warning, attach error counter | P02-T03 |
| P02-T05 | Pin maps và program metadata | Hỗ trợ restart/debug/rollback | Pin path convention, program version/checksum metadata | P02-T02 |
| P02-T06 | Rollback program khi load/attach fail | Không làm mất data plane đang chạy | Previous-program retention và rollback procedure | P02-T05 |
| P02-T07 | Đọc per-CPU counters định kỳ | Biến XDP counters thành metrics | Counter aggregator packets/bytes theo labels bounded | P02-T02 |
| P02-T08 | Consume ringbuf events | Đẩy sampled security events lên pipeline sau | Ringbuf consumer có backpressure và reconnect handling | P02-T02 |
| P02-T09 | Công bố `/metrics` | Prometheus scrape được Agent | Metrics endpoint cho health, mode, counters, map utilization | P02-T07 |
| P02-T10 | Lưu và load last-valid snapshot local | Đảm bảo restart không cần Control Plane ngay | Snapshot file/db local, checksum verification | P02-T01 |
| P02-T11 | Triển khai healthcheck và safe detach policy | Vận hành an toàn khi stop/restart | Health endpoint, uptime metric, optional detach theo config | P02-T09 |
| P02-T12 | Redact sensitive config/log values | Tránh lộ secret từ agent logs | Log redaction cho token, key, DSN sensitive | P02-T01 |

## Tiêu chí chấp nhận

- Agent attach XDP native thành công trên interface cấu hình, hoặc fallback generic có metric/cảnh báo khi policy cho phép.
- Load/attach failure không detach program đang chạy nếu rollback không thành công.
- `/metrics` expose agent up, XDP mode, attach errors, packet counters, redirect counters và map utilization.
- Agent restart có thể load last-valid snapshot local trước khi sync snapshot mới.
- Ringbuf consumer không block packet path và có counter cho event dropped/consume errors.

## Kiểm chứng

- Chạy Agent trong lab với VETH hoặc NIC test, xác nhận XDP program attach bằng `ip link` và `bpftool prog`.
- Kill/restart Agent, xác nhận program/map state không bị mất ngoài detach policy đã cấu hình.
- Ép native attach fail trên interface không hỗ trợ để xác nhận fallback/cảnh báo.
- Kiểm tra `/metrics` và xác nhận metric names/labels bounded.
- Tạo ringbuf event từ packet fixture và xác nhận Agent consume không crash.

## Truy vết PRD

- PRD-002: Agent metrics endpoint và map utilization.
- PRD-003: native XDP attach, fallback, load failure handling.
- PRD-007: expose redirect/neighbor metrics groundwork.
- PRD-010: last-valid snapshot, control-plane fail-safe, agent restart behavior.

## Ghi chú và rủi ro

- Nếu Go binding không hỗ trợ libbpf feature cần dùng, bọc C/libbpf nhỏ và giữ API userspace ổn định.
- Safe detach cần theo policy: production thường không tự detach khi stop nếu điều đó làm backend mất protection.
- Prometheus labels không được chứa raw source IP/CIDR để tránh cardinality cao.
- Log phải redact secret/config sensitive ngay từ phase này.

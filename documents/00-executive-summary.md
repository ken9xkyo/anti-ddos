# Executive Summary

## Mục Tiêu Hệ Thống

Anti-DDoS Scrubbing Gateway là hệ thống lọc DDoS L3/L4 đặt trước các backend service. Lưu lượng IPv4 đi vào WAN NIC được xử lý sớm bằng XDP/eBPF để giảm tải kernel networking stack và chỉ chuyển tiếp traffic hợp lệ tới backend bằng L2 MAC rewrite cộng `XDP_REDIRECT` qua `DEVMAP`.

Hệ thống hiện tại tập trung vào MVP một node Ubuntu 24.04, native XDP, IPv4, Control API, PostgreSQL, Admin Dashboard, Prometheus/Grafana, sampled security events, audit, alerting và Multi-Tenant RBAC.

## Điều Hệ Thống Có Và Không Có

| Có | Không có trong scope hiện tại |
|---|---|
| Lọc IPv4 L3/L4 ở XDP hot path | Không terminate TLS |
| Protected service allowlist theo destination IP/protocol/port | Không proxy HTTP |
| Whitelist, blacklist, UDP reflection source-port block | Không xử lý L7/DPI |
| Token bucket rate limit theo source/service/source_service | Không thay thế WAF |
| Policy snapshot versioned, checksum, A/B map apply an toàn | Không tự suy luận service inventory từ route |
| Agent-Control sync, heartbeat, apply ack | Không tự attach NIC production nếu chưa phê duyệt |
| Tenant-scoped Control API, PostgreSQL RLS defense-in-depth | Không hỗ trợ IPv6 trong active datapath |

## Thành Phần Chính

| Plane | Thành phần | Vai trò |
|---|---|---|
| Data Plane | `bpf/xdp_data_plane.bpf.c`, eBPF maps | Parse packet, enforce policy, count, sample event, redirect/drop/pass |
| Forwarding Plane | L2 MAC rewrite, `tx_devmap` | Chuyển traffic sạch tới output interface/backend |
| Node Plane | `cmd/agent`, `internal/agent` | Load/attach XDP, pin maps/program, apply snapshot, expose `/metrics`, sync Control API |
| Control Plane | `cmd/control-api`, `internal/control` | API, PostgreSQL source of truth, snapshots, RBAC, audit, alerts |
| Management Plane | `web/dashboard`, Prometheus, Grafana | UI vận hành, metrics, event investigation, tenant/user management |

Sơ đồ tổng quan: [diagrams/system-context.mmd](diagrams/system-context.mmd), [diagrams/container-architecture.mmd](diagrams/container-architecture.mmd).

## Runtime Flow Tóm Tắt

1. Operator định nghĩa service, rule, whitelist, blacklist, UDP port block, feed và baseline trong Admin Dashboard.
2. Control API lưu cấu hình tenant-scoped trong PostgreSQL, audit mutation, build policy snapshot khi cần.
3. Agent register/heartbeat với Control API, fetch snapshot version mới hơn.
4. Agent verify checksum/object checksum/capacity, resolve forwarding metadata nếu cần, populate inactive A/B maps.
5. Agent cập nhật `tx_devmap`, flip `runtime_config.active_slot`, persist last-valid snapshot và gửi apply ack.
6. XDP hot path dùng active slot để match service, whitelist, blacklist, UDP source port block, rule và redirect/drop.
7. Agent xuất Prometheus metrics, forward sampled security events về Control API, dashboard hiển thị trạng thái tenant.

## Rủi Ro Cốt Lõi

| Rủi ro | Biện pháp hiện tại |
|---|---|
| Attach XDP sai NIC làm gián đoạn traffic | Makefile/README cảnh báo, chỉ chạy Agent sau khi chốt interface; lab VETH được ưu tiên |
| Policy lỗi làm mất traffic hợp lệ | A/B map apply, verify snapshot, last-valid snapshot, rollback snapshot |
| Forwarding metadata thiếu | Fail closed với `REASON_NEIGHBOR_UNRESOLVED`; resolver dùng netlink và neighbor probe |
| Tenant data leak | `tenant_id` trên dữ liệu nghiệp vụ, transaction set `anti_ddos.tenant_id`, PostgreSQL RLS |
| Secret lộ qua log/audit/docs | Redaction helpers, credential refs, Telegram token masking, docs không ghi secret thật |

## Các Quyết Định Đang Khóa

- Active data plane là IPv4-only.
- Protected backend service inventory là nguồn chính thức từ Network/SRE, không suy luận tự động.
- Detections/anomaly hiện là alert-only; không auto-create/auto-enforce mitigation rules.
- UDP reflection source-port blocking có seed disabled mặc định; chỉ enabled có chủ đích sau khi deploy BPF/Agent mới.
- Control plane dùng shared database/shared schema với tenant isolation qua `tenant_id` và RLS.

## Source Alignment

- Scope/README: `README.md`
- Decision log: `.specs/project/STATE.md`
- Data plane: `bpf/xdp_data_plane.bpf.c`, `include/anti_ddos/bpf_contract.h`
- Agent: `cmd/agent/main.go`, `internal/agent/agent.go`, `internal/agent/policy_apply.go`
- Control API: `cmd/control-api/main.go`, `internal/control/server.go`
- Dashboard: `web/dashboard/src/navigation.ts`, `web/dashboard/src/api.ts`

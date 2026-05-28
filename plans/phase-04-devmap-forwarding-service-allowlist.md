# Phase 04 - DEVMAP Forwarding và Service Allowlist

## Mục tiêu

Đảm bảo gateway chỉ redirect traffic sạch tới backend/service đã khai báo bằng L2 MAC rewrite và `XDP_REDIRECT` qua `BPF_MAP_TYPE_DEVMAP`. Packet ngoài allowlist hoặc redirect target lỗi phải fail-closed bằng `XDP_DROP`, tăng counter rõ reason và tạo đủ input cho dashboard/alert.

## Phạm vi

- Triển khai `service_allowlist` lookup trong XDP theo dst IPv4, protocol và dst port.
- Agent phân giải output ifindex và next-hop/backend MAC từ routing/ARP/neighbor table trước khi publish policy.
- Agent populate `tx_devmap` và `service_allowlist` từ snapshot đã validate.
- XDP rewrite Ethernet source/destination MAC và gọi `bpf_redirect_map(&tx_devmap, service.devmap_key, XDP_DROP)`.
- Backend return path có thể asymmetric; MVP không NAT/DNAT và không proxy.
- Control API CRUD service triển khai đầy đủ ở Phase 05; phase này dùng config/mock snapshot để kiểm chứng data path.

## Công việc

| ID | Công việc | Mục đích | Kết quả bàn giao | Phụ thuộc |
|---|---|---|---|---|
| P04-T01 | Định nghĩa final `service_key` và `service_value` | Đồng bộ XDP map với snapshot/API | Key dst_v4/proto/dst_port; value service_id, policy_id, action, output_ifindex, devmap_key, neighbor_status, dst_mac, src_mac | Phase 03 |
| P04-T02 | Triển khai Agent route/neighbor resolver | Biết redirect packet ra interface nào và MAC nào | Resolver đọc route, ifindex, interface MAC, ARP/neighbor MAC, status resolved/unresolved | P04-T01 |
| P04-T03 | Kiểm tra output interface và neighbor state | Không publish policy redirect sai path | Lỗi validation cho interface missing/down, MAC missing, neighbor unresolved | P04-T02 |
| P04-T04 | Populate `tx_devmap` | Tạo target output interface cho `XDP_REDIRECT` | Agent update `BPF_MAP_TYPE_DEVMAP` theo devmap_key/output_ifindex | P04-T03 |
| P04-T05 | Populate `service_allowlist` active/inactive slot | Đưa service registry thành hot-path policy | Map entries có dst/proto/port và resolved redirect metadata | P04-T04 |
| P04-T06 | Triển khai service lookup trong XDP | Chặn traffic ngoài allowlist sớm | Logic lookup active service slot sau parse/source checks | P04-T05 |
| P04-T07 | Triển khai `REASON_NOT_ALLOWED_SERVICE` | Visibility cho service miss | Counter/drop/event cho packet không match service allowlist | P04-T06 |
| P04-T08 | Triển khai neighbor unresolved fail-closed drop | Không redirect khi MAC/neighbor không tin cậy | XDP drop `REASON_NEIGHBOR_UNRESOLVED`, counter và sampled event | P04-T06 |
| P04-T09 | Triển khai Ethernet source/destination MAC rewrite | Chuẩn bị packet cho backend-facing NIC | Helper rewrite `eth->h_dest` bằng backend/next-hop MAC và `eth->h_source` bằng output interface MAC | P04-T08 |
| P04-T10 | Triển khai DEVMAP redirect return path | Chuyển traffic sạch tới backend | XDP return `bpf_redirect_map(&tx_devmap, service.devmap_key, XDP_DROP)` | P04-T09 |
| P04-T11 | Triển khai redirect/error counters | Quan sát được success/failure forwarding | Counters `redirected`, `redirect_error`, `neighbor_unresolved`, `not_allowed_service` theo service/proto/interface | P04-T10 |
| P04-T12 | Công bố redirect và neighbor metrics | Dashboard/Prometheus thấy forwarding state | Metrics `anti_ddos_redirected_packets_total`, `anti_ddos_redirect_errors_total`, `anti_ddos_neighbor_resolution_status` | P04-T11 |
| P04-T13 | Kiểm thử traffic không thuộc allowlist | Xác nhận không forward nhầm | Packet tới port/proto/dst không cho phép bị drop/count | P04-T12 |
| P04-T14 | Kiểm thử end-to-end VETH/namespace DEVMAP forwarding | Xác nhận redirect path hoạt động thật | Client namespace -> WAN veth -> XDP -> DEVMAP -> backend namespace | P04-T10 |
| P04-T15 | Viết tài liệu redirect failure behavior | Vận hành biết khi nào cần cảnh báo/rollback | Runbook ngắn cho output interface down, DEVMAP missing, neighbor unresolved, return path sai | P04-T12 |

## Tiến độ thực hiện

Ngày cập nhật: 2026-05-28

Evidence chính: `make phase4-verify` PASS; report ở `reports/phase-04-devmap-forwarding-service-allowlist.md`. Phase này dùng mock/bootstrap policy và VETH namespace lab, chưa attach XDP vào NIC thật và chưa triển khai Control Plane CRUD service.

| ID | Status | Evidence |
|---|---|---|
| P04-T01 | Done | `service_key` và `service_value` giữ contract dst_v4/proto/dst_port, service/policy/action, output ifindex, devmap key, neighbor status và MAC rewrite metadata. |
| P04-T02 | Done | Agent có `ForwardingResolver` netlink đọc route, link, ifindex, output MAC và neighbor MAC/state; unit tests dùng fake netlink client. |
| P04-T03 | Done | Resolver và snapshot validation reject interface missing/down, source MAC invalid, route mismatch, neighbor missing/failed/unresolved và service shape sai. |
| P04-T04 | Done | `ApplyPolicySnapshot` populate `tx_devmap` theo devmap_key/output_ifindex và rollback touched keys khi apply lỗi. |
| P04-T05 | Done | Service allowlist A/B slot populate từ validated snapshot, active slot flip không cần reload XDP. |
| P04-T06 | Done | XDP lookup active `service_allowlist` theo dst/proto/port trước blacklist/rate path. |
| P04-T07 | Done | Service miss drop `REASON_NOT_ALLOWED_SERVICE` với counter/event sampling path. |
| P04-T08 | Done | Neighbor unresolved trong service value drop `REASON_NEIGHBOR_UNRESOLVED`. |
| P04-T09 | Done | XDP rewrite `eth->h_dest` và `eth->h_source` bằng MAC resolved từ service value. |
| P04-T10 | Done | XDP return `bpf_redirect_map(&tx_devmap, service.devmap_key, XDP_DROP)` cho packet allowlisted. |
| P04-T11 | Done | Counters cover redirected, redirect_error, neighbor_unresolved và not_allowed_service. |
| P04-T12 | Done | Prometheus metrics expose redirected packets, redirect errors, not allowed service, neighbor unresolved và neighbor resolution status. |
| P04-T13 | Done | Packet fixture và VETH test xác nhận port không allowlist không tới backend. |
| P04-T14 | Done | `scripts/lab/phase4-devmap-veth-test.sh` xác nhận client namespace -> WAN XDP -> DEVMAP -> backend namespace với MAC rewrite đúng. |
| P04-T15 | Done | Runbook ở `docs/runbooks/forwarding-failure-behavior.md`. |

## Tiêu chí chấp nhận

- Packet tới backend IP/protocol/port đã khai báo được L2 rewrite và return `XDP_REDIRECT` qua `tx_devmap`.
- Packet không match service allowlist bị `XDP_DROP` với reason `not_allowed_service`.
- Neighbor unresolved, output interface lỗi hoặc DEVMAP target lỗi fail-closed bằng drop với counter/metric riêng.
- `service_allowlist` và `tx_devmap` cập nhật qua snapshot không cần restart Agent hay XDP program.
- Prometheus scrape được redirect success, redirect error, neighbor unresolved và neighbor resolution status.
- E2E namespace/VETH test chứng minh backend chỉ nhận traffic allowlisted.

## Kiểm chứng

- Packet fixture cho allowed TCP/UDP/ICMP service trả `XDP_REDIRECT` và không đi theo diagnostic/fallback return path.
- Negative tests cho port không cho phép, protocol không cho phép và dst IP không thuộc service.
- Kiểm thử unresolved neighbor: policy bị reject hoặc packet bị drop `REASON_NEIGHBOR_UNRESOLVED` theo mode đã thiết kế.
- Kiểm thử missing DEVMAP entry: `bpf_redirect_map(..., XDP_DROP)` fail-closed và tăng redirect error metrics.
- Network namespace/VETH integration test xác nhận backend chỉ thấy traffic đã allowlist và MAC headers được rewrite đúng.
- Prometheus scrape redirect/neighbor metrics và dashboard Phase 06 có đủ input hiển thị.

## Truy vết PRD

- PRD-002: forwarding status, redirect counters và neighbor health trên metrics/dashboard.
- PRD-003: packet sạch match allowlist được rewrite L2 và `XDP_REDIRECT`; target lỗi drop fail-closed.
- PRD-007: dashboard protected backend service registry sinh `service_allowlist` và `tx_devmap`.
- PRD-008: redirect/neighbor failure là input cho Telegram alerting.
- PRD-010: apply lỗi giữ policy snapshot gần nhất.
- PRD-011: route/link/neighbor evidence phục vụ ISP escalation khi cần.

## Ghi chú và rủi ro

- MVP giữ nguyên IP, không NAT/DNAT; mọi thay đổi sang kernel routing/proxy là ngoài scope phase này.
- Diagnostic/fallback return path chỉ được bật bằng policy riêng, không phải success path P1.
- Backend return path asymmetric làm troubleshooting phức tạp hơn; runbook phải ghi rõ.
- Neighbor/MAC sai có thể redirect nhầm hoặc drop traffic hợp lệ; validation và alert phải ưu tiên fail-closed.

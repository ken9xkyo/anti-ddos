# Trang Services

## Mục đích

`Services` quản lý registry các protected service được Anti-DDoS bảo vệ. Trang này dùng để xem service allowlist, cấu hình forwarding qua output interface, theo dõi apply failure và disable service khi cần.

## Ai dùng

- `viewer`: xem service registry, bộ lọc và apply failure.
- `operator`: tạo, sửa và disable service.
- `admin`: có toàn bộ quyền operator.

## Thành phần UI

- `Protected Services`: panel bộ lọc và nút `Add service`.
- Bộ lọc:
  - `Search`: tìm theo name, owner, backend, output interface hoặc ports.
  - `Protocol`: `All`, `TCP`, `UDP`, `ICMP`.
  - `State`: `All`, `Enabled`, `Disabled`.
- `Latest Apply Failure`: xuất hiện khi agent báo apply policy thất bại.
- Form `Add Service` hoặc `Edit Service`:
  - Trường định danh: `Name`, `Description`, `Owner`, `Tags`.
  - Trường traffic/service: `Backend CIDR`, `Protocol`, `Allowed ports`, `Criticality`, `Protection mode`, `Priority`.
  - Trường forwarding: `Output interface`, `Resolved ifindex`, `Source MAC`, `Neighbor status`.
  - Trường audit: `Reason`.
  - Checkbox `Enabled`.
- Form disable service: nhập `Reason` và chọn `Confirm disable`.
- `Service Registry`: bảng service gồm name, backend, protocol, ports, output, owner, mode, neighbor, counters, apply, state và actions.

## Dữ liệu và API liên quan

- Dashboard đọc service từ dữ liệu dashboard polling.
- Tạo service gọi service create API; sửa service gọi service update API; disable service gọi service delete/disable API với audit reason.
- Output interface được gợi ý từ metadata `interfaces` do Agent report qua heartbeat/register.

## Thao tác chính

1. Dùng search và filter để tìm service cần kiểm tra.
2. Chọn `Add service` để tạo service mới. Service mới mặc định disabled để tránh apply nhầm.
3. Chọn output interface từ danh sách agent-reported nếu có. Dashboard tự điền `Resolved ifindex` và `Source MAC` khi metadata đủ.
4. Nếu bật `Enabled`, bảo đảm có `Resolved ifindex` và `Source MAC`; UI sẽ chặn nếu thiếu.
5. Khi sửa service, nhập `Reason` cụ thể như lý do thay backend, đổi owner hoặc bật enforce.
6. Khi disable service, xác nhận bằng reason. Service bị disable không còn active như service đang bật nhưng vẫn còn trong registry để audit.

## Trạng thái rỗng và lỗi

- Nếu chưa có service, bảng hiển thị `No protected services configured`.
- Nếu bộ lọc không khớp, bảng hiển thị `No services match the current filters`.
- Nếu enabled mà thiếu forwarding metadata, UI báo `resolved ifindex is required before enabling a service` hoặc `source MAC is required before enabling a service`.
- Nếu có apply failure, panel riêng hiển thị agent, policy version, stage, reason và thời điểm report.

## Lưu ý vận hành

- Không nhập thủ công next-hop MAC trong dashboard. Agent resolve/cấu hình next-hop MAC trên host khi apply policy snapshot.
- Control API chạy trong container compose nên không thể tự netlink-lookup NIC host thật. Interface metadata phải đến từ Agent.
- Chỉ enable service khi đã xác nhận đúng output interface, ifindex, source MAC và backend CIDR.
- Với `ICMP`, `Allowed ports` bị disabled vì ICMP không dùng port TCP/UDP.

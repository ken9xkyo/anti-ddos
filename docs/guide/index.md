# Hướng Dẫn Sử Dụng Anti-DDoS Admin Dashboard

Tài liệu này dành cho người vận hành Anti-DDoS Scrubbing Gateway qua Admin Dashboard. Nội dung tập trung vào cách đọc trạng thái, thao tác chính và các lưu ý an toàn trên từng trang của dashboard hiện tại.

Admin Dashboard là giao diện vận hành của Control Plane. Dashboard không phải landing page, không thay thế Grafana, và không tự động thực hiện BGP, RTBH, FlowSpec hay thao tác hạ tầng ngoài các API điều khiển đã có.

## Đối tượng sử dụng

| Vai trò | Mục tiêu chính | Quyền trên dashboard |
|---|---|---|
| `viewer` | Theo dõi hệ thống, xem service, alert, event, feed, snapshot | Chỉ đọc; không thấy hoặc không dùng được nút tạo/sửa/disable/sync/rollback |
| `operator` | Trực vận hành, thay đổi policy runtime | Được thao tác service, rule, whitelist, feed, snapshot rollback, test alert và ISP runbook |
| `admin` | Quản trị truy cập và secret reference | Bao gồm quyền operator; thêm user management, password reset, session revoke, Telegram token và feed credential reference |

Backend vẫn là lớp enforce RBAC chính. UI ẩn control nguy hiểm với role thấp hơn để giảm nhầm lẫn, nhưng mọi mutation vẫn phải được API kiểm tra lại.

## Nhóm menu

| Nhóm | Trang | Hướng dẫn |
|---|---|---|
| Operations | `Overview` | [overview.md](overview.md) |
| Operations | `Incidents` | [incidents.md](incidents.md) |
| Policy | `Services` | [services.md](services.md) |
| Policy | `Rules` | [rules.md](rules.md) |
| Policy | `Whitelist` | [whitelist.md](whitelist.md) |
| Policy | `Blacklist` | [blacklist.md](blacklist.md) |
| Policy | `Detection` | [detection.md](detection.md) |
| Intelligence | `Reputation` | [reputation.md](reputation.md) |
| Control | `Snapshots` | [snapshots.md](snapshots.md) |
| Control | `Access` | [access.md](access.md) |
| Infrastructure | `Fleet` | [fleet.md](fleet.md) |
| Infrastructure | `Investigation` | [investigation.md](investigation.md) |

Luồng đăng nhập, thanh điều hướng, topbar, refresh và logout được mô tả trong [login-and-shell.md](login-and-shell.md).

## Quy ước thao tác an toàn

- Mọi thay đổi quan trọng cần có `Reason`. Lý do này được gửi trong body hoặc header `X-Audit-Reason` để phục vụ audit.
- Disable rule, whitelist, blacklist và feed là soft-disable. Bản ghi vẫn còn để xem lại lịch sử và không bị xóa vật lý ngay khỏi hệ thống.
- Snapshot rollback không ghi đè snapshot cũ. Dashboard yêu cầu xác nhận và tạo snapshot mới từ version được chọn.
- Service mới mặc định disabled. Khi enable service, dashboard yêu cầu metadata forwarding hợp lệ như `resolved_ifindex` và `resolved_src_mac`.
- Dashboard không nhập thủ công next-hop MAC cho service. Agent chịu trách nhiệm resolve/cấu hình next-hop MAC trên host khi áp policy snapshot.
- Không attach XDP vào NIC thật nếu chưa xác nhận role interface, service inventory và rollback plan ở cấp vận hành.

## Luồng dữ liệu tổng quát

Sau khi đăng nhập, dashboard gọi các endpoint `/v1` của Control API để lấy overview, agents, services, rules, events, baselines, anomalies, feed sources, feed runs, feed conflicts, Telegram config và alerts. Dữ liệu chính được refresh định kỳ khoảng 3 giây và cũng có thể refresh thủ công từ topbar.

Các trang CRUD như `Rules`, `Whitelist`, `Blacklist`, `Snapshots`, `Access` và một số phần của `Reputation` có luồng tải riêng khi mở trang hoặc sau khi thao tác. Điều này giúp overview không phải kéo dữ liệu nặng như raw snapshot trong vòng polling mặc định.

## Trạng thái chung

- `Loading dashboard data`: dashboard chưa có dữ liệu đầu tiên hoặc đang đợi Control API phản hồi.
- Banner lỗi ở đầu màn hình: request dashboard thất bại hoặc Control API trả lỗi.
- `Freshness` trên topbar: thời điểm refresh gần nhất; trạng thái stale xuất hiện khi dữ liệu không được cập nhật trong vài giây.
- Dòng rỗng trong bảng: không có dữ liệu trong cửa sổ hiện tại, hoặc bộ lọc không khớp bản ghi nào.

## Tài liệu liên quan

- [Admin Dashboard v2](../Admin-Dashboard-v2.md)
- [Control API](../Control-Api.md)
- [Docker Compose Deployment](../deployment/docker-compose.md)
- [Metric Catalog](../observability/metric-catalog.md)

# Đăng Nhập Và Dashboard Shell

## Mục đích

Trang đăng nhập và shell chung là điểm vào của Admin Dashboard. Shell cung cấp sidebar, topbar, trạng thái refresh, thông tin người dùng và vùng hiển thị từng trang nghiệp vụ.

## Ai dùng

Tất cả role đều dùng luồng này: `viewer`, `operator` và `admin`. Quyền thao tác cụ thể được áp dụng sau khi đăng nhập, dựa trên role của user trả về từ `/v1/me` hoặc `/v1/auth/login`.

## Thành phần UI

- Màn hình đăng nhập hiển thị thương hiệu `Anti-DDoS Operations`, trường `Username`, trường `Password` và nút `Sign in`.
- Sidebar hiển thị menu 2 cấp: `Operation` gồm `Dashboard`, `Incidents`, `Detections`, `Events`; `Configuration` gồm `Services`, `Rules`, `Whitelist`, `Blacklist`; `Threat Intelligence` gồm `Reputation`; `Setting` gồm `Snapshots`, `Accounts`, `Nodes`.
- Topbar hiển thị tiêu đề trang hiện tại, chip `username · role`, freshness pill, nút refresh và nút logout.
- Banner lỗi xuất hiện dưới topbar khi request tới dashboard hoặc API thất bại.
- Panel `Loading dashboard data` xuất hiện khi shell đã đăng nhập nhưng chưa có dữ liệu dashboard.

## Dữ liệu và API liên quan

- `POST /v1/auth/login`: đăng nhập bằng username/password, nhận session token và user.
- `GET /v1/me`: kiểm tra session hiện tại khi mở lại dashboard.
- Các endpoint dashboard được gọi sau khi có user hợp lệ, gồm overview, agents, services, rules, security events, baselines, anomalies, feed, Telegram config và alerts.

## Thao tác chính

1. Nhập username và password.
2. Chọn `Sign in`.
3. Sau khi đăng nhập thành công, dashboard vào thẳng `Dashboard`.
4. Dùng sidebar để chuyển trang.
5. Chọn nút refresh trên topbar khi cần lấy dữ liệu ngay thay vì chờ polling.
6. Chọn logout để xóa token trong trình duyệt và quay lại màn hình đăng nhập.

## Trạng thái rỗng và lỗi

- Sai thông tin đăng nhập hoặc Control API trả lỗi sẽ hiển thị error line trong login panel.
- Nếu dashboard data chưa tải xong, shell giữ trạng thái loading thay vì render trang rỗng.
- Nếu refresh thất bại, dữ liệu cũ vẫn có thể còn trên màn hình nhưng banner lỗi cho biết request mới không thành công.

## Lưu ý vận hành

- Token được lưu ở local storage của dashboard client. Logout sẽ xóa token phía client.
- Freshness stale không luôn đồng nghĩa hệ thống lỗi; nó cho biết dashboard chưa nhận dữ liệu mới trong ngưỡng hiện tại.
- Viewer có thể xem nhiều trang nhưng các nút mutation sẽ bị ẩn hoặc disabled tùy trang.

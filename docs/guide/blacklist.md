# Trang Blacklist

## Mục đích

`Blacklist` hiển thị manual blacklist entries của user và global feed-origin reputation rows ở chế độ read-only.

## Ai dùng

- `user`: tạo, sửa và disable manual blacklist entry của chính mình.
- `admin`: chỉ xem read-only khi đang ở `View config` context; admin normal session quản lý feed tại tab `Reputation`.

## Thành phần UI

- `Blacklist CRUD`: header hiển thị số block entries hoặc số bản ghi khớp filter.
- Bộ lọc:
  - `Search`: tìm theo CIDR, source, reason hoặc rule.
  - `Source`: lọc theo source cụ thể như `manual` hoặc `abuseipdb`.
  - `Origin`: `All`, `Manual`, `Feed`.
  - `State`: `All`, `Enabled`, `Disabled`.
  - `Expiry`: `All`, `Valid`, `Expired`, `No expiry`.
- Data Grid với các cột: `CIDR`, `Origin`, `Source`, `Score`, `Rule ID`, `Expires`, `State`, `Reason`, `Actions`.
- Drawer `Add Blacklist Entry` hoặc `Edit ...` gồm: `CIDR`, `Source`, `Score`, `Rule ID`, `Expires at`, `Enabled`, `Reason`.
- Confirm dialog `Disable ...` yêu cầu reason.

## Dữ liệu và API liên quan

- Trang gọi API `/v1/blacklist/entries` với query filter và server-side pagination.
- Manual create/update/disable vẫn gọi `/v1/blacklist` và `/v1/blacklist/{id}`.
- Feed-origin rows đến từ global active reputation, có `origin=feed` và `editable=false`.
- Search/filter có debounce ngắn để tránh gọi API quá dày khi nhập.
- Create/update/disable blacklist đều rebuild policy snapshot.
- Dashboard luôn gửi action `drop`; backend từ chối action khác.

## Thao tác chính

1. Dùng bộ lọc để thu hẹp danh sách block entry theo source, trạng thái hoặc expiry.
2. Chọn `Add blacklist` để thêm CIDR mới.
3. Điền `Source`, `Score`, expiry nếu block chỉ nên tồn tại có thời hạn.
4. Nếu entry liên quan một rule hiện có, nhập `Rule ID`.
5. Nhập `Reason` và chọn `Save blacklist`.
6. Chọn `Disable` để soft-disable entry và nhập reason.

## Trạng thái rỗng và lỗi

- Nếu chưa có blacklist entry manual, bảng hiển thị `No blacklist entries configured`.
- Nếu filter không khớp, bảng hiển thị `No blacklist entries match the current filters`.
- Trường `Score` phải là số nguyên không âm nếu được nhập.

## Lưu ý vận hành

- Disable là soft-disable: entry vẫn còn để audit nhưng không đi vào snapshot active tiếp theo.
- Feed-origin rows không có nút edit/disable và backend trả lỗi nếu cố mutate qua blacklist endpoint.
- Trang `Reputation` chỉ dành cho admin normal session để quản lý global feed sources.
- Whitelist vẫn có precedence trước blacklist khi packet đã match protected service.

# Trang Blacklist

## Mục đích

`Blacklist` hiển thị danh sách block CIDR hiệu lực từ manual entries và threat feed như AbuseIPDB. Trang này dùng để thêm, sửa, lọc và soft-disable nguồn tấn công cần chặn thủ công; feed rows chỉ để xem.

## Ai dùng

- `viewer`: xem manual/feed blacklist và dùng bộ lọc.
- `operator`: tạo, sửa và disable manual blacklist entry.
- `admin`: có toàn bộ quyền operator.

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

- Nếu chưa có blacklist entry manual/feed, bảng hiển thị `No blacklist entries configured`.
- Nếu filter không khớp, bảng hiển thị `No blacklist entries match the current filters`.
- Trường `Score` phải là số nguyên không âm nếu được nhập.

## Lưu ý vận hành

- Disable là soft-disable: entry vẫn còn để audit nhưng không đi vào snapshot active tiếp theo.
- Feed rows đến từ threat feed reputation và hiển thị `feed read only`; không thể edit hoặc disable từ trang Blacklist.
- Trang `Reputation` vẫn là nơi cấu hình feed source, sync feed và xem conflict/run history.
- Nếu manual blacklist trùng chính xác CIDR với feed reputation, manual entry enabled được ưu tiên trong effective snapshot. CIDR chồng lấn nhưng không trùng chính xác vẫn dựa vào LPM precedence ở dataplane.
- Whitelist vẫn có precedence trước blacklist khi packet đã match protected service.

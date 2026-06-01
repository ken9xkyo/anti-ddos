# Trang Blacklist

## Mục đích

`Blacklist` quản lý manual block-list CIDR. Trang này dùng để thêm, sửa, lọc và soft-disable nguồn tấn công cần chặn thủ công ngoài threat feed.

## Ai dùng

- `viewer`: xem manual blacklist và dùng bộ lọc.
- `operator`: tạo, sửa và disable manual blacklist entry.
- `admin`: có toàn bộ quyền operator.

## Thành phần UI

- `Blacklist CRUD`: header hiển thị số block entries hoặc số bản ghi khớp filter.
- Bộ lọc:
  - `Search`: tìm theo CIDR, source, reason hoặc rule.
  - `Source`: lọc theo source cụ thể như `manual`.
  - `State`: `All`, `Enabled`, `Disabled`.
  - `Expiry`: `All`, `Valid`, `Expired`, `No expiry`.
- Data Grid với các cột: `CIDR`, `Source`, `Score`, `Rule ID`, `Expires`, `State`, `Reason`, `Actions`.
- Drawer `Add Blacklist Entry` hoặc `Edit ...` gồm: `CIDR`, `Source`, `Score`, `Rule ID`, `Expires at`, `Enabled`, `Reason`.
- Confirm dialog `Disable ...` yêu cầu reason.

## Dữ liệu và API liên quan

- Trang gọi API `/v1/blacklist` với query filter.
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

- Nếu chưa có manual blacklist entry, bảng hiển thị `No blacklist entries configured`.
- Nếu filter không khớp, bảng hiển thị `No blacklist entries match the current filters`.
- Trường `Score` phải là số nguyên không âm nếu được nhập.

## Lưu ý vận hành

- Disable là soft-disable: entry vẫn còn để audit nhưng không đi vào snapshot active tiếp theo.
- Manual blacklist chỉ quản lý bảng `manual_blacklist_entries`; blacklist từ threat feed vẫn nằm ở trang `Reputation`.
- Nếu manual blacklist trùng chính xác CIDR với feed reputation, manual entry enabled được ưu tiên trong effective snapshot. CIDR chồng lấn nhưng không trùng chính xác vẫn dựa vào LPM precedence ở dataplane.
- Whitelist vẫn có precedence trước blacklist khi packet đã match protected service.

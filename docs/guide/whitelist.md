# Trang Whitelist

## Mục đích

`Whitelist` quản lý allow-list CIDR. Trang này dùng để thêm, sửa, lọc và soft-disable whitelist entry theo scope global hoặc theo service.

## Ai dùng

- `viewer`: xem whitelist và dùng bộ lọc.
- `operator`: tạo, sửa và disable whitelist entry.
- `admin`: có toàn bộ quyền operator.

## Thành phần UI

- `Whitelist CRUD`: header hiển thị số allow entries hoặc số bản ghi khớp filter.
- Bộ lọc:
  - `Search`: tìm theo CIDR, label, owner, reason hoặc service.
  - `Scope`: `All`, `Global`, `Service`.
  - `Service`: lọc theo service cụ thể.
  - `State`: `All`, `Enabled`, `Disabled`.
  - `Expiry`: `All`, `Valid`, `Expired`, `No expiry`.
- Data Grid với các cột: `CIDR`, `Scope`, `Service`, `Label`, `Owner`, `Priority`, `Expires`, `State`, `Actions`.
- Drawer `Add Whitelist Entry` hoặc `Edit ...` gồm: `CIDR`, `Scope`, `Service`, `Label`, `Owner`, `Priority`, `Expires at`, `Enabled`, `Reason`.
- Confirm dialog `Disable ...` yêu cầu reason.

## Dữ liệu và API liên quan

- Trang gọi API whitelist với query filter.
- Search/filter có debounce ngắn để tránh gọi API quá dày khi nhập.
- Create/update/disable whitelist đều rebuild policy snapshot.

## Thao tác chính

1. Dùng bộ lọc để thu hẹp danh sách allow entry theo scope, service, trạng thái hoặc expiry.
2. Chọn `Add whitelist` để thêm CIDR mới.
3. Chọn `Scope`:
   - `Global`: áp dụng toàn cục, không cần service.
   - `Service`: cần chọn service cụ thể.
4. Điền `Owner`, `Priority`, expiry nếu whitelist chỉ nên tồn tại có thời hạn.
5. Nhập `Reason` và chọn `Save whitelist`.
6. Chọn `Disable` để soft-disable entry và nhập reason.

## Trạng thái rỗng và lỗi

- Nếu chưa có whitelist entry, bảng hiển thị `No whitelist entries configured`.
- Nếu filter không khớp, bảng hiển thị `No whitelist entries match the current filters`.
- Trường `Priority` phải là số nguyên không âm nếu được nhập.

## Lưu ý vận hành

- Whitelist conflict có thể xuất hiện trong anomaly evidence để triage nguồn trusted. Detection không còn dùng whitelist để chặn hoặc kích hoạt auto-enforcement.
- Service filter dùng effective service filter. Global entry vẫn có thể xuất hiện tùy filter vì entry global có hiệu lực rộng hơn service cụ thể.
- Disable là soft-disable: entry vẫn còn để audit nhưng không đi vào snapshot active tiếp theo.

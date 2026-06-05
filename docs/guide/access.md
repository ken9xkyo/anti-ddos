# Trang Access

## Mục đích

`Access` quản lý membership của active tenant trong Admin Dashboard và Control API. Trang này dùng để grant user vào tenant, sửa role/status, reset password và revoke session trong tenant hiện tại.

## Ai dùng

- `viewer`: xem danh sách tenant members nếu API cho phép đọc authenticated.
- `operator`: xem danh sách tenant members ở chế độ read-only.
- `admin`: tạo/grant member, sửa membership, reset password và revoke session.
- `platform_admin`: có thể switch tenant ở topbar; khi vào tenant có effective `admin`.

## Thành phần UI

- `Tenant Access`: header `tenant RBAC · <tenant>` và nút `Add user` cho admin.
- Data Grid user gồm: `Username`, `Role`, `Status`, `Force change`, `Last login`, `Created`, `Actions`.
- Drawer `Add User` gồm `Username`, `Temporary password`, `Role`, `Status`, checkbox `Force password change`, `Reason`.
- Drawer `Edit ...` gồm `Role`, `Status`, checkbox `Force password change`, `Reason`.
- Drawer `Reset ... Password` gồm `Temporary password`, checkbox `Force password change`, `Reason`.
- Confirm dialog `Revoke ... Sessions` yêu cầu `Reason`.

## Dữ liệu và API liên quan

- Trang lazy-load active-tenant members qua API users.
- Admin mutation dùng API create/grant user, patch membership, password reset và revoke sessions.
- Password raw không được trả về trong response hoặc audit payload.

## Thao tác chính

1. Admin chọn `Add user` để tạo global identity nếu cần và grant membership với role ban đầu trong active tenant.
2. Đặt `Force password change` khi cấp temporary password để user phải đổi password.
3. Chọn `Edit` để thay role, status hoặc force password change.
4. Chọn `Reset` để cấp temporary password mới và revoke session liên quan.
5. Chọn `Sessions` để revoke active sessions của user trong active tenant.
6. Luôn nhập `Reason` cụ thể cho từng thay đổi.

## Trạng thái rỗng và lỗi

- Nếu chưa có member nào, grid hiển thị `No tenant members`.
- Nếu user không phải admin, cột action hiển thị read-only và không có nút `Add user`.
- Backend chặn thao tác làm mất admin active cuối cùng trong tenant; lỗi sẽ hiển thị inline.

## Lưu ý vận hành

- Không chia sẻ temporary password qua kênh không an toàn.
- Không downgrade hoặc revoke admin khi chưa xác nhận còn admin active khác trong tenant.
- `Force password change` giúp giảm rủi ro dùng lâu dài temporary password.
- Revoke sessions làm các phiên hiện tại của user trong tenant bị vô hiệu hóa.

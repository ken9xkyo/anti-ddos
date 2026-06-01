# Trang Access

## Mục đích

`Access` quản lý local RBAC user của Admin Dashboard và Control API. Trang này dùng để tạo user, sửa role/status, reset password và revoke session.

## Ai dùng

- `viewer`: xem danh sách user nếu API cho phép đọc authenticated.
- `operator`: xem danh sách user ở chế độ read-only.
- `admin`: tạo user, sửa user, reset password và revoke session.

## Thành phần UI

- `User Management`: header `local RBAC` và nút `Add user` cho admin.
- Data Grid user gồm: `Username`, `Role`, `Status`, `Force change`, `Last login`, `Created`, `Actions`.
- Drawer `Add User` gồm `Username`, `Temporary password`, `Role`, `Status`, checkbox `Force password change`, `Reason`.
- Drawer `Edit ...` gồm `Role`, `Status`, checkbox `Force password change`, `Reason`.
- Drawer `Reset ... Password` gồm `Temporary password`, checkbox `Force password change`, `Reason`.
- Confirm dialog `Revoke ... Sessions` yêu cầu `Reason`.

## Dữ liệu và API liên quan

- Trang lazy-load users qua API users.
- Admin mutation dùng API create user, patch user, password reset và revoke sessions.
- Password raw không được trả về trong response hoặc audit payload.

## Thao tác chính

1. Admin chọn `Add user` để tạo user mới với role ban đầu.
2. Đặt `Force password change` khi cấp temporary password để user phải đổi password.
3. Chọn `Edit` để thay role, status hoặc force password change.
4. Chọn `Reset` để cấp temporary password mới và revoke session liên quan.
5. Chọn `Sessions` để revoke active sessions của user.
6. Luôn nhập `Reason` cụ thể cho từng thay đổi.

## Trạng thái rỗng và lỗi

- Nếu chưa có local user nào, grid hiển thị `No local users`.
- Nếu user không phải admin, cột action hiển thị read-only và không có nút `Add user`.
- Backend chặn thao tác làm mất admin active cuối cùng; lỗi sẽ hiển thị inline.

## Lưu ý vận hành

- Không chia sẻ temporary password qua kênh không an toàn.
- Không downgrade hoặc revoke admin khi chưa xác nhận còn admin active khác.
- `Force password change` giúp giảm rủi ro dùng lâu dài temporary password.
- Revoke sessions làm các phiên hiện tại của user bị vô hiệu hóa.

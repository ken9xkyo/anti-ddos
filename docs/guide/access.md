# Trang Accounts

`Accounts` la trang admin-only de quan ly tai khoan. He thong khong con tenant membership.

## Ai dung

- `admin`: tao/sua/revoke user, reset password, revoke sessions va mo read-only config cua user.
- `user`: khong thay navigation `Accounts`.

## Thanh phan UI

- Header `Accounts` voi nut `Add user`.
- Grid user gom username, role, status, force password change, last login, created va actions.
- Actions: `View config`, `Edit`, `Reset`, `Sessions`.
- Drawer create/edit/reset gom role `admin` hoac `user`, status, password khi can, force password change va reason.

## Thao tac chinh

1. Chon `Add user` de tao account moi.
2. Chon `Edit` de doi role/status hoac force password change.
3. Chon `Reset` de dat temporary password va revoke sessions lien quan.
4. Chon `Sessions` de revoke sessions hien tai cua user.
5. Chon `View config` tren user active de mo dashboard read-only trong owner context cua user do.

## Luu y

- Backend chan thao tac lam mat admin active cuoi cung.
- Admin trong `View config` context khong co mutation controls va backend tra `403` neu goi mutation config.

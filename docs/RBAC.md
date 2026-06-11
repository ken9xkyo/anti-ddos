# RBAC Admin/User

Trạng thái: cập nhật ngày 2026-06-11 theo mô hình không còn tenant.

Control Plane chỉ còn hai role public: `admin` và `user`. Tenant, tenant memberships, tenant switcher, `platform_role`, `operator` và `viewer` đã retired khỏi API/UI/session mới.

## Role Model

| Role | Quyền chính |
|---|---|
| `user` | Đọc và mutation config vận hành thuộc chính mình: Services, Rules, Whitelist, Manual Blacklist, UDP Ports, Snapshots, Baselines/Anomalies, Agents/Events/Alerts và Telegram Channel. |
| `admin` | Quản lý account lifecycle: create/update/revoke/reset password/revoke sessions. Admin có thể mở dashboard read-only của một user qua Accounts nhưng không được mutation config của user đó. |

## Auth Và Session

- `POST /v1/auth/login` chỉ nhận `username` và `password`.
- `User.role` chỉ là `admin` hoặc `user`.
- Response không có `tenants`, `active_tenant` hoặc `platform_role`.
- `POST /v1/admin/view-user` dành cho `admin`, nhận `{ "user_id": "..." }`, trả session/context đang xem user. User response có `viewing_user` và `read_only=true`.
- `/v1/tenants*` đã retired.

## Data Ownership

Operational data được cô lập bằng `owner_user_id`:

- User request dùng `owner_user_id = actor.ID`.
- Admin view-user request dùng `owner_user_id = target user`.
- Mutation config gọi guard `requireConfigMutation`; admin view-user bị `403`.
- Admin-only mutations chỉ áp dụng cho account lifecycle.

Migration `owner_user_rbac_no_tenant` là destructive: map `operator/viewer -> user`, giữ `admin`, drop `platform_role`, revoke sessions cũ, xóa operational data cũ, drop tenant tables/session tenant field/RLS tenant policy và chuyển các bảng nghiệp vụ sang `owner_user_id`.

## Agent

Agent register không dùng `X-Tenant-ID` hoặc `X-Tenant-Slug` nữa. Request register phải truyền một trong hai header:

- `X-Owner-User-ID`
- `X-Owner-Username`

Heartbeat, snapshot, apply và events resolve owner từ `agent_id` sau khi register.

## Dashboard

- Không còn tenant switcher hoặc Tenants navigation.
- Accounts chỉ hiện với `admin`.
- Accounts có `View config` để admin mở dashboard read-only của user.
- User thấy đầy đủ controls mutation config/Telegram của chính mình.
- Admin trong view-user context chỉ thấy dữ liệu và không thấy/nút mutation config.
- Threat Feed/Reputation không còn navigation hoặc API user-facing trong scope này.

## Verification

Các gate chính:

```bash
go test ./internal/control -run 'RBAC|Migration|DashboardAPIIntegration|ControlCoreIntegration|Server'
make go-test
make ui-test
make ui-build
make control-postgres-test
```

# RBAC Hiện Tại

Trạng thái: tài liệu này được lập từ source code hiện có trong working tree ngày 2026-06-11. Phạm vi chỉ mô tả RBAC multi-tenant hiện tại, không đề xuất thay đổi quyền, schema hoặc API.

RBAC của Anti-DDoS Control Plane dùng một identity toàn cục trong `app_users`, nhưng quyền vận hành được quyết định theo tenant qua `tenant_memberships`. Mỗi session có `active_tenant_id`; Control API biến session đó thành `Actor` có effective role trong tenant đang chọn. Dữ liệu nghiệp vụ có `tenant_id` và được cô lập bằng app-level tenant context kết hợp PostgreSQL Row Level Security.

Sơ đồ luồng: [Mermaid](diagrams/system-architecture/tenant-rbac-flow.mmd), [SVG](diagrams/system-architecture/tenant-rbac-flow.svg).

## 1. Role Model

| Role | Phạm vi | Quyền chính |
|---|---|---|
| `viewer` | Tenant membership | Đọc dashboard, services, rules, events, alerts, feeds, snapshots và trạng thái hệ thống trong active tenant. Không được mutation. |
| `operator` | Tenant membership | Bao gồm quyền viewer; được thực hiện operational mutations như service/rule/whitelist/blacklist/UDP port/feed non-secret/snapshot/Telegram/baseline trong active tenant. Được quản lý lifecycle của `viewer` trong tenant đó. |
| `admin` | Tenant membership | Bao gồm quyền operator; được quản lý mọi tenant member trong active tenant và được thấy/sửa secret credential state như feed `credential_ref`. |
| `platform_admin` | Global role trong `app_users.platform_role` | Quản lý tenant lifecycle, list tenant gồm revoked khi dùng `include_revoked=true`, switch vào active tenant với effective role `admin`, rồi quản lý member trong tenant đang chọn. |

`app_users.role` vẫn tồn tại để tương thích migration và legacy bootstrap, nhưng effective authorization sau multi-tenant RBAC đến từ active `tenant_memberships.role`. `platform_admin` là role bổ sung toàn cục, không thay thế tenant role trong response session.

## 2. Auth, Session Và Effective Role

Luồng đăng nhập:

1. `POST /v1/auth/login` xác thực `username`/`password` trong `app_users`.
2. Request có thể gửi `tenant_slug`; nếu bỏ trống, server chọn tenant active mặc định từ danh sách access của user, ưu tiên `default` khi có.
3. `AuthenticateForTenant` resolve danh sách `tenants[]`, chọn active tenant và set `user.role` thành role trong tenant đó.
4. Server tạo `user_sessions` với `active_tenant_id`, trả `Session` gồm token, `active_tenant` và danh sách tenant access.

Luồng request authenticated:

- `requireActor` lấy bearer token hoặc cookie `anti_ddos_session`, gọi `AuthenticateToken`, resolve lại active tenant hiện tại và set `contextWithTenant(r.Context(), actor.TenantID)`.
- Mọi handler dashboard/control-plane sau đó chạy trong tenant context của actor.
- `POST /v1/tenants/switch` cập nhật `user_sessions.active_tenant_id`, ghi audit `switch_tenant`, rồi trả session với effective role mới.

Normal user chỉ switch được sang tenant active mà user có active membership. `platform_admin` được `userTenantAccesses` trả mọi tenant active với effective role `admin`, nên có thể switch vào tenant active bất kỳ.

## 3. Ma Trận Quyền

| Capability | `viewer` | `operator` | `admin` | `platform_admin` |
|---|---:|---:|---:|---:|
| Đọc dashboard/control-plane trong active tenant | Có | Có | Có | Có khi đã có active tenant |
| Service, forwarding policy, rule, whitelist, blacklist, UDP source-port block | Không | Có | Có | Có khi switched vào tenant |
| Snapshot build/rollback/diff | Đọc | Mutation | Mutation | Mutation khi switched vào tenant |
| Baseline/anomaly operational actions | Đọc | Mutation | Mutation | Mutation khi switched vào tenant |
| Telegram config/test | Không | Có, token write-only và response masked | Có | Có khi switched vào tenant |
| Feed source non-secret lifecycle/sync | Đọc | Có | Có | Có khi switched vào tenant |
| Feed `credential_ref` create/update/visibility | Không | Không | Có, response masked | Có khi switched vào tenant |
| Tenant member list | Có | Có | Có | Có trong active tenant |
| Tạo/sửa/reset/revoke viewer | Không | Có | Có | Có khi switched vào tenant |
| Tạo/sửa/reset/revoke operator/admin | Không | Không | Có | Có khi switched vào tenant |
| Tenant create/update/list revoked | Không | Không | Không | Có |

Backend luôn là enforcement chính. UI ẩn hoặc disable control theo role để giảm lỗi thao tác, nhưng mọi mutation vẫn phải qua store-level checks như `requireOperator`, `requireTenantUserCreatePermission`, `requireTenantUserTargetPermission` và các guard Admin-only.

## 4. User Và Membership Lifecycle

Identity và membership tách rời:

- `app_users` chứa identity toàn cục: username, password hash, legacy `role`, `platform_role`, trạng thái user và password flags.
- `tenant_memberships` chứa access theo tenant: `tenant_id`, `user_id`, `role`, `status`.
- `GET /v1/users` list member của active tenant bằng tenant context, không list global users.
- `POST /v1/users` tạo identity nếu chưa có, hoặc grant/reactivate membership nếu identity đã tồn tại.

Quy tắc mutation:

- Tenant `admin` có full member management trong active tenant.
- Tenant `operator` chỉ được tạo/reactivate/update/reset/revoke target role `viewer`.
- `viewer` không được tạo user, cấu hình Telegram, tạo feed hoặc thực hiện mutation.
- Password reset yêu cầu password tối thiểu 12 ký tự, có thể set `force_password_change`, và revoke session của user trong active tenant.
- Revoke user là revoke membership trong active tenant, đồng thời revoke session có cùng `active_tenant_id`.
- Không được làm tenant mất active admin cuối cùng; `ensureActiveAdminRemains` chặn revoke/downgrade admin cuối cùng.

Invariant quan trọng: non-platform identity có active role `operator` không được có active membership ở tenant khác. Invariant này được enforce ở cả application layer (`validateOperatorSingleTenantMembership`) và database trigger `enforce_operator_single_tenant_membership`. Migration `operator_single_tenant` fail-fast nếu dữ liệu cũ đã vi phạm.

## 5. Tenant Management

Tenant lifecycle nằm ở platform scope:

- `GET /v1/tenants` trả tenant active mà actor có thể dùng.
- `GET /v1/tenants?include_revoked=true` chỉ dành cho `platform_admin`, trả cả active và revoked để quản trị.
- `POST /v1/tenants` và `PATCH /v1/tenants/{id}` yêu cầu `platform_admin`.
- Tenant mới có `slug`, `name`, `status`; status hợp lệ là `active` hoặc `revoked`.
- `platform_admin` không tự mutation dữ liệu tenant bằng platform transaction; luồng vận hành chuẩn là switch vào active tenant rồi dùng effective role `admin` của tenant đó.

Tenant `default` được tạo trong migration `multi_tenant_rbac` và nhận dữ liệu cũ để giữ compatibility cho các API/flow hiện có.

## 6. Data Isolation Và RLS

Migration `multi_tenant_rbac` thêm `tenant_id` cho các bảng nghiệp vụ như agents, services, forwarding policies, rules, whitelist, blacklist, feeds, reputation, snapshots, apply status, events, baselines, anomalies, Telegram, alerts, UDP source-port blocks và audit. Sau khi backfill, các cột này được set `NOT NULL`.

Cơ chế isolation:

- `beginTenantTx` set `anti_ddos.tenant_id=<tenant>` và clear `anti_ddos.platform`.
- `beginPlatformTx` clear `anti_ddos.tenant_id` và set `anti_ddos.platform=true`.
- RLS policy `tenant_isolation` chỉ cho đọc/ghi row có `tenant_id` bằng `current_setting('anti_ddos.tenant_id')`, hoặc cho platform transaction khi `anti_ddos.platform=true`.
- Tenant-scoped store methods dùng `beginContextTenantTx` hoặc `beginActorTenantTx`; mutation ghi `tenant_id=actor.TenantID`.
- Background jobs chạy theo tenant bằng cách iterate active tenants hoặc resolve tenant từ parent resource trước khi ghi dữ liệu tenant.

Một số uniqueness chuyển từ global sang tenant-scoped, ví dụ agents theo `(tenant_id, hostname)`, backend services theo `(tenant_id, name)`, feed sources theo `(tenant_id, name)`, UDP source ports theo `(tenant_id, port)` và alert policies theo tenant/type/severity/channel. `policy_snapshots` dùng primary key `(tenant_id, version)`, nên snapshot version là theo tenant.

## 7. API Enforcement

Các endpoint `/v1` cho dashboard/control-plane đều yêu cầu authenticated actor, trừ auth, health, metrics và agent endpoints có cơ chế token riêng. Lỗi role được map thành `403` khi error là `errForbidden` hoặc message chứa role-required pattern; lỗi validation khác thường là `400`.

Các nhóm enforcement chính:

- Read endpoints: authenticated và tenant-scoped qua context/RLS.
- Operational mutations: gọi `requireOperator`, nên `operator` và `admin` được phép; `viewer` bị chặn.
- User/member mutations: dùng helper riêng để cho operator quản lý viewer nhưng chặn operator chạm operator/admin.
- Tenant mutations: yêu cầu `actor.PlatformRole == platform_admin`.
- Secret-sensitive mutations: feed credential yêu cầu `admin`; Telegram token được operator/admin cấu hình nhưng luôn masked trong response/audit.
- Agent register yêu cầu `X-Tenant-ID` hoặc `X-Tenant-Slug`; các agent subroute sau đó resolve tenant từ `agent_id`.

## 8. Dashboard Behavior

Admin Dashboard phản ánh nhưng không thay thế backend enforcement:

- Topbar hiện tenant switcher khi `user.tenants.length > 1`; operator một tenant không thấy switcher.
- User chip hiển thị `username · role` và thêm `platform_role` nếu có.
- Navigation `Tenants` chỉ hiện với `platform_admin`.
- `Accounts` dùng `AccessView` để quản lý member của active tenant.
- `AccessView` cho admin nút `Add user`; operator thấy `Add viewer` và role luôn bị ép về `viewer`.
- Operator chỉ thấy action edit/reset/session trên row viewer; operator/admin row hiển thị read-only.
- Các trang operational dùng `canMutate = user.role === 'admin' || user.role === 'operator'`; viewer không thấy hoặc không dùng được mutation controls.
- `TenantsView` gọi `/v1/tenants?include_revoked=true`, cho platform admin add/edit tenant và jump sang Accounts bằng tenant switch.

## 9. Secret Và Audit Handling

Mọi mutation quan trọng yêu cầu reason từ body `reason` hoặc header `X-Audit-Reason`; reason được ghi vào `audit_events`.

Secret handling hiện tại:

- Telegram `bot_token_ref` được lưu raw trong DB nhưng response/audit chỉ dùng masked value.
- Feed `credential_ref` chỉ Admin được create/update; Admin response hiển thị masked `***`, còn non-admin response omit credential state.
- Tests RBAC kiểm tra raw Telegram token và raw feed credential không xuất hiện trong audit payload.
- Password raw không được trả về response hoặc audit; reset password revoke session liên quan trong active tenant.

## 10. Gotchas Vận Hành

- `app_users.role` không nên dùng để quyết định quyền hiện tại; dùng effective role trong `tenant_memberships` của active tenant.
- Non-platform operator không thể được reuse làm viewer ở tenant khác nếu còn active operator membership.
- RLS tables cần chạy trong transaction đã set tenant context; query ngoài tenant/platform context sẽ lỗi hoặc không thấy dữ liệu.
- Platform transaction dành cho tenant/global maintenance, không phải bypass để mutation dữ liệu tenant tùy ý.
- Snapshot version là theo tenant; rollback/build snapshot phải nằm trong tenant transaction đúng.
- Revoked tenant không phải target switch hợp lệ cho normal user; platform admin list được revoked tenant để quản trị trạng thái.
- UI chỉ là lớp bảo vệ thao tác; khi nghi ngờ, kiểm tra backend store guard và integration test.

## 11. Nguồn Xác Thực Và Test Coverage

Source chính:

- `internal/control/types.go`: constants `RoleAdmin`, `RoleOperator`, `RoleViewer`, `PlatformRoleAdmin` và DTO session/user/tenant.
- `internal/control/store.go`: bootstrap admin, authenticate, token-to-actor, user create/list/revoke.
- `internal/control/tenant.go`: tenant context, tenant/platform tx, role helper, operator single-tenant validation.
- `internal/control/tenant_store.go`: tenant list/create/update/switch.
- `internal/control/admin_console.go`: user update/password reset/session revoke và active-admin invariant.
- `internal/control/migrations.go`: migration `multi_tenant_rbac`, RLS policy và trigger `operator_single_tenant`.
- `web/dashboard/src/DashboardShell.tsx`, `AccessView.tsx`, `TenantsView.tsx`: UI behavior theo role.

Tests liên quan:

- `internal/control/rbac_test.go`: operator-viewer lifecycle, secret masking, platform tenant management, switch restrictions và operator single-tenant invariant.
- `internal/control/migrations_test.go`: migration fail-fast khi operator có nhiều active memberships.
- `internal/control/server_test.go`, `admin_dashboard_integration_test.go`, `feed_test.go`, `alert_test.go`: coverage bổ sung cho RBAC trên endpoint và dashboard workflow.

Khuyến nghị xác thực khi sửa RBAC: chạy `go test ./internal/control -run 'RBAC|Migration|Server'`; với thay đổi lớn hơn, chạy thêm `make control-postgres-test`.

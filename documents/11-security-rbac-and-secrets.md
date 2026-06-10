# Security, RBAC And Secrets

Sơ đồ RBAC: [diagrams/rbac-tenant-flow.mmd](diagrams/rbac-tenant-flow.mmd)

## Security Model

Hệ thống dùng nhiều lớp bảo vệ:

1. API authentication bằng bearer token/session cho user và shared token cho Agent.
2. Tenant-aware authorization ở application layer.
3. PostgreSQL RLS trên bảng tenant-scoped.
4. Audit mọi mutation có actor/reason.
5. Secret redaction trong log/audit/API/UI.
6. XDP/NIC operational guardrails để tránh self-inflicted outage.

## User Roles

| Role | Scope | Quyền |
|---|---|---|
| `viewer` | Tenant active | Read-only dashboard/API |
| `operator` | Tenant active, một active tenant membership nếu non-platform | Mutation operational resources, quản lý viewer trong tenant |
| `admin` | Tenant active | Quản lý policy và user tenant, quyền cao hơn với feed credentials |
| `platform_admin` | Cross-tenant platform role | List/create/update tenants, switch tenant, bootstrap/admin-level operations |

`platform_role` tách khỏi tenant membership role. Platform admin được project thành admin access trên active tenants.

## Tenant Context

- Login có optional `tenant_slug`.
- Session lưu `active_tenant_id`.
- User response có `active_tenant` và `tenants[]`.
- Tenant switch tạo session/token mới với active tenant khác.
- Agent register yêu cầu `X-Tenant-ID` hoặc `X-Tenant-Slug`; các call Agent sau resolve tenant từ `agent_id`.

## PostgreSQL RLS

RLS policy dùng:

- `anti_ddos.tenant_id` cho tenant-scoped transaction.
- `anti_ddos.platform=true` cho platform transaction.

Mọi bảng nghiệp vụ sau migration v7 có `tenant_id NOT NULL`. Application phải mở transaction bằng helper tenant/platform tương ứng để query không bị RLS chặn hoặc leak.

## Permission Rules Đáng Chú Ý

- `requireOperator` cho phép `admin` và `operator`, từ chối `viewer`.
- Non-platform `operator` không được có nhiều active tenant memberships.
- Operator chỉ được quản lý viewer, không quản lý peer operator/admin.
- Feed credential mutation yêu cầu `admin` khi credential ref thay đổi.
- Tenants management yêu cầu `platform_admin`.

## Secret Handling

| Secret | Contract |
|---|---|
| `ANTI_DDOS_DB_DSN` | Env only, không ghi vào docs/log |
| `ANTI_DDOS_AGENT_SHARED_TOKEN` | Env in control-api, placeholder trong `.env.example` |
| `ANTI_DDOS_AGENT_TOKEN` | Host Agent env, redacted khi log lỗi |
| Feed credentials | Dùng credential ref như `env://VAR_NAME` hoặc `secret://anti-ddos/name`; không log plaintext |
| Telegram token | API/UI mask output; audit/log không chứa raw token |
| Admin password | `control-admin bootstrap --password-stdin`; `ADMIN_PASSWORD` chỉ dùng lab non-interactive |

## XDP/NIC Safety

- Compose stack không attach XDP; chỉ chạy management/control services.
- Host Agent mới attach XDP, thông qua `make agent-start` hoặc binary trực tiếp.
- Không dùng `agent-start` trên NIC thật nếu chưa xác nhận WAN/output roles.
- `agent-remove` detach Agent XDP và output `xdp_pass` theo guard trong Makefile.
- Output NIC có XDP program khác `xdp_pass` không được replace tự động.

## Source Alignment

- Roles/types: `internal/control/types.go`
- Tenant transactions/RLS context: `internal/control/tenant.go`
- Tenant store and switch: `internal/control/tenant_store.go`
- User/admin console: `internal/control/admin_console.go`, `internal/control/store.go`
- RBAC tests: `internal/control/rbac_test.go`
- Redaction: `internal/agent/redaction.go`, `internal/control/store.go`
- Safety commands: `Makefile`, `README.md`

# Requirements And Success Criteria

## Functional Requirements

| ID | Requirement | Acceptance criteria | Source |
|---|---|---|---|
| FR-01 | XDP chỉ xử lý IPv4 L3/L4; non-IPv4 pass | Non-IPv4 trả `XDP_PASS`, malformed/fragment drop | `bpf/xdp_data_plane.bpf.c` |
| FR-02 | Service allowlist là điều kiện bắt buộc | Không match `service_allowlist_*` thì `XDP_DROP` với reason 4 | `bpf/xdp_data_plane.bpf.c` |
| FR-03 | Whitelist có precedence trên blacklist, UDP port block và rule | Source whitelisted global hoặc đúng service bỏ qua các enforcement sau | `bpf/xdp_data_plane.bpf.c` |
| FR-04 | Blacklist drop khi không whitelisted | Match blacklist action drop thì `REASON_BLACKLIST` | `bpf/xdp_data_plane.bpf.c` |
| FR-05 | UDP source-port block chặn reflection ports khi enabled | UDP packet có source port enabled bị `REASON_UDP_AMP_SOURCE_PORT` | `internal/control/policy_store.go`, `bpf/xdp_data_plane.bpf.c` |
| FR-06 | Rule enforcement hỗ trợ observe, drop, sample, rate_limit | Drop/rate limit chỉ drop khi mode enforce; observe chỉ đếm/sample | `bpf/xdp_data_plane.bpf.c` |
| FR-07 | Redirect traffic sạch qua DEVMAP | Service resolved, action redirect, MAC rewrite OK thì `XDP_REDIRECT` | `bpf/xdp_data_plane.bpf.c` |
| FR-08 | Agent apply policy snapshot theo A/B slots | Populate inactive slot trước, sau đó flip `runtime_config.active_slot` | `internal/agent/policy_apply.go` |
| FR-09 | Control API quản lý policy source of truth | Services, rules, whitelist, blacklist, feeds, snapshots, audit có REST endpoints | `internal/control/server.go` |
| FR-10 | Dashboard dùng Control API, không gọi DB trực tiếp | UI API client chỉ gọi `/v1/*` | `web/dashboard/src/api.ts` |
| FR-11 | Tenant là Customer Account boundary | Mọi operational resource có tenant context; không query tenant-scoped resource ngoài active tenant hoặc audited platform workflow | `internal/control/tenant.go` |
| FR-12 | Observability gồm metrics và sampled security events | Agent `/metrics`; event batch tối đa 1000; Control API lưu `security_events` tenant-scoped | `internal/agent/agent.go`, `internal/control/events.go` |
| FR-13 | Auth/session trả SaaS context | Login/me response có `active_tenant`, memberships và effective role cho active tenant |
| FR-14 | Platform roles tách khỏi tenant roles | `platform_owner`, `platform_admin`, `platform_support`, `platform_auditor` không tự động bypass tenant audit |
| FR-15 | Tenant roles canonical | `tenant_owner`, `tenant_admin`, `security_operator`, `network_operator`, `viewer`, `auditor` là role product-facing duy nhất |
| FR-16 | Tenant lifecycle được kiểm soát | Provision/active/suspend/offboard/revoke có actor, reason và audit |
| FR-17 | Membership lifecycle được kiểm soát | Invite/activate/suspend/revoke membership revoke hoặc invalidate session tương ứng |
| FR-18 | Agent registration tenant-bound | Register yêu cầu tenant identifier hợp lệ; heartbeat/snapshot/apply/events resolve tenant từ agent identity |
| FR-19 | Audit endpoint tenant-aware | `auditor`, `tenant_admin`, `tenant_owner` chỉ thấy audit tenant; `platform_auditor`, `platform_admin`, `platform_owner` thấy platform audit theo policy |
| FR-20 | Platform support/break-glass được ràng buộc | Access phải tenant-specific, time-bound, reason-required và audited |

## Non-Functional Requirements

| ID | Requirement | Acceptance criteria |
|---|---|---|
| NFR-01 | An toàn vận hành NIC | Lệnh production XDP phải yêu cầu interface đã phê duyệt và rollback plan |
| NFR-02 | Không lộ secret | Token/credential chỉ dùng env hoặc ref; audit/log/docs không ghi raw secret |
| NFR-03 | Policy rollout atomic ở data plane | Snapshot lỗi không làm mất active policy trước đó |
| NFR-04 | Tenant isolation defense-in-depth | `tenant_id` trên bảng nghiệp vụ, RLS enabled/forced hoặc isolation guard tương đương |
| NFR-05 | Repeatable lab deploy | `make env-init`, `make compose-config`, `make deploy`, `make dev-health` chạy được khi Docker có sẵn |
| NFR-06 | Testability | Có unit, integration, UI, BPF fixture, VETH lab tests |
| NFR-07 | Auditable cross-tenant operations | Mọi platform action vào tenant data có tenant target, reason, actor, TTL nếu support |

## RBAC Requirements

### Platform Roles

| Role | Quyền chính |
|---|---|
| `platform_owner` | Sở hữu platform RBAC, phê duyệt break-glass policy, revoke tenant, quản lý `platform_admin`, `platform_support`, `platform_auditor` |
| `platform_admin` | Provision/update/suspend tenant, bootstrap vận hành platform, cấp support access theo policy |
| `platform_support` | Access tenant cụ thể trong thời hạn được cấp để hỗ trợ khách hàng; không có quyền mặc định ngoài grant |
| `platform_auditor` | Read-only platform audit, tenant lifecycle history và support access history |

### Tenant Roles

| Role | Quyền chính |
|---|---|
| `tenant_owner` | Quản trị cao nhất của Customer Account, membership/settings/offboarding và mọi operational resource |
| `tenant_admin` | Quản lý members, services, policies, snapshots, alerts, integrations và audit tenant |
| `security_operator` | Quản lý security controls: rules, whitelist, blacklist, UDP blocks, feeds, snapshots, incidents |
| `network_operator` | Quản lý network controls: protected services, forwarding, agents/nodes và interface metadata |
| `viewer` | Read-only operational dashboard và API trong active tenant |
| `auditor` | Read-only audit, change history, alert history và compliance view trong active tenant |

## Safety Requirements

- Không attach XDP trên NIC thật từ tài liệu hoặc automation bàn giao nếu chưa có phê duyệt.
- Production service list gồm tối thiểu: name, backend IP/CIDR, protocol, ports, owner, criticality, output interface, next-hop/return path.
- Output interface native DEVMAP có thể cần `xdp_pass` tùy driver như `ixgbe`; không replace XDP program lạ trên output NIC.
- Snapshot mới phải có `object_checksum` khớp BPF object Agent đang chạy.
- Agent token và Telegram/feed credentials phải được redacted khi log lỗi.
- Platform support access vào Customer Account phải có reason và TTL trước khi mở session.

## Definition Of Done Cho Rebuild

Một implementation tương tự được xem là đạt nếu:

1. Build được BPF object, Go binaries và dashboard.
2. Chạy được Control API migrations v1-v8-equivalent và bootstrap `platform_owner`/`platform_admin` đầu tiên.
3. Dashboard login được, switch active tenant được, các màn hình chính gọi API thành công.
4. BPF fixture test xác nhận packet decision flow cốt lõi.
5. Agent VETH lifecycle và DEVMAP forwarding lab pass, không cần NIC thật.
6. Snapshot build/apply/rollback pass với apply ack đúng.
7. Tenant RBAC/RLS tests pass, gồm role split `security_operator`/`network_operator`, read-only `viewer`/`auditor`, agent tenant-bound và cross-tenant deny.
8. Platform support/break-glass tests pass, gồm TTL, reason và audit.

## Source Alignment

- Test targets: `Makefile`
- Current RBAC tests/source anchors: `internal/control/rbac_test.go`, `internal/control/types.go`, `internal/control/tenant.go`
- Policy validation tests: `internal/control/policy_validation_test.go`, `internal/agent/policy_snapshot_test.go`
- BPF fixture: `tests/xdp/xdp_fixture_test.c`
- VETH labs: `scripts/lab/agent-lifecycle-veth-test.sh`, `scripts/lab/devmap-forwarding-veth-test.sh`

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
| FR-11 | Multi-tenant RBAC áp dụng toàn control plane | Session có active tenant; tenant-scoped transaction set GUC cho RLS | `internal/control/tenant.go` |
| FR-12 | Observability gồm metrics và sampled security events | Agent `/metrics`; event batch tối đa 1000; Control API lưu `security_events` | `internal/agent/agent.go`, `internal/control/events.go` |

## Non-Functional Requirements

| ID | Requirement | Acceptance criteria |
|---|---|---|
| NFR-01 | An toàn vận hành NIC | Lệnh production XDP phải yêu cầu interface đã phê duyệt và rollback plan |
| NFR-02 | Không lộ secret | Token/credential chỉ dùng env hoặc ref; audit/log/docs không ghi raw secret |
| NFR-03 | Policy rollout atomic ở data plane | Snapshot lỗi không làm mất active policy trước đó |
| NFR-04 | Tenant isolation defense-in-depth | `tenant_id` trên bảng nghiệp vụ, RLS enabled và forced |
| NFR-05 | Repeatable lab deploy | `make env-init`, `make compose-config`, `make deploy`, `make dev-health` chạy được khi Docker có sẵn |
| NFR-06 | Testability | Có unit, integration, UI, BPF fixture, VETH lab tests |

## RBAC Requirements

| Role | Quyền chính |
|---|---|
| `viewer` | Read-only dashboard/API trong tenant active |
| `operator` | Mutation policy/ops trong tenant active, quản lý viewer trong tenant của mình, không multi-tenant active membership |
| `admin` | Quản lý policy, user/membership tenant, feed credential changes cần admin khi credential ref thay đổi |
| `platform_admin` | Cross-tenant platform role, tạo/sửa tenant, switch tenant, xem include revoked tenant |

## Safety Requirements

- Không attach XDP trên NIC thật từ tài liệu hoặc automation bàn giao nếu chưa có phê duyệt.
- Production service list gồm tối thiểu: name, backend IP/CIDR, protocol, ports, owner, criticality, output interface, next-hop/return path.
- Output interface native DEVMAP có thể cần `xdp_pass` tùy driver như `ixgbe`; không replace XDP program lạ trên output NIC.
- Snapshot mới phải có `object_checksum` khớp BPF object Agent đang chạy.
- Agent token và Telegram/feed credentials phải được redacted khi log lỗi.

## Definition Of Done Cho Rebuild

Một implementation tương tự được xem là đạt nếu:

1. Build được BPF object, Go binaries và dashboard.
2. Chạy được Control API migrations v1-v8 và bootstrap platform admin.
3. Dashboard login được, switch tenant được, các màn hình chính gọi API thành công.
4. BPF fixture test xác nhận packet decision flow cốt lõi.
5. Agent VETH lifecycle và DEVMAP forwarding lab pass, không cần NIC thật.
6. Snapshot build/apply/rollback pass với apply ack đúng.
7. Tenant RBAC/RLS tests pass.

## Source Alignment

- Test targets: `Makefile`
- RBAC tests: `internal/control/rbac_test.go`
- Policy validation tests: `internal/control/policy_validation_test.go`, `internal/agent/policy_snapshot_test.go`
- BPF fixture: `tests/xdp/xdp_fixture_test.c`
- VETH labs: `scripts/lab/agent-lifecycle-veth-test.sh`, `scripts/lab/devmap-forwarding-veth-test.sh`

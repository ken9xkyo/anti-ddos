# Testing And Verification

## Test Strategy

Test suite chia theo risk surface:

| Surface | Test type | Command |
|---|---|---|
| eBPF fixture | Compile/load object and packet fixture | `make bpf-test` |
| Go unit/integration | Agent/control logic | `make go-test` |
| Go vet | Static sanity | `make go-vet` |
| Race detector | Shared state/concurrency | `make go-race` |
| Dashboard unit/build | React/Vite | `make ui-test`, `make ui-build` |
| PostgreSQL integration | Control API + DB | `make control-postgres-test` |
| VETH XDP lifecycle | Safe lab attach/detach | `make agent-lifecycle-veth-test` |
| VETH DEVMAP forwarding | Forwarding and xdp_pass lab | `make devmap-forwarding-veth-test` |
| Services UI E2E | Dashboard flow | `make services-ui-e2e` |

## Primary Gates

| Gate | Command | Khi nào chạy |
|---|---|---|
| Fast local | `make test` | Trước commit thường |
| Full local | `make test-all` | Trước bàn giao/release |
| Dashboard bundle | `make admin-dashboard-test` | Khi đổi UI/API dashboard |
| Control DB | `make control-postgres-test` | Khi đổi migrations/RBAC/store/API |

`make test` chạy BPF fixture, Go tests, UI tests và UI build. `make test-all` thêm lint, race và integration tests.

## Integration Test Groups

| Target | Script |
|---|---|
| `control-core-postgres-test` | `scripts/lab/control-core-postgres-test.sh` |
| `observability-postgres-test` | `scripts/lab/observability-postgres-test.sh` |
| `anomaly-alert-only-postgres-test` | `scripts/lab/anomaly-alert-only-postgres-test.sh` |
| `anomaly-auto-enforce-postgres-test` | Legacy alias for alert-only test |
| `threat-feed-postgres-test` | `scripts/lab/threat-feed-postgres-test.sh` |
| `alerting-postgres-test` | `scripts/lab/alerting-postgres-test.sh` |
| `dashboard-postgres-test` | `scripts/lab/dashboard-postgres-test.sh` |

Một số tests tự dùng PostgreSQL container riêng nếu `ANTI_DDOS_CONTROL_TEST_DSN` không được set.

## Acceptance Scenarios

| Scenario | Expected result |
|---|---|
| Packet không match service | XDP drop với `REASON_NOT_ALLOWED_SERVICE` |
| Whitelisted source trùng service | Bỏ qua blacklist/UDP port/rule enforcement |
| Blacklisted source không whitelist | Drop với `REASON_BLACKLIST` |
| UDP reflection source port enabled | Drop với `REASON_UDP_AMP_SOURCE_PORT` |
| Snapshot version cũ | Agent reject vì không newer than active version |
| Object checksum mismatch | Agent reject validate |
| Unresolved neighbor | Apply resolve fail hoặc XDP drop `REASON_NEIGHBOR_UNRESOLVED` |
| `viewer` mutation | 403 backend hoặc UI không hiện action |
| `auditor` mutation | 403 backend hoặc UI chỉ hiện audit/read-only surfaces |
| `security_operator` đổi forwarding/service | 403; UI không hiện network mutation controls |
| `network_operator` đổi rule/list/feed/snapshot enforcement | 403; UI không hiện security mutation controls |
| `tenant_owner`/`tenant_admin` quản lý member | Invite/suspend/revoke membership audited; session bị revoke khi cần |
| Cross-tenant query | Không trả dữ liệu tenant khác; RLS/isolation guard chặn |
| Tenant suspended | Mutation và agent registration mới bị chặn; audit/read-only theo policy còn kiểm soát |
| Platform support access | Chỉ vào tenant được grant, có TTL/reason/banner và audit events |
| Agent register thiếu tenant | Reject; không tạo agent orphan |
| Feed failure | Record feed run/status, giữ last valid entries/snapshot |
| Prometheus missing | Dashboard/control report unconfigured, không crash |

## SaaS RBAC Test Matrix

| Area | Minimum tests |
|---|---|
| Auth/session | Login returns active tenant, memberships, effective role; tenant switch validates membership/support grant |
| Tenant lifecycle | Provision, activate, suspend, offboard, revoke require platform role and audit |
| Membership lifecycle | Invite, activate, suspend, revoke enforce `tenant_owner`/`tenant_admin` permission and invalidate sessions |
| Resource authorization | Services/forwarding require network permission; rules/lists/feeds/snapshots require security permission |
| Read-only roles | `viewer` and `auditor` cannot mutate through UI or API |
| Platform audit | Platform auditor read-only; support/break-glass access tracked |
| Tenant isolation | DB/API tests prove tenant-scoped resources cannot leak across Customer Accounts |

## Documentation Verification

Sau khi cập nhật tài liệu:

- Kiểm tra link nội bộ trong `documents/`.
- Kiểm tra Mermaid syntax của `documents/diagrams/*.mmd`.
- So endpoint list với `internal/control/server.go`.
- So DB migrations với `internal/control/migrations.go`.
- So BPF ABI/maps với `include/anti_ddos/bpf_contract.h` và `bpf/xdp_data_plane.bpf.c`.
- Search validation bảo đảm target role names nhất quán trong requirements, RBAC, API, dashboard và rebuild docs.
- Search validation bảo đảm billing/entitlement/subscription/plan/quota chỉ xuất hiện như out-of-scope hoặc thuật ngữ vận hành không liên quan RBAC.
- Search validation bảo đảm cross-tenant/platform access luôn đi kèm audit và reason requirements.

## Source Alignment

- Make targets: `Makefile`
- BPF tests: `tests/xdp/xdp_fixture_test.c`
- Go tests: `internal/**/*.go` test files
- Current RBAC/source anchors: `internal/control/rbac_test.go`, `internal/control/tenant.go`
- Dashboard tests: `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`
- Lab scripts: `scripts/lab/*.sh`, `scripts/e2e/phase4_services_forwarding.py`

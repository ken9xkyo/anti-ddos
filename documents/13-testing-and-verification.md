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
| Viewer mutation | 403 backend hoặc UI không hiện action |
| Operator multi-tenant active violation | Migration v8 hoặc tenant access guard chặn |
| Feed failure | Record feed run/status, giữ last valid entries/snapshot |
| Prometheus missing | Dashboard/control report unconfigured, không crash |

## Documentation Verification

Sau khi cập nhật tài liệu:

- Kiểm tra link nội bộ trong `documents/`.
- Kiểm tra Mermaid syntax của `documents/diagrams/*.mmd`.
- So endpoint list với `internal/control/server.go`.
- So DB migrations với `internal/control/migrations.go`.
- So BPF ABI/maps với `include/anti_ddos/bpf_contract.h` và `bpf/xdp_data_plane.bpf.c`.

## Source Alignment

- Make targets: `Makefile`
- BPF tests: `tests/xdp/xdp_fixture_test.c`
- Go tests: `internal/**/*.go` test files
- Dashboard tests: `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`
- Lab scripts: `scripts/lab/*.sh`, `scripts/e2e/phase4_services_forwarding.py`

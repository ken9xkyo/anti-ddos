# Policy Snapshot And Enforcement

Sơ đồ lifecycle: [diagrams/policy-snapshot-lifecycle.mmd](diagrams/policy-snapshot-lifecycle.mmd)

## Mục Tiêu

Policy snapshot là contract giữa Control Plane và Node Agent. Control API build snapshot từ PostgreSQL tenant-scoped state. Agent verify snapshot, populate eBPF maps theo inactive A/B slot, rồi flip runtime config để active policy đổi atomically.

## Snapshot JSON Shape

Top-level fields:

| Field | Type | Bắt buộc | Mục đích |
|---|---|---|---|
| `schema_version` | int | yes | Hiện là `1` |
| `version` | uint32 | yes | Monotonic non-zero policy version |
| `checksum` | string | yes | SHA-256 canonical snapshot |
| `object_checksum` | string | yes | SHA-256 BPF object mà snapshot target |
| `feature_flags` | string array | no | Capability flags |
| `runtime` | object | yes | Malformed policy, sample denom |
| `whitelist_v4` | array | no | CIDR entries |
| `blacklist_v4` | array | no | CIDR entries |
| `udp_source_port_blocks` | array | no | UDP source ports |
| `services` | array | no | Protected service keys/forwarding metadata |
| `rules` | array | no | Rule configs |

Supported feature flags hiện tại: `policy_snapshot_v1`, `ipv4`, `ab_policy_maps`, `tx_devmap`, `udp_src_port_block`.

## Entry Contracts

| Entry | Key fields | Map target |
|---|---|---|
| CIDR | `entry_id`, `cidr`, `priority`, `action`, `source_type`, `scope`, optional `service_id`, `score`, `rule_id`, `expires_at_unix_ns` | `whitelist_v4_*`, `blacklist_v4_*` |
| UDP port block | `entry_id`, `port`, optional `expires_at_unix_ns` | `udp_src_port_blocks_*` |
| Service | `service_id`, `forwarding_policy_id`, `dst_v4`, `dst_port`, `proto`, `action`, `output_ifindex`, `devmap_key`, `neighbor_status`, `dst_mac`, `src_mac` | `service_allowlist_*`, `tx_devmap` |
| Rule | `rule_id`, `priority`, `action`, `mode`, `service_id`, `dimension`, thresholds, bursts, sample denom, expiry | `rule_config_*` |

## Validation Rules

Agent `VerifyPolicySnapshot` kiểm tra:

- `schema_version == 1`.
- `version` non-zero và mới hơn current version nếu current set.
- `object_checksum` không rỗng và khớp runtime object checksum nếu provided.
- `checksum` khớp canonical snapshot.
- `runtime.malformed_policy == ACTION_DROP`.
- `runtime.sample_denom <= ANTI_DDOS_MAX_EVENT_SAMPLE_DENOM`.
- Feature flags nằm trong supported list.
- Entry counts không vượt map capacity.
- Optional memory budget không vượt nếu configured.
- Services phải có metadata complete sau forwarding resolution.

## Control Plane Build Semantics

Control API build snapshot từ:

- Enabled services và forwarding policies.
- Enabled/non-expired whitelist entries.
- Manual blacklist và reputation entries đã normalize/deduplicate.
- Enabled/non-expired UDP source port blocks.
- Enabled/non-expired rules.
- BPF `object_checksum` từ `ANTI_DDOS_XDP_OBJECT`.

Snapshot được lưu vào `policy_snapshots` với `version`, `checksum`, `object_checksum`, JSON body, `created_by`, optional `rollback_from`.

## Agent Apply Transaction

1. Read current `runtime_config`.
2. Verify snapshot cho phép unresolved services.
3. Resolve forwarding metadata nếu service thiếu ifindex/MAC/neighbor status.
4. Sign lại snapshot sau resolution.
5. Verify lại snapshot không cho unresolved services.
6. Chọn inactive slot `1 - current.active_slot`.
7. Clear inactive slot maps.
8. Populate whitelist, blacklist, UDP port block, services, rules.
9. Update `tx_devmap` targets.
10. Update `runtime_config[0]` với active slot mới và policy version.
11. Persist last-valid snapshot.
12. Update runtime metrics và trả result `applied`.

Nếu bất kỳ stage nào fail, Agent trả result `failed` với `error_stage`, `error_reason`; active slot cũ vẫn giữ nguyên.

## Snapshot Diff And Rollback

Control API hỗ trợ:

- `GET /v1/snapshots`
- `GET /v1/snapshots/{version}`
- `GET /v1/snapshots/diff?from=&to=`
- `POST /v1/snapshots/build`
- `POST /v1/snapshots/rollback`

Diff so sánh object checksum, runtime, services, whitelist, blacklist, UDP source port blocks và rules. Rollback tạo snapshot version mới dựa trên target version, không làm giảm version.

## Source Alignment

- Snapshot schema/verify/sign: `internal/agent/policy_snapshot.go`
- Agent apply: `internal/agent/policy_apply.go`
- Last-valid snapshot: `internal/agent/snapshot.go`
- Control snapshot builder: `internal/control/snapshot.go`
- Snapshot diff: `internal/control/snapshot_diff.go`
- Snapshot tests: `internal/agent/policy_snapshot_test.go`, `internal/control/snapshot_test.go`

# Low-Level Design - Anti-DDoS Scrubbing Gateway eBPF/XDP

Trạng thái: tài liệu LLD được lập từ source code, [System-Architecture-Design.md](System-Architecture-Design.md), [High-Level-Design.md](High-Level-Design.md), [Control-Api.md](Control-Api.md) và README trong working tree ngày 2026-06-04.

Tài liệu này mô tả thiết kế mức thấp của Anti-DDoS Scrubbing Gateway hiện hữu: ABI giữa Go và eBPF, packet hot path trong `xdp_entry`, snapshot policy, quy trình Agent apply A/B slot, forwarding resolution, Control API/PostgreSQL boundary, observability và các failure mode vận hành. Tài liệu không đề xuất thay đổi code runtime, API, database schema, eBPF map layout hoặc dependency.

## 1. Mục Tiêu, Phạm Vi Và Personas

### 1.1 Mục tiêu LLD

- Cung cấp tài liệu đủ chi tiết để engineer có thể bảo trì data plane, Agent và Control Plane mà không phải suy diễn ABI hoặc flow runtime.
- Ràng buộc mô tả vào source hiện có, đặc biệt là `include/anti_ddos/bpf_contract.h`, `bpf/xdp_data_plane.bpf.c`, `internal/agent` và `internal/control`.
- Ghi rõ điểm fail-closed, điều kiện apply snapshot thành công, cách rollback runtime slot và surface observability.
- Giữ ranh giới rõ giữa source of truth PostgreSQL, desired policy snapshot và runtime eBPF maps.

### 1.2 In scope

- IPv4, L3/L4 scrubbing trên một node Ubuntu 24.04, native XDP là đường chạy chính.
- Service allowlist, whitelist, blacklist, UDP source-port block, runtime rule, rate-limit, event sampling và DEVMAP redirect.
- Node Agent load/attach XDP, verify BPF contract, sync policy snapshot, resolve forwarding metadata, apply A/B maps và expose metrics.
- Control API/PostgreSQL làm source of truth cho policy, user, agent, snapshot, events, alerts và audit.
- Admin Dashboard/Prometheus/Grafana là surface vận hành trên các API và metrics hiện hữu.

### 1.3 Out of scope

- IPv6 data plane.
- L7 inspection, TLS termination, HTTP reverse proxy, DPI hoặc WAF behavior.
- BGP, RTBH, FlowSpec hoặc ISP escalation automation production.
- Multi-node HA production, tenant/group model hoặc distributed consensus cho policy.
- Tự động thay thế XDP program khác đang chạy trên production NIC.

### 1.4 Personas và success criteria

| Persona | Nhu cầu | LLD implication |
|---|---|---|
| Viewer | Xem health, traffic decisions, events, alerts, snapshots | Read-only API và dashboard phải phản ánh đúng Agent/snapshot state |
| Operator | Thay đổi service/rule/policy, rollback snapshot, xử lý sự cố | Mutation cần reason, audit, snapshot diff và apply status rõ ràng |
| Admin | Quản trị user/session/secret | Backend RBAC là enforcement chính, raw secret không xuất hiện trong response/audit |

Success criteria runtime:

- Packet IPv4 không khớp service allowlist bị drop với `REASON_NOT_ALLOWED_SERVICE`.
- Snapshot chỉ được apply khi schema, checksum, object checksum, map capacity và forwarding metadata hợp lệ.
- Apply failure trước `runtime_config` flip không đổi active slot và không persist last-valid snapshot mới.
- Agent báo cáo apply result về `policy_apply_status`, bao gồm stage lỗi, map stats và devmap stats.
- XDP counters, sampled events, Agent metrics và Control metrics đủ để điều tra drop/redirect/failure.

## 2. Runtime Boundaries

| Boundary | Source chính | Trách nhiệm thấp cấp |
|---|---|---|
| Data Plane | `bpf/xdp_data_plane.bpf.c`, `include/anti_ddos/bpf_contract.h` | Parse packet, lookup active maps, enforce policy, count decision, sample event, rewrite MAC và redirect/drop/pass |
| Node Agent | `cmd/agent/main.go`, `internal/agent` | Load BPF object, validate map/program spec, pin maps/program, attach XDP, sync/apply snapshot, read counters/ringbuf |
| Control Plane | `cmd/control-api/main.go`, `internal/control` | Auth/RBAC, policy CRUD, snapshot build/rollback/fetch, agent register/heartbeat/apply, events/audit/alerts |
| Persistence | `internal/control/migrations.go` | PostgreSQL tables, constraints, indexes, immutable snapshot history và audit partitions |
| Management | `web/dashboard/src`, `deploy/prometheus`, `deploy/grafana` | Dashboard, Prometheus scrape config, Grafana dashboard và operator workflows |

Control Plane không ghi trực tiếp vào eBPF maps. eBPF maps là projection local của snapshot đã được Agent verify/apply. PostgreSQL là source of truth.

## 3. BPF ABI Và Map Contract

Sơ đồ source-to-runtime: [Mermaid](diagrams/low-level-design/bpf-map-contract.mmd), [SVG](diagrams/low-level-design/bpf-map-contract.svg).

ABI nằm ở hai phía:

- C side: `include/anti_ddos/bpf_contract.h` định nghĩa enum, struct layout và capacity macro được dùng bởi `bpf/xdp_data_plane.bpf.c`.
- Go side: `internal/agent/contract.go` mirror struct layout để populate/lookup eBPF maps bằng `github.com/cilium/ebpf`.
- Spec validation: `internal/agent/contracts_bpf.go` kiểm tra BPF object có `xdp_entry`, đúng map type và đúng `MaxEntries` trước khi load collection.

### 3.1 Action, reason và dimension constants

| Nhóm | Giá trị chính |
|---|---|
| L4 proto | `L4_ICMP=1`, `L4_TCP=6`, `L4_UDP=17` |
| Packet action | `ACTION_PASS=0`, `ACTION_DROP=1`, `ACTION_RATE_LIMIT=2`, `ACTION_OBSERVE=3`, `ACTION_SAMPLE=4`, `ACTION_NOT_FORWARD=5`, `ACTION_REDIRECT=6` |
| Drop reason | `REASON_MALFORMED=1`, `REASON_BLACKLIST=3`, `REASON_NOT_ALLOWED_SERVICE=4`, `REASON_RATE_LIMIT=5`, `REASON_RULE_DROP=6`, `REASON_MAP_ERROR=7`, `REASON_REDIRECT_ERROR=8`, `REASON_NEIGHBOR_UNRESOLVED=9`, `REASON_FRAGMENT=10`, `REASON_UDP_AMP_SOURCE_PORT=11` |
| Policy scope | `POLICY_SCOPE_GLOBAL=0`, `POLICY_SCOPE_SERVICE=1` |
| Neighbor status | `NEIGHBOR_UNRESOLVED=0`, `NEIGHBOR_RESOLVED=1` |
| Rate dimension | source, /24 subnet, service, source-service |

Rule mode hiện tại được encode numeric: `0` là observe mode, `1` là enforce mode. Drop/rate-limit chỉ drop packet khi mode enforce.

### 3.2 Map inventory

| Map | Type | Capacity | Key/value | Vai trò |
|---|---:|---:|---|---|
| `runtime_config` | ARRAY | 1 | `u32 -> runtime_config_value` | Active slot, policy version, malformed action, sample denominator |
| `whitelist_v4_a/b` | LPM_TRIE | 65,536 | `lpm_v4_key -> cidr_policy_value` | Source CIDR allowlist global/service |
| `blacklist_v4_a/b` | LPM_TRIE | 1,000,000 | `lpm_v4_key -> cidr_policy_value` | Manual/feed CIDR denylist |
| `udp_src_port_blocks_a/b` | HASH | 4,096 | `u32 port -> udp_src_port_block_value` | Global UDP reflection/amplification source-port block |
| `service_allowlist_a/b` | HASH | 16,384 | `service_key -> service_value` | Destination service match và forwarding metadata |
| `rule_config_a/b` | ARRAY | 4,096 | `rule_id -> rule_value` | Runtime default rule per service hoặc global |
| `rate_state` | LRU_HASH | 2,000,000 | `rate_key -> rate_value` | Token bucket state |
| `drop_counters` | PERCPU_HASH | 262,144 | `counter_key -> counter_value` | Aggregated packet/byte counters |
| `events` | RINGBUF | 64 MiB | `event_record` | Sampled security events |
| `tx_devmap` | DEVMAP | 128 | `devmap_key -> ifindex` | XDP redirect output targets |
| `prog_array` | PROG_ARRAY | 16 | unused by current hot path | Reserved tail-call surface |

### 3.3 A/B slot invariant

Policy-bearing maps are double-buffered: slot `0` uses suffix `_a`, slot `1` uses suffix `_b`. `runtime_config.active_slot` is the only hot-path switch. Agent always writes the inactive slot first, then flips `runtime_config` after all map population and `tx_devmap` updates succeed.

Important invariants:

- `active_slot` must be `0` or `1`; invalid value causes XDP drop with `REASON_MAP_ERROR`.
- `policy_version` must be non-zero for data plane to run; zero/missing runtime config fails closed.
- `rule_id` `0` is treated as no rule by `lookup_active_rule`.
- Service key is `(dst_v4, dst_port, proto)`, not source-sensitive.
- `service_value` must carry `ACTION_REDIRECT`, output ifindex, devmap key, resolved neighbor status and both MAC addresses before Agent can populate service map.

## 4. XDP Packet Hot Path

Sơ đồ chi tiết: [Mermaid](diagrams/low-level-design/xdp-hot-path.mmd), [SVG](diagrams/low-level-design/xdp-hot-path.svg).

Entry point là `xdp_entry(struct xdp_md *ctx)`. Packet path không gọi Control API, không đọc DB và không thực hiện allocation ngoài ringbuf event sampling.

### 4.1 Parse và runtime guard

1. Lookup `runtime_config[0]`.
2. Nếu config missing hoặc `policy_version == 0`, packet bị drop `REASON_MAP_ERROR`.
3. Nếu `active_slot > 1`, packet bị drop `REASON_MAP_ERROR` và có thể sample event.
4. `parse_packet` xử lý Ethernet/IPv4/L4:
   - Non-IPv4 trả `XDP_PASS` và count action pass.
   - IPv4 malformed bị drop `REASON_MALFORMED`.
   - IPv4 fragment bị drop `REASON_FRAGMENT`.
   - TCP/UDP/ICMP được map sang proto constants; protocol khác thành `L4_UNKNOWN`.

### 4.2 Service allowlist và threat precedence

Sau khi parse thành công:

1. `lookup_active_service(active_slot, meta)` lookup `service_allowlist_a/b`.
2. Không match service thì drop fail-closed `REASON_NOT_ALLOWED_SERVICE`.
3. Nếu match service, `meta.service_id` và `meta.rule_id` lấy từ `service_value`.
4. Whitelist lookup theo source IPv4. Entry áp dụng khi scope global hoặc scope service với đúng `service_id`.
5. Nếu không whitelist:
   - Blacklist action drop sẽ drop `REASON_BLACKLIST` và có thể override `meta.rule_id` bằng blacklist rule id.
   - UDP packet có source port trong `udp_src_port_blocks_a/b` sẽ drop `REASON_UDP_AMP_SOURCE_PORT`.
6. Whitelist bypass blacklist và UDP source-port block, nhưng không bypass service allowlist, neighbor guard hoặc redirect validation.

### 4.3 Forwarding guard, rule và redirect

1. `service->neighbor_status` phải là `NEIGHBOR_RESOLVED`, nếu không drop `REASON_NEIGHBOR_UNRESOLVED`.
2. Nếu source không whitelist, `lookup_active_rule` lấy `default_rule_id`:
   - `ACTION_DROP` + enforce mode: count/sample và drop `REASON_RULE_DROP`.
   - `ACTION_DROP` + observe mode: count/sample observe, sau đó vẫn cho đi tiếp.
   - `ACTION_SAMPLE`: sample theo `rule.sample_denom`, sau đó cho đi tiếp.
   - `ACTION_RATE_LIMIT`: token bucket theo dimension; over limit + enforce thì drop `REASON_RATE_LIMIT`; observe mode chỉ count/sample.
   - `ACTION_OBSERVE`: count/sample observe, sau đó cho đi tiếp.
3. Redirect chỉ được thực hiện khi `service->action == ACTION_REDIRECT` và `rewrite_eth_addrs` thành công.
4. `bpf_redirect_map(&tx_devmap, service->devmap_key, XDP_DROP)` phải trả `XDP_REDIRECT`; nếu không count/sample `REASON_REDIRECT_ERROR`.
5. Redirect thành công count action `ACTION_REDIRECT`, reason `REASON_NONE`.

### 4.4 Counters và sampled events

`count_packet` aggregate theo `counter_key`: reason, rule, service, proto, action và TCP SYN bit. `maybe_sample` ghi `event_record` vào ringbuf `events` khi denominator bật. `sample_denom` runtime/rule bị clamp bởi `ANTI_DDOS_MAX_EVENT_SAMPLE_DENOM`.

Counter map là PERCPU để giảm contention. Agent chịu trách nhiệm aggregate khi đọc metrics; Control Plane không nằm trên packet hot path.

## 5. Policy Snapshot Design

Snapshot JSON là desired runtime policy được Control API build và Agent apply. Schema Go nằm trong `internal/agent/policy_snapshot.go`.

### 5.1 JSON shape

`PolicySnapshot` gồm:

- `schema_version`, `version`, `checksum`, `object_checksum`, `feature_flags`.
- `runtime`: `malformed_policy`, `sample_denom`.
- `whitelist_v4`: CIDR allow entries.
- `blacklist_v4`: manual/feed CIDR drop entries.
- `udp_source_port_blocks`: global UDP source-port block entries.
- `services`: destination service and forwarding metadata.
- `rules`: rule action, mode, threshold, dimension, burst, sampling and expiry.

Supported feature flags hiện tại: `policy_snapshot_v1`, `ipv4`, `ab_policy_maps`, `tx_devmap`, `udp_src_port_block`.

### 5.2 Canonical checksum và object checksum

`SignPolicySnapshot` canonicalize snapshot trước khi SHA-256 checksum:

- Clear `checksum`.
- Copy and sort feature flags, whitelist, blacklist, UDP source-port blocks, services and rules.
- Default `runtime.malformed_policy` về `ACTION_DROP` khi zero.
- Marshal canonical shape và tính SHA-256.

`object_checksum` là SHA-256 của BPF object mà snapshot target. Agent verify `object_checksum` với object đã load để tránh apply snapshot vào ABI/map contract sai.

### 5.3 Validation rules

`VerifyPolicySnapshot` kiểm tra:

- `schema_version == 1`, `version > 0`, checksum tồn tại và khớp canonical checksum.
- Snapshot mới hơn current active version khi `CurrentVersion` được truyền.
- `object_checksum` khớp expected object checksum khi expected có giá trị.
- Runtime malformed policy phải là `ACTION_DROP`; sample denominator không vượt `1,000,000`.
- Feature flags đều nằm trong allowlist.
- CIDR là IPv4, không expired, không duplicate exact map key.
- UDP source-port block không duplicate port và không expired.
- Service key hợp lệ, service id non-zero, proto/port hợp lệ, action redirect.
- `devmap_key` không vượt capacity và không conflict output ifindex.
- Rule id trong range, không duplicate, không expired, sample denominator hợp lệ.
- Estimated memory không vượt budget nếu `MemoryBudgetBytes` được cấu hình.

Control Plane cho phép unresolved service khi verify snapshot build (`AllowUnresolvedServices: true`) để dashboard/operator không phải nhập next-hop MAC thủ công. Agent verify lần đầu cũng cho phép unresolved, resolve bằng host netlink, re-sign snapshot rồi verify lại với resolved forwarding metadata bắt buộc.

### 5.4 Snapshot builder trong Control Plane

`internal/control/snapshot.go` build effective snapshot từ PostgreSQL:

- Lấy `object_checksum` từ configured XDP object.
- Dùng feature flags base `policy_snapshot_v1`, `ipv4`, `ab_policy_maps`, `tx_devmap`; thêm `udp_src_port_block` khi có active UDP source-port block.
- Build rules, services, whitelist, blacklist và UDP source-port blocks từ bảng tương ứng.
- Manual blacklist ưu tiên feed reputation entry khi cùng exact CIDR.
- Assign default rules vào service dựa trên global/service rule selection hiện hữu.
- `policyContentFingerprint` bỏ qua version/checksum để tránh tạo snapshot mới khi content không đổi.
- Rollback tạo snapshot version mới từ target version cũ và set `rollback_from`.

## 6. Agent Load, Attach Và Apply A/B Slot

Sơ đồ apply: [Mermaid](diagrams/low-level-design/policy-apply-ab-slot.mmd), [SVG](diagrams/low-level-design/policy-apply-ab-slot.svg).

### 6.1 Load and attach

`LoadAndAttach` trong `internal/agent/loader.go`:

1. Remove memlock limit và tạo runtime directories.
2. Tính BPF object checksum.
3. Load collection spec từ `cfg.XDPObject`.
4. Validate `xdp_entry` và toàn bộ expected maps bằng `ValidateCollectionSpec`.
5. Enable map pinning và load collection với `PinPath`.
6. Load hoặc tạo last-valid snapshot tại `cfg.SnapshotPath`.
7. Seed `runtime_config` từ last-valid snapshot.
8. Apply bootstrap policy nếu `BootstrapPolicyPath` được cấu hình.
9. Pin `xdp_entry`, attach hoặc update pinned XDP link trên `WANIface`.
10. Lưu metadata gồm object checksum, program, interface, attach mode và previous checksum nếu đổi object.

Native XDP là mặc định. Generic fallback chỉ dùng khi cấu hình cho phép.

### 6.2 Control sync

`RunControlSync`:

- Register agent nếu chưa có local `agent_id`, gửi hostname, interfaces, kernel/Ubuntu version, XDP mode, devmap support và agent version.
- Mỗi 5 giây heartbeat với active policy version và interface inventory.
- Nếu `desired_policy_version > active`, fetch `GET /v1/agents/{id}/snapshot?active_version=N`.
- Apply snapshot bằng `ApplyPolicySnapshot`.
- Ack `POST /v1/agents/{id}/apply` với status, stage lỗi, map stats và devmap stats.

Agent auth dùng bearer token khi cấu hình. Nếu Control API token được cấu hình mà Agent không có token, sync có thể bị reject.

### 6.3 Apply transaction semantics

`ApplyPolicySnapshot` là local transaction best-effort quanh eBPF maps:

1. Read `runtime_config`, lấy previous version và active slot.
2. Verify snapshot với current version, object checksum, capacity và memory budget, cho phép unresolved services.
3. Resolve unresolved services nếu cần.
4. Re-sign snapshot sau resolution và verify lại, lần này forwarding metadata phải resolved.
5. Compute inactive slot `1 - active_slot`.
6. Clear inactive policy maps.
7. Populate whitelist, blacklist, UDP source-port blocks, service allowlist và rule config vào inactive slot.
8. Update `tx_devmap` với các devmap key/ifindex từ services.
9. Flip `runtime_config` sang inactive slot, version mới và runtime config mới.
10. Persist last-valid snapshot nếu `SnapshotPath` được cấu hình.
11. Update runtime snapshot in memory và metrics.

Rollback behavior:

- Failure trước `runtime_config` flip clear lại inactive slot và không đổi active slot.
- Failure khi update `tx_devmap` rollback các devmap keys đã chạm nếu có backup.
- Failure sau flip nhưng trước persist last-valid cố gắng restore old `runtime_config`, rollback devmap và clear inactive slot.
- Result luôn có `status`, `version`, `previous_version`, `active_slot`, `error_stage`, `error_reason`, `map_stats`, `devmap_stats`.

Known error stages gồm `runtime_config`, `validate`, `resolve_forwarding`, `clear_inactive`, `populate_whitelist`, `populate_blacklist`, `populate_udp_source_port_blocks`, `populate_services`, `populate_rules`, `populate_tx_devmap`, `runtime_flip`, `persist_last_valid`.

### 6.4 DEVMAP update guard

`updateDevmapTargets` refuse thay đổi một `devmap_key` đang tồn tại trỏ tới ifindex khác. Điều này tránh đổi output target đang active mà không có safe handoff. Nếu cần đổi key->ifindex trong vận hành, operator nên tạo policy với devmap key mới hoặc chuẩn bị maintenance window/cleanup explicit theo runbook.

## 7. Forwarding Resolver Và DEVMAP

Forwarding metadata có thể nằm sẵn trong snapshot hoặc được Agent resolve trên host. `NetlinkForwardingResolver.ResolveService` cần:

- `output_interface` không rỗng.
- Service id non-zero, proto/port hợp lệ.
- Output link tồn tại, có ifindex, đang UP và có source MAC 6-byte non-zero.
- Route tới `DstV4` đi qua đúng output ifindex.
- Neighbor target là gateway nếu route có gateway, nếu không là backend IP trực tiếp.
- Neighbor cache có resolved state hợp lệ hoặc probe thành công bằng netlink `NeighSet` với `NTF_USE`.

Nếu neighbor không resolved trong timeout, apply fail ở `resolve_forwarding`; active slot và last-valid snapshot giữ nguyên.

Native DEVMAP caveat: một số driver như `ixgbe` cần output NIC có XDP TX queues. Repo có chương trình `bpf/xdp_pass.bpf.c` và Makefile target `agent-start` có thể attach `xdp_pass` lên output interfaces, nhưng không thay thế non-`xdp_pass` program hiện có.

## 8. Control API, PostgreSQL, RBAC Và Audit

### 8.1 HTTP boundary

Control API routes nằm trong `internal/control/server.go`. Endpoint nghiệp vụ dưới `/v1`; `/healthz` và `/metrics` là ngoại lệ.

Nhóm endpoint chính:

- Auth/current user: `/v1/auth/login`, `/v1/auth/logout`, `/v1/me`, `/v1/me/password`.
- Users/session admin: `/v1/users`, `/v1/users/{id}/password-reset`, `/v1/users/{id}/sessions/revoke`.
- Policy objects: `/v1/services`, `/v1/forwarding-policies`, `/v1/whitelist`, `/v1/rules`, `/v1/blacklist`, `/v1/udp-source-port-blocks`, `/v1/feed-sources`.
- Snapshots: `/v1/snapshots`, `/v1/snapshots/build`, `/v1/snapshots/diff`, `/v1/snapshots/rollback`.
- Agent API: `/v1/agents/register`, `/v1/agents/{id}/heartbeat`, `/v1/agents/{id}/snapshot`, `/v1/agents/{id}/apply`, `/v1/agents/{id}/events`.
- Observability: `/v1/security-events`, dashboard endpoints, baselines/anomalies, alerts/Telegram.

JSON decoder reject unknown fields. Mutation reason lấy từ body `reason` trước, fallback header `X-Audit-Reason`.

### 8.2 RBAC

- Viewer: authenticated read.
- Operator: mutation operational cho service/policy/feed/snapshot/anomaly/alert actions.
- Admin: bao gồm Operator, thêm user management, password/session privileged operation và secret credential writes.

Dashboard chỉ ẩn control theo role; backend là enforcement chính.

### 8.3 PostgreSQL source of truth

Các bảng runtime-critical trong `internal/control/migrations.go`:

- `backend_services`, `forwarding_policies`, `rules`, `whitelist_entries`, `manual_blacklist_entries`, `feed_sources`, `reputation_entries`, `udp_source_port_blocks`.
- `policy_snapshots` lưu immutable snapshot JSON, checksum, object checksum và rollback lineage.
- `agents`, `agent_interfaces`, `policy_apply_status`.
- `security_events` phục vụ điều tra và anomaly.
- `alerts`, `alert_deliveries`, Telegram config.
- `audit_events` partition theo thời gian.

Policy delete/disable trong nhiều domain là soft-disable để giữ audit/history và cho phép rebuild/rollback có ngữ cảnh.

### 8.4 Agent apply acknowledgement

`RecordAgentApply` upsert `policy_apply_status` theo `(agent_id, policy_version)`. Khi status failed, Control Plane có thể tạo alert với evidence gồm agent id, policy version, error stage, error reason và devmap stats.

## 9. Observability Design

### 9.1 XDP to Agent

- `drop_counters`: Agent đọc định kỳ, aggregate PERCPU values và expose Prometheus metrics theo action/reason/service/rule/proto.
- `events` ringbuf: Agent `ConsumeRingbuf` decode `event_record`, normalize event và forward batch tới Control API.
- Map utilization và snapshot version được expose qua Agent metrics.

### 9.2 Agent to Control API

Agent forward sampled events qua `/v1/agents/{id}/events`. Control API normalize source IP và /24 prefix, lưu vào `security_events`, tăng metrics accepted/rejected và cung cấp query endpoints cho dashboard/investigation.

### 9.3 Metrics surfaces

| Surface | Endpoint | Nội dung |
|---|---|---|
| Agent | `/metrics` trên host, mặc định `:9091` | XDP attach mode, object checksum, active snapshot, counters, ringbuf, control forwarding metrics |
| Control API | `/metrics` trong compose, mặc định `:8080` | HTTP metrics, DB-backed gauges, event ingest, agent/apply health |
| Dashboard | `/v1/dashboard/*`, `/v1/security-events*`, `/v1/alerts*` | Fleet, services, rules, snapshots, events, alerts và investigation |
| Prometheus/Grafana | deploy config | Scrape, recording rules và visual dashboard |

## 10. Failure Modes Và Safety Behavior

| Failure | Detection/source | Runtime behavior | Operator signal |
|---|---|---|---|
| Missing/zero `runtime_config` | XDP map lookup | Drop `REASON_MAP_ERROR` | Agent metrics/counters |
| Invalid active slot | XDP guard | Drop `REASON_MAP_ERROR` | Counters/events nếu sampled |
| Unknown service | `service_allowlist` miss | Drop `REASON_NOT_ALLOWED_SERVICE` | Drop counters, security events |
| Malformed IPv4 | Parser | Drop `REASON_MALFORMED` | Drop counters |
| IPv4 fragment | Parser | Drop `REASON_FRAGMENT` | Drop counters |
| Blacklisted source | LPM blacklist | Drop `REASON_BLACKLIST` nếu không whitelisted | Events, blacklist view |
| UDP reflection source port | UDP port block map | Drop `REASON_UDP_AMP_SOURCE_PORT` nếu không whitelisted | Events, UDP blocks view |
| Unresolved neighbor | service value guard or Agent resolver | XDP drop or apply fail | `policy_apply_status.error_stage=resolve_forwarding` hoặc counters |
| Conflicting devmap target | Agent `updateDevmapTargets` | Apply fail before slot flip | `populate_tx_devmap`, alert |
| Runtime flip failure | `runtime_config.Update` | Rollback devmap/inactive slot, old slot remains | `runtime_flip`, apply status |
| Last-valid persist failure | file write | Attempt restore old runtime config | `persist_last_valid`, apply status |
| Output NIC lacks XDP TX queues | kernel/driver redirect error | Redirect can fail or traffic timeout | `xdp_redirect_err`, README ixgbe runbook |

Operational safety:

- `agent-start` requires approved WAN interface and refuses to replace non-`xdp_pass` output XDP program.
- Compose stack alone does not attach XDP.
- Production NIC attach requires explicit rollback plan outside this LLD.

## 11. Verification Gates

Fast gates:

```bash
go test ./...
make bpf-test
```

Broader gates when environment supports them:

```bash
make test
make test-all
make agent-lifecycle-veth-test
make devmap-forwarding-veth-test
```

LLD-specific verification:

- Markdown links resolve for HLD/SAD/API docs, source files and diagrams.
- Mermaid sources render to SVG without syntax error:
  - `docs/diagrams/low-level-design/xdp-hot-path.mmd`
  - `docs/diagrams/low-level-design/policy-apply-ab-slot.mmd`
  - `docs/diagrams/low-level-design/bpf-map-contract.mmd`
- No code, API schema, migration, BPF contract, Make target or dependency file changes are required for this documentation update.

## 12. Source References

Primary source files:

- `include/anti_ddos/bpf_contract.h`
- `bpf/xdp_data_plane.bpf.c`
- `bpf/xdp_pass.bpf.c`
- `internal/agent/contract.go`
- `internal/agent/contracts_bpf.go`
- `internal/agent/loader.go`
- `internal/agent/control_client.go`
- `internal/agent/policy_snapshot.go`
- `internal/agent/policy_apply.go`
- `internal/agent/forwarding_resolver.go`
- `internal/agent/counters.go`
- `internal/agent/ringbuf.go`
- `internal/agent/event_forwarder.go`
- `internal/control/server.go`
- `internal/control/snapshot.go`
- `internal/control/agent_store.go`
- `internal/control/events.go`
- `internal/control/migrations.go`
- `cmd/agent/main.go`
- `cmd/control-api/main.go`

Documentation references:

- [README.md](../README.md)
- [High-Level-Design.md](High-Level-Design.md)
- [System-Architecture-Design.md](System-Architecture-Design.md)
- [Control-Api.md](Control-Api.md)
- [Admin-Dashboard-v2.md](Admin-Dashboard-v2.md)
- [deployment/docker-compose.md](deployment/docker-compose.md)

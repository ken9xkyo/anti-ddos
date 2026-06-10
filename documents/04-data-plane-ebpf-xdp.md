# Data Plane eBPF/XDP

Sơ đồ packet decision: [diagrams/packet-decision-flow.mmd](diagrams/packet-decision-flow.mmd)

## Mục Tiêu

Data plane phải xử lý packet càng sớm càng tốt tại XDP hook, không phụ thuộc DB/network call, và chỉ dùng dữ liệu từ eBPF maps. Hành vi mặc định là fail closed với traffic IPv4 không thuộc protected service hoặc metadata forwarding chưa đủ.

## eBPF Program

| Program | Section | Vai trò |
|---|---|---|
| `xdp_entry` | `SEC("xdp")` | Main packet hot path trên WAN ingress |
| `xdp_pass` | `SEC("xdp")` trong `bpf/xdp_pass.bpf.c` | Pass-through helper cho output NIC khi driver/native DEVMAP yêu cầu XDP TX queues |

## ABI Constants

| Nhóm | Giá trị chính |
|---|---|
| Protocol | `L4_ICMP=1`, `L4_TCP=6`, `L4_UDP=17` |
| Action | `PASS=0`, `DROP=1`, `RATE_LIMIT=2`, `OBSERVE=3`, `SAMPLE=4`, `NOT_FORWARD=5`, `REDIRECT=6` |
| Reason | `NONE=0`, `MALFORMED=1`, `BOGON=2`, `BLACKLIST=3`, `NOT_ALLOWED_SERVICE=4`, `RATE_LIMIT=5`, `RULE_DROP=6`, `MAP_ERROR=7`, `REDIRECT_ERROR=8`, `NEIGHBOR_UNRESOLVED=9`, `FRAGMENT=10`, `UDP_AMP_SOURCE_PORT=11` |
| Scope | `GLOBAL=0`, `SERVICE=1` |
| Neighbor | `UNRESOLVED=0`, `RESOLVED=1` |
| Rate dimension | `SOURCE=0`, `SUBNET=1`, `SERVICE=2`, `SOURCE_SERVICE=3` |

## Map Inventory

| Map | Type | Capacity | Vai trò |
|---|---|---:|---|
| `whitelist_v4_a/b` | `LPM_TRIE` | 65,536 | CIDR whitelist A/B slot |
| `blacklist_v4_a/b` | `LPM_TRIE` | 1,000,000 | CIDR blacklist A/B slot |
| `udp_src_port_blocks_a/b` | `HASH` | 4,096 | UDP reflection source-port block A/B slot |
| `service_allowlist_a/b` | `HASH` | 16,384 | Protected service match A/B slot |
| `rule_config_a/b` | `ARRAY` | 4,096 | Rule config A/B slot |
| `tx_devmap` | `DEVMAP` | 128 | Output ifindex targets cho redirect |
| `rate_state` | `LRU_HASH` | 2,000,000 | Token bucket state |
| `drop_counters` | `PERCPU_HASH` | 262,144 | Packet/byte counters theo reason/rule/service/proto/action |
| `events` | `RINGBUF` | 64 MiB | Sampled event records |
| `runtime_config` | `ARRAY[1]` | 1 | Active slot, policy version, sample denom |
| `prog_array` | `PROG_ARRAY` | 16 | Dự phòng/tail call contract, hiện không phải hot path chính |

## Packet Hot Path

1. Lookup `runtime_config[0]`; nếu thiếu, policy version bằng 0 hoặc active slot ngoài `0..1` thì drop với `REASON_MAP_ERROR`.
2. Parse Ethernet + IPv4. Non-IPv4 pass. Malformed hoặc IPv4 fragment drop.
3. Lookup protected service bằng key `dst_v4`, `dst_port`, `proto`. Không match thì drop với `REASON_NOT_ALLOWED_SERVICE`.
4. Lookup whitelist theo source IPv4. Whitelist áp dụng nếu scope global hoặc scope service trùng `service_id`.
5. Nếu không whitelist, lookup blacklist; action drop thì drop với `REASON_BLACKLIST`.
6. Nếu không whitelist và packet UDP, lookup `udp_src_port_blocks`; match thì drop với `REASON_UDP_AMP_SOURCE_PORT`.
7. Nếu service `neighbor_status` chưa resolved thì drop với `REASON_NEIGHBOR_UNRESOLVED`.
8. Nếu không whitelist, lookup default rule của service và áp dụng action/mode.
9. Rewrite Ethernet destination/source MAC từ `service_value`.
10. Redirect qua `bpf_redirect_map(&tx_devmap, service->devmap_key, XDP_DROP)`.

## Rule Semantics

| Action | Observe mode | Enforce mode |
|---|---|---|
| `drop` | Count/sample như observed rule drop, không drop packet | Drop với `REASON_RULE_DROP` |
| `rate_limit` | Tính token bucket, count/sample over-limit, không drop | Drop khi over-limit với `REASON_RATE_LIMIT` |
| `sample` | Sample với `rule.sample_denom` hoặc 1 | Không khác biệt theo mode |
| `observe` | Count/sample và tiếp tục | Không drop |

Token bucket dùng `rate_state` theo dimension. `SOURCE_SERVICE` là fallback khi dimension không phải source/subnet/service.

## Counter And Event Contract

`drop_counters` dùng `counter_key` gồm reason, rule_id, service_id, proto, action, tcp_syn. Counter lưu packets/bytes. `events` ringbuf gửi `event_record` gồm timestamp monotonic, policy version, src/dst IPv4, ports, proto, flags, action, reason, service_id, rule_id, packet length.

## Implementation Constraints

- Chỉ exact service match theo destination IPv4/protocol/port từ current `service_key`.
- LPM lookup hiện xây key prefixlen 32 cho source IPv4; snapshot builder phải encode CIDR tương thích với map key.
- IPv4 fragment bị drop, không reassemble.
- Redirect yêu cầu output ifindex có trong `tx_devmap`; driver native như `ixgbe` có thể cần `xdp_pass` trên output interface.

## Source Alignment

- ABI: `include/anti_ddos/bpf_contract.h`
- Main XDP program: `bpf/xdp_data_plane.bpf.c`
- Output pass helper: `bpf/xdp_pass.bpf.c`
- Agent ABI validation: `internal/agent/contracts_bpf.go`
- BPF fixture tests: `tests/xdp/xdp_fixture_test.c`

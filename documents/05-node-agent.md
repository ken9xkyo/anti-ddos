# Node Agent

Sơ đồ Agent-Control: [diagrams/agent-control-sequence.mmd](diagrams/agent-control-sequence.mmd)

## Mục Tiêu

Node Agent là process chạy trên scrubbing host, chịu trách nhiệm load/attach XDP, pin eBPF maps/program/link, seed runtime config, apply policy snapshot, expose metrics, consume ringbuf events và đồng bộ với Control API.

## Entrypoint

`cmd/agent/main.go`:

- Load config từ environment bằng `agent.LoadConfigFromEnv`.
- Tạo `agent.New`.
- Chạy `Agent.Run(ctx)` với signal handling `SIGINT`/`SIGTERM`.
- Log JSON ra stderr và redact error string.

## Environment Contract

| Env | Default | Bắt buộc | Mục đích |
|---|---|---|---|
| `ANTI_DDOS_WAN_IFACE` | none | yes | Interface attach `xdp_entry` |
| `ANTI_DDOS_XDP_OBJECT` | `build/bpf/xdp_data_plane.bpf.o` | yes | BPF object path |
| `ANTI_DDOS_XDP_MODE` | `native` | yes | `native` hoặc `generic` |
| `ANTI_DDOS_XDP_ALLOW_GENERIC_FALLBACK` | `false` | no | Cho phép fallback generic khi native fail |
| `ANTI_DDOS_METRICS_ADDR` | `127.0.0.1:9091` | yes | Agent HTTP `/metrics`, `/healthz` |
| `ANTI_DDOS_BPF_PIN_DIR` | `/sys/fs/bpf/anti-ddos` | yes | bpffs root cho maps/links/programs |
| `ANTI_DDOS_SNAPSHOT_PATH` | `/var/lib/anti-ddos/agent/last-valid-snapshot.json` | yes | Last-valid snapshot |
| `ANTI_DDOS_BOOTSTRAP_POLICY_PATH` | empty | no | Snapshot local apply khi startup |
| `ANTI_DDOS_POLICY_MEMORY_BUDGET_BYTES` | `0` | no | Optional snapshot memory guard |
| `ANTI_DDOS_SAFE_DETACH_ON_EXIT` | `false` | no | Detach XDP khi Agent exit |
| `ANTI_DDOS_CONTROL_URL` | empty | no | Bật Control API sync |
| `ANTI_DDOS_AGENT_TOKEN` | empty | no | Bearer token cho Agent-Control |
| `ANTI_DDOS_AGENT_STATE_PATH` | `/var/lib/anti-ddos/agent/control-state.json` | khi Control URL set | Persist `agent_id` |

## Load And Attach Lifecycle

1. Remove memlock limit.
2. Ensure runtime directories.
3. Hash BPF object thành `object_checksum`.
4. Load collection spec bằng `github.com/cilium/ebpf`.
5. Validate program/maps expected qua `ValidateCollectionSpec`.
6. Enable map pinning vào `${BPF_PIN_DIR}/maps`.
7. Load collection, lấy program `xdp_entry`.
8. Load hoặc tạo last-valid snapshot, seed `runtime_config`.
9. Nếu có bootstrap policy path, load và apply snapshot.
10. Pin program vào `${BPF_PIN_DIR}/programs/xdp_entry`.
11. Attach XDP vào `ANTI_DDOS_WAN_IFACE`, pin link vào `${BPF_PIN_DIR}/links/xdp_<iface>`.
12. Ghi metadata JSON cạnh snapshot path.

## Control Sync

Khi `ANTI_DDOS_CONTROL_URL` có giá trị:

- Nếu chưa có `agent_id`, Agent gọi `POST /v1/agents/register` với hostname, interfaces, kernel, Ubuntu version, XDP mode, devmap support.
- Cứ 5 giây heartbeat tới `POST /v1/agents/{id}/heartbeat`.
- Nếu `desired_policy_version` lớn hơn active version, Agent gọi `GET /v1/agents/{id}/snapshot?active_version=n`.
- Agent apply snapshot bằng `ApplyPolicySnapshot`.
- Agent ack kết quả bằng `POST /v1/agents/{id}/apply`.
- Ringbuf events được batch forward tới `POST /v1/agents/{id}/events`.

Agent register trực tiếp cần `X-Tenant-ID` hoặc `X-Tenant-Slug`; sau register, heartbeat/snapshot/apply/events resolve tenant từ `agent_id`.

## Metrics And Health

Agent expose:

- `GET /healthz`: `starting` với 503 trước khi attach xong, `ok` sau khi ready.
- `GET /metrics`: Prometheus metrics gồm agent up, XDP mode, object checksum, snapshot version, counters, map stats, forwarding counters.

`Agent.collect` đọc `drop_counters`, set forwarding counters theo runtime snapshot và map stats.

## Forwarding Resolver

Agent dùng netlink resolver để hoàn thiện service forwarding metadata khi snapshot service chưa resolved:

- Validate output interface, destination IPv4, protocol/port.
- Resolve link, route, neighbor.
- Probe missing neighbor bằng `NeighSet` với `NTF_USE`.
- Fail apply nếu metadata không resolve được khi cần.

## Failure Behavior

| Stage | Hành vi |
|---|---|
| Config invalid | Exit code 2 |
| Load/attach fail | Agent startup fail, không ready |
| Snapshot validate fail | Apply result `failed`, active slot không đổi |
| Populate inactive fail | Clear inactive slot |
| Devmap update fail | Rollback touched devmap entries nếu có rollback closure |
| Persist last-valid fail | Restore runtime config cũ và rollback |
| Control API lỗi | Log warning redacted, tiếp tục tick sau |

## Source Alignment

- Config: `internal/agent/config.go`
- Entrypoint: `cmd/agent/main.go`
- Load/attach: `internal/agent/loader.go`
- Apply snapshot: `internal/agent/policy_apply.go`
- Control sync: `internal/agent/control_client.go`
- Metrics: `internal/agent/metrics.go`, `internal/agent/counters.go`
- Ringbuf/events: `internal/agent/ringbuf.go`, `internal/agent/event_forwarder.go`
- Forwarding resolver: `internal/agent/forwarding_resolver.go`

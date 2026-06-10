# Runbooks And Troubleshooting

## Runbook: Bootstrap Lab Stack

1. Tạo `.env` từ template:

```bash
make env-init
```

2. Sửa các giá trị `change-me-*` trong `.env` nếu không phải lab cục bộ.
3. Validate compose:

```bash
make compose-config
```

4. Start stack:

```bash
make deploy
```

5. Bootstrap admin:

```bash
make admin-bootstrap
```

6. Check health:

```bash
make dev-health
```

## Runbook: Register Host Agent Safely

1. Xác nhận WAN/output interface roles bằng văn bản.
2. Xác nhận service inventory và return path.
3. Build Agent/BPF:

```bash
make agent-build
```

4. Dry-run command nếu cần:

```bash
make -n AGENT_WAN_IFACE=<wan> AGENT_OUTPUT_IFACES=<out> agent-start
```

5. Start chỉ trên approved interfaces:

```bash
make AGENT_WAN_IFACE=<wan> AGENT_OUTPUT_IFACES=<out> agent-start
```

6. Theo dõi log và metrics:

```bash
tail -f build/agent/anti-ddos-agent.log
curl -fsS http://127.0.0.1:9091/healthz
```

## Runbook: Build And Apply Snapshot

1. Tạo hoặc sửa service/rule/list qua Dashboard/API.
2. Vào Snapshots, build snapshot hoặc gọi `POST /v1/snapshots/build`.
3. Kiểm tra snapshot version và diff.
4. Agent heartbeat sẽ nhận `desired_policy_version` mới và fetch snapshot.
5. Kiểm tra `policy_apply_status` qua Dashboard Nodes/Snapshots hoặc Control metrics.
6. Nếu apply fail, đọc `error_stage` và `error_reason`.

## Runbook: Rollback Snapshot

1. Xác định target version tốt gần nhất.
2. Xem diff giữa current và target.
3. Gọi rollback qua Dashboard hoặc `POST /v1/snapshots/rollback` với `target_version` và `reason`.
4. Rollback tạo snapshot version mới, không hạ version.
5. Chờ Agent apply ack `applied`.
6. Nếu Agent không apply, kiểm tra object checksum và forwarding metadata.

## Runbook: Feed Failure

1. Vào Reputation, kiểm tra feed source status, `last_error`, `feed_runs`.
2. Kiểm tra credential ref, network reachability, interval và quota.
3. Không enable feed credential plaintext trong logs.
4. Chạy manual sync nếu cần.
5. Xác nhận last valid reputation entries/snapshot vẫn giữ nếu sync fail.
6. Nếu kéo dài, tạo hoặc evaluate alert/ISP escalation theo quy trình SOC.

## Runbook: Telegram Test

1. Vào Incidents, kiểm tra Telegram config.
2. Token phải là ref/masked value, không paste raw token vào ticket/log.
3. Operator/Admin chạy Telegram test.
4. Kiểm tra alert deliveries.
5. Nếu fail, kiểm tra `ANTI_DDOS_TELEGRAM_API_URL`, chat ID, token ref và network egress.

## Troubleshooting

| Triệu chứng | Khả năng | Cách xử lý |
|---|---|---|
| Dashboard login fail | Sai credential, session revoked, DB/API down | Check Control API logs, `/healthz`, admin bootstrap |
| Dashboard báo Prometheus unconfigured | `ANTI_DDOS_PROMETHEUS_URL` rỗng | Set env hoặc chấp nhận trạng thái lab không có Prometheus |
| Agent không ready | Config thiếu, attach fail, BPF load fail | Check `ANTI_DDOS_WAN_IFACE`, BPF object, privileges, log redacted |
| Snapshot apply fail `validate` | Checksum/schema/object/capacity sai | Rebuild snapshot, kiểm tra BPF object checksum |
| Snapshot apply fail `resolve_forwarding` | Interface/neighbor/route thiếu | Xác nhận output interface, route, ARP/neighbor |
| XDP redirect timeout | Output NIC cần pass-through XDP | Attach `xdp_pass` nếu driver/native yêu cầu |
| Packet bị drop `NOT_ALLOWED_SERVICE` | Chưa có service exact match | Kiểm tra destination IPv4/proto/port trong service snapshot |
| Packet bị drop `NEIGHBOR_UNRESOLVED` | Forwarding metadata chưa resolved | Kiểm tra resolver và service metadata |
| Viewer thấy action mutation | UI RBAC regression | Chạy dashboard tests, kiểm tra `canMutate` |
| Tenant data leak nghi ngờ | RLS/GUC transaction lỗi | Kiểm tra `beginContextTenantTx`, RLS enabled/forced, RBAC tests |

## Emergency Stop

Nếu cần dừng Agent:

```bash
make agent-stop
```

Nếu cần remove XDP pins/detach theo guard:

```bash
make AGENT_WAN_IFACE=<wan> AGENT_OUTPUT_IFACES=<out> agent-remove
```

Không dùng lệnh destructive thủ công trên production NIC nếu chưa biết program đang attach là gì.

## Source Alignment

- Make safety targets: `Makefile`
- Deploy docs: `docs/deployment/docker-compose.md`
- Agent code: `internal/agent/agent.go`, `internal/agent/loader.go`, `internal/agent/policy_apply.go`
- Control snapshots/feed/alerts: `internal/control/snapshot.go`, `internal/control/feed.go`, `internal/control/alert.go`

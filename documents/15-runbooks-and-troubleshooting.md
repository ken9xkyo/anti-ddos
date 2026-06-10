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

5. Bootstrap `platform_owner`/`platform_admin`:

```bash
make admin-bootstrap
```

6. Check health:

```bash
make dev-health
```

7. Provision lab Customer Account, tạo `tenant_owner`/`tenant_admin`, rồi switch active tenant trước khi tạo service/policy/agent.

## Runbook: Tenant Onboarding

1. `platform_owner`/`platform_admin` tạo tenant ở trạng thái `provisioned` với customer name/slug.
2. Ghi reason và customer reference trong audit.
3. Tạo hoặc mời `tenant_owner` đầu tiên.
4. `tenant_owner`/`tenant_admin` xác nhận membership active.
5. Network/SRE cung cấp service inventory và interface role matrix.
6. `platform_owner`/`platform_admin` chuyển tenant sang `active` khi onboarding checklist đạt.
7. Tạo protected services, forwarding metadata và policy ban đầu trong tenant active.

## Runbook: Membership Change

1. `tenant_owner`/`tenant_admin` mở Accounts trong active tenant.
2. Invite/suspend/revoke member theo role canonical.
3. Với `tenant_owner`, yêu cầu ít nhất một owner active còn lại trước khi revoke/suspend.
4. Ghi reason cho mutation.
5. Revoke hoặc refresh sessions của membership bị suspend/revoke.
6. Kiểm tra audit tenant hiển thị actor, target user, role và reason.

## Runbook: Platform Support Access

1. `platform_admin`/`platform_owner` tạo support grant cho một tenant cụ thể.
2. Grant phải có `platform_support` actor, ticket/reason và expiry.
3. Platform support switch vào tenant qua support session, UI phải hiển thị banner reason/expiry.
4. Mọi sensitive read/export/mutation phải ghi audit với platform support actor.
5. Hết TTL thì session không còn authorize được.
6. Sau sự cố, `platform_auditor` hoặc `platform_admin` review support audit.

## Runbook: Register Host Agent Safely

1. Xác nhận active Customer Account đúng.
2. Xác nhận WAN/output interface roles bằng văn bản.
3. Xác nhận service inventory và return path.
4. Build Agent/BPF:

```bash
make agent-build
```

5. Dry-run command nếu cần:

```bash
make -n AGENT_WAN_IFACE=<wan> AGENT_OUTPUT_IFACES=<out> agent-start
```

6. Start chỉ trên approved interfaces và tenant-bound agent token/config:

```bash
make AGENT_WAN_IFACE=<wan> AGENT_OUTPUT_IFACES=<out> agent-start
```

7. Theo dõi log và metrics:

```bash
tail -f build/agent/anti-ddos-agent.log
curl -fsS http://127.0.0.1:9091/healthz
```

## Runbook: Build And Apply Snapshot

1. Tạo hoặc sửa service/rule/list qua Dashboard/API trong active tenant.
2. Vào Snapshots, build snapshot hoặc gọi `POST /v1/snapshots/build`.
3. Kiểm tra snapshot version và diff trong cùng tenant.
4. Agent heartbeat sẽ nhận `desired_policy_version` mới và fetch snapshot tenant-bound.
5. Kiểm tra `policy_apply_status` qua Dashboard Nodes/Snapshots hoặc Control metrics.
6. Nếu apply fail, đọc `error_stage` và `error_reason`.

## Runbook: Rollback Snapshot

1. Xác định target version tốt gần nhất trong active tenant.
2. Xem diff giữa current và target.
3. Gọi rollback qua Dashboard hoặc `POST /v1/snapshots/rollback` với `target_version` và `reason`.
4. Rollback tạo snapshot version mới, không hạ version.
5. Chờ Agent apply ack `applied`.
6. Nếu Agent không apply, kiểm tra object checksum và forwarding metadata.

## Runbook: Feed Failure

1. Vào Reputation, kiểm tra feed source status, `last_error`, `feed_runs`.
2. Kiểm tra credential ref, network reachability, sync interval và upstream rate/error response.
3. Không enable feed credential plaintext trong logs.
4. Chạy manual sync nếu cần.
5. Xác nhận last valid reputation entries/snapshot vẫn giữ nếu sync fail.
6. Nếu kéo dài, tạo hoặc evaluate alert/ISP escalation theo quy trình SOC.

## Runbook: Telegram Test

1. Vào Incidents, kiểm tra Telegram config.
2. Token phải là ref/masked value, không paste raw token vào ticket/log.
3. `tenant_owner`, `tenant_admin` hoặc `security_operator` được cấp quyền chạy Telegram test.
4. Kiểm tra alert deliveries.
5. Nếu fail, kiểm tra `ANTI_DDOS_TELEGRAM_API_URL`, chat ID, token ref và network egress.

## Runbook: Tenant Suspension And Offboarding

1. `platform_owner`/`platform_admin` xác nhận reason, requester và customer notification reference.
2. Suspend tenant nếu cần chặn mutation/agent registration ngay.
3. Export audit/config theo retention policy nếu offboarding.
4. Chuyển tenant sang `offboarding` để khóa mutation mới trừ cleanup workflow.
5. Revoke hoặc rotate agent tokens và integration credentials.
6. Khi checklist xong, `platform_owner` chuyển tenant sang `revoked`.
7. Lưu final audit event và retention marker.

## Troubleshooting

| Triệu chứng | Khả năng | Cách xử lý |
|---|---|---|
| Dashboard login fail | Sai credential, session revoked, DB/API down | Check Control API logs, `/healthz`, platform bootstrap |
| User không switch được tenant | Membership suspended/revoked hoặc tenant suspended | Kiểm tra membership lifecycle, tenant state và audit |
| Platform support không vào được tenant | Grant hết hạn, thiếu reason hoặc tenant mismatch | Tạo grant mới đúng tenant, reason và TTL |
| Dashboard báo Prometheus unconfigured | `ANTI_DDOS_PROMETHEUS_URL` rỗng | Set env hoặc chấp nhận trạng thái lab không có Prometheus |
| Agent không ready | Config thiếu, tenant register lỗi, attach fail, BPF load fail | Check tenant identifier, `ANTI_DDOS_WAN_IFACE`, BPF object, privileges, log redacted |
| Snapshot apply fail `validate` | Checksum/schema/object/capacity sai | Rebuild snapshot, kiểm tra BPF object checksum |
| Snapshot apply fail `resolve_forwarding` | Interface/neighbor/route thiếu | Xác nhận output interface, route, ARP/neighbor |
| XDP redirect timeout | Output NIC cần pass-through XDP | Attach `xdp_pass` nếu driver/native yêu cầu |
| Packet bị drop `NOT_ALLOWED_SERVICE` | Chưa có service exact match | Kiểm tra destination IPv4/proto/port trong service snapshot |
| Packet bị drop `NEIGHBOR_UNRESOLVED` | Forwarding metadata chưa resolved | Kiểm tra resolver và service metadata |
| `viewer` hoặc `auditor` thấy action mutation | UI RBAC regression | Chạy dashboard tests, kiểm tra action visibility |
| Tenant data leak nghi ngờ | RLS/GUC transaction lỗi hoặc API thiếu tenant filter | Kiểm tra tenant transaction helper, RLS enabled/forced, RBAC tests |

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
- Current tenant/RBAC source anchors: `internal/control/tenant.go`, `internal/control/tenant_store.go`, `internal/control/rbac_test.go`

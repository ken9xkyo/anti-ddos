# Anti-DDoS Scrubbing Gateway eBPF/XDP

Anti-DDoS Scrubbing Gateway là hệ thống lọc DDoS L3/L4 đặt trước các dịch vụ backend. Lưu lượng đi vào WAN NIC của scrubbing server được xử lý sớm bằng XDP/eBPF; chỉ lưu lượng hợp lệ theo allowlist của protected service mới được L2 MAC rewrite và chuyển tiếp bằng `XDP_REDIRECT` qua DEVMAP tới interface hướng backend.

MVP này tập trung vào một node Ubuntu 24.04, IPv4, native XDP, policy snapshot an toàn, dashboard vận hành, Prometheus/Grafana, audit và Multi-Tenant RBAC. Control plane dùng shared database/shared schema với `tenant_id` trên dữ liệu nghiệp vụ và PostgreSQL RLS làm lớp cô lập defense-in-depth. Hệ thống không kết thúc TLS, không proxy HTTP, không xử lý L7/DPI và không thay thế WAF.

## Thành phần chính

| Plane | Thành phần | Vai trò |
|---|---|---|
| Data Plane | XDP/eBPF, eBPF maps | Phân tích packet, drop/rate-limit/redirect, ghi bộ đếm và sự kiện lấy mẫu |
| Forwarding Plane | L2 MAC rewrite, DEVMAP | Chỉ redirect lưu lượng sạch tới backend/service đã khai báo |
| Node Plane | Node Agent | Load/attach/rollback XDP, đồng bộ policy snapshot, expose `/metrics` |
| Control Plane | Control API, PostgreSQL | Quản lý tenants, memberships, dịch vụ, policy, feed, snapshot, audit và rollback |
| Management Plane | Admin Dashboard, Prometheus, Grafana | Hiển thị thời gian thực, tenant switcher, metrics, điều tra event và dashboard vận hành |

## Cảnh báo an toàn XDP/NIC

Không attach XDP vào NIC thật nếu chưa xác nhận rõ vai trò của WAN/LAN/output interface và inventory của protected backend service. Các lệnh khởi động nhanh bằng Docker Compose chỉ khởi động management/control stack; chúng không attach XDP và không tác động trực tiếp tới lưu lượng production.

Khi cần chạy Agent, hãy ưu tiên VETH/lab interface. Nếu chạy trên NIC thật, cần có phê duyệt vận hành riêng và rollback plan.

## Khởi động nhanh bằng Docker Compose

Yêu cầu: Docker Engine và Docker Compose plugin.

```bash
make env-init
# Sửa các giá trị change-me-* trong .env trước khi dùng ngoài lab cục bộ.

make compose-config
make deploy
make dev-health
```

Khởi tạo Admin đầu tiên:

```bash
make admin-bootstrap
```

Lệnh bootstrap chạy migrations nếu cần, tạo tenant mặc định `default`, tạo user đầu tiên với `platform_role=platform_admin` và gán membership `admin` trong tenant `default`.

Dùng trong lab không tương tác:

```bash
ADMIN_PASSWORD='replace-with-a-strong-password' make admin-bootstrap
```

Mở các giao diện:

- Admin Dashboard: `http://127.0.0.1:8088`
- Control API: `http://127.0.0.1:8080`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000`

Tài liệu chi tiết: [docs/deployment/docker-compose.md](docs/deployment/docker-compose.md).

## Multi-Tenant RBAC Và Data Isolation

Sau migration, các endpoint control-plane chạy trong active tenant của session:

- `POST /v1/auth/login` nhận optional `tenant_slug`; response trả `active_tenant`, danh sách `tenants[]` và role effective trong tenant.
- `platform_admin` có thể list/create/update tenants, switch tenant qua `/v1/tenants`, rồi tạo operator/viewer trong tenant đang chọn.
- `viewer`, `operator`, `admin` là role theo tenant membership; non-platform `operator` chỉ có một active tenant membership, không switch sang tenant khác, được quản lý lifecycle của viewer trong tenant đó; `admin` quản lý toàn bộ membership trong tenant, và `app_users.role` chỉ còn là legacy migration source.
- Telegram config là tenant-scoped; Operator/Admin cấu hình được Telegram của tenant, còn feed credential chỉ Admin được thấy/sửa.
- Dữ liệu policy, services, feeds, events, snapshots, agents, alerts và audit đều có `tenant_id`; PostgreSQL RLS yêu cầu app transaction set `anti_ddos.tenant_id`.
- Tenant dashboard ưu tiên dữ liệu control-plane tenant-scoped. Global Prometheus traffic không được trộn vào dashboard tenant nếu metric chưa có tenant label.

Tenant `default` chứa dữ liệu cũ sau migration để giữ compatibility cho đường dẫn API hiện có.

## Quy trình Dev/Test/Deploy

```bash
make help
make dev-up
make dev-logs
make dev-down
```

Kiểm thử nhanh:

```bash
make test
```

Bộ kiểm thử đầy đủ hơn cho admin dashboard và integration PostgreSQL:

```bash
make test-all
```

Một số kiểm thử tích hợp PostgreSQL sẽ tự dùng PostgreSQL container riêng khi không có `ANTI_DDOS_CONTROL_TEST_DSN`.
Có thể chạy riêng theo nhóm bằng các target `control-core-postgres-test`, `observability-postgres-test`,
`anomaly-alert-only-postgres-test`, `threat-feed-postgres-test`, `alerting-postgres-test` và
`dashboard-postgres-test`.
Sau thay đổi RBAC/RLS, ưu tiên chạy thêm target tổng hợp:

```bash
make control-postgres-test
```

## Chạy Node Agent trên host

Prometheus trong compose thu thập metrics từ Agent qua `host.docker.internal:9091`. Agent chỉ nên chạy sau khi đã chốt interface lab/an toàn:

```bash
make AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-start
make AGENT_WAN_IFACE=enp94s0f0 AGENT_OUTPUT_IFACES=enp134s0f1 agent-remove
```

Nếu chưa có interface được phê duyệt, hãy dùng các script lab VETH thay vì Agent trên NIC thật.

Control API tenant-aware yêu cầu `POST /v1/agents/register` có thêm `X-Tenant-Slug` hoặc `X-Tenant-ID`. Khi gọi Agent API trực tiếp, dùng tenant slug mặc định:

```bash
curl -sS \
  -H "Authorization: Bearer ${ANTI_DDOS_AGENT_SHARED_TOKEN}" \
  -H "X-Tenant-Slug: default" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"node-a","xdp_mode":"native","devmap_support":true}' \
  http://127.0.0.1:8080/v1/agents/register
```

Sau khi register, heartbeat/snapshot/apply/events tự resolve tenant từ `agent_id`. Nếu host Agent binary chưa truyền tenant header khi register, control sync sẽ bị từ chối với lỗi `tenant header is required`; dùng tenant-aware Agent build hoặc đăng ký qua API có header trước khi vận hành control loop.

### Lưu ý DEVMAP trên output NIC

Với native XDP forwarding, một số driver như `ixgbe` cần output interface cũng có XDP TX queues trước khi nhận packet từ `tx_devmap`. Nếu Agent chạy `xdp_entry` trên WAN ingress nhưng redirect tới backend bị timeout và tracepoint báo `xdp_redirect_err err=-95`, hãy attach chương trình pass-through tối thiểu lên interface hướng backend:

```bash
make build/bpf/xdp_pass.bpf.o
sudo ip link set dev <backend-output-iface> xdpdrv obj build/bpf/xdp_pass.bpf.o sec xdp
bpftool net
```

Ví dụ lab đã xác thực: `enp94s0f0` chạy `xdp_entry`, `enp134s0f1` chạy `xdp_pass`, service `118.107.78.137:2283/tcp` redirect thành công qua DEVMAP. Không thay thế một XDP program đang chạy trên output NIC nếu chưa có phê duyệt vận hành. Lệnh attach này là trạng thái runtime; sau reboot, NIC reset hoặc detach XDP cần attach lại cho đến khi Agent quản lý output XDP tự động.

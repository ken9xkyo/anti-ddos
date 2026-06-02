# Anti-DDoS Scrubbing Gateway eBPF/XDP

Anti-DDoS Scrubbing Gateway là hệ thống lọc DDoS L3/L4 đặt trước các dịch vụ backend. Lưu lượng đi vào WAN NIC của scrubbing server được xử lý sớm bằng XDP/eBPF; chỉ lưu lượng hợp lệ theo allowlist của protected service mới được L2 MAC rewrite và chuyển tiếp bằng `XDP_REDIRECT` qua DEVMAP tới interface hướng backend.

MVP này tập trung vào một node Ubuntu 24.04, IPv4, native XDP, policy snapshot an toàn, dashboard vận hành, Prometheus/Grafana và audit/RBAC. Hệ thống không kết thúc TLS, không proxy HTTP, không xử lý L7/DPI và không thay thế WAF.

## Thành phần chính

| Plane | Thành phần | Vai trò |
|---|---|---|
| Data Plane | XDP/eBPF, eBPF maps | Phân tích packet, drop/rate-limit/redirect, ghi bộ đếm và sự kiện lấy mẫu |
| Forwarding Plane | L2 MAC rewrite, DEVMAP | Chỉ redirect lưu lượng sạch tới backend/service đã khai báo |
| Node Plane | Node Agent | Load/attach/rollback XDP, đồng bộ policy snapshot, expose `/metrics` |
| Control Plane | Control API, PostgreSQL | Quản lý người dùng, dịch vụ, policy, feed, snapshot, audit và rollback |
| Management Plane | Admin Dashboard, Prometheus, Grafana | Hiển thị thời gian thực, metrics, điều tra event và dashboard vận hành |

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
`anomaly-auto-enforce-postgres-test`, `threat-feed-postgres-test`, `alerting-postgres-test` và
`dashboard-postgres-test`.

## Chạy Node Agent trên host

Prometheus trong compose thu thập metrics từ Agent qua `host.docker.internal:9091`. Agent chỉ nên chạy sau khi đã chốt interface lab/an toàn:

```bash
make agent-build

sudo env \
  ANTI_DDOS_WAN_IFACE=<approved-lab-or-wan-iface> \
  ANTI_DDOS_XDP_OBJECT=build/bpf/xdp_data_plane.bpf.o \
  ANTI_DDOS_METRICS_ADDR=0.0.0.0:9091 \
  ANTI_DDOS_CONTROL_URL=http://127.0.0.1:8080 \
  ANTI_DDOS_AGENT_TOKEN=<same-value-as-ANTI_DDOS_AGENT_SHARED_TOKEN> \
  build/agent/anti-ddos-agent
```

Nếu chưa có interface được phê duyệt, hãy dùng các script lab VETH thay vì Agent trên NIC thật.

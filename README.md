# Anti-DDoS Scrubbing Gateway eBPF/XDP

Anti-DDoS Scrubbing Gateway la he thong loc DDoS L3/L4 dat truoc backend service. Traffic di vao WAN NIC cua scrubbing server duoc xu ly som bang XDP/eBPF; chi traffic hop le theo protected service allowlist moi duoc L2 MAC rewrite va chuyen tiep bang `XDP_REDIRECT` qua DEVMAP toi backend-facing interface.

MVP nay tap trung vao mot node Ubuntu 24.04, IPv4, native XDP, policy snapshot an toan, dashboard van hanh, Prometheus/Grafana va audit/RBAC. He thong khong terminate TLS, khong proxy HTTP, khong xu ly L7/DPI va khong thay the WAF.

## Thanh Phan Chinh

| Plane | Thanh phan | Vai tro |
|---|---|---|
| Data Plane | XDP/eBPF, eBPF maps | Parse packet, drop/rate-limit/redirect, ghi counters va sampled events |
| Forwarding Plane | L2 MAC rewrite, DEVMAP | Chi redirect traffic sach toi backend/service da khai bao |
| Node Plane | Node Agent | Load/attach/rollback XDP, sync policy snapshot, expose `/metrics` |
| Control Plane | Control API, PostgreSQL | Quan ly users, services, policies, feeds, snapshots, audit va rollback |
| Management Plane | Admin Dashboard, Prometheus, Grafana | Hien thi realtime, metric, dieu tra event va dashboard van hanh |

## Trang Thai Repo

- Phase 01-08 da co verification report trong `reports/`.
- Control API, Admin CLI, Agent va React/Vite Admin Dashboard da co source trong repo.
- Prometheus scrape config va Grafana dashboard co san trong `deploy/`.
- Compose lab stack chay PostgreSQL, Control API, Prometheus, Grafana va Admin Dashboard. Node Agent van chay tren host de tranh dua quyen XDP/NIC vao container.

## Canh Bao An Toan XDP/NIC

Khong attach XDP vao NIC that neu chua xac nhan ro WAN/LAN/output interface role va protected backend service inventory. Cac lenh quick start Docker Compose chi khoi dong management/control stack; chung khong attach XDP va khong tac dong truc tiep toi traffic production.

Khi can chay Agent, uu tien VETH/lab interface. Neu chay tren NIC that, can co phe duyet van hanh rieng va rollback plan.

## Quick Start Docker Compose

Yeu cau: Docker Engine va Docker Compose plugin.

```bash
cp .env.example .env
# Sua cac gia tri change-me-* trong .env truoc khi dung ngoai lab local.

make phase1-build
docker compose build control-api admin-dashboard
docker compose up -d
```

Kiem tra health:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:9090/-/ready
curl -fsS http://127.0.0.1:3000/api/health
curl -fsS http://127.0.0.1:8088/
```

Bootstrap Admin dau tien:

```bash
printf '%s\n' 'replace-with-a-strong-password' \
  | docker compose run --rm --no-deps --entrypoint control-admin control-api \
      bootstrap --username admin --password-stdin
```

Mo cac giao dien:

- Admin Dashboard: `http://127.0.0.1:8088`
- Control API: `http://127.0.0.1:8080`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000`

Tai lieu chi tiet: [docs/deployment/docker-compose.md](docs/deployment/docker-compose.md).

## Chay Node Agent Tren Host

Prometheus trong compose scrape Agent qua `host.docker.internal:9091`. Agent chi nen chay sau khi da chot interface lab/an toan:

```bash
make phase2-build

sudo env \
  ANTI_DDOS_WAN_IFACE=<approved-lab-or-wan-iface> \
  ANTI_DDOS_XDP_OBJECT=build/bpf/xdp_data_plane.bpf.o \
  ANTI_DDOS_METRICS_ADDR=0.0.0.0:9091 \
  ANTI_DDOS_CONTROL_URL=http://127.0.0.1:8080 \
  ANTI_DDOS_AGENT_TOKEN=<same-value-as-ANTI_DDOS_AGENT_SHARED_TOKEN> \
  build/agent/anti-ddos-agent
```

Neu chua co interface duoc phe duyet, dung cac lab script VETH thay vi Agent tren NIC that.

## Kiem Thu

```bash
make phase1-build
docker compose config
docker compose build control-api admin-dashboard
go test ./...
npm --prefix web/dashboard test -- --run
npm --prefix web/dashboard run build
```

Mot so integration test PostgreSQL se tu dung PostgreSQL container rieng khi khong co `ANTI_DDOS_CONTROL_TEST_DSN`.

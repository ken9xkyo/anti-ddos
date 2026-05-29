# Trien Khai Lab Stack Bang Docker Compose

Tai lieu nay huong dan chay lab stack cho Anti-DDoS management/control plane. Stack gom PostgreSQL, Control API, Prometheus, Grafana va Admin Dashboard. Node Agent khong nam trong compose vi Agent can quyen eBPF/XDP va interface host.

## Kien Truc Runtime

```mermaid
flowchart LR
    Dashboard["Admin Dashboard :8088"] --> API["Control API :8080"]
    API --> DB["PostgreSQL :5432"]
    API --> Prom["Prometheus :9090"]
    Grafana["Grafana :3000"] --> Prom
    Prom --> API
    Prom -. scrape host.docker.internal:9091 .-> Agent["Node Agent on host"]
    Agent -. sync .-> API
```

Tat ca port public mac dinh bind ve `127.0.0.1`. Cac service noi bo noi chuyen qua Docker network `anti-ddos-mgmt`.

## File Lien Quan

| File | Muc dich |
|---|---|
| `Makefile` | Entry point cho dev, test va deploy lab stack |
| `docker-compose.yml` | Dinh nghia full lab stack, healthcheck, init va log rotation |
| `.env.example` | Mau bien moi truong, chi chua placeholder |
| `deploy/README.md` | Index ngan cho Docker, Prometheus va Grafana assets |
| `deploy/docker/control-api.Dockerfile` | Multi-stage build cho `control-api` va `control-admin` |
| `deploy/docker/admin-dashboard.Dockerfile` | Build React/Vite va serve bang Nginx |
| `deploy/prometheus/compose-prometheus.yml` | Prometheus config cho compose |
| `deploy/grafana/provisioning/` | Datasource Prometheus va dashboard provider |

## Chuan Bi

1. Cai Docker Engine va Docker Compose plugin.
2. Tao env local:

```bash
make env-init
```

3. Sua cac gia tri `change-me-*` trong `.env`.

4. Validate compose config:

```bash
make compose-config
```

Mac dinh compose mount read-only `${ANTI_DDOS_XDP_OBJECT_HOST:-./build/bpf/xdp_data_plane.bpf.o}` vao `/run/anti-ddos/xdp_data_plane.bpf.o` trong Control API container. `make deploy` tu build BPF object truoc khi start stack de tranh Agent reject snapshot vi `object_checksum mismatch`.

Khong commit `.env`. Repo chi track `.env.example`.

## Khoi Dong Stack

```bash
make deploy
make dev-health
```

`make deploy` la alias cua `make dev-up`; target nay build BPF object, build image `control-api`/`admin-dashboard`, roi chay `docker compose up -d`.

Kiem tra trang thai container:

```bash
make dev-ps
make deploy-logs
```

Control API tu chay PostgreSQL migrations khi `control-api serve` start.

## Bootstrap Admin

Sau khi PostgreSQL va Control API healthy, tao Admin dau tien:

```bash
make admin-bootstrap
```

Lenh tren doc password an tu TTY. Trong lab non-interactive co the truyen qua bien moi truong:

```bash
ADMIN_USERNAME=admin \
ADMIN_PASSWORD='replace-with-a-strong-password' \
make admin-bootstrap
```

Target nay dung binary `control-admin` da duoc build trong cung image voi Control API va tai su dung `ANTI_DDOS_DB_DSN` tu compose.

Dang nhap:

- Admin Dashboard: `http://127.0.0.1:8088`
- Username: gia tri `ADMIN_USERNAME`, mac dinh `admin`
- Password: gia tri vua truyen qua prompt hoac `ADMIN_PASSWORD`

Neu bootstrap da chay truoc do, CLI se bao Admin da ton tai. Day la hanh vi mong muon.

## Grafana Va Prometheus

Grafana co san datasource:

- Name: `Prometheus`
- UID: `DS_PROMETHEUS`
- URL noi bo: `http://prometheus:9090`

Dashboard `Anti-DDoS P1 Operations` duoc provision tu `deploy/grafana/anti-ddos-p1-dashboard.json`.

Prometheus scrape:

- `control-api:8080` trong Docker network.
- `host.docker.internal:9091` cho Node Agent chay tren host.

Agent target se `DOWN` cho den khi Agent host chay va bind metrics tai `0.0.0.0:9091`.

## Chay Node Agent Tren Host

Chi chay Agent khi da co interface lab hoac WAN duoc phe duyet. Khong dung lenh nay tren NIC production neu chua co interface role va rollback plan.

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

`ANTI_DDOS_AGENT_TOKEN` tren host phai khop voi `ANTI_DDOS_AGENT_SHARED_TOKEN` trong `.env` de Control API chap nhan Agent register, heartbeat, event forward va snapshot sync.

## Ports Mac Dinh

| Service | URL |
|---|---|
| Admin Dashboard | `http://127.0.0.1:8088` |
| Control API | `http://127.0.0.1:8080` |
| Prometheus | `http://127.0.0.1:9090` |
| Grafana | `http://127.0.0.1:3000` |
| PostgreSQL | `127.0.0.1:5432` |

Doi port bang `.env` neu host da co service dung port tuong ung. `make dev-health` lay port published tu Docker Compose nen van dung khi doi port.

## Bao Mat Va Gioi Han Lab

- Compose phuc vu lab/dev, khong phai HA production deployment.
- Cac port bind loopback de tranh expose ra mang ngoai mac dinh.
- Khong dua raw token, DSN, password that vao repo.
- Control API va Dashboard container chay non-root, drop capabilities va dung `no-new-privileges`.
- Tat ca service dung `init: true` de reap process con va logging driver `json-file` voi rotation cau hinh bang `DOCKER_LOG_MAX_SIZE`/`DOCKER_LOG_MAX_FILE`.
- PostgreSQL, Prometheus va Grafana dung named volume de giu du lieu qua restart.
- `ANTI_DDOS_XDP_OBJECT` trong Control API container tro toi file duoc bind mount tu `ANTI_DDOS_XDP_OBJECT_HOST`.

## Kiem Thu

Kiem thu nhanh cho BPF fixture, Go unit tests va dashboard:

```bash
make test
```

Gate day du hon cho admin dashboard va PostgreSQL integration:

```bash
make test-all
```

Kiem tra compose rieng:

```bash
make compose-config
make compose-build
```

## Phase 4 Services / Forwarding UI E2E

E2E nay tao mot protected service tam thoi dang disabled, sua, roi xoa qua dashboard. Test khong enable service va khong attach XDP vao NIC that. Neu can xac thuc mot host interface cu the trong dropdown, dat `ANTI_DDOS_E2E_OUTPUT_INTERFACE=<iface>` va `ANTI_DDOS_E2E_REQUIRE_OUTPUT_INTERFACE=1`.

Dashboard mac dinh tao service disabled. Khi enable service live, form chi yeu cau `resolved_ifindex` va `resolved_src_mac` tu Agent-reported interface; `resolved_next_hop_mac` khong con la truong nhap tay. Neu next-hop chua co san, forwarding resolver se resolve khi build snapshot; neu resolver khong thay host NIC/neighbor trong compose thi build/apply fail-closed voi loi lookup/neighbor de operator sua route/ARP/interface thay vi nhap MAC thu cong.

```bash
python3 -m venv .venv-e2e
.venv-e2e/bin/python -m pip install -r requirements-e2e.txt
.venv-e2e/bin/python -m playwright install chromium

ANTI_DDOS_E2E_MUTATE_LIVE=1 \
ADMIN_DASHBOARD_URL=http://127.0.0.1:8088 \
ADMIN_DASHBOARD_USERNAME=admin \
ADMIN_DASHBOARD_PASSWORD='<admin-password>' \
PYTHON=.venv-e2e/bin/python \
make services-ui-e2e
```

Credential chi truyen qua bien moi truong local. Khong commit password vao repo hoac script.

## Lenh Van Hanh

Dung stack:

```bash
make deploy-down
```

Dung stack va xoa data lab:

```bash
make dev-reset
```

Xem log:

```bash
make deploy-logs
```

Kiem tra Prometheus targets:

```bash
curl -fsS 'http://127.0.0.1:9090/api/v1/targets?state=active'
```

## Troubleshooting

| Trieu chung | Huong xu ly |
|---|---|
| `control-api` unhealthy | Kiem tra `make deploy-logs` va DSN/PostgreSQL health |
| Admin Dashboard login that bai | Dam bao da bootstrap Admin va dung password moi tao |
| Grafana khong co du lieu | Kiem tra Prometheus datasource va target `anti-ddos-control` |
| Agent target `DOWN` | Day la binh thuong neu Agent host chua chay; khi chay Agent can bind `ANTI_DDOS_METRICS_ADDR=0.0.0.0:9091` |
| Port conflict | Doi `*_PORT` trong `.env` |

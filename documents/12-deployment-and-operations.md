# Deployment And Operations

Sơ đồ deployment: [diagrams/deployment-topology.mmd](diagrams/deployment-topology.mmd)

## Supported Lab Topology

Docker Compose chạy management/control stack:

- PostgreSQL
- Control API
- Prometheus
- Grafana
- Admin Dashboard

Node Agent chạy trên host vì cần quyền eBPF/XDP và access interface. Compose không attach XDP.

Target SaaS operations giả định mỗi lab/prod workflow có ít nhất một Customer Account (`Tenant`) active trước khi đăng ký agent, tạo protected service hoặc build snapshot.

## Default Ports

| Service | Host bind |
|---|---|
| PostgreSQL | `127.0.0.1:5432` |
| Control API | `127.0.0.1:8080` |
| Admin Dashboard | `0.0.0.0:8088` |
| Prometheus | `127.0.0.1:9090` |
| Grafana | `127.0.0.1:3000` |
| Host Agent metrics | Default `127.0.0.1:9091`; Makefile host workflow defaults to `0.0.0.0:9091` when set |

## Quick Lab Flow

```bash
make env-init
make compose-config
make deploy
make admin-bootstrap
make dev-health
```

`make deploy` maps to `dev-up`, which builds BPF object and compose images before `docker compose up -d`.

After bootstrap, create or activate a lab Customer Account, assign tenant membership to `tenant_owner`/`tenant_admin`, then perform service/policy/agent operations inside that tenant. In a target SaaS rebuild, platform bootstrap should create a `platform_owner` or `platform_admin` account; tenant users should be created through tenant membership workflows.

## Compose Services

| Service | Image/build | Notes |
|---|---|---|
| `postgres` | `postgres:16.9-alpine3.22` default | Persistent volume `postgres_data` |
| `control-api` | `deploy/docker/control-api.Dockerfile` | Static Go binaries, read-only FS, no privileges |
| `prometheus` | `prom/prometheus:v3.5.2` default | Scrapes control and host Agent |
| `grafana` | `grafana/grafana:12.4.3-security-02` default | Dashboard JSON mounted |
| `admin-dashboard` | `deploy/docker/admin-dashboard.Dockerfile` | React build served by nginx |

## Tenant Operations Guardrails

- Tenant provisioning/suspension/offboarding/revocation is platform workflow and must be audited.
- Tenant onboarding must create at least one `tenant_owner` and one approved service inventory before production policy rollout.
- Agent registration requires tenant identifier; do not register a production agent into a placeholder/default tenant.
- Tenant suspension should block new mutation and agent registration while preserving audit and required read-only support workflows.
- Tenant offboarding must define export/retention/deletion steps before revocation.
- Platform support access to tenant operations must be time-bound, reason-required and visible in audit.

## Host Agent Operations

Build:

```bash
make agent-build
```

Start on approved interfaces only:

```bash
make AGENT_WAN_IFACE=<approved-wan-iface> AGENT_OUTPUT_IFACES=<backend-iface> agent-start
```

Stop/remove:

```bash
make agent-stop
make AGENT_WAN_IFACE=<approved-wan-iface> AGENT_OUTPUT_IFACES=<backend-iface> agent-remove
```

Important variables:

- `AGENT_WAN_IFACE`
- `AGENT_OUTPUT_IFACES`
- `AGENT_OUTPUT_XDP_MODE`
- `AGENT_BPF_PIN_DIR`
- `AGENT_METRICS_ADDR`
- `AGENT_CONTROL_URL`
- `AGENT_TOKEN`
- `AGENT_XDP_MODE`
- `AGENT_ALLOW_GENERIC_FALLBACK`
- `AGENT_SAFE_DETACH_ON_EXIT`

## Native DEVMAP Output Interface

Một số driver như `ixgbe` cần output interface cũng có pass-through XDP program để native DEVMAP redirect hoạt động. Build và attach helper:

```bash
make build/bpf/xdp_pass.bpf.o
sudo ip link set dev <backend-output-iface> xdpdrv obj build/bpf/xdp_pass.bpf.o sec xdp
```

Không replace một XDP program đang chạy trên output NIC nếu chưa có phê duyệt.

## Operational Run Commands

| Command | Mục đích |
|---|---|
| `make dev-ps` | Xem compose service status |
| `make dev-logs` | Follow logs |
| `make deploy-logs` | Alias logs |
| `make dev-down` | Stop stack |
| `make dev-reset` | Stop và xóa volumes lab |
| `make compose-config` | Validate compose config |
| `make dev-health` | Check health endpoints |

## Source Alignment

- Compose: `docker-compose.yml`
- Deploy docs hiện có: `docs/deployment/docker-compose.md`, `deploy/README.md`
- Dockerfiles: `deploy/docker/control-api.Dockerfile`, `deploy/docker/admin-dashboard.Dockerfile`
- Make targets: `Makefile`
- Env template: `.env.example`

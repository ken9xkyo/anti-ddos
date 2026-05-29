# Deploy Assets

Thu muc nay chua cac artifact dung cho lab Docker Compose stack cua Anti-DDoS management/control plane.

| Path | Muc dich |
|---|---|
| `docker/` | Dockerfile va Nginx config cho `control-api`, `control-admin` va Admin Dashboard |
| `prometheus/` | Prometheus scrape config va recording rules cho compose |
| `grafana/` | Grafana datasource, dashboard provider va dashboard JSON |

Runtime entrypoint chinh la `Makefile`:

```bash
make env-init
make deploy
make dev-health
```

Runbook chi tiet: [docs/deployment/docker-compose.md](../docs/deployment/docker-compose.md).

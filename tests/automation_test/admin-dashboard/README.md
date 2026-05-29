# Admin Dashboard Live Automation

This suite drives the real React/Vite Admin Dashboard against a real Control API and disposable PostgreSQL database. Prometheus, Telegram, and threat feed endpoints are local mock HTTP servers, so the run does not need external credentials or Internet services.

## Setup

```bash
python3 -m venv .venv-e2e
.venv-e2e/bin/python -m pip install -r requirements-e2e.txt
.venv-e2e/bin/python -m playwright install chromium
```

Docker, Go, Node, and npm must be available.

## Run

```bash
.venv-e2e/bin/python tests/automation_test/admin-dashboard/run_admin_dashboard.py
```

Useful options:

```bash
.venv-e2e/bin/python tests/automation_test/admin-dashboard/run_admin_dashboard.py --headed
.venv-e2e/bin/python tests/automation_test/admin-dashboard/run_admin_dashboard.py --keep-postgres
```

The runner creates test data with the `auto-admin-dashboard-` prefix, starts local services on free ports, and removes the disposable PostgreSQL container on exit unless `--keep-postgres` is used.


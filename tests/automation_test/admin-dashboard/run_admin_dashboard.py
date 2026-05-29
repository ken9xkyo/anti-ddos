#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

from api_client import ApiClient
from fixtures import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    AGENT_TOKEN,
    TELEGRAM_TOKEN_ENV,
    TELEGRAM_TOKEN_VALUE,
    seed_environment,
)
from support_servers import SupportServers


ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = Path(__file__).resolve().parent


class ManagedProcess:
    def __init__(self, name: str, command: list[str], *, cwd: Path, env: dict[str, str], log_dir: Path):
        self.name = name
        self.log_path = log_dir / f"{name}.log"
        self.log_file = self.log_path.open("wb")
        self.process = subprocess.Popen(command, cwd=cwd, env=env, stdout=self.log_file, stderr=subprocess.STDOUT)

    def assert_running(self) -> None:
        status = self.process.poll()
        if status is not None:
            raise RuntimeError(f"{self.name} exited with {status}\n{tail(self.log_path)}")

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log_file.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run live full-stack Playwright automation for Admin Dashboard v2")
    parser.add_argument("--headed", action="store_true", help="run Chromium in headed mode")
    parser.add_argument("--keep-postgres", action="store_true", help="leave the disposable PostgreSQL container running for debugging")
    parser.add_argument("--prefix", default="", help="override generated test-data prefix")
    parser.add_argument("--timeout", type=int, default=90, help="service startup timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_command("docker")
    ensure_command("go")
    ensure_command("npm")
    ensure_playwright_available()

    log_dir = Path(tempfile.mkdtemp(prefix="admin-dashboard-e2e-"))
    prefix = args.prefix or f"auto-admin-dashboard-{int(time.time())}"
    pg_name = f"{prefix}-pg".replace("_", "-")[:60]
    control_api: ManagedProcess | None = None
    vite: ManagedProcess | None = None
    support = SupportServers().start()
    postgres_started = False

    try:
        print(f"logs: {log_dir}")
        dsn = start_postgres(pg_name, timeout=args.timeout)
        postgres_started = True
        control_port = free_port()
        dashboard_port = free_port()
        control_url = f"http://127.0.0.1:{control_port}"
        dashboard_url = f"http://127.0.0.1:{dashboard_port}"
        env = control_env(dsn, control_port, support)

        run_bootstrap(env, log_dir)
        control_api = ManagedProcess(
            "control-api",
            ["go", "run", "./cmd/control-api", "serve"],
            cwd=ROOT,
            env=env,
            log_dir=log_dir,
        )
        wait_for_http(control_url + "/healthz", timeout=args.timeout, process=control_api)

        api = ApiClient(control_url)
        api.login(ADMIN_USERNAME, ADMIN_PASSWORD)
        seed = seed_environment(api, support, prefix)

        vite_env = os.environ.copy()
        vite_env["ANTI_DDOS_TEST_CONTROL_URL"] = control_url
        vite_env["ANTI_DDOS_E2E_VITE_PORT"] = str(dashboard_port)
        vite = ManagedProcess(
            "vite-dashboard",
            [
                "npm",
                "--prefix",
                str(ROOT / "web/dashboard"),
                "run",
                "dev",
                "--",
                "--config",
                str(SCRIPT_DIR / "vite.e2e.config.mjs"),
                "--host",
                "127.0.0.1",
                "--port",
                str(dashboard_port),
                "--strictPort",
            ],
            cwd=ROOT,
            env=vite_env,
            log_dir=log_dir,
        )
        wait_for_http(dashboard_url, timeout=args.timeout, process=vite)

        from browser_flows import run_browser_suite

        run_browser_suite(
            dashboard_url,
            seed,
            feed_url=support.feed.url,
            headless=not args.headed,
        )
        print("admin dashboard live full-stack automation passed")
        return 0
    finally:
        if vite is not None:
            vite.stop()
        if control_api is not None:
            control_api.stop()
        support.stop()
        if postgres_started and not args.keep_postgres:
            run(["docker", "rm", "-f", pg_name], check=False)
        elif postgres_started:
            print(f"kept PostgreSQL container: {pg_name}")


def ensure_command(name: str) -> None:
    if shutil.which(name) is None:
        raise SystemExit(f"{name} is required")


def ensure_playwright_available() -> None:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            "playwright is required. Run: python3 -m venv .venv-e2e, "
            ".venv-e2e/bin/python -m pip install -r requirements-e2e.txt, "
            "and .venv-e2e/bin/python -m playwright install chromium"
        ) from exc


def control_env(dsn: str, port: int, support: SupportServers) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "ANTI_DDOS_CONTROL_ADDR": f"127.0.0.1:{port}",
        "ANTI_DDOS_DB_DSN": dsn,
        "ANTI_DDOS_AGENT_SHARED_TOKEN": AGENT_TOKEN,
        "ANTI_DDOS_XDP_OBJECT": "missing-ok.o",
        "ANTI_DDOS_PROMETHEUS_URL": support.prometheus.url,
        "ANTI_DDOS_TELEGRAM_API_URL": support.telegram.url,
        "ANTI_DDOS_SESSION_TTL": "12h",
        "ANTI_DDOS_AGENT_STALE_AFTER": "60s",
        "ANTI_DDOS_EVENT_SAMPLE_DENOM": "10",
        TELEGRAM_TOKEN_ENV: TELEGRAM_TOKEN_VALUE,
        "ADMIN_DASHBOARD_FEED_TOKEN": "feed-token-value",
    })
    return env


def run_bootstrap(env: dict[str, str], log_dir: Path) -> None:
    log_path = log_dir / "control-admin-bootstrap.log"
    with log_path.open("wb") as log_file:
        result = subprocess.run(
            ["go", "run", "./cmd/control-admin", "bootstrap", "--username", ADMIN_USERNAME, "--password-stdin"],
            cwd=ROOT,
            env=env,
            input=(ADMIN_PASSWORD + "\n").encode("utf-8"),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"bootstrap failed\n{tail(log_path)}")


def start_postgres(name: str, *, timeout: int) -> str:
    password = "admin_dashboard_test_password"
    database = "anti_ddos_test"
    run(["docker", "rm", "-f", name], check=False)
    run([
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-e",
        f"POSTGRES_PASSWORD={password}",
        "-e",
        f"POSTGRES_DB={database}",
        "-p",
        "127.0.0.1::5432",
        "postgres:16-alpine",
    ])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["docker", "exec", name, "pg_isready", "-U", "postgres", "-d", database], check=False)
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("postgres container did not become ready")
    port_result = run(["docker", "port", name, "5432/tcp"])
    mapped = port_result.stdout.decode("utf-8").strip().splitlines()[0]
    port = mapped.rsplit(":", 1)[-1]
    return f"postgres://postgres:{password}@127.0.0.1:{port}/{database}?sslmode=disable"


def wait_for_http(url: str, *, timeout: int, process: ManagedProcess | None = None) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        if process is not None:
            process.assert_running()
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {url}: {last_error}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed with {result.returncode}\n{result.stdout.decode('utf-8', errors='replace')}")
    return result


def tail(path: Path, lines: int = 80) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(text[-lines:])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        traceback.print_exc()
        raise SystemExit(1)

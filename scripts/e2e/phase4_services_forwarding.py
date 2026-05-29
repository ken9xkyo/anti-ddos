#!/usr/bin/env python3
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import expect, sync_playwright
except ImportError as exc:
    raise SystemExit(
        "playwright is required. Run: python3 -m venv .venv-e2e, "
        ".venv-e2e/bin/python -m pip install -r requirements-e2e.txt, "
        "and .venv-e2e/bin/python -m playwright install chromium"
    ) from exc


BASE_URL = os.environ.get("ADMIN_DASHBOARD_URL", "http://localhost:8088").rstrip("/")
USERNAME = os.environ.get("ADMIN_DASHBOARD_USERNAME", "")
PASSWORD = os.environ.get("ADMIN_DASHBOARD_PASSWORD", "")
MUTATION_GUARD = os.environ.get("ANTI_DDOS_E2E_MUTATE_LIVE", "")
APPLY_WAIT_SECONDS = int(os.environ.get("ANTI_DDOS_E2E_APPLY_WAIT_SECONDS", "90"))
OUTPUT_INTERFACE = os.environ.get("ANTI_DDOS_E2E_OUTPUT_INTERFACE", "backend0")
REQUIRE_OUTPUT_INTERFACE = os.environ.get("ANTI_DDOS_E2E_REQUIRE_OUTPUT_INTERFACE", "")


def fail(message: str) -> None:
    raise SystemExit(message)


def api_request(path: str, method: str = "GET", token: str = "", payload=None, expected=(200,), headers=None):
    body = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(BASE_URL + path, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            text = response.read().decode()
            data = json.loads(text) if text else None
            if response.status not in expected:
                fail(f"{method} {path} returned {response.status}: {text}")
            return data
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        if exc.code not in expected:
            fail(f"{method} {path} returned {exc.code}: {text}")
        return json.loads(text) if text else None


def api_login() -> str:
    if not USERNAME or not PASSWORD:
        fail("ADMIN_DASHBOARD_USERNAME and ADMIN_DASHBOARD_PASSWORD are required")
    session = api_request("/v1/auth/login", method="POST", payload={"username": USERNAME, "password": PASSWORD})
    return session["token"]


def list_services(token: str):
    services = api_request("/v1/dashboard/services", token=token)
    return services if isinstance(services, list) else []


def find_service(token: str, name: str):
    for service in list_services(token):
        if service.get("name") == name:
            return service
    return None


def cleanup_service(token: str, name: str) -> None:
    service = find_service(token, name)
    if not service:
        return
    api_request(
        f"/v1/services/{service['id']}",
        method="DELETE",
        token=token,
        headers={"X-Audit-Reason": "phase4 e2e cleanup after failure"},
        expected=(200,),
    )


def wait_for_no_checksum_mismatch(token: str) -> None:
    deadline = time.monotonic() + APPLY_WAIT_SECONDS
    last_error = ""
    while time.monotonic() < deadline:
        overview = api_request("/v1/dashboard/overview", token=token)
        statuses = overview.get("latest_apply_status") or []
        mismatches = [
            status for status in statuses
            if "object_checksum mismatch" in (status.get("error_reason") or "")
        ]
        if not mismatches:
            return
        last_error = mismatches[0].get("error_reason") or ""
        time.sleep(3)
    fail(f"agent apply status still reports object_checksum mismatch: {last_error}")


def rebuild_snapshot(token: str) -> None:
    api_request(
        "/v1/snapshots/build",
        method="POST",
        token=token,
        payload={"reason": "phase4 e2e refresh BPF object checksum"},
    )


def fill_service_form(page, name: str, ports: str, owner: str, reason: str) -> None:
    form = page.locator("form.service-form")
    form.locator("label", has_text="Name").locator("input").fill(name)
    form.locator("label", has_text="Backend CIDR").locator("input").fill("203.0.113.250/32")
    form.locator("label", has_text="Protocol").locator("select").select_option("tcp")
    form.locator("label", has_text="Allowed ports").locator("input").fill(ports)
    fill_output_interface(form, OUTPUT_INTERFACE)
    form.locator("label", has_text="Owner").locator("input").fill(owner)
    form.locator("label", has_text="Criticality").locator("input").fill("high")
    form.locator("label", has_text="Protection mode").locator("select").select_option("enforce")
    form.locator("label", has_text="Reason").locator("input").fill(reason)
    enabled = form.locator("label.checkbox-field input[type='checkbox']")
    if enabled.is_checked():
        enabled.uncheck()


def fill_output_interface(form, name: str) -> None:
    field = form.locator("label", has_text="Output interface")
    select = field.locator("select")
    if select.count() > 0:
        options = select.locator("option").evaluate_all("(items) => items.map((item) => item.value)")
        if len(options) < 2:
            fail("output interface selector did not expose any host interface options")
        if name in options:
            selected = name
        elif REQUIRE_OUTPUT_INTERFACE == "1":
            fail(f"output interface {name} was not reported by the Agent")
        else:
            selected = options[1]
        select.select_option(selected)
        expect(select).to_have_value(selected)
        return
    field.locator("input").fill(name)


def main() -> None:
    if MUTATION_GUARD != "1":
        fail("ANTI_DDOS_E2E_MUTATE_LIVE=1 is required because this test creates and deletes a live service")

    token = api_login()
    rebuild_snapshot(token)
    wait_for_no_checksum_mismatch(token)
    service_name = "phase4-e2e-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    created = False

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=os.environ.get("ANTI_DDOS_E2E_HEADLESS", "1") != "0")
            page = browser.new_page()
            page.goto(BASE_URL)
            page.wait_for_load_state("networkidle")
            page.get_by_label("Username").fill(USERNAME)
            page.get_by_label("Password").fill(PASSWORD)
            page.get_by_role("button", name=re.compile(r"Sign in", re.I)).click()
            expect(page.get_by_text("Packets/s")).to_be_visible(timeout=15000)

            page.get_by_role("button", name=re.compile(r"^Services$", re.I)).click()
            expect(page.get_by_text("Services / Forwarding")).to_be_visible()
            page.get_by_role("button", name=re.compile(r"Add service", re.I)).click()
            fill_service_form(page, service_name, "443, 8443", "e2e", "phase4 e2e create disabled service")
            page.get_by_role("button", name=re.compile(r"Save service", re.I)).click()
            expect(page.get_by_text(f"{service_name} created")).to_be_visible(timeout=15000)
            created = True

            row = page.locator("tbody tr", has_text=service_name)
            expect(row).to_be_visible(timeout=15000)
            expect(row).to_contain_text("disabled")
            expect(row).to_contain_text("443, 8443")

            page.locator(".filter-row label", has_text="Search").locator("input").fill(service_name)
            page.locator(".filter-row label", has_text="State").locator("select").select_option("disabled")
            expect(page.locator("tbody tr", has_text=service_name)).to_be_visible()
            page.locator(".filter-row label", has_text="State").locator("select").select_option("enabled")
            expect(page.locator("tbody tr", has_text=service_name)).to_have_count(0)
            page.locator(".filter-row label", has_text="State").locator("select").select_option("disabled")

            page.get_by_role("button", name=re.compile(rf"edit {re.escape(service_name)}", re.I)).click()
            fill_service_form(page, service_name, "443, 8443, 9443", "e2e-updated", "phase4 e2e update disabled service")
            page.get_by_role("button", name=re.compile(r"Save service", re.I)).click()
            expect(page.get_by_text(f"{service_name} updated")).to_be_visible(timeout=15000)
            row = page.locator("tbody tr", has_text=service_name)
            expect(row).to_contain_text("9443")
            expect(row).to_contain_text("e2e-updated")

            page.get_by_role("button", name=re.compile(rf"delete {re.escape(service_name)}", re.I)).click()
            page.get_by_label(re.compile(r"^Reason$")).fill("phase4 e2e cleanup disabled service")
            page.get_by_role("button", name=re.compile(r"Confirm delete", re.I)).click()
            expect(page.get_by_text(f"{service_name} deleted")).to_be_visible(timeout=15000)
            expect(page.locator("tbody tr", has_text=service_name)).to_have_count(0)
            browser.close()

        created = False
        if find_service(token, service_name):
            fail(f"{service_name} still exists after UI delete")
        wait_for_no_checksum_mismatch(token)
        print(f"phase4 services forwarding UI E2E passed for {service_name}")
    except PlaywrightTimeoutError as exc:
        fail(f"playwright timeout while testing {service_name}: {exc}")
    finally:
        if created:
            cleanup_service(token, service_name)


if __name__ == "__main__":
    main()

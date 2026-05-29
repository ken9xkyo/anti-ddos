#!/usr/bin/env python3
from __future__ import annotations

import re

from fixtures import SeedData

try:
    from playwright.sync_api import Page, expect, sync_playwright
except ImportError as exc:
    raise SystemExit(
        "playwright is required. Run: python3 -m venv .venv-e2e, "
        ".venv-e2e/bin/python -m pip install -r requirements-e2e.txt, "
        "and .venv-e2e/bin/python -m playwright install chromium"
    ) from exc


DESKTOP_VIEWPORT = {"width": 2200, "height": 1200}


def run_browser_suite(
    base_url: str,
    seed: SeedData,
    *,
    feed_url: str,
    headless: bool = True,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        try:
            page = browser.new_context(viewport=DESKTOP_VIEWPORT).new_page()
            login(page, base_url, seed.admin_username, seed.admin_password)
            assert_shell_navigation(page)
            assert_overview(page, seed)
            assert_admin_only_visibility(page)
            logout(page)
            page.context.close()

            page = browser.new_context(viewport=DESKTOP_VIEWPORT).new_page()
            login(page, base_url, seed.viewer_username, seed.viewer_password)
            assert_viewer_read_only(page, seed)
            page.context.close()

            page = browser.new_context(viewport=DESKTOP_VIEWPORT).new_page()
            login(page, base_url, seed.operator_username, seed.operator_password)
            assert_incidents_operator_actions(page)
            assert_services_workflow(page, seed)
            assert_rules_workflow(page, seed)
            assert_whitelist_workflow(page, seed)
            assert_detection(page, seed)
            assert_reputation_operator_workflow(page, seed, feed_url)
            assert_snapshots_workflow(page)
            assert_fleet(page)
            assert_investigation(page)
            page.context.close()

            page = browser.new_context(viewport=DESKTOP_VIEWPORT).new_page()
            login(page, base_url, seed.admin_username, seed.admin_password)
            assert_admin_telegram_config(page)
            assert_admin_reputation_credentials(page, seed, feed_url)
            assert_access_workflow(page, seed)
            assert_responsive_smoke(browser, base_url, seed)

            assert_dashboard_poll_failure(page)
        finally:
            browser.close()


def login(page: Page, base_url: str, username: str, password: str) -> None:
    page.goto(base_url)
    page.wait_for_load_state("domcontentloaded")
    try:
        page.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass
    expect(page.get_by_role("button", name=re.compile(r"Sign in", re.I))).to_be_visible(timeout=15000)
    page.get_by_label(re.compile(r"^Username$", re.I)).fill(username)
    page.get_by_label(re.compile(r"^Password$", re.I)).fill(password)
    page.get_by_role("button", name=re.compile(r"Sign in", re.I)).click()
    expect(page.get_by_text("Packets/s", exact=True)).to_be_visible(timeout=30000)
    expect(page.locator(".user-chip")).to_contain_text(username, timeout=15000)


def logout(page: Page) -> None:
    page.get_by_role("button", name=re.compile(r"logout", re.I)).click()
    expect(page.get_by_role("button", name=re.compile(r"Sign in", re.I))).to_be_visible(timeout=15000)


def goto_tab(page: Page, label: str) -> None:
    page.get_by_role("button", name=re.compile(rf"^{re.escape(label)}\b", re.I)).click()
    expect(page.locator(".topbar h1")).to_have_text(label, timeout=15000)


def assert_shell_navigation(page: Page) -> None:
    for tab in [
        "Overview",
        "Incidents",
        "Services",
        "Rules",
        "Whitelist",
        "Detection",
        "Reputation",
        "Snapshots",
        "Access",
        "Fleet",
        "Investigation",
    ]:
        goto_tab(page, tab)
    goto_tab(page, "Overview")
    page.get_by_role("button", name=re.compile(r"refresh", re.I)).click()
    expect(page.get_by_text("Packets/s", exact=True)).to_be_visible(timeout=15000)


def assert_overview(page: Page, seed: SeedData) -> None:
    goto_tab(page, "Overview")
    expect_visible_text(page, "prometheus healthy")
    expect_visible_text(page, "198.51.100.0/24")
    expect_visible_text(page, seed.service["name"])
    expect_visible_text(page, re.compile(r"isp_escalation_needed|test_alert"))
    page.wait_for_function("document.querySelectorAll('.chart-panel svg').length >= 2")


def assert_admin_only_visibility(page: Page) -> None:
    goto_tab(page, "Access")
    expect(page.get_by_role("button", name=re.compile(r"Add user", re.I))).to_be_visible(timeout=15000)
    goto_tab(page, "Incidents")
    expect(page.get_by_role("button", name=re.compile(r"Save config", re.I))).to_be_visible()
    goto_tab(page, "Reputation")
    page.get_by_role("button", name=re.compile(r"Add feed", re.I)).click()
    drawer = page.locator(".admin-drawer")
    expect(drawer.get_by_label(re.compile(r"Credential ref", re.I))).to_be_enabled()
    drawer.get_by_role("button", name=re.compile(r"Cancel", re.I)).click()


def assert_viewer_read_only(page: Page, seed: SeedData) -> None:
    goto_tab(page, "Services")
    expect_visible_text(page, seed.service["name"])
    expect(page.get_by_role("button", name=re.compile(r"Add service", re.I))).to_have_count(0)
    expect_visible_text(page, "read only")

    goto_tab(page, "Rules")
    expect_visible_text(page, seed.rule["name"])
    expect(page.get_by_role("button", name=re.compile(r"Add rule", re.I))).to_have_count(0)
    expect(page.get_by_role("button", name=re.compile(r"^Edit$", re.I))).to_have_count(0)

    goto_tab(page, "Incidents")
    expect(page.get_by_role("button", name=re.compile(r"Test alert", re.I))).to_be_disabled()
    expect(page.get_by_role("button", name=re.compile(r"Save config", re.I))).to_have_count(0)

    goto_tab(page, "Access")
    expect(page.get_by_role("button", name=re.compile(r"Add user", re.I))).to_have_count(0)
    expect(page.get_by_role("button", name=re.compile(r"^Reset$", re.I))).to_have_count(0)


def assert_incidents_operator_actions(page: Page) -> None:
    goto_tab(page, "Incidents")
    page.get_by_role("button", name=re.compile(r"Test alert", re.I)).click()
    expect_visible_text(page, re.compile(r"test_alert: sent", re.I), timeout=20000)
    page.get_by_role("button", name=re.compile(r"ISP runbook", re.I)).click()
    expect_visible_text(page, re.compile(r"isp_escalation_needed: sent", re.I), timeout=20000)
    expect_visible_text(page, "No automatic BGP, RTBH or FlowSpec action")


def assert_services_workflow(page: Page, seed: SeedData) -> None:
    goto_tab(page, "Services")
    name = f"{seed.prefix}-ui-service"
    page.get_by_role("button", name=re.compile(r"Add service", re.I)).click()
    form = page.locator("form.service-form")
    expect(form.locator("label", has_text="Name").locator("input")).to_be_visible()
    expect(form.locator("label.checkbox-field input[type='checkbox']")).not_to_be_checked()
    expect(page.get_by_label(re.compile(r"next-hop mac", re.I))).to_have_count(0)
    form.locator("label", has_text="Name").locator("input").fill(name)
    form.locator("label", has_text="Backend CIDR").locator("input").fill("203.0.113.20/32")
    form.locator("label", has_text="Allowed ports").locator("input").fill("443, 8443")
    form.locator("label", has_text="Output interface").locator("select").select_option("backend0")
    form.locator("label", has_text="Owner").locator("input").fill("automation")
    form.locator("label", has_text="Reason").locator("input").fill("automation create UI service")
    form.get_by_role("button", name=re.compile(r"Save service", re.I)).click()
    expect_visible_text(page, f"{name} created", timeout=20000)

    toolbar = page.locator(".data-toolbar")
    toolbar.locator("label", has_text="Search").locator("input").fill(name)
    toolbar.locator("label", has_text="State").locator("select").select_option("disabled")
    expect(page.locator("tbody tr", has_text=name)).to_be_visible(timeout=15000)
    toolbar.locator("label", has_text="State").locator("select").select_option("enabled")
    expect(page.locator("tbody tr", has_text=name)).to_have_count(0)
    toolbar.locator("label", has_text="State").locator("select").select_option("disabled")

    page.get_by_role("button", name=re.compile(rf"edit {re.escape(name)}", re.I)).click()
    form.locator("label", has_text="Allowed ports").locator("input").fill("443, 8443, 9443")
    form.locator("label", has_text="Reason").locator("input").fill("automation update UI service")
    form.get_by_role("button", name=re.compile(r"Save service", re.I)).click()
    expect_visible_text(page, f"{name} updated", timeout=20000)
    expect(page.locator("tbody tr", has_text=name)).to_contain_text("9443")

    page.get_by_role("button", name=re.compile(rf"disable {re.escape(name)}", re.I)).click()
    page.get_by_label(re.compile(r"^Reason$", re.I)).fill("automation disable UI service")
    page.get_by_role("button", name=re.compile(r"Confirm disable", re.I)).click()
    expect_visible_text(page, f"{name} disabled", timeout=20000)


def assert_rules_workflow(page: Page, seed: SeedData) -> None:
    goto_tab(page, "Rules")
    expect_visible_text(page, seed.rule["name"], timeout=20000)
    name = f"{seed.prefix}-ui-rule"
    page.get_by_role("button", name=re.compile(r"Add rule", re.I)).click()
    drawer = page.locator(".admin-drawer")
    drawer.get_by_label(re.compile(r"^Name", re.I)).fill(name)
    drawer.get_by_label(re.compile(r"^PPS", re.I)).fill("1200")
    drawer.get_by_label(re.compile(r"^Owner", re.I)).fill("soc")
    drawer.locator("label.json-textarea-field", has_text="Match expression").locator("textarea").fill("{invalid")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation create UI rule")
    drawer.get_by_role("button", name=re.compile(r"Save rule", re.I)).click()
    expect_visible_text(page, re.compile(r"JSON|property|Unexpected", re.I), timeout=10000)
    drawer.locator("label.json-textarea-field", has_text="Match expression").locator("textarea").fill('{"src_prefix":"198.51.100.0/24"}')
    drawer.locator("label.json-textarea-field", has_text="Evidence").locator("textarea").fill('{"source":"automation"}')
    drawer.get_by_role("button", name=re.compile(r"Save rule", re.I)).click()
    data_grid_row(page, name)

    row = data_grid_row(page, name)
    row.get_by_role("button", name=re.compile(r"^Edit$", re.I)).click()
    drawer.get_by_label(re.compile(r"^PPS", re.I)).fill("1500")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation update UI rule")
    drawer.get_by_role("button", name=re.compile(r"Save rule", re.I)).click()
    expect(data_grid_row(page, name)).to_contain_text("1500", timeout=20000)

    data_grid_row(page, name).get_by_role("button", name=re.compile(r"^Disable$", re.I)).click()
    page.get_by_label(re.compile(r"^Reason", re.I)).fill("automation disable UI rule")
    page.get_by_role("button", name=re.compile(r"Disable rule", re.I)).click()
    expect(data_grid_row(page, name)).to_contain_text("disabled", timeout=20000)


def assert_whitelist_workflow(page: Page, seed: SeedData) -> None:
    goto_tab(page, "Whitelist")
    expect_visible_text(page, seed.whitelist["cidr"], timeout=20000)
    cidr = "203.0.113.55/32"
    page.get_by_role("button", name=re.compile(r"Add whitelist", re.I)).click()
    drawer = page.locator(".admin-drawer")
    drawer.get_by_label(re.compile(r"^CIDR", re.I)).fill(cidr)
    select_mui_option(page, drawer, "Scope", "Service")
    select_mui_option(page, drawer, "Service", seed.service["name"])
    drawer.get_by_label(re.compile(r"^Label", re.I)).fill("ui-partner")
    drawer.get_by_label(re.compile(r"^Owner", re.I)).fill("noc")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation create UI whitelist")
    drawer.get_by_role("button", name=re.compile(r"Save whitelist", re.I)).click()
    data_grid_row(page, cidr)

    data_grid_row(page, cidr).get_by_role("button", name=re.compile(r"^Edit$", re.I)).click()
    drawer.get_by_label(re.compile(r"^Label", re.I)).fill("ui-partner-renamed")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation update UI whitelist")
    drawer.get_by_role("button", name=re.compile(r"Save whitelist", re.I)).click()
    expect(data_grid_row(page, cidr)).to_contain_text("ui-partner-renamed", timeout=20000)

    data_grid_row(page, cidr).get_by_role("button", name=re.compile(r"^Disable$", re.I)).click()
    page.get_by_label(re.compile(r"^Reason", re.I)).fill("automation disable UI whitelist")
    page.get_by_role("button", name=re.compile(r"Disable entry", re.I)).click()
    expect(data_grid_row(page, cidr)).to_contain_text("disabled", timeout=20000)


def assert_detection(page: Page, seed: SeedData) -> None:
    goto_tab(page, "Detection")
    expect_visible_text(page, seed.service["name"], timeout=20000)
    expect_visible_text(page, "approved")
    expect_visible_text(page, re.compile(r"pps_spike|auto_enforced", re.I))
    expect_visible_text(page, "Active Rules")


def assert_reputation_operator_workflow(page: Page, seed: SeedData, feed_url: str) -> None:
    goto_tab(page, "Reputation")
    expect_visible_text(page, seed.feed["name"], timeout=20000)
    page.get_by_role("button", name=re.compile(r"Add feed", re.I)).click()
    drawer = page.locator(".admin-drawer")
    expect(drawer.get_by_label(re.compile(r"Credential ref", re.I))).to_be_disabled()
    name = f"{seed.prefix}-operator-feed"
    drawer.get_by_label(re.compile(r"^Name", re.I)).fill(name)
    drawer.get_by_label(re.compile(r"^URL", re.I)).fill(feed_url)
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation operator create feed")
    drawer.get_by_role("button", name=re.compile(r"Save feed", re.I)).click()
    data_grid_row(page, name)

    row = data_grid_row(page, seed.feed["name"])
    row.get_by_role("button", name=re.compile(r"^Sync$", re.I)).click()
    page.get_by_label(re.compile(r"^Reason", re.I)).fill("automation operator sync feed")
    page.get_by_role("button", name=re.compile(r"Sync feed", re.I)).click()
    expect_visible_text(page, "Feed Run History")
    expect_visible_text(page, "Whitelist Conflicts")

    data_grid_row(page, name).get_by_role("button", name=re.compile(r"^Disable$", re.I)).click()
    page.get_by_label(re.compile(r"^Reason", re.I)).fill("automation operator disable feed")
    page.get_by_role("button", name=re.compile(r"Disable feed", re.I)).click()
    expect(data_grid_row(page, name)).to_contain_text("disabled", timeout=20000)


def assert_snapshots_workflow(page: Page) -> None:
    goto_tab(page, "Snapshots")
    expect_visible_text(page, "Snapshot Versions", timeout=20000)
    page.get_by_role("button", name=re.compile(r"Load diff", re.I)).click()
    expect_visible_text(page, re.compile(r"diff v\d+ -> v\d+ loaded", re.I), timeout=20000)
    expect_visible_text(page, "Semantic Diff")
    page.get_by_role("button", name=re.compile(r"^Rollback$", re.I)).first.click()
    page.get_by_label(re.compile(r"^Reason", re.I)).fill("automation rollback snapshot")
    page.get_by_role("button", name=re.compile(r"Create rollback", re.I)).click()
    expect(page.locator(".confirm-dialog")).to_have_count(0, timeout=20000)


def assert_fleet(page: Page) -> None:
    goto_tab(page, "Fleet")
    expect_visible_text(page, "auto-admin-dashboard-node-a", timeout=20000)
    expect_visible_text(page, "native")
    expect_visible_text(page, "backend0")
    expect_visible_text(page, "Map Utilization")


def assert_investigation(page: Page) -> None:
    goto_tab(page, "Investigation")
    expect_visible_text(page, "198.51.100.10", timeout=20000)
    page.get_by_label(re.compile(r"^Target", re.I)).fill("198.51.100.10")
    page.get_by_role("button", name=re.compile(r"Investigate", re.I)).click()
    expect_visible_text(page, "Investigation results for 198.51.100.10", timeout=20000)
    expect_visible_text(page, "198.51.100.10")


def assert_admin_telegram_config(page: Page) -> None:
    goto_tab(page, "Incidents")
    page.get_by_label(re.compile(r"Bot token ref", re.I)).fill("env://ADMIN_DASHBOARD_TELEGRAM_TOKEN")
    page.get_by_label(re.compile(r"Chat ID", re.I)).fill("5678")
    page.get_by_label(re.compile(r"^Reason", re.I)).fill("automation update Telegram config")
    page.get_by_role("button", name=re.compile(r"Save config", re.I)).click()
    expect_visible_text(page, "telegram config saved", timeout=20000)


def assert_admin_reputation_credentials(page: Page, seed: SeedData, feed_url: str) -> None:
    goto_tab(page, "Reputation")
    name = f"{seed.prefix}-admin-feed"
    page.get_by_role("button", name=re.compile(r"Add feed", re.I)).click()
    drawer = page.locator(".admin-drawer")
    credential = drawer.get_by_label(re.compile(r"Credential ref", re.I))
    expect(credential).to_be_enabled()
    drawer.get_by_label(re.compile(r"^Name", re.I)).fill(name)
    drawer.get_by_label(re.compile(r"^URL", re.I)).fill(feed_url)
    credential.fill("env://ADMIN_DASHBOARD_FEED_TOKEN")
    drawer.get_by_label(re.compile(r"^License note", re.I)).fill("automation admin credential ref")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation admin create credential feed")
    drawer.get_by_role("button", name=re.compile(r"Save feed", re.I)).click()
    data_grid_row(page, name)


def assert_access_workflow(page: Page, seed: SeedData) -> None:
    goto_tab(page, "Access")
    username = f"{seed.prefix}-managed"
    expect_visible_text(page, seed.operator_username, timeout=20000)
    page.get_by_role("button", name=re.compile(r"Add user", re.I)).click()
    drawer = page.locator(".admin-drawer")
    drawer.get_by_label(re.compile(r"^Username", re.I)).fill(username)
    drawer.get_by_label(re.compile(r"Temporary password", re.I)).fill("Temporary password phrase 1")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation create managed user")
    drawer.get_by_role("button", name=re.compile(r"^Save$", re.I)).click()
    data_grid_row(page, username)

    data_grid_row(page, username).get_by_role("button", name=re.compile(r"^Edit$", re.I)).click()
    select_mui_option(page, drawer, "Role", "Operator")
    select_mui_option(page, drawer, "Status", "Active")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation update managed user")
    drawer.get_by_role("button", name=re.compile(r"^Save$", re.I)).click()
    expect(data_grid_row(page, username)).to_contain_text("operator", timeout=20000)

    data_grid_row(page, username).get_by_role("button", name=re.compile(r"^Reset$", re.I)).click()
    drawer.get_by_label(re.compile(r"Temporary password", re.I)).fill("Replacement password phrase 1")
    drawer.get_by_label(re.compile(r"^Reason", re.I)).fill("automation reset managed user")
    drawer.get_by_role("button", name=re.compile(r"^Save$", re.I)).click()
    data_grid_row(page, username)

    data_grid_row(page, username).get_by_role("button", name=re.compile(r"^Sessions$", re.I)).click()
    page.get_by_label(re.compile(r"^Reason", re.I)).fill("automation revoke managed sessions")
    page.get_by_role("button", name=re.compile(r"Revoke sessions", re.I)).click()
    data_grid_row(page, username)


def assert_responsive_smoke(browser, base_url: str, seed: SeedData) -> None:
    for viewport in [{"width": 390, "height": 844}, {"width": 1280, "height": 720}]:
        context = browser.new_context(viewport=viewport)
        page = context.new_page()
        try:
            login(page, base_url, seed.viewer_username, seed.viewer_password)
            for tab in ("Overview", "Services", "Fleet"):
                goto_tab(page, tab)
                expect(page.locator(".topbar h1")).to_be_visible()
            has_overlap = page.evaluate("""() => {
                const topbar = document.querySelector('.topbar');
                const content = document.querySelector('.content-stack');
                if (!topbar || !content) return false;
                return topbar.getBoundingClientRect().bottom > content.getBoundingClientRect().top + 2;
            }""")
            if has_overlap:
                raise AssertionError(f"topbar overlaps content at viewport {viewport}")
        finally:
            context.close()


def assert_dashboard_poll_failure(page: Page) -> None:
    page.context.set_offline(True)
    try:
        page.get_by_role("button", name=re.compile(r"refresh", re.I)).click()
        expect(page.locator(".banner.error")).to_be_visible(timeout=20000)
    finally:
        page.context.set_offline(False)


def data_grid_row(page: Page, text: str):
    row = page.locator(".MuiDataGrid-row", has_text=text)
    expect(row).to_be_visible(timeout=20000)
    return row


def select_mui_option(page: Page, root, label: str, option: str) -> None:
    root.get_by_label(re.compile(rf"^{re.escape(label)}$", re.I)).click()
    page.get_by_role("option", name=re.compile(rf"^{re.escape(option)}$", re.I)).click()


def expect_visible_text(page: Page, text: str | re.Pattern, *, timeout: int = 15000) -> None:
    expect(page.get_by_text(text).nth(0)).to_be_visible(timeout=timeout)

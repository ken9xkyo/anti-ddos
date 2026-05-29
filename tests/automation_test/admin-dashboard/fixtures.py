#!/usr/bin/env python3
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from api_client import ApiClient
from support_servers import SupportServers


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "correct horse battery staple"
VIEWER_PASSWORD = "viewer password phrase"
OPERATOR_PASSWORD = "operator password phrase"
AGENT_TOKEN = "agent-secret"
TELEGRAM_TOKEN_ENV = "ADMIN_DASHBOARD_TELEGRAM_TOKEN"
TELEGRAM_TOKEN_VALUE = "123456:abcdefghijklmnopqrstuvwxyzABCDEF"


@dataclass
class SeedData:
    prefix: str
    admin_username: str
    admin_password: str
    viewer_username: str
    viewer_password: str
    operator_username: str
    operator_password: str
    service: dict[str, Any]
    rule: dict[str, Any]
    whitelist: dict[str, Any]
    feed: dict[str, Any]
    snapshots: list[dict[str, Any]]
    agent_id: str


def seed_environment(api: ApiClient, support: SupportServers, prefix: str) -> SeedData:
    viewer_username = f"{prefix}-viewer"
    operator_username = f"{prefix}-operator"

    api.post("/v1/users", {
        "reason": "automation create viewer",
        "username": viewer_username,
        "password": VIEWER_PASSWORD,
        "role": "viewer",
    })
    api.post("/v1/users", {
        "reason": "automation create operator",
        "username": operator_username,
        "password": OPERATOR_PASSWORD,
        "role": "operator",
    })

    agent_id = register_agent(api)
    service = api.post("/v1/services", service_payload(f"{prefix}-api-https", enabled=True))
    baseline = api.post("/v1/baselines", baseline_payload(service["id"]))
    api.post(f"/v1/baselines/{baseline['id']}/approve", {"reason": "automation approve baseline"})
    rule = api.post("/v1/rules", rule_payload(f"{prefix}-ttl-rule", service["id"]))
    api.agent_post(f"/v1/agents/{agent_id}/events", AGENT_TOKEN, security_event_payload(service["ebpf_id"], rule["ebpf_id"]))

    whitelist = api.post("/v1/whitelist", whitelist_payload("192.0.2.10/32", "automation trusted customer source"))
    feed = api.post("/v1/feed-sources", feed_payload(f"{prefix}-internal-feed", support.feed.url))
    operator = ApiClient(api.base_url)
    operator.login(operator_username, OPERATOR_PASSWORD)
    operator.post(f"/v1/feed-sources/{feed['id']}/sync", {"reason": "automation seed feed sync"})

    api.post("/v1/telegram/config", {
        "reason": "automation configure Telegram",
        "bot_token_ref": f"env://{TELEGRAM_TOKEN_ENV}",
        "chat_id": "1234",
        "parse_mode": "HTML",
        "enabled": True,
    })
    operator.post("/v1/anomalies/evaluate", {"reason": "automation anomaly evaluation"})
    operator.post("/v1/alerts/evaluate-isp-escalation", {
        "reason": "automation ISP runbook",
        "service_id": service["id"],
        "vector": "udp_flood",
        "peak_bps": 8000000,
        "peak_pps": 1000,
        "packet_loss_ratio": 0.15,
    })

    snapshots = wait_for_snapshots(api, 2)
    latest = snapshots[0]["version"]
    api.agent_post(f"/v1/agents/{agent_id}/apply", AGENT_TOKEN, {
        "policy_version": latest,
        "status": "applied",
        "map_stats": {"service_allowlist": {"entries": 1}, "rule_config": {"entries": 2}},
        "devmap_stats": {"updated": 1},
    })

    return SeedData(
        prefix=prefix,
        admin_username=ADMIN_USERNAME,
        admin_password=ADMIN_PASSWORD,
        viewer_username=viewer_username,
        viewer_password=VIEWER_PASSWORD,
        operator_username=operator_username,
        operator_password=OPERATOR_PASSWORD,
        service=service,
        rule=rule,
        whitelist=whitelist,
        feed=feed,
        snapshots=snapshots,
        agent_id=agent_id,
    )


def register_agent(api: ApiClient) -> str:
    response = api.agent_post("/v1/agents/register", AGENT_TOKEN, {
        "hostname": "auto-admin-dashboard-node-a",
        "xdp_mode": "native",
        "devmap_support": True,
        "agent_version": "automation",
        "interfaces": agent_interfaces(),
    })
    agent_id = response["agent_id"]
    api.agent_post(f"/v1/agents/{agent_id}/heartbeat", AGENT_TOKEN, {
        "status": "online",
        "active_policy_version": 1,
        "xdp_mode": "native",
        "uptime_seconds": 120,
        "map_utilization": {"service_allowlist": {"entries": 1, "capacity": 16384}},
        "interfaces": agent_interfaces(),
    })
    return agent_id


def agent_interfaces() -> list[dict[str, Any]]:
    return [
        {
            "name": "backend0",
            "ifindex": 8,
            "mac": "02:00:00:00:00:08",
            "role": "backend",
            "link_speed_bps": 10000000000,
        },
        {
            "name": "wan0",
            "ifindex": 7,
            "mac": "02:00:00:00:00:07",
            "role": "wan",
            "link_speed_bps": 10000000000,
        },
    ]


def service_payload(name: str, *, enabled: bool) -> dict[str, Any]:
    return {
        "reason": f"automation create {name}",
        "name": name,
        "description": "automation service fixture",
        "backend_cidr": "203.0.113.10/32",
        "protocol": "tcp",
        "allowed_ports": [443],
        "output_interface": "backend0",
        "owner": "sre",
        "criticality": "high",
        "protection_mode": "enforce",
        "enabled": enabled,
        "priority": 100,
        "tags": ["automation"],
        "resolved_ifindex": 8,
        "resolved_next_hop_mac": "02:00:00:00:00:09",
        "resolved_src_mac": "02:00:00:00:00:08",
        "neighbor_resolution_status": "resolved",
    }


def baseline_payload(service_id: str) -> dict[str, Any]:
    return {
        "reason": "automation create baseline",
        "service_id": service_id,
        "interface": "wan0",
        "protocol": "tcp",
        "port": 443,
        "window": "5m",
        "expected_pps": 100,
        "expected_bps": 10000,
        "expected_cps": 10,
        "history_hours": 24,
        "confidence": 0.95,
        "evidence": {"source": "automation"},
    }


def rule_payload(name: str, service_id: str) -> dict[str, Any]:
    return {
        "reason": f"automation create {name}",
        "service_id": service_id,
        "name": name,
        "priority": 100,
        "match_expr": {"src_prefix": "198.51.100.0/24"},
        "action": "observe",
        "mode": "observe",
        "threshold_pps": 500,
        "threshold_bps": 500000,
        "threshold_cps": 50,
        "dimension": "source_service",
        "burst_packets": 1,
        "ttl_seconds": 900,
        "evidence": {"seed": True},
        "confidence": 0.8,
        "enabled": True,
        "owner": "soc",
    }


def whitelist_payload(cidr: str, reason: str, service_id: str = "") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "reason": reason,
        "cidr": cidr,
        "scope": "service" if service_id else "global",
        "label": "trusted-customer",
        "owner": "sre",
        "priority": 100,
        "enabled": True,
    }
    if service_id:
        payload["service_id"] = service_id
    return payload


def feed_payload(name: str, url: str) -> dict[str, Any]:
    return {
        "reason": f"automation create {name}",
        "name": name,
        "type": "internal_json",
        "url": url,
        "required_for_production": True,
        "enabled": True,
        "interval_seconds": 3600,
        "license_note": "automation fixture",
        "quota_metadata": {"ttl_seconds": 3600},
        "status": "placeholder",
    }


def security_event_payload(service_ebpf_id: int, rule_ebpf_id: int) -> dict[str, Any]:
    return {
        "events": [{
            "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "policy_version": 1,
            "src_ip": "198.51.100.10",
            "dst_ip": "203.0.113.10",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": 6,
            "tcp_flags": 2,
            "action": 1,
            "reason": 5,
            "service_id": service_ebpf_id,
            "rule_id": rule_ebpf_id,
            "pkt_len": 60,
            "sample_rate": 10,
            "metadata": {"source": "automation"},
        }],
    }


def wait_for_snapshots(api: ApiClient, minimum: int) -> list[dict[str, Any]]:
    deadline = time.monotonic() + 20
    snapshots: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        snapshots = api.get("/v1/snapshots?include_snapshot=false")
        if len(snapshots) >= minimum:
            return snapshots
        time.sleep(0.5)
    raise RuntimeError(f"expected at least {minimum} snapshots, got {len(snapshots)}")

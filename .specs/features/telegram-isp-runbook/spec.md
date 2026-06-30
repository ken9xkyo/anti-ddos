# Telegram Alerting & ISP Runbook Specification

## Problem Statement

Volumetric and protocol DDoS attacks must be mitigated and monitored in real-time. In addition to kernel-level drops, operators and administrators must be immediately notified of incidents, rule violations, and critical system faults (e.g., threat feed sync failures). Furthermore, during extreme volumetric attacks that exceed local scrubbing capacity, admins need a standardized, evaluated payload (an ISP Escalation Runbook) to coordinate with external ISP NOCs to drop or redirect traffic before it saturates physical link capacities.

## Goals

- [ ] Route all platform alerts (info, warning, critical) through the administrator's system-wide Telegram channel configuration.
- [ ] Provide reliable multi-attempt alert delivery to Telegram with deduplication and backoff retries.
- [ ] Generate notifications on threat intelligence feed failures or sync interruptions to prevent stale reputation lists.
- [ ] Allow admins to manually evaluate peak traffic metrics (PPS/BPS) and trigger an ISP Runbook Escalation payload.
- [ ] Maintain a permanent log of all alert deliveries, attempts, and response payloads.

## Out of Scope

| Feature | Reason |
| :--- | :--- |
| Automated BGP FlowSpec/RTBH routing injection | High risk of self-denial of service. BGP/FlowSpec injection is explicitly restricted to manual operator execution in external systems. |
| Non-Telegram alerting channels (e.g., Slack, Email) | Out of scope for Phase 09. Telegram is the primary alert hub. |
| Multi-recipient routing configuration | All alerts route to the single system-wide admin Telegram configuration. |

---

## User Stories

### P1: System-wide Telegram Alert Dispatch ⭐ MVP

**User Story**: As a Platform Administrator, I want to configure a single system-wide Telegram bot channel so that all system-generated and tenant-specific incident alerts are dispatched to the operations group.

**Why P1**: Critical for operational observability; the scrubbing system runs headlessly and needs a push notification system.

**Acceptance Criteria**:
1. WHEN an admin upserts the Telegram channel credentials (`bot_token_ref`, `chat_id`, `parse_mode`) THEN the system SHALL validate the inputs and store them securely with masked token values.
2. WHEN an alert is registered in the database THEN the system SHALL check alert deduplication constraints and dispatch the alert message to the configured Telegram API endpoint.
3. WHEN the Telegram API returns a retryable status (e.g., `429 Too Many Requests` or `5xx`) THEN the system SHALL retry delivery up to 3 times using exponential backoff.
4. WHEN an admin clicks the "Test Alert" button THEN the system SHALL dispatch a mock alert message to verify live connectivity.

**Independent Test**:
- Call `POST /v1/telegram/test` and confirm successful message receipt in the Telegram group/channel. Check `alert_deliveries` table logs for success status.

---

### P2: Threat Feed Failure Alerting

**User Story**: As a Platform Administrator, I want the system to alert me when threat intelligence feed synchronization fails repeatedly, so that I can investigate connectivity or api issues before reputation rules become stale.

**Why P2**: Feeds protect the system from known malicious actors. Stale feeds degrade scrubbing effectiveness.

**Acceptance Criteria**:
1. WHEN a threat feed sync fails THEN the system SHALL log the failure in `feed_runs`.
2. WHEN threat feed failures persist across consecutive sync periods THEN the system SHALL trigger a `critical` severity alert of type `feed_sync_failure`.
3. WHEN the `feed_sync_failure` alert is generated THEN the system SHALL deliver a detailed notification to the admin Telegram channel containing the feed name and the last successful sync timestamp.

**Independent Test**:
- Force a feed sync failure (e.g., by setting an invalid URL) and trigger a sync, then verify that an alert is registered in `alerts` and received on Telegram.

---

### P3: Manual ISP Escalation Runbook

**User Story**: As a Platform Administrator, I want to evaluate peak traffic metrics and generate an ISP Escalation payload from the dashboard, so that I can copy the detailed checklist and send it to the upstream ISP NOC.

**Why P3**: Standardizes communication under stressful, link-saturating conditions.

**Acceptance Criteria**:
1. WHEN an admin requests ISP escalation evaluation for a target CIDR or service THEN the system SHALL query Prometheus for peak PPS/BPS metrics over the last 1 minute.
2. WHEN the metrics are evaluated THEN the system SHALL create an `isp_escalation_needed` alert populated with targets, peak rates, packet loss ratios, and top traffic sources.
3. WHEN the escalation alert is created THEN the system SHALL output a standard manual checklist for SRE action.

**Independent Test**:
- Trigger `POST /v1/alerts/evaluate-isp-escalation` and verify that the returned JSON contains the Prometheus metrics, top sources, and correct checklist tasks.

---

## Edge Cases

- **Telegram Rate Limits (HTTP 429)**: System must check the `Retry-After` header or apply a standard 30-second delay before retrying alert delivery.
- **Missing or Invalid Token**: If no active admin Telegram configuration exists, alert status must be marked as `failed` immediately with a clear error logged, bypassing retry cycles to save resources.
- **Prometheus Query Offline**: If Prometheus is unreachable during ISP runbook evaluation, the system must degrade gracefully, using default values (`0` or user-supplied overrides) for peak rates instead of failing the request.

---

## Requirement Traceability

| Requirement ID | Story / Feature | Phase | Status |
| :--- | :--- | :--- | :--- |
| ALRT-001 | P1: Telegram configuration and validation | Specify | Pending |
| ALRT-002 | P1: Deduplicated alert message dispatching | Specify | Pending |
| ALRT-003 | P1: Retry queue with backoff | Specify | Pending |
| ALRT-004 | P2: Feed sync failure notification | Specify | Pending |
| ALRT-005 | P3: Prometheus query evaluation for ISP runbook | Specify | Pending |
| ALRT-006 | P3: Runbook manual checklist generation | Specify | Pending |

---

## Success Criteria

- [ ] Test alerts are successfully delivered to Telegram under 3 seconds.
- [ ] Persisted alert records show exact delivery statuses, attempt counts, and raw Telegram JSON responses in `alert_deliveries`.
- [ ] Prolonged feed failures consistently produce alerts and dispatch Telegram alerts.
- [ ] Admin dashboard renders the complete alert list and provides the interactive ISP Escalation Runbook trigger panel.

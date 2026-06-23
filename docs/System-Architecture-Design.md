# System Architecture Design: Anti-DDoS Scrubbing Gateway

This document provides a detailed specification of the components, role-based access controls, database schema, end-to-end runtime flows, and API boundaries of the Anti-DDoS Scrubbing Gateway.

---

## 1. System Topology & Integration Context

The gateway is deployed at the network ingress point of the infrastructure being protected. It acts as an active L3/L4 filtering scrub-point before traffic reaches target application servers.

```
       [ Volumetric Attack / Clean Traffic ]
                        |
                        v
         +-----------------------------+
         |     Scrubbing host (NIC)    |
         |                             |
         |   +---------------------+   |
         |   | eBPF/XDP Data Plane |   |
         |   +---------------------+   |
         |      | (Drop)    | (Redirect)
         |      v           v          |
         |  [Discard]   [tx_devmap]    |
         +------------------|----------+
                            |
                            v
               +-------------------------+
               | Protected Application   |
               | Servers (Backend)       |
               +-------------------------+
```

- **In-Line Scrubbing:** The host NIC receives all incoming WAN traffic. The eBPF driver hook filters out malicious packets immediately on the RX queues, forwarding clean traffic via L2 devmap redirection to the backend application servers.
- **Out-of-Band Management:** Administration, configuration adjustments, threat sync, and dashboard views occur out-of-band via the Control Plane API, decoupled from the packet processing path.

---

## 2. Component Architecture

| Component | Technology / Stack | Primary Responsibilities | Port / Communication Protocol |
|---|---|---|---|
| **Admin Dashboard** | React, Vite, Nginx | - Visual interface for policy configurations, real-time metrics, node monitoring, and audit trails.<br>- Handles admin impersonation view-user sessions. | HTTP/S (Port 80/443) |
| **Control API** | Go (standard HTTP library), `pgx` | - Auth, JWT verification, and RBAC enforcement.<br>- CRUD handlers for configurations.<br>- Snapshot compilation and integrity signing.<br>- Incident reporting, Telegram routing, and Agent APIs. | REST / JSON (Port 8080) |
| **PostgreSQL DB** | PostgreSQL 15+ | - Transactional store for users, sessions, service policies, audit logs, incidents, and threat intelligence state. | SQL / TCP (Port 5432) |
| **Node Agent** | Go, `cilium/ebpf` | - Detaches/attaches XDP programs to interfaces.<br>- Heartbeat reporter.<br>- Double-buffers and updates kernel eBPF map values. | REST / JSON (Port 8080 client) |
| **XDP Data Plane** | eBPF (`clang`, `libbpf` headers) | - In-kernel packet parsing and security set evaluation.<br>- Performs atomic map-driven drops, pass-throughs, and redirection. | Kernel Space / RX Queues |
| **Observability** | Prometheus, Grafana | - Scrapes host load metrics, XDP packet drops, and agent heartbeat records.<br>- Serves real-time data back to the dashboard charts. | PromQL / HTTP (Port 9090/3000) |

### XDP Kernel Map Specifications:
- `app_whitelist_map` (`BPF_MAP_TYPE_HASH`): Matches trusted IPv4 CIDRs to bypass filtering.
- `app_blacklist_map` (`BPF_MAP_TYPE_HASH`): Matches blocked IPv4 CIDRs. Contains both user-defined blocks and admin-synced global feed reputations.
- `udp_port_blocks` (`BPF_MAP_TYPE_HASH`): Matches source ports/ranges for UDP reflection mitigation.
- `custom_rules_map` (`BPF_MAP_TYPE_ARRAY`): Prioritized list of firewall rules containing protocol matches, port thresholds, rate limits, and TCP flag masks.
- `active_slot_selector` (`BPF_MAP_TYPE_ARRAY`): Controls the active double-buffered A/B mapping index.

---

## 3. RBAC, Session Management & Data Ownership

The system operates under strict access isolation, preventing cross-tenant data leaks and securing system configurations.

### Security Roles:
1. **User** (`RoleUser`):
   - Access is strictly isolated using their account ID (`owner_user_id`).
   - Can manage their own protected Services, custom Rules, Whitelist, Manual Blacklist, UDP port blockages, and backup Snapshots.
   - **Bypasses:** Bypasses Telegram alerts configuration and Incidents/Alerts endpoints entirely. The UI suppresses these items, and direct API endpoints return `403 Forbidden`.
2. **Admin** (`RoleAdmin`):
   - System-wide scope. Accesses global tables (threat feeds, audit trails) and can manage admin-global firewall configurations.
   - Full control over platform-wide alerting, Telegram integration parameters, and ISP Escalation alerts.
3. **Admin View-User Session:**
   - Allows admins to enter a read-only configuration context of a user to diagnose configuration issues.
   - The token contains the target's ID in the `view_owner_user_id` claim.
   - All mutation endpoints explicitly check this claim; if present, they reject requests with `403 Forbidden`.

### Node Agent Authentication & Ownership:
- During deployment, the Node Agent is registered with the Control Plane using a tenant owner token.
- Registration returns a unique cryptographically generated `agent_id` stored on the host.
- Subsequent calls for heartbeats, snapshots, and logs are authenticated using the `agent_id`, which maps back to the corresponding `owner_user_id` in the database.

---

## 4. Database Schema & Policy Compilation

```
    +-----------------+           +--------------------+
    |    app_users    |           |    user_sessions   |
    +-----------------+           +--------------------+
    | id (PK)         |<----------| id (PK)            |
    | username        |           | user_id (FK)       |
    | password_hash   |           | view_owner_id (FK) |
    +-----------------+           +--------------------+
             |
             | 1
             |
             | N (owner_user_id)
    +-----------------------------------------------------------------------+
    | Owner-Scoped Config Tables                                            |
    | (services, rules, whitelist, blacklist, udp_ports, snapshots, alerts) |
    +-----------------------------------------------------------------------+
```

### Database Tables:
- **Core Session Scope:**
  - `app_users`: User identities, hashed passwords (`bcrypt`), system roles (`admin`, `user`), and accounts state (`active`, `revoked`).
  - `user_sessions`: Active access session records. Contains `view_owner_user_id` for admin view sessions.
- **Tenant Configuration Data (Scoped by `owner_user_id`):**
  - `services`: Monitored CIDRs, protocols, neighbor gateway resolution targets.
  - `rules`: Flow specifications, limits, actions, and priority rankings.
  - `whitelist` / `blacklist`: IPv4 CIDR sets.
  - `udp_source_port_blocks`: Source port range limits.
  - `policy_snapshots`: Chronological archive of compiled signed policy blocks.
  - `telegram_configs`: Stores global Telegram integration settings (scoped to the admin user in a system-wide context).
  - `alerts` & `alert_deliveries`: Logs of security incidents and their dispatch logs.
- **Global Threat Reputation (Unscoped - `owner_user_id IS NULL`):**
  - `feed_sources`: URL endpoints of external threat feeds, Cron schedule, weight values.
  - `feed_runs`: Statistics log of background intelligence ingestion syncs.
  - `reputation_entries`: Global IP block lists populated by feed sync runs.
  - `feed_conflicts`: Overlap conflict logs between global feed reputations and tenant whitelists.

### Policy Compilation & Effective Reputation Union:
- When a configuration changes, the Control Plane builds an effective `PolicySnapshot`.
- **Merging Reputations:** The compilation engine queries the active tenant's whitelist, blacklist, rules, and services. In addition, it fetches all global active reputation entries (`reputation_entries`).
- It computes a union of the tenant's manual blacklist and the global reputation entries. Any IP block derived from global feeds is injected into the snapshot with `Source: "threat-feed"` and `Editable: false`.
- The merged list is serialized into JSON, signed with a SHA-256 hash, and assigned a version integer.

---

## 5. End-to-End Runtime Flows

### A. Configuration Update & Snapshot Deployment Flow
1. **User Action:** The tenant modifies configurations (e.g., updates service ports) on the React Dashboard, submitting a change reason.
2. **Control Validation:** The Control Plane validates limits and syntax inside a PostgreSQL transaction. On success, it increments the version tag and triggers the snapshot compiler.
3. **Snapshot Compilation:** The control plane merges configuration sets (including global feed reputations), generates the signed `PolicySnapshot`, and saves it to the `policy_snapshots` database table.
4. **Heartbeat Polling:** The Go Node Agent polls `/v1/agents/{id}/heartbeat` every 5 seconds, reporting its currently active version.
5. **Snapshot Synchronization:** If the reported version is older than the latest snapshot, the Agent requests the new configuration payload via `/v1/agents/{id}/snapshot`.
6. **In-Kernel Apply (Double-Buffer):**
   - The Agent parses the rules and populates the inactive A/B map slot in kernel memory.
   - Resolves target gateway MAC addresses via ARP.
   - Atomically switches the active map slot index.
   - Reports successful deployment status to `/v1/agents/{id}/apply`.

### B. Telegram Alert Dispatching Flow
1. **DDoS Detection:** The eBPF program detects traffic breaching configured thresholds (e.g., PPS/BPS values) and writes a drop incident event to the perf ring buffer.
2. **Telemetry Log Forwarding:** The Node Agent reads the event from the ring buffer and dispatches a JSON telemetry log to the Control Plane API via `/v1/agents/{id}/events`.
3. **Alert Creation:** The control plane evaluates the telemetry log. If the severity triggers alert policies, it records a new alert in the `alerts` database table.
4. **Unscoped Config Resolution:** The alert dispatcher fetches the system-wide Telegram settings (configured by the platform admin) using an unscoped database query.
5. **Notification Dispatch:** The Control Plane sends the formatted alert message directly to the Telegram bot endpoint (`POST https://api.telegram.org/bot{token}/sendMessage`).

---

## 6. API Boundary Specifications

### Auth & Session management
- `POST /v1/auth/login`: Authenticates credentials; returns JWT session token.
- `GET /v1/me`: Retrieves details of the authenticated user.
- `POST /v1/me/password`: Updates the caller's password.
- `POST /v1/admin/view-user`: (Admin only) Sets the session context to view a user read-only.

### Tenant Configuration Management (User / Admin-Global Scopes)
- `GET/POST /v1/services` & `PATCH/DELETE /v1/services/{id}`: Service specifications.
- `GET/POST /v1/rules` & `PATCH/DELETE /v1/rules/{id}`: Rules engine configuration.
- `GET/POST /v1/whitelist` & `DELETE /v1/whitelist/{id}`: Traffic bypass sets.
- `GET/POST /v1/blacklist` & `DELETE /v1/blacklist/{id}`: IP blocking filters.
- `GET/POST /v1/udp-source-port-blocks` & `DELETE /v1/udp-source-port-blocks/{id}`: UDP port range blocks.
- `GET/POST /v1/snapshots` & `POST /v1/snapshots/restore`: Backup snapshot operations.

### Alerts & Telegram Settings (Admin Only)
- `GET /v1/alerts`: Returns system incidents and alerts log.
- `GET /v1/alerts/{id}/deliveries`: Retrieves Telegram dispatch logs for a specific alert.
- `POST /v1/alerts/evaluate-isp-escalation`: Evaluates traffic rates and registers manual ISP escalation logs.
- `GET/POST /v1/telegram/config`: Configures the platform-wide Telegram integration parameters.
- `POST /v1/telegram/test`: Triggers a test alert to verify the Telegram configuration.

### Global Threat Reputation (Admin Only)
- `GET/POST /v1/feed-sources` & `PATCH/DELETE /v1/feed-sources/{id}`: Intelligence feeds definitions.
- `POST /v1/feed-sources/{id}/sync`: Triggers manual sync on a feed source.
- `GET /v1/feed-runs`: Lists synchronization logs.
- `GET /v1/feed-conflicts` & `POST /v1/feed-conflicts/{id}/resolve`: Resolves overlaps between whitelists and feeds.

### Node Agent Interface
- `POST /v1/agents/register`: Registers a host node; returns a unique `agent_id`.
- `GET /v1/agents/{id}/heartbeat`: Heartbeat polling endpoint.
- `GET /v1/agents/{id}/snapshot`: Fetches the latest compiled policy snapshot.
- `POST /v1/agents/{id}/apply`: Confirms eBPF maps load status.
- `POST /v1/agents/{id}/events`: Forwards eBPF packet-drop telemetry events.


# Admin Dashboard

Admin Dashboard is the React/Vite operations console for the Anti-DDoS Control Plane. It renders account management for admins, owner-scoped operational views for users, read-only user config views for admin support, and global reputation management for normal admin sessions.

## Role Behavior

| Role/session | UI behavior |
|---|---|
| `user` | Can view effective policy and mutate own Services, user-global/service Rules, Whitelist, Manual Blacklist, UDP Ports, and Snapshots. Cannot access Telegram configuration or Incidents. |
| `admin` normal session | Can manage Accounts, Reputation feed sources/runs/conflicts, and admin-global Rules, Whitelist, Manual Blacklist, and UDP Ports. Can view, configure, and test Telegram alerts, manage Incidents (including triggering ISP Escalations), and open `View config` for an active user. |
| `admin` view-user session | Can read target user dashboard/config data. Mutation controls are hidden and backend mutations return `403`. |

The topbar shows `username · role`. When admin is viewing user config, it also shows `viewing <username>` and `read only`.

## Navigation & UI Views

The dashboard sidebar divides views into three key conceptual groups: **Operation**, **Configuration**, and **Setting**.

| Group | Tab Name | Route/View Name | Scopes & Access Restrictions |
|---|---|---|---|
| **Operation** | Dashboard | `OverviewView` | Accessible to all logged-in roles. |
| | Incidents | `IncidentsView` | Restricted to **normal admins** only. Hidden from users. |
| | Events | `InvestigationView` | Accessible to all logged-in roles. |
| **Configuration**| Services | `ServicesView` | Mutable by `user` owners; Read-only for `admin` view sessions. |
| | Rules | `RulesAdminView` | Scoped (Admins edit `admin_global` rules, users edit user/service rules). |
| | Whitelist | `WhitelistAdminView` | Scoped (Admins edit `admin_global` whitelists, users edit user/service whitelists). |
| | Blacklist | `BlacklistAdminView` | Scoped (Includes threat feed blocks showing `editable=false`). |
| | Reputation | `ReputationView` | Restricted to **normal admins** only. Hidden from users. |
| | UDP Ports | `UDPPortsAdminView` | Scoped (Admins edit `admin_global` blocks, users edit user/service blocks). |
| **Setting** | Snapshots | `SnapshotsView` | Scoped configuration version control (Backup/Restore). |
| | Accounts | `AccessView` | Restricted to **normal admins** only. Hidden from users. |
| | Nodes | `FleetView` | Lists live Anti-DDoS agent nodes and daemon statuses. |

---

## Detailed UI View Features

### 1. Dashboard (Overview)
- **Live Metrics Dashboard:**
  - *Packets/s:* Ingress packet processing speed at the active packet filter level.
  - *Bits/s:* Net aggregate bandwidth throughput.
  - *Connections/s:* Approximate number of active TCP connections per second.
  - *Agents Healthy:* Alive agent count out of total registered daemon nodes.
  - *Drop/Redirect/Not Allowed rates:* Real-time decision metrics calculated per second.
- **Traffic Shape & Decision Rates Charts:** Renders two dynamic Bar Charts indicating traffic throughput categories and action outcomes (drops, drops by rate limits, redirects, accepts).
- **Control Plane Status:** Details Promethean scraping health, the active central policy snapshot configuration version, and fleet-wide sync apply statistics.
- **Current Operational Signal:** Displays details of the latest system alert triggered across the platform (Severity, Type, Dedupe Key, Affected Service).
- **Security Event Lists:** Summarizes the top threat targets: Top source `/24` subnets, top destination/vector ports, and sample decisions.
- **Latest Apply Status Table:** Lists all Anti-DDoS agent hostnames, their active policy version, state (`applied` or `failed`), error stage/reason, and last report time.

### 2. Incidents (Admin Only)
- **Telegram Channel Configuration Form:**
  - Inputs: Bot token, Chat ID, and Parse mode select option (`HTML`, `Markdown`, `MarkdownV2`).
  - Audit trail reason field is required before submit.
  - Shows masked configuration status (`enabled`, token presence status).
- **Test Alert Engine:** Action button triggers `POST /v1/telegram/test` to verify live channel messaging delivery using a mock system alert.
- **ISP Escalation Trigger:** Renders an interface to evaluate network loads and dispatch manual escalation alerts containing PPS/BPS metric aggregates.
- **Alert Log Table:** Logs all generated security notifications indicating severity level, type, source service target, deduplication state, dispatch count, creation time, and metadata.

### 3. Events (Audit Logs)
- Displays search-enabled tables containing user action audits, configuration modifications, and system security telemetry logs.
- Filtering options allow searches by keyword, actor ID, or specific timestamp ranges.

### 4. Services
- **Service Configuration Table:** Lists all protected services, CIDRs, protocol, allowed ports, output interfaces, neighbor gateway resolution values, MACs, and operational state.
- **Service Form Editor:**
  - Create, Update, or Delete configurations.
  - Inputs: Name, Description, Backend CIDR, Protocol (TCP/UDP/Any), Allowed Ports, Output Interface, Owner User ID, Criticality (`low`, `medium`, `high`, `critical`), Protection Mode (`active` or `passive`), Priority, Tags, and Audit reason.
  - Integrates neighbor gateway address resolution (`ifindex`, `resolved_src_mac`) based on the selected output interface.
  - Shows `View Only` banners and disables save/delete buttons in read-only session modes.

### 5. Rules (Traffic Filters)
- **Rules Table:** Displays traffic filtering actions (Drop, Accept, Redirect, Rate Limit) mapped to matching criteria (IP subnets, protocol, port ranges, TCP flags).
- **Rule Form Editor:**
  - Allows config operators to write granular firewall actions.
  - Inputs: Action, Source IP/CIDR, Destination IP/CIDR, Protocol, Source Port range, Destination Port range, Rate limits (max pps, max bps), Priority, and Audit reason.
  - Restricts editing permissions based on user configuration scope.

### 6. Whitelist
- **IP Bypass Configuration:** Table for adding trusted subnets that should bypass threat filtering.
- **Form Editor:** Input CIDR ranges, select target scope, describe reason, and submit with audit details.

### 7. Blacklist
- **Manual and Ingested blocks:** Table displays IP/subnets marked for drop.
- **Threat Feed Indicators:** Rows synced from threat feeds show as `Source: threat-feed` and display a lock icon indicating `editable=false` (these cannot be manually modified).
- **Form Editor:** Permits operators to block custom subnets, assign a Time-to-Live (TTL) expiration, and supply audit reasoning.

### 8. Reputation (Admin Only)
- **Threat Feed Management:** Renders controls to manage external IP intelligence feeds.
- **Feed Source Editor:** Fields include URL, Schedule (Cron syntax), Enabled switch, Weight multiplier, Default action, and Audit reason.
- **Sync Trigger:** Manual button to trigger asynchronous feed ingestion tasks.
- **Feed Runs History:** Log listing past synchronization runs, processed IP count, run duration, and error codes.
- **Reputation Conflicts:** Details conflicts where user rule settings overlap with feed reputations, allowing admins to view or resolve conflicts.

### 9. UDP Ports (Reflection Defenses)
- Lists UDP port ranges blocked or rate-limited to avoid amplification attacks.
- Editor form allows choosing port ranges, scopes, and target actions.

### 10. Snapshots (Policy Versions)
- **Snapshot Version Grid:** Lists backup configuration records including version, SHA-256 identifier, author, audit description, and generation timestamp.
- **Backup & Restore Operations:**
  - Backup: Allows creating a new state checkpoint with a reason.
  - Restore: Activates a past snapshot and propagates the configuration across the fleet.

### 11. Accounts (Admin Only)
- **User Records Table:** Lists username, role, state, and status.
- **User Actions Form:**
  - Add users, toggle statuses (active, suspended), and enforce password changes upon next login.
  - **View Config Impersonation:** Button lets normal administrators launch a read-only view session to inspect a specific user's dashboard and policy files without seeing their login credentials.

### 12. Nodes (Agents status)
- Displays registered Anti-DDoS traffic filter agent daemons.
- Indicates hostname, WAN interfaces, output interfaces, active kernel XDP attachment modes (`native` or `generic`), daemon version, and last heartbeat timestamps.

---

## Main Workflows

- Login calls `POST /v1/auth/login` with `username` and `password`.
- Dashboard polling loads overview, agents, services, rules, and recent security events. Telegram config and alerts are only requested and loaded if the user role is `admin`.
- Feed endpoints are loaded only when `user.role === "admin"` and the session is not read-only and not viewing another user.
- Services/Snapshots render mutation controls only for mutable user sessions.
- Rules/Whitelist/Manual Blacklist/UDP Ports render mutation controls for mutable user policy scopes and normal admin admin-global policy scopes; row actions still honor `editable=false`.
- Incidents tab allows admins to view platform alerts, configure/test Telegram integrations, and evaluate/trigger manual ISP Escalations.
- Accounts lets admins create/update/revoke users, reset passwords, revoke sessions and open read-only user config context.
- Reputation lets normal admins create/update/disable/sync global feed sources and review feed runs/conflicts.
- Blacklist displays manual rows and feed-origin rows; feed-origin rows have `editable=false`.

## Backend API Contracts

| Domain | Method/path | Role/session | Semantics |
|---|---|---|---|
| Auth | `POST /v1/auth/login` | Public | Login |
| Current user | `GET /v1/me`, `POST /v1/me/password` | Authenticated | Load user or change own password |
| Admin view | `POST /v1/admin/view-user` | `admin` | Open read-only config context for active user |
| Users | `GET/POST /v1/users`, `PATCH/DELETE /v1/users/{id}`, password/session subroutes | `admin` | Account lifecycle |
| User config | Services, Snapshots | `user` owner only for mutation | Mutate own user-owned config; read-only admin context can read |
| Telegram config | `/v1/telegram/config`, `/v1/telegram/test` | normal `admin` session | Configure and test Telegram alert delivery |
| Alerts / Incidents | `/v1/alerts`, `/v1/alerts/*` | `admin` | List alerts, get delivery status, or trigger manual ISP Escalation |
| Policy config | Rules, Whitelist, Blacklist, UDP Ports | `user` for `user_global`/`service`, normal `admin` for `admin_global` | Mutate scoped policy; effective reads include read-only rows where applicable |
| Reputation | `/v1/feed-sources*`, `/v1/feed-runs`, `/v1/feed-conflicts` | normal `admin` session | Manage global threat feeds |
| Dashboard read | Overview, Agents, Services, Rules, Events | Authenticated owner context | Poll general dashboard data |

## Verification

- Unit/component tests: `make ui-test`
- Production build: `make ui-build`
- Backend contract and alerting tests: `make alerting-postgres-test` and `go test ./internal/control -run 'RBAC|DashboardAPIIntegration|ControlCoreIntegration|Server'`

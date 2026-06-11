# Admin Dashboard Guide

Dashboard chi con hai role public: `admin` va `user`.

| Role | Muc dich | Quyen UI |
|---|---|---|
| `user` | Van hanh config Anti-DDoS cua chinh minh | Co controls mutation cho services, rules, whitelist, manual blacklist, UDP ports, snapshots, Telegram va baseline/anomaly workflow |
| `admin` | Quan ly tai khoan va ho tro user | Thay Accounts; co the mo `View config` read-only cua user; khong mutation config user |

## Navigation

| Group | Trang |
|---|---|
| Operation | Dashboard, Incidents, Detections, Events |
| Configuration | Services, Rules, Whitelist, Blacklist, UDP Ports |
| Setting | Snapshots, Accounts, Nodes |

`Accounts` chi hien voi admin. `Tenants` va `Reputation` da retired.

## Data loading

Sau khi dang nhap, dashboard goi cac endpoint owner-scoped de lay overview, agents, services, rules, security events, baselines, anomalies, Telegram config va alerts. Dashboard khong goi `/v1/tenants*` hoac `/v1/feed-*`.

## Safety

- Moi mutation quan trong can `reason` trong body hoac `X-Audit-Reason`.
- Delete/disable policy object la soft-disable de giu audit/history.
- UI an mutation controls theo role, nhung backend van la enforcement chinh.

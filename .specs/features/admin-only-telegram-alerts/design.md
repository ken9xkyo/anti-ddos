# Technical Design: Admin-Only Telegram Alerts

This document details the code and structure changes necessary to implement the admin-only Telegram alert feature.

## Architecture Overview

All Telegram configuration (bot token, chat ID, parse mode, enabled/disabled state) and alert routing policies will be owned globally by the active system administrator.

```
┌──────────────────┐      Creates Alert      ┌──────────────────┐
│   User/System    │ ──────────────────────> │      Alerts      │
└──────────────────┘                         └──────────────────┘
                                                       │
                                                       │ Triggers Delivery
                                                       ▼
┌──────────────────┐  Reads Admin Config     ┌──────────────────┐
│  Admin Telegram  │ <────────────────────── │   deliverAlert   │
│  Config & Policy │                         └──────────────────┘
└──────────────────┘
```

## Proposed Changes

### Go Backend

#### [MODIFY] [alert_handlers.go](file:///root/anti-ddos/internal/control/alert_handlers.go)
- Require admin role check in `handleTelegramConfig` and `handleTelegramTest` using `requireAdmin(actor)`.
- Non-admin calls must return `403 Forbidden`.

#### [MODIFY] [alert.go](file:///root/anti-ddos/internal/control/alert.go)
- Update `UpsertTelegramConfig` to enforce admin role check (`requireAdmin(actor)`).
- Implement `getAdminTelegramConfigRaw(ctx)` which joins `telegram_configs` with `app_users` filtering on `u.role = 'admin'` and runs in an unscoped context (`beginUnscopedTx`).
- Update `deliverAlert` to query the admin's Telegram configuration using `getAdminTelegramConfigRaw(ctx)`.
- Update `alertPolicy` to fetch policy configs from the admin's owned alert policies.

---

### Frontend Dashboard

#### [MODIFY] [api.ts](file:///root/anti-ddos/web/dashboard/src/api.ts)
- In `dashboard(user)` method, check if `user?.role === 'admin'`. If false, bypass calling `/v1/telegram/config` and instead resolve a default disabled `TelegramConfig` object.

#### [MODIFY] [DashboardShell.tsx](file:///root/anti-ddos/web/dashboard/src/DashboardShell.tsx)
- Pass `canMutate={isAdmin && !user.read_only && !user.viewing_user}` to `<IncidentsView />` component for the incidents tab.

#### [MODIFY] [IncidentsView.tsx](file:///root/anti-ddos/web/dashboard/src/views/IncidentsView.tsx)
- Change `canConfigureTelegram` check to `canMutate && user.role === 'admin'`.
- Update the unauthorized message to: `"Telegram configuration changes require admin access."`

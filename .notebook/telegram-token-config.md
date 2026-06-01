# Telegram Token Config
> DB-stored Telegram token with write-only API/UI behavior

Entry: `internal/control/alert.go:Store.UpsertTelegramConfig()`
Flow: Admin form -> `/v1/telegram/config` -> `telegram_configs.bot_token_ref`

Storage:
- Raw token stored in `telegram_configs.bot_token_ref`
- Legacy `env://` and `secret://anti-ddos/` refs still resolve through `resolveTelegramBotToken()`
- `GetTelegramConfig()` returns masked config; delivery uses `getTelegramConfigRaw()`

Masking:
- Public `TelegramConfig.bot_token_ref` is `*****` when any token/ref is configured
- `*****` or empty input on update preserves the existing token
- Dashboard field: `web/dashboard/src/views/IncidentsView.tsx`

Delivery:
- `internal/control/alert.go:Store.deliverAlert()` resolves raw token before `TelegramClient.SendMessage()`
- Audit redaction still runs through `internal/control/store.go:marshalRedactedJSON()`

Tests:
- Go coverage: `internal/control/alert_test.go`, phase 09/admin dashboard integration tests
- UI coverage: `web/dashboard/src/App.test.tsx`, `web/dashboard/src/api.test.ts`
- Browser flow: `tests/automation_test/admin-dashboard/browser_flows.py`

Updated: 2026-06-01

# Quick Task 004: Remove Service Owner Input and Use Username

**Date:** 2026-06-30
**Status:** In Progress

## Description

Bỏ phần điền thông tin owner khi user tạo service mới, lấy username của user để làm owner và không cho thay đổi.

## Files Changed

- `internal/control/policy_store.go` — Backend: force service owner to actor's username at creation and keep it unchanged during updates.
- `web/dashboard/src/views/ServicesView.tsx` — UI: accept user prop, initialize owner to user's username, hide owner input on service creation, and disable it on edit.
- `web/dashboard/src/DashboardShell.tsx` — UI: pass logged-in user to ServicesView.
- `web/dashboard/src/api.ts` — API: avoid requesting telegram config in viewing-user mode to prevent 403.
- `tests/automation_test/admin-dashboard/browser_flows.py` — Test: remove owner field filling during service creation in E2E tests.
- `tests/automation_test/admin-dashboard/fixtures.py` — Test: fix user role mismatch for admin-only endpoints in seeder.

## Verification

- [ ] Run backend tests: `make go-test`
- [ ] Run dashboard unit tests: `make ui-test`
- [ ] Run UI integration/E2E tests: `make services-ui-e2e`

## Commit

`[hash]` — feat(service): set owner to user username and prevent changes

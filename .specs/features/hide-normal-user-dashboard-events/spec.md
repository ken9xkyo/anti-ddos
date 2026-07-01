# Hide Dashboard and Events from Normal Users Specification

## Problem Statement

Currently, normal users (with the `user` role) have access to the Dashboard Overview (showing global traffic metrics) and Security Events (showing detailed firewall events). Under the security isolation model, normal users should only manage their own services and rules, and should not be able to view global dashboard metrics or general security event logs.

## Goals

- [ ] Prevent normal users from viewing the Dashboard and Events buttons/sections in the frontend.
- [ ] Reject access on the backend to `/v1/dashboard/overview` and `/v1/security-events` (and its subroutes) for non-admin users, returning 403 Forbidden.
- [ ] Default the active tab for normal users to "Services" when loading the app.

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature     | Reason         |
| ----------- | -------------- |
| Block `/v1/dashboard/services` | Normal users legitimately need to list their owned services. |
| Block `/v1/dashboard/rules` | Normal users legitimately need to list their owned rules. |
| Modify rule/service ownership rules | Only endpoint visibility and API authorization are in scope. |

---

## User Stories

### P1: Restrict UI Navigation and Views ⭐ MVP

**User Story**: As a normal user, I want the Dashboard and Events tabs to be hidden from the sidebar, so that I don't see views I am not authorized to access.

**Why P1**: Essential first step for hiding features from unauthorized users in the UI.

**Acceptance Criteria**:
1. WHEN a logged-in user has the `user` role, THEN the system SHALL hide "Dashboard" and "Events" from the navigation sidebar.
2. WHEN a user with the `user` role loads the frontend application, THEN the system SHALL set the default active tab to "Services".
3. WHEN a user with the `user` role has `overview` or `investigation` as the active tab (e.g. by manual redirection), THEN the frontend SHALL automatically reset the active tab to "Services".

**Independent Test**: Can log in as a normal user and verify that the sidebar only contains Services, Rules, Whitelist, Blacklist, and UDP Ports, and that the app defaults to showing the Services view.

---

### P1: Enforce Backend API Access Protection ⭐ MVP

**User Story**: As an administrator, I want the control plane API to reject requests from normal users to `/v1/dashboard/overview`, `/v1/security-events`, `/v1/security-events/summary`, and `/v1/security-events/investigate` with an HTTP 403 Forbidden status, ensuring they cannot bypass the UI to scrape global system statistics or events.

**Why P1**: Crucial for security; frontend hiding is not sufficient on its own.

**Acceptance Criteria**:
1. WHEN a user with the `user` role requests `/v1/dashboard/overview`, THEN the backend API SHALL return an HTTP 403 Forbidden error with a message indicating admin privileges are required.
2. WHEN a user with the `user` role requests `/v1/security-events`, `/v1/security-events/summary`, or `/v1/security-events/investigate`, THEN the backend API SHALL return an HTTP 403 Forbidden error.

**Independent Test**: Send HTTP request to `/v1/dashboard/overview` with a normal user token and assert that the response is HTTP 403 Forbidden.

---

### P1: Prevent Frontend Crashes on API Restrictions ⭐ MVP

**User Story**: As a frontend application, I want to skip calling the blocked endpoints for normal users during the periodic dashboard sync, so that the application does not trigger console errors or fail to load data.

**Why P1**: Since the dashboard is loaded via a single unified client method (`api.dashboard()`), blocking backend endpoints will cause the whole sync to fail for normal users unless the client is updated to conditionally skip them.

**Acceptance Criteria**:
1. WHEN the frontend syncs dashboard data for a user with the `user` role, THEN the `api.dashboard` method SHALL resolve mock/empty structures for `/v1/dashboard/overview` and `/v1/security-events?limit=50` and SHALL NOT make actual network requests to them.

**Independent Test**: Verify that when a normal user logs in, the console is free of 403 network errors, and other dashboard data (services, rules) loads successfully.

---

## Edge Cases

- WHEN a user with the `admin` role uses "impersonate" / "view config" of a standard user, THEN the admin's view configuration session operates under the admin context or is read-only, but let's make sure the admin view-user behavior is preserved and the admin UI still displays dashboard/events normally.
- WHEN a user's role is updated from `user` to `admin` or vice-versa, THEN the session refresh/token reissue SHALL correctly apply the new permissions on both backend and frontend.

---

## Requirement Traceability

Each requirement gets a unique ID for tracking across design, tasks, and validation.

| Requirement ID | Story | Phase | Status |
| -------------- | ----- | ----- | ------ |
| RBAC-DASH-01 | P1: Restrict UI Navigation and Views | Verified | Verified |
| RBAC-DASH-02 | P1: Restrict UI Navigation and Views | Verified | Verified |
| RBAC-DASH-03 | P1: Restrict UI Navigation and Views | Verified | Verified |
| RBAC-DASH-04 | P1: Enforce Backend API Access Protection | Verified | Verified |
| RBAC-DASH-05 | P1: Prevent Frontend Crashes on API Restrictions | Verified | Verified |

**Status values:** Pending → In Design → In Tasks → Implementing → Verified

**Coverage:** 5 total, 5 mapped to tasks, 0 unmapped

---

## Success Criteria

How we know the feature is successful:
- [x] Non-admin users cannot see Dashboard or Events in the UI.
- [x] Non-admin user sessions attempting to curl `/v1/dashboard/overview` or `/v1/security-events` receive 403 Forbidden.
- [x] Frontend unit tests build and pass successfully.

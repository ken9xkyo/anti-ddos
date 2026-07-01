# Admin Assigned User Default Output Interface Specification

## Problem Statement

Currently, when standard users (with the `user` role) create a protected service, they have to manually select the network interface (`output_interface`) for traffic forwarding. Under the network isolation model, administrators want to restrict standard users to specific network interfaces. Normal users should not need to choose or even see the output interface. Instead, the administrator should assign a default output interface to each user, which will be automatically applied when they create services.

## Goals

- [ ] Add a `default_output_interface` field to the `app_users` database table.
- [ ] Provide an option in the Admin's user management panel to assign a default output interface to users.
- [ ] Hide the "Output interface" selection field from the Service creation/edit forms for users with the `user` role.
- [ ] Automatically default a service's `output_interface` to the owner's `default_output_interface` during service creation on the backend.
- [ ] Prevent standard users from changing a service's `output_interface` when updating a service.

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature     | Reason         |
| ----------- | -------------- |
| Multiple output interfaces per user | Out of scope for MVP; a single default interface is sufficient. |
| Automatic migration of existing service interfaces | Existing services will keep their current `output_interface`. |
| Interface speed / bandwidth restriction | Bandwidth control is out of scope. |

---

## User Stories

### P1: Admin Assigns Default Output Interface ⭐ MVP

**User Story**: As an administrator, I want to assign a default output interface to a user, so that the user's services default to this interface.

**Why P1**: Essential for the admin to configure the isolation of users to interfaces.

**Acceptance Criteria**:
1. WHEN creating or editing a user with the `user` role, THEN the administrator SHALL be able to select a default output interface from a dropdown of available agent interfaces.
2. WHEN the user role is `admin`, THEN the default output interface selection SHALL NOT be shown or editable in the user drawer.
3. WHEN updating a user, THEN the selected `default_output_interface` SHALL be saved to the database.

**Independent Test**: Log in as an admin, edit a standard user, set the default output interface to `backend0`, save, and verify that the user's detail record now contains `default_output_interface: "backend0"`.

---

### P1: Hide Output Interface from User Service UI ⭐ MVP

**User Story**: As a standard user, I do not want to see or select the output interface when creating or editing a service, so that my configuration is simplified.

**Why P1**: Simplifies the UI for normal users and prevents them from attempting to select unauthorized interfaces.

**Acceptance Criteria**:
1. WHEN a user with the `user` role opens the Service creation or edit drawer, THEN the "Output interface" field/dropdown SHALL NOT be displayed.
2. WHEN an admin views or impersonates a standard user's config, THEN the "Output interface" field/dropdown SHALL NOT be displayed.

**Independent Test**: Log in as a standard user, click "Add Service", and verify that there is no "Output interface" field in the form.

---

### P1: Default Output Interface on Backend Service Creation ⭐ MVP

**User Story**: As the system, I want to automatically assign the user's default output interface to any service they create, so that the traffic is correctly routed without user action.

**Why P1**: Ensures traffic isolation policy is applied securely on the backend even if the UI field is hidden.

**Acceptance Criteria**:
1. WHEN a service is created by a user with the `user` role, THEN the backend SHALL fetch the user's `default_output_interface`.
2. WHEN the creator user has no `default_output_interface` assigned (i.e. it is empty), THEN the backend SHALL reject service creation with a validation error: `default output interface not assigned by administrator`.
3. WHEN the creator user has a valid `default_output_interface`, THEN the backend SHALL set the service's `output_interface` to this default.
4. WHEN a service is updated by a user with the `user` role, THEN the backend SHALL keep the original `output_interface` of the service, ignoring any interface modifications from the user.

**Independent Test**: Create a service via the API as a standard user who has `default_output_interface` set to `backend0` (omitting `output_interface` in the payload) and verify that the service is successfully created with `output_interface: "backend0"`.

---

## Edge Cases

- WHEN a user is updated to a new default output interface, THEN existing services SHALL NOT have their output interfaces automatically modified (they retain their original interface).
- WHEN a user with `user` role attempts to manually craft an HTTP POST/PUT request containing a different `output_interface` value, THEN the backend SHALL override it with their default interface (for creation) or retain the original interface (for update).

---

## Requirement Traceability

| Requirement ID | Story | Phase | Status |
| -------------- | ----- | ----- | ------ |
| USER-IFACE-01  | P1: Admin Assigns Default Output Interface | Design | Pending |
| USER-IFACE-02  | P1: Admin Assigns Default Output Interface | Design | Pending |
| USER-IFACE-03  | P1: Hide Output Interface from User Service UI | Design | Pending |
| USER-IFACE-04  | P1: Hide Output Interface from User Service UI | Design | Pending |
| USER-IFACE-05  | P1: Default Output Interface on Backend Service Creation | Design | Pending |
| USER-IFACE-06  | P1: Default Output Interface on Backend Service Creation | Design | Pending |

**Status values:** Pending → In Design → In Tasks → Implementing → Verified

**Coverage:** 6 total, 0 mapped to tasks, 6 unmapped ⚠️

---

## Success Criteria

How we know the feature is successful:
- [ ] Admin can assign `default_output_interface` to users via the user management page.
- [ ] Normal users do not see the "Output interface" dropdown in the Services tab when creating/editing services.
- [ ] Creating a service as a normal user automatically defaults the service's `output_interface` to their default output interface.
- [ ] Backend tests and frontend build pass successfully.

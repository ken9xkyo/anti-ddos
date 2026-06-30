# Allocated CIDR Management Specification

## Problem Statement

Currently, any user can configure a backend service with any arbitrary IPv4 CIDR, which poses a security and operational risk. We need a way for admins to allocate specific CIDRs to users, and restrict users (and admins configuring services on behalf of users) so they can only select or configure services within their allocated CIDRs.

## Goals

- [ ] Provide an interface/API for admins to allocate one or more CIDR blocks to specific users.
- [ ] Enforce that allocated CIDR blocks across different users are strictly disjoint (no overlaps).
- [ ] Enforce backend validation when creating or updating services, ensuring the service's `backend_cidr` is within the user's allocated CIDRs.
- [ ] Prevent deleting a CIDR allocation if there are active services configured within that block.
- [ ] Ensure existing services continue to work by migrating/auto-allocating their current CIDRs to their owners.

## Out of Scope

| Feature | Reason |
| --- | --- |
| Dynamic resizing of allocated blocks | Complex network slicing logic is not needed; admins can manually add/delete blocks. |
| Datapath/eBPF check of user allocation | Validating service configuration at the Control Plane API layer is sufficient. The XDP datapath will naturally enforce whitelisted/forwarded CIDRs configured at the API layer. |
| IPv6 CIDR allocations | The active policy snapshot and XDP C code currently support IPv4 destination hosts/ports only. |

---

## User Stories

### P1: Admin Allocation Management ⭐ MVP

**User Story**: As an Admin, I want to allocate and manage CIDRs for users so that I can control which IP blocks they are allowed to configure for services.

**Why P1**: This is the foundation of the feature. Without the ability to allocate CIDRs to users, we cannot enforce any restrictions.

**Acceptance Criteria**:
1. WHEN an admin views a user's details THEN the system SHALL list all CIDRs allocated to that user.
2. WHEN an admin allocates a CIDR (e.g., `192.168.1.0/24`) to a user THEN the system SHALL check if it overlaps with *any* CIDR allocated to *any* other user.
3. WHEN the new CIDR overlaps with another user's allocation THEN the system SHALL reject the request with a `400 Bad Request` validation error.
4. WHEN the new CIDR is disjoint THEN the system SHALL save the allocation with a unique ID, user ID, CIDR block, and timestamp.
5. WHEN a non-admin user attempts to allocate or delete a CIDR allocation THEN the system SHALL return a `403 Forbidden` error.

**Independent Test**: Verify via API that an admin token can GET/POST to `/v1/users/{userId}/allocated-cidrs`, while a user token receives `403 Forbidden` for POST/DELETE. Check that overlapping allocations are rejected.

---

### P1: Blocking Deletion of Active Allocations ⭐ MVP

**User Story**: As an Admin, I want the system to block deleting a CIDR allocation if it is currently in use so that I don't accidentally break active services.

**Why P1**: Ensures operational safety and consistency between allocations and services.

**Acceptance Criteria**:
1. WHEN an admin requests to delete an allocation THEN the system SHALL check if there are active services owned by the user whose `backend_cidr` falls within the allocation block.
2. WHEN active services exist within that allocation THEN the system SHALL reject the deletion with a `400 Bad Request` error listing the blocking services.
3. WHEN no active services exist within that allocation THEN the system SHALL delete the allocation.

**Independent Test**: Attempt to delete an allocation containing a service and verify it is blocked. Reconfigure the service, then verify deletion succeeds.

---

### P1: Service Configuration Restriction ⭐ MVP

**User Story**: As a User or an Admin configuring a service, I want to configure a backend service using a CIDR within the owner's allocated list so that my traffic routing is set up properly.

**Why P1**: This is the core restriction. Users and admins alike must not be allowed to configure services using arbitrary unallocated networks.

**Acceptance Criteria**:
1. WHEN a service is created or updated THEN the system SHALL check if the service's `backend_cidr` is contained within or equal to one of the service owner's allocated CIDRs.
2. WHEN the service's `backend_cidr` is valid (contained within an allocation) THEN the system SHALL allow the creation or update.
3. WHEN the service's `backend_cidr` is NOT contained within any allocated CIDR of the owner THEN the system SHALL reject the request with a `400 Bad Request` validation error.
4. This validation check SHALL apply equally to both standard Users and Admins.

**Independent Test**: Create a service with a CIDR inside and outside the user's allocated block via the API and verify the success/failure responses.

---

### P2: User Allocated CIDRs View

**User Story**: As a User, I want to see my allocated CIDRs in the dashboard so that I know which networks I am allowed to use for my services.

**Why P2**: Enhances the user experience and helps the user avoid validation errors by showing their boundaries beforehand.

**Acceptance Criteria**:
1. WHEN a user requests `/v1/me/allocated-cidrs` THEN the system SHALL return their list of allocated CIDR networks.
2. WHEN a user opens the Create/Edit Service dialog in the dashboard THEN the interface SHALL display the list of their allocated CIDRs as helper text or as a selection dropdown.

**Independent Test**: Log in as a normal user, fetch `/v1/me/allocated-cidrs`, and verify that the UI shows the matching list in the service creation form.

---

### P2: Safe Upgrade Migration

**User Story**: As a System Administrator, I want existing services to continue working when this feature is deployed so that there is no operational interruption.

**Why P2**: Prevents deployment-time failures of existing service configurations.

**Acceptance Criteria**:
1. WHEN the database migrations are run THEN the system SHALL automatically allocate the existing services' `backend_cidr` blocks to their respective owners in the new allocation table.

**Independent Test**: Verify that running the migration with pre-existing services inserts corresponding rows into the new table.

---

## Edge Cases

- WHEN a user has no CIDRs allocated THEN the system SHALL block them from creating any services.
- WHEN an invalid IP/CIDR string is submitted THEN the system SHALL return a validation error.
- WHEN multiple allocations exist for a user and one is deleted THEN the remaining allocations are still active and validation applies against them.

---

## Requirement Traceability

| Requirement ID | Story | Phase | Status |
| --- | --- | --- | --- |
| CIDR-ALLOC-01 | P1: Admin Allocation Management | Specify | Pending |
| CIDR-ALLOC-02 | P1: Blocking Deletion of Active Allocations | Specify | Pending |
| CIDR-ALLOC-03 | P1: Service Configuration Restriction | Specify | Pending |
| CIDR-ALLOC-04 | P2: User Allocated CIDRs View | Specify | Pending |
| CIDR-ALLOC-05 | P2: Safe Upgrade Migration | Specify | Pending |

**Coverage:** 5 total, 0 mapped to tasks, 5 unmapped ⚠️

---

## Success Criteria

- [ ] Admins can allocate CIDRs to users via API and Web UI.
- [ ] Overlapping CIDR allocations across different users are prevented.
- [ ] Users and admins cannot configure backend services outside their allocated CIDR blocks.
- [ ] Deletion of active CIDR allocations is blocked.
- [ ] Backwards-compatibility is maintained for all existing services.

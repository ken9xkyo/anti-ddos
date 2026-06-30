# Allocated CIDR Management Context

**Gathered:** 2026-06-30
**Spec:** `.specs/features/allocated-cidr-management/spec.md`
**Status:** Ready for design

---

## Feature Boundary

This feature implements admin management of CIDR blocks allocated to users. Users (and admins configuring services on behalf of users) are restricted to configuring services with backend CIDRs that are contained within their allocated CIDR blocks.

---

## Implementation Decisions

### CIDR Containment Check
- The system must use subnet containment validation. A service's `backend_cidr` is valid if it is equal to or a subnet of one of the user's allocated CIDRs (e.g. allocated `10.0.0.0/24` allows a service to be configured with `10.0.0.5/32`).
- Validation is implemented in Go at the Control API layer using SQL network operators (`<<=`).

### Strictly Disjoint Allocations
- CIDR allocations across different users must be strictly disjoint.
- The system must validate that a newly allocated CIDR does not overlap with any existing CIDR allocated to *any* other user.
- This overlap check can be executed using PostgreSQL network overlap operator (`&&`) in a transaction to prevent race conditions.

### Admin Validation and Rules
- Admins are not exempt from the validation checks when configuring services.
- If an admin creates or updates a service for a user (or for themselves), the service's `backend_cidr` must still be contained within the CIDRs allocated to that owner.

### Deletion and Active Services
- Deleting a CIDR allocation is blocked if there are active services currently configured within that CIDR block.
- The administrator must first delete or reconfigure the services to point to different CIDR blocks before the allocation can be removed.

---

## Specific References
- Overlap detection in SQL: `cidr && other_cidr` returns true if they overlap.
- Containment detection in SQL: `backend_cidr <<= allocated_cidr` returns true if `backend_cidr` is a subnet of or equal to `allocated_cidr`.

---

## Deferred Ideas
- None — discussion stayed within feature scope.

# Optimize Add Service Specification

## Problem Statement

Currently, the "Add Service" form on the dashboard is cluttered and requires operators to navigate 16+ input fields. Many of these are technical metadata (such as resolved MAC addresses and interface indexes) or fields with sensible defaults (like criticality and protection mode). This makes service registration tedious and prone to configuration fatigue. We need to optimize this form to minimize required inputs by default, keeping non-essential settings in an expandable "Advanced Settings" section.

## Goals

- [ ] Simplify the "Add Service" interface to display only 5 basic fields by default: Name, Backend CIDR, Protocol, Allowed Ports, Output Interface, plus the audit Reason field.
- [ ] Pre-select the first available agent-reported interface in the Output Interface dropdown.
- [ ] Hide the "Advanced Settings" section completely during service creation (Add Service mode).
- [ ] Render the "Advanced Settings" section as a collapsed drawer/toggle only during service edit mode.
- [ ] Remove the frontend requirement to input `resolved_ifindex` and `resolved_src_mac` before enabling a service; services will default to Enabled (`true`) upon creation and resolve network metadata automatically in the background.
- [ ] Maintain full compatibility with the existing backend database schema, validation rules, and automated E2E tests.

## Out of Scope

| Feature | Reason |
| --- | --- |
| Schema modifications to `backend_services` | Database schema changes are unnecessary as we can supply standard default values from the frontend form state. |
| Removing fields from the edit mode | All fields must remain editable, either directly in the basic form or via the advanced toggle. |

---

## User Stories

### P1: Simplified Add Service Form ⭐ MVP

**User Story**: As an Operator, I want to see only the essential fields when adding a service so that I can register a new service quickly and with minimal effort.

**Why P1**: This is the core requirement to reduce configuration complexity and user friction during initial setup.

**Acceptance Criteria**:
1. WHEN the "Add Service" form is opened THEN only the following fields SHALL be visible:
   - **Name** (Text input)
   - **Backend CIDR** (Text input, with allocated CIDR helper text)
   - **Protocol** (Select dropdown: TCP, UDP, ICMP)
   - **Allowed ports** (Text input, disabled if Protocol is ICMP)
   - **Output interface** (Select dropdown or text input)
   - **Reason** (Text input)
2. WHEN the form is initialized THEN the Output Interface field SHALL default to the first available agent-reported interface (if any are present).
3. The submit button ("Save service") and "Cancel" button SHALL be clearly visible below the basic fields.
4. The "Advanced Settings" section SHALL NOT be rendered or visible in any form in "Add Service" mode.

**Independent Test**: Open the "Add Service" dialog and verify that only Name, Backend CIDR, Protocol, Allowed Ports, Output Interface, and Reason are visible, while "Advanced Settings" toggle is completely absent.

---

### P1: Collapsible Advanced Settings in Edit Mode ⭐ MVP

**User Story**: As an Operator, I want to toggle an "Advanced Settings" section in Edit mode so that I can access and customize advanced options (such as enabling/disabling the service, changing protection mode, adding description/tags, or overriding resolved network metadata) when editing an existing service.

**Why P1**: Ensures all advanced configuration options remain fully functional and accessible without cluttering the primary user experience.

**Acceptance Criteria**:
1. The form SHALL include an expandable/collapsible section titled "Advanced Settings" located above the action buttons ONLY when editing an existing service.
2. The section SHALL be collapsed by default.
3. Clicking on the "Advanced Settings" header/toggle SHALL expand or collapse the section.
4. WHEN expanded, the section SHALL display the following fields:
   - **Enabled** (Checkbox)
   - **Description** (Text input)
   - **Tags** (Text input)
   - **Criticality** (Text input, defaulting to "high")
   - **Protection mode** (Select dropdown: Observe, Enforce, defaulting to "enforce")
   - **Priority** (Number input)
   - **Neighbor status** (Select dropdown: Unresolved, Resolved, defaulting to "unresolved")
   - **Resolved ifindex** (Number input)
   - **Source MAC** (Text input)

**Independent Test**: Open "Edit Service" dialog, click the "Advanced Settings" toggle to verify that it reveals all advanced fields and that toggling it again hides them without affecting their values.

---

### P2: Seamless Service Enablement

**User Story**: As an Operator, I want newly created services to be enabled by default and automatically resolve metadata, without requiring manual inputs for resolved network settings.

**Why P2**: Simplifies workflow and relies on the agent backend to resolve neighbor IP/MAC information autonomously.

**Acceptance Criteria**:
1. WHEN a service is created THEN it SHALL default to `Enabled` status (`true`).
2. There SHALL NOT be any validation blocking submission of an enabled service with empty `resolved_ifindex` or `resolved_src_mac` fields.

**Independent Test**: Add a service without expanding or modifying any metadata. Save it, and verify in the services list that its state is "enabled" and neighbor resolution automatically kicks off.

---

## Edge Cases

- **Output Interface Defaults**: If no agents are connected or no interfaces are reported, the Output Interface dropdown should revert to a manual text input (as it currently does) or show a blank default.
- **Reason Default**: The audit reason is required by the backend. It should be pre-filled with a generic placeholder like `"create protected service"` or `"update service"` depending on the form mode.

---

## Requirement Traceability

| Requirement ID | Story | Phase | Status |
| --- | --- | --- | --- |
| OPT-SVC-01 | P1: Simplified Add Service Form | Specify | Pending |
| OPT-SVC-02 | P1: Collapsible Advanced Settings in Edit Mode | Specify | Pending |
| OPT-SVC-03 | P2: Seamless Service Enablement | Specify | Pending |

**Coverage:** 3 total, 0 mapped to tasks, 3 unmapped ⚠️

---

## Success Criteria

- [ ] "Add Service" form displays only 5 basic fields + Audit Reason, hiding "Advanced Settings" entirely.
- [ ] Expandable "Advanced Settings" contains all other fields in "Edit Service" mode, collapsed by default.
- [ ] Form defaults all non-entered advanced fields to correct values, with `enabled: true`.
- [ ] No validation blocking enablement on empty resolved metadata on the frontend.
- [ ] Existing Playwright E2E tests and Vite frontend tests continue to pass.

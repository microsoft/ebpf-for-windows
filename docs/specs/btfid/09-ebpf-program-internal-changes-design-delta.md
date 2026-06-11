<!-- Delta artifact: Internal Changes to ebpf_program_t alignment set -->

# Internal Changes to ebpf_program_t — Design Delta

## 1. Change Context

- **Area**: Internal Changes to `ebpf_program_t`
- **Requirements source**: `docs\specs\btfid\09-ebpf-program-internal-changes.md`
- **Existing design doc**: N/A — no existing design document was provided for this run
- **Code scope**: `libs\execution_context`
- **Test scope**: `libs\execution_context\unit`; selected tests under `tests\`
- **Goal**: identify the minimal design deltas needed to align the internal-state requirements with the current execution-context implementation and test baseline

[KNOWN] The current execution-context implementation already uses `ebpf_program_t` as the owner of comparable provider/helper state: it stores the two existing program-information NMR client handles, one `program_information_rundown_reference`, provider data pointers, helper-function ID storage, and a helper-address callback/context pair. The current lifecycle registers those clients during creation, populates provider data in attach callbacks, waits for rundown and clears extension program data on detach, and deregisters/freezes current state during final teardown. [KNOWN] No in-scope code currently adds any BTF-resolved binding record, BTF-resolved address array, BTF-resolved count, or BTF-resolved callback/context to `ebpf_program_t`. (Evidence: CE-001, CE-002, CE-003, CE-004, CE-005)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-PROG-001 | Add | Required | Add a BTF-resolved binding record model on `ebpf_program_t` rather than relying only on current single-provider program-data pointers. | CE-001, CE-005 |
| DD-002 | REQ-PROG-002 | Add | Required | Add BTF-resolved binding-array storage plus count on `ebpf_program_t`. | CE-001, CE-005 |
| DD-003 | REQ-PROG-003 | Add | Required | Add BTF-resolved address-array storage plus count on `ebpf_program_t`. | CE-001, CE-004, CE-005 |
| DD-004 | REQ-PROG-004 | Modify | Required | Extend current helper-address callback/context storage with a BTF-resolved callback/context path. | CE-001, CE-004, CE-005 |
| DD-005 | REQ-PROG-005 | Add | Required | Add creation-time allocation of BTF-resolved arrays based on import-table size. | CE-002, CE-003, CE-005 |
| DD-006 | REQ-PROG-006 | Modify | Required | Extend current create/free NMR client lifecycle with registration/deregistration for the BTF-resolved-function NPI. | CE-002, CE-004, CE-005 |
| DD-007 | REQ-PROG-007 | Modify | Required | Extend provider attach handling to populate BTF-resolved bindings and address state. | CE-003, CE-005 |
| DD-008 | REQ-PROG-008 | Modify | Required | Extend load/readiness validation from current generic program-information readiness to BTF provider completeness. | CE-002, CE-003, CE-005 |
| DD-009 | REQ-PROG-009 | Modify | Required | Extend provider detach handling to clear BTF addresses, invoke a BTF callback, and wait for rundown. | CE-003, CE-004, CE-005 |
| DD-010 | REQ-PROG-010 | Modify | Required | Extend final teardown to deregister any BTF client and free all BTF arrays. | CE-004, CE-005 |
| DD-011 | REQ-PROG-011 | Add/Constrain | Required | Apply existing lock-guarded update patterns to the new BTF-resolved fields. | CE-001, CE-003, CE-004 |
| DD-012 | REQ-PROG-012 | No-Impact/Constrain | Required | Extend the existing `ebpf_program_t` lifecycle rather than creating a separate state owner. | CE-001, CE-002, CE-003, CE-004 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-PROG-001
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`; `[UNKNOWN: any header or shared declaration site for a new binding struct]`
- **Before**: Current `ebpf_program_t` stores generic provider-related pointers and handles, but there is no per-BTF binding record that tracks module GUID, binding handle, provider data, and attached state. (Evidence: CE-001, CE-005)
- **After**: Add an internal BTF binding record type and store one record per tracked BTF-resolved provider binding.
- **Rationale**: The source requires per-binding identity and attachment state, not just generic provider data pointers.

### DD-002

- **Upstream REQ-ID**: REQ-PROG-002
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current `ebpf_program_t` has no BTF-resolved binding-array pointer or binding-count field. (Evidence: CE-001, CE-005)
- **After**: Add binding-array storage and binding-count state to the program object.
- **Rationale**: The source requires lifetime-persistent binding-set storage.

### DD-003

- **Upstream REQ-ID**: REQ-PROG-003
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-004, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`; `[ASSUMPTION] include\bpf2c.h` only if the internal array must also feed native runtime context
- **Before**: Current dynamic program-owned array state is helper-centric (`helper_function_ids`), and no BTF-resolved address array exists on `ebpf_program_t`. (Evidence: CE-001, CE-004, CE-005)
- **After**: Add program-owned BTF-resolved address storage and count.
- **Rationale**: The source requires address state to remain distinct from binding metadata.

### DD-004

- **Upstream REQ-ID**: REQ-PROG-004
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-004, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`; `[ASSUMPTION] libs\execution_context\ebpf_program.h` if a registration helper analogous to `ebpf_program_register_for_helper_changes(...)` is added
- **Before**: Current callback/context storage is helper-specific only. (Evidence: CE-001, CE-004)
- **After**: Add BTF-resolved callback/context storage, either parallel to or generalized from the current helper callback/context pair.
- **Rationale**: The source requires a distinct BTF address-change notification surface.

### DD-005

- **Upstream REQ-ID**: REQ-PROG-005
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-003, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current creation initializes provider/client state and registers existing program-information clients, but does not allocate BTF-resolved arrays. Comparable dynamic helper storage is allocated later by `ebpf_program_set_helper_function_ids(...)`. (Evidence: CE-002, CE-003)
- **After**: Allocate the BTF-resolved arrays during creation based on import-table size.
- **Rationale**: The source requires creation-time sizing and storage.

### DD-006

- **Upstream REQ-ID**: REQ-PROG-006
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-004, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current program creation/free already manages two NMR client registrations for program-information providers only. (Evidence: CE-002, CE-004)
- **After**: Add a BTF-resolved-function client registration/deregistration path alongside the existing clients.
- **Rationale**: The source requires a distinct NPI subscription for BTF-resolved callbacks.

### DD-007

- **Upstream REQ-ID**: REQ-PROG-007
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current attach callbacks populate general/type-specific program data and helper counts, but do not populate any BTF binding or address arrays. (Evidence: CE-003)
- **After**: Extend attach handling to populate both BTF binding metadata and BTF-resolved addresses.
- **Rationale**: The source requires attach-time population of both categories of state.

### DD-008

- **Upstream REQ-ID**: REQ-PROG-008
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-003, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current creation succeeds only when the current program-information providers load; later runtime checks use the generic extension/provider baseline. No BTF provider-completeness state exists. (Evidence: CE-002, CE-003)
- **After**: Add BTF provider-completeness validation as part of load/readiness state.
- **Rationale**: The source requires provider-complete readiness for the BTF-resolved feature.

### DD-009

- **Upstream REQ-ID**: REQ-PROG-009
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-004, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current detach waits for rundown and clears `extension_program_data`, but it does not clear BTF address state or invoke a BTF-specific callback. (Evidence: CE-003, CE-005)
- **After**: Extend detach handling to clear BTF-resolved addresses, invoke the BTF callback, and wait for the appropriate rundown protection.
- **Rationale**: The source requires all three detach-time actions.

### DD-010

- **Upstream REQ-ID**: REQ-PROG-010
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-004, CE-005
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current final teardown deregisters current program-information clients and frees helper IDs, but there is no BTF-resolved client or BTF array cleanup path. (Evidence: CE-004, CE-005)
- **After**: Extend teardown to release all BTF-resolved registrations and arrays.
- **Rationale**: The source requires BTF-resolved state not to outlive the program.

### DD-011

- **Upstream REQ-ID**: REQ-PROG-011
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-003, CE-004
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: Current attach/detach and callback-context updates already use `program->lock` for some mutable internal state, especially provider data and callback/context storage. (Evidence: CE-001, CE-003, CE-004)
- **After**: Apply equivalent lock-guarded update rules to all new BTF-resolved fields.
- **Rationale**: The source carries `_Guarded_by_(lock)` annotations for the new fields.

### DD-012

- **Upstream REQ-ID**: REQ-PROG-012
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-002, CE-003, CE-004
- **Expected code change locations**: Existing `ebpf_program_t` lifecycle code only
- **Before**: `ebpf_program_t` already owns provider/helper state and its lifecycle. (Evidence: CE-001, CE-002, CE-003, CE-004)
- **After**: Keep BTF-resolved state inside that existing object and lifecycle.
- **Rationale**: This preserves the current execution-context object model and minimizes lifecycle duplication.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-PROG-001 | MISSING | DD-001 | `libs\execution_context\ebpf_program.c`; `[UNKNOWN: new binding struct declaration site]` | No BTF binding record exists today. |
| REQ-PROG-002 | MISSING | DD-002 | `libs\execution_context\ebpf_program.c` | No BTF binding-array storage exists today. |
| REQ-PROG-003 | MISSING | DD-003 | `libs\execution_context\ebpf_program.c`; `[ASSUMPTION] include\bpf2c.h` | No BTF address-array storage exists today. |
| REQ-PROG-004 | PARTIAL | DD-004 | `libs\execution_context\ebpf_program.c`; `[ASSUMPTION] libs\execution_context\ebpf_program.h` | Callback/context infrastructure exists, but only for helpers. |
| REQ-PROG-005 | MISSING | DD-005 | `libs\execution_context\ebpf_program.c` | No creation-time BTF array allocation exists. |
| REQ-PROG-006 | PARTIAL | DD-006 | `libs\execution_context\ebpf_program.c` | NMR registration machinery exists, but not for a BTF NPI. |
| REQ-PROG-007 | PARTIAL | DD-007 | `libs\execution_context\ebpf_program.c` | Attach callbacks exist, but do not populate BTF state. |
| REQ-PROG-008 | PARTIAL | DD-008 | `libs\execution_context\ebpf_program.c` | Generic provider readiness exists, but not BTF provider completeness. |
| REQ-PROG-009 | PARTIAL | DD-009 | `libs\execution_context\ebpf_program.c` | Detach/rundown exists, but no BTF clear+notify path exists. |
| REQ-PROG-010 | PARTIAL | DD-010 | `libs\execution_context\ebpf_program.c` | Current cleanup exists, but not for BTF state. |
| REQ-PROG-011 | PARTIAL | DD-011 | `libs\execution_context\ebpf_program.c` | Lock-guarded update patterns exist, but not for BTF fields. |
| REQ-PROG-012 | SATISFIED | No-Impact/Constrain | None | Existing `ebpf_program_t` lifecycle is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] The current design already centralizes comparable mutable provider/helper state on `ebpf_program_t`; the deltas preserve that centralization. (Evidence: CE-001, CE-002, CE-003, CE-004)
- [KNOWN] The current design already uses NMR registration in create/free and provider callbacks in attach/detach; the deltas preserve that lifecycle shape while extending it. (Evidence: CE-002, CE-003, CE-004)
- [KNOWN] The current design already treats helper IDs and callback/context storage as program-owned mutable state; the deltas extend that ownership model to BTF-resolved state. (Evidence: CE-001, CE-004)

## 6. Application Notes

1. [KNOWN] No existing design document was provided, so these deltas are synthesized additions rather than edits against a prior design artifact.
2. [KNOWN] The key gap is not absence of an internal lifecycle owner; it is absence of any BTF-specific state within the existing owner.
3. [KNOWN] Some exact declaration sites remain `[UNKNOWN]` because the examined code contains no BTF-resolved implementation to anchor them.

## Coverage
- **Examined**: `docs\specs\btfid\09-ebpf-program-internal-changes.md`; `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_program.h`
- **Method**: targeted `view` on the current `ebpf_program_t` structure, create/attach/detach/free paths, helper-state setter/clear logic, and helper callback registration; targeted `rg` for BTF-resolved symbols
- **Excluded**: detailed BTF provider registration payload design and native runtime execution details
- **Limitations**: no BTF-resolved internal-state implementation exists in the examined scope, so several future touch points remain `[UNKNOWN]`

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\execution_context\ebpf_program.c:38-101` | Current `ebpf_program_t` stores program-information NMR handles, one rundown reference, helper-function ID state, and a helper-address callback/context pair. | Establishes the current internal-state baseline. |
| CE-002 | `libs\execution_context\ebpf_program.c:738-895` | `ebpf_program_create(...)` initializes current client-registration state, registers two program-information clients, and fails if those providers do not load. | Establishes the current creation/registration baseline. |
| CE-003 | `libs\execution_context\ebpf_program.c:314-619` | Current attach/detach callbacks populate or clear program-information state, update helper counts, and wait for rundown on detach. | Establishes the current attach/detach lifecycle baseline. |
| CE-004 | `libs\execution_context\ebpf_program.c:667-733`, `libs\execution_context\ebpf_program.c:1813-1873`, `libs\execution_context\ebpf_program.c:2690-2701` | Final teardown deregisters current clients and frees helper IDs; helper IDs and helper callback/context are managed explicitly on the program object. | Establishes the current teardown and mutable helper-state baseline. |
| CE-005 | Exact searches over `libs\execution_context`, `include`, and `tests` for `btf_resolved_function` returned no matches. | No BTF-resolved internal-state implementation exists in the examined scope. | Establishes the BTF internal-state gap. |

<!-- Delta artifact: Internal Changes to ebpf_program_t alignment set -->

# Internal Changes to ebpf_program_t — Requirements / Code / Test Traceability

## Coverage

- **Target**: internal `ebpf_program_t` requirements for BTF-resolved functions, joined against `libs\execution_context` code and related tests
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\09-ebpf-program-internal-changes.md`
  - `view` on `libs\execution_context\ebpf_program.c` and `libs\execution_context\ebpf_program.h`
  - `view` on `libs\execution_context\unit\execution_context_unit_test.cpp` and `libs\execution_context\unit\execution_context_unit_test_jit.cpp`
  - `rg "btf_resolved_function|helper_function_addresses_changed_callback|ebpf_program_set_helper_function_ids|NmrRegisterClient|EBPF_EXTENSION_FAILED_TO_LOAD"` over `libs\execution_context`, `include`, and relevant `tests`
- **Excluded**: detailed BTF provider-registration payload design and runtime execution mechanics outside the internal-state focus of this area
- **Limitations**: no BTF-resolved internal-state implementation exists in the examined scope, so several future code/test change locations remain `[UNKNOWN]`

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\09-ebpf-program-internal-changes.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-PROG-001 through REQ-PROG-012 |
| `libs\execution_context\ebpf_program.c` | Code | Implementation baseline | Current `ebpf_program_t` structure and lifecycle |
| `libs\execution_context\ebpf_program.h` | Code | API/supporting baseline | Current helper callback registration surface |
| `libs\execution_context\unit\execution_context_unit_test.cpp` | Test code | Validation baseline | Current provider-registration/create-failure tests |
| `libs\execution_context\unit\execution_context_unit_test_jit.cpp` | Test code | Validation baseline | Current helper-ID/address tests |
| Existing design document | Design doc | None provided | Recorded as absent for this run |
| Existing validation document | Validation doc | None provided | Recorded as absent for this run |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-PROG-001 | Represent each tracked BTF binding with module GUID, binding handle, provider data, and attached state. | MISSING | MISSING | No BTF binding record exists today. |
| REQ-PROG-002 | Store BTF binding-array pointer and count on `ebpf_program_t`. | MISSING | MISSING | No BTF binding-array state exists today. |
| REQ-PROG-003 | Store BTF address array and count on `ebpf_program_t`. | MISSING | MISSING | Current comparable array state is helper IDs only. |
| REQ-PROG-004 | Store a BTF address-change callback and context on `ebpf_program_t`. | PARTIAL | MISSING | Callback/context infrastructure exists, but only for helpers. |
| REQ-PROG-005 | Allocate BTF arrays during creation from import-table size. | MISSING | MISSING | No creation-time BTF allocation exists. |
| REQ-PROG-006 | Register an NMR client for the BTF-resolved-function NPI during initialization. | PARTIAL | MISSING | NMR registration machinery exists, but not for a BTF NPI. |
| REQ-PROG-007 | Populate BTF bindings and addresses on provider attach. | PARTIAL | MISSING | Attach callbacks exist, but do not populate BTF state. |
| REQ-PROG-008 | Verify all required providers are attached during program load. | PARTIAL | MISSING | Current readiness is generic program-information readiness only. |
| REQ-PROG-009 | On detach, clear addresses, invoke callback, and wait for rundown. | PARTIAL | MISSING | Rundown/clear provider state exists, but no BTF clear+notify path exists. |
| REQ-PROG-010 | On free, deregister the NMR client and free BTF arrays. | PARTIAL | MISSING | Current cleanup exists, but not for BTF state. |
| REQ-PROG-011 | Honor lock-guarding annotations for BTF state access. | PARTIAL | MISSING | Current lock-guarded patterns exist, but not for BTF fields. |
| REQ-PROG-012 | Extend the existing `ebpf_program_t` lifecycle instead of introducing a second state owner. | SATISFIED | SATISFIED | Existing object lifecycle is already the right extension point. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-PROG-001 | Represent each tracked BTF binding with module GUID, binding handle, provider data, and attached state. | CE-001, CE-005 | MISSING | DD-001 | `libs\execution_context\ebpf_program.c`; `[UNKNOWN: new binding struct declaration site]` | TE-001, TE-004 | MISSING | VD-001 | `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]` | No BTF binding record exists today. |
| REQ-PROG-002 | Store BTF binding-array pointer and count on `ebpf_program_t`. | CE-001, CE-005 | MISSING | DD-002 | `libs\execution_context\ebpf_program.c` | TE-001, TE-004 | MISSING | VD-002 | `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]` | No BTF binding-array state exists today. |
| REQ-PROG-003 | Store BTF address array and count on `ebpf_program_t`. | CE-001, CE-004, CE-005 | MISSING | DD-003 | `libs\execution_context\ebpf_program.c`; `[ASSUMPTION] include\bpf2c.h` | TE-003, TE-004 | MISSING | VD-003 | `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]` | Current comparable array state is helper IDs only. |
| REQ-PROG-004 | Store a BTF address-change callback and context on `ebpf_program_t`. | CE-001, CE-004, CE-005 | PARTIAL | DD-004 | `libs\execution_context\ebpf_program.c`; `[ASSUMPTION] libs\execution_context\ebpf_program.h` | TE-003, TE-004 | MISSING | VD-004 | `[UNKNOWN: BTF callback unit tests]` | Callback/context infrastructure exists, but only for helpers. |
| REQ-PROG-005 | Allocate BTF arrays during creation from import-table size. | CE-002, CE-003, CE-005 | MISSING | DD-005 | `libs\execution_context\ebpf_program.c` | TE-001, TE-004 | MISSING | VD-005 | `[UNKNOWN: BTF creation-path unit tests]` | No creation-time BTF allocation exists. |
| REQ-PROG-006 | Register an NMR client for the BTF-resolved-function NPI during initialization. | CE-002, CE-004, CE-005 | PARTIAL | DD-006 | `libs\execution_context\ebpf_program.c` | TE-001, TE-002, TE-004 | MISSING | VD-006 | `[UNKNOWN: BTF client-registration tests]` | NMR registration machinery exists, but not for a BTF NPI. |
| REQ-PROG-007 | Populate BTF bindings and addresses on provider attach. | CE-003, CE-005 | PARTIAL | DD-007 | `libs\execution_context\ebpf_program.c` | TE-002, TE-004 | MISSING | VD-007 | `[UNKNOWN: BTF provider-attach tests]` | Attach callbacks exist, but do not populate BTF state. |
| REQ-PROG-008 | Verify all required providers are attached during program load. | CE-002, CE-003, CE-005 | PARTIAL | DD-008 | `libs\execution_context\ebpf_program.c` | TE-001, TE-004 | MISSING | VD-008 | `[UNKNOWN: BTF readiness tests]` | Current readiness is generic program-information readiness only. |
| REQ-PROG-009 | On detach, clear addresses, invoke callback, and wait for rundown. | CE-003, CE-004, CE-005 | PARTIAL | DD-009 | `libs\execution_context\ebpf_program.c` | TE-002, TE-004 | MISSING | VD-009 | `[UNKNOWN: BTF detach cleanup tests]` | Rundown/clear provider state exists, but no BTF clear+notify path exists. |
| REQ-PROG-010 | On free, deregister the NMR client and free BTF arrays. | CE-004, CE-005 | PARTIAL | DD-010 | `libs\execution_context\ebpf_program.c` | TE-001, TE-004 | MISSING | VD-010 | `[UNKNOWN: BTF teardown tests]` | Current cleanup exists, but not for BTF state. |
| REQ-PROG-011 | Honor lock-guarding annotations for BTF state access. | CE-001, CE-003, CE-004 | PARTIAL | DD-011 | `libs\execution_context\ebpf_program.c` | TE-002, TE-004 | MISSING | VD-011 | `[UNKNOWN: BTF concurrency/state-transition tests]` | Current lock-guarded patterns exist, but not for BTF fields. |
| REQ-PROG-012 | Extend the existing `ebpf_program_t` lifecycle instead of introducing a second state owner. | CE-001, CE-002, CE-003, CE-004 | SATISFIED | No-Impact | None | TE-001, TE-002, TE-003 | SATISFIED | No-Impact | None | Existing object lifecycle is already the right extension point. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The source requires BTF binding and address state on `ebpf_program_t`, but current internal state is still limited to generic provider data, helper IDs, and helper callback/context. | CE-001, CE-005 | Apply DD-001 through DD-004. |
| CR-002 | Upstream-downstream | The source requires a BTF-specific create/attach/detach/free lifecycle, but current lifecycle manages only program-information providers and helper state. | CE-002, CE-003, CE-004, CE-005 | Apply DD-005 through DD-011. |
| CR-003 | Coverage gap | The current tests exercise provider validation and helper-state behavior but contain no BTF-resolved internal-state coverage. | TE-001, TE-002, TE-003, TE-004 | Apply VD-001 through VD-011. |

## Open Questions

1. [UNKNOWN: the exact declaration site for `ebpf_btf_resolved_function_binding_t` in the implementation once the feature is added.]
2. [UNKNOWN: whether any BTF callback registration helper will be exposed through `ebpf_program.h` or kept internal to `ebpf_program.c`.]
3. [KNOWN] No existing design or validation document was provided, so these delta artifacts are synthesized from requirements plus code/test evidence only.

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\execution_context\ebpf_program.c:38-101` | Current `ebpf_program_t` stores program-information NMR handles, one rundown reference, helper-function ID state, and a helper-address callback/context pair. | Establishes the current internal-state baseline. |
| CE-002 | `libs\execution_context\ebpf_program.c:738-895` | `ebpf_program_create(...)` initializes current client-registration state, registers two program-information clients, and fails if those providers do not load. | Establishes the current creation/registration baseline. |
| CE-003 | `libs\execution_context\ebpf_program.c:314-619` | Current attach/detach callbacks populate or clear program-information state, update helper counts, and wait for rundown on detach. | Establishes the current attach/detach lifecycle baseline. |
| CE-004 | `libs\execution_context\ebpf_program.c:667-733`, `libs\execution_context\ebpf_program.c:1813-1873`, `libs\execution_context\ebpf_program.c:2690-2701` | Final teardown deregisters current clients and frees helper IDs; helper IDs and helper callback/context are managed explicitly on the program object. | Establishes the current teardown and mutable helper-state baseline. |
| CE-005 | Exact searches over `libs\execution_context`, `include`, and `tests` for `btf_resolved_function` returned no matches. | No BTF-resolved internal-state implementation exists in the examined scope. | Establishes the BTF internal-state gap. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test.cpp:2540-2559` | Unit tests validate `ebpf_program_create(...)` success/failure based on current provider availability and verify helper-function ID/address lookup after success. | Establishes the current create/provider/helper-state baseline. |
| TE-002 | `libs\execution_context\unit\execution_context_unit_test.cpp:2563-2694` | Unit tests validate rejection of invalid current program-data/provider payloads. | Establishes the current provider-validation baseline. |
| TE-003 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp:379-389` | Unit tests validate current helper-function ID storage and helper-address lookup. | Establishes the current helper-state baseline. |
| TE-004 | Exact searches over `libs\execution_context`, `include`, and `tests` for `btf_resolved_function` returned no matches. | No BTF-resolved internal-state validation exists in the examined tree. | Establishes the feature-specific validation gap. |

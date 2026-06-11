<!-- Delta artifact: Internal Changes to ebpf_program_t alignment set -->

# Internal Changes to ebpf_program_t — Validation Delta

## 1. Change Context

- **Area**: Internal Changes to `ebpf_program_t`
- **Requirements source**: `docs\specs\btfid\09-ebpf-program-internal-changes.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this run
- **Code scope**: `libs\execution_context`
- **Test scope**: `libs\execution_context\unit`; selected tests under `tests\`
- **Goal**: identify the minimal validation-spec deltas needed to align test coverage with the internal-state requirements

[KNOWN] Current tests already exercise the existing internal-state baseline: unit tests verify `ebpf_program_create(...)` success/failure based on current program-information providers, validate provider-data rejection paths, and verify helper-function ID storage plus helper-address lookup. [KNOWN] No current test covers BTF-resolved binding records, BTF-resolved binding/address arrays on `ebpf_program_t`, BTF-resolved client registration, or BTF-resolved detach cleanup. (Evidence: TE-001, TE-002, TE-003, TE-004)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-PROG-001 | Add | Required | Add tests for the shape and lifecycle of the BTF binding record. | TE-001, TE-004 |
| VD-002 | REQ-PROG-002 | Add | Required | Add tests for BTF binding-array storage and count on `ebpf_program_t`. | TE-001, TE-004 |
| VD-003 | REQ-PROG-003 | Add | Required | Add tests for BTF-resolved address-array storage and count. | TE-003, TE-004 |
| VD-004 | REQ-PROG-004 | Add | Required | Add tests for BTF callback/context registration and update behavior. | TE-003, TE-004 |
| VD-005 | REQ-PROG-005 | Add | Required | Add tests that creation allocates BTF state from the import-table size. | TE-001, TE-004 |
| VD-006 | REQ-PROG-006 | Add | Required | Add tests that program initialization registers and free deregisters the BTF-resolved-function client. | TE-001, TE-002, TE-004 |
| VD-007 | REQ-PROG-007 | Add | Required | Add tests that provider attach populates BTF bindings and addresses. | TE-002, TE-004 |
| VD-008 | REQ-PROG-008 | Add | Required | Add tests that load/readiness fails when required BTF providers are not attached. | TE-001, TE-004 |
| VD-009 | REQ-PROG-009 | Add | Required | Add tests that detach clears BTF addresses, invokes the callback, and waits for rundown. | TE-002, TE-004 |
| VD-010 | REQ-PROG-010 | Add | Required | Add tests that free releases all BTF registrations and arrays. | TE-001, TE-004 |
| VD-011 | REQ-PROG-011 | Add | Required | Add concurrency or state-transition tests for lock-guarded BTF field updates. | TE-002, TE-004 |
| VD-012 | REQ-PROG-012 | No-Impact | Not required | Extend the current unit-test model for program creation/provider attach/helper-state validation instead of creating a separate validation architecture. | TE-001, TE-002, TE-003 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-PROG-001
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]`
- **Before**: Current tests validate current provider/helper state, but no test inspects or exercises a BTF binding record. (Evidence: TE-001, TE-004)
- **After**: Add tests that validate per-binding storage of module GUID, binding handle, provider data, and attached state.
- **Rationale**: The source requires an explicit binding record.

### VD-002

- **Upstream REQ-ID**: REQ-PROG-002
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]`
- **Before**: No test validates a BTF binding-array pointer/count on the program object. (Evidence: TE-004)
- **After**: Add tests for allocation, population, count tracking, and teardown of the BTF binding array.
- **Rationale**: The current create/provider tests do not imply BTF binding-array behavior.

### VD-003

- **Upstream REQ-ID**: REQ-PROG-003
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-003, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]`
- **Before**: Current tests validate helper-address lookup only. No test validates BTF address-array storage or count. (Evidence: TE-003, TE-004)
- **After**: Add tests for BTF-resolved address-array allocation, population, clearing, and count tracking.
- **Rationale**: The helper-address tests are not sufficient proxies for BTF address storage.

### VD-004

- **Upstream REQ-ID**: REQ-PROG-004
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-003, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF callback unit tests]`
- **Before**: Current tests do not cover any BTF-specific callback/context registration or callback invocation. (Evidence: TE-004)
- **After**: Add tests for BTF callback/context storage and notification behavior.
- **Rationale**: Current helper-state tests do not cover the BTF callback contract.

### VD-005

- **Upstream REQ-ID**: REQ-PROG-005
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF creation-path unit tests]`
- **Before**: Current creation tests validate provider-driven success/failure only; they do not validate BTF-array allocation from import-table size. (Evidence: TE-001)
- **After**: Add tests that verify creation allocates the BTF arrays with import-table-sized capacity.
- **Rationale**: The source requires creation-time allocation semantics.

### VD-006

- **Upstream REQ-ID**: REQ-PROG-006
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF client-registration tests]`
- **Before**: Current tests cover only the current program-information provider registration/validation flow. (Evidence: TE-001, TE-002)
- **After**: Add tests that verify BTF client registration on initialization and deregistration on free.
- **Rationale**: The BTF NPI subscription is a new lifecycle responsibility.

### VD-007

- **Upstream REQ-ID**: REQ-PROG-007
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF provider-attach tests]`
- **Before**: Current provider tests validate the current program-info payload only; they do not validate BTF binding/address population. (Evidence: TE-002)
- **After**: Add tests that provider attach populates BTF binding metadata and BTF address state.
- **Rationale**: This is feature-specific behavior absent from the current tests.

### VD-008

- **Upstream REQ-ID**: REQ-PROG-008
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF readiness tests]`
- **Before**: Current creation/invoke failure tests validate current provider readiness only. (Evidence: TE-001)
- **After**: Add tests that BTF-specific readiness fails when required BTF providers are unavailable.
- **Rationale**: Current readiness tests do not imply BTF completeness.

### VD-009

- **Upstream REQ-ID**: REQ-PROG-009
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF detach cleanup tests]`
- **Before**: Current tests do not validate BTF-specific detach cleanup or notification behavior. (Evidence: TE-004)
- **After**: Add tests that detach clears BTF addresses, invokes the callback, and observes rundown sequencing.
- **Rationale**: The current provider-data tests do not cover the required BTF detach semantics.

### VD-010

- **Upstream REQ-ID**: REQ-PROG-010
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF teardown tests]`
- **Before**: Current tests do not validate release of BTF arrays or BTF NMR client cleanup. (Evidence: TE-004)
- **After**: Add tests that program free releases all BTF state.
- **Rationale**: Final cleanup is a new feature-specific obligation.

### VD-011

- **Upstream REQ-ID**: REQ-PROG-011
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-004
- **Expected test change locations**: `[UNKNOWN: BTF concurrency/state-transition tests]`
- **Before**: Current tests do not validate lock-guarded transitions on new BTF fields. (Evidence: TE-004)
- **After**: Add tests for attach/detach/update sequences that exercise concurrent or ordered mutation of BTF field state.
- **Rationale**: The source imposes lock-guarded state, which should be validated once added.

### VD-012

- **Upstream REQ-ID**: REQ-PROG-012
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-003
- **Expected test change locations**: None
- **Before**: Existing unit tests already define the validation model for program creation, provider validation, and helper-state behavior. (Evidence: TE-001, TE-002, TE-003)
- **After**: No new validation architecture is required; extend the existing unit-test model with BTF-aware cases.
- **Rationale**: The current test shape is already the right extension point.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-PROG-001 | MISSING | VD-001 | `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]` | No BTF binding-record test exists. |
| REQ-PROG-002 | MISSING | VD-002 | `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]` | No BTF binding-array test exists. |
| REQ-PROG-003 | MISSING | VD-003 | `[UNKNOWN: BTF internal-state unit tests under libs\execution_context\unit]` | No BTF address-array test exists. |
| REQ-PROG-004 | MISSING | VD-004 | `[UNKNOWN: BTF callback unit tests]` | No BTF callback/context test exists. |
| REQ-PROG-005 | MISSING | VD-005 | `[UNKNOWN: BTF creation-path unit tests]` | No creation-time BTF-allocation test exists. |
| REQ-PROG-006 | MISSING | VD-006 | `[UNKNOWN: BTF client-registration tests]` | No BTF client-registration test exists. |
| REQ-PROG-007 | MISSING | VD-007 | `[UNKNOWN: BTF provider-attach tests]` | No BTF attach population test exists. |
| REQ-PROG-008 | MISSING | VD-008 | `[UNKNOWN: BTF readiness tests]` | No BTF readiness/load test exists. |
| REQ-PROG-009 | MISSING | VD-009 | `[UNKNOWN: BTF detach cleanup tests]` | No BTF detach cleanup test exists. |
| REQ-PROG-010 | MISSING | VD-010 | `[UNKNOWN: BTF teardown tests]` | No BTF teardown test exists. |
| REQ-PROG-011 | MISSING | VD-011 | `[UNKNOWN: BTF concurrency/state-transition tests]` | No BTF lock-guarded-state test exists. |
| REQ-PROG-012 | SATISFIED | No-Impact | None | Existing unit-test model is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] Existing validation already covers current program creation/provider validation and helper-state behavior; the proposed deltas preserve that validation structure. (Evidence: TE-001, TE-002, TE-003)
- [KNOWN] No current test mentions any BTF-resolved internal-state symbol, so the proposed deltas add new feature-specific coverage rather than modifying established BTF assertions. (Evidence: TE-004)

## 6. Application Notes

1. [KNOWN] No existing validation plan was provided, so these deltas are synthesized additions rather than edits to a prior plan.
2. [KNOWN] The main validation gap is complete absence of BTF-specific internal-state coverage.
3. [KNOWN] Several future test locations remain `[UNKNOWN]` because the BTF internal-state implementation is not yet present in the examined code.

## Coverage
- **Examined**: `libs\execution_context\unit\execution_context_unit_test.cpp`; `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; selected tests under `tests`
- **Method**: targeted `view` on provider-registration/create-failure tests and helper-ID/address tests; targeted `rg` for BTF-resolved symbols and helper-state APIs in tests
- **Excluded**: tests that do not exercise program internal state, provider registration, or helper-state setup
- **Limitations**: no BTF-resolved internal-state tests currently exist, so several future test files remain `[UNKNOWN]`

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test.cpp:2540-2559` | Unit tests validate `ebpf_program_create(...)` success/failure based on current provider availability and verify helper-function ID/address lookup after success. | Establishes the current create/provider/helper-state baseline. |
| TE-002 | `libs\execution_context\unit\execution_context_unit_test.cpp:2563-2694` | Unit tests validate rejection of invalid current program-data/provider payloads. | Establishes the current provider-validation baseline. |
| TE-003 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp:379-389` | Unit tests validate current helper-function ID storage and helper-address lookup. | Establishes the current helper-state baseline. |
| TE-004 | Exact searches over `libs\execution_context`, `include`, and `tests` for `btf_resolved_function` returned no matches. | No BTF-resolved internal-state validation exists in the examined tree. | Establishes the feature-specific validation gap. |

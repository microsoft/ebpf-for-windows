<!-- Delta artifact: Native Module Loading alignment set -->

# Native Module Loading — Validation Delta

## 1. Change Context

- **Area**: Native Module Loading
- **Requirements source**: `docs\specs\btfid\07-native-module-loading.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this run
- **Code scope**: `libs\execution_context`
- **Test scope**: `libs\execution_context\unit`; selected native-module tests under `tests\`
- **Goal**: identify the minimal validation-spec deltas needed to align test coverage with the native-module-loading requirements

[KNOWN] Current tests already validate the existing native-module load path and helper-centric runtime mechanics: unit tests cover negative native-module IOCTL shapes, API/end-to-end tests cover native-module load/reload/authorization behavior, and the bpf2c plugin and standalone bpf2c harnesses both populate `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. [KNOWN] No current test covers wildcard BTF client registration, BTF provider attach/detach callbacks, provider-binding state, or BTF-specific address-change notifications in the actual native-loading path. (Evidence: TE-001, TE-002, TE-003, TE-004, TE-005, TE-006)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-LOAD-001 | Add | Required | Add tests for native-module client registration against the BTF-resolved-function NPI with wildcard module-id semantics. | TE-001, TE-002, TE-004, TE-005 |
| VD-002 | REQ-LOAD-002 | Add | Required | Add tests for provider-module-GUID matching against the BTF import table during attach. | TE-004, TE-005 |
| VD-003 | REQ-LOAD-003 | Add | Required | Add native-loading tests that copy BTF provider addresses into the existing `btf_resolved_function_data` field and record provider-binding state. | TE-004, TE-005, TE-006 |
| VD-004 | REQ-LOAD-004 | Add | Required | Add tests that verify unrelated BTF providers are declined with `STATUS_NOINTERFACE`. | TE-004, TE-005 |
| VD-005 | REQ-LOAD-005 | Add | Required | Add tests for BTF provider detach clearing addresses and marking bindings detached. | TE-004, TE-005 |
| VD-006 | REQ-LOAD-006 | Add | Required | Add tests for BTF address-change callback invocation and any required in-flight execution coordination. | TE-004, TE-005 |
| VD-007 | REQ-LOAD-007 | Add | Required | Add tests for multiple BTF providers and execution gating until all required providers are attached. | TE-002, TE-003, TE-004, TE-005 |
| VD-008 | REQ-LOAD-008 | Add | Required | Add tests that distinguish provider-binding state from per-function and helper-resolution state. | TE-004, TE-005 |
| VD-009 | REQ-LOAD-009 | No-Impact | Not required | Extend the existing native-module load and bpf2c runtime-context tests instead of creating a separate validation architecture. | TE-001, TE-002, TE-003 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-LOAD-001
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-004, TE-005
- **Expected test change locations**: `[UNKNOWN: native module client/provider integration tests]`; possibly `tests\end_to_end`
- **Before**: Current tests cover native-module authorization and loading through the existing private native NPI path, but no test registers a native module as a client for a BTF-resolved-function NPI. (Evidence: TE-001, TE-002)
- **After**: Add tests for wildcard BTF client registration and attach-callback delivery for all BTF providers.
- **Rationale**: The BTF client registration path is not implied by current native-load tests.

### VD-002

- **Upstream REQ-ID**: REQ-LOAD-002
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005
- **Expected test change locations**: `[UNKNOWN: BTF provider attach tests]`
- **Before**: No current test checks provider module GUID matching against a BTF import table during native-module attach. (Evidence: TE-004, TE-005)
- **After**: Add tests that accept matching BTF providers and reject non-imported providers.
- **Rationale**: This is a new provider-identity contract absent from current helper-centric tests.

### VD-003

- **Upstream REQ-ID**: REQ-LOAD-003
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005, TE-006
- **Expected test change locations**: `[UNKNOWN: native-loading/provider-binding tests]`; existing `tests\bpf2c_plugin`; existing `tests\bpf2c_tests`
- **Before**: Current user-mode/runtime harness tests already populate and observe `runtime_context->btf_resolved_function_data`, but no test covers provider-binding records or native-loading attach-time address copying in execution-context. (Evidence: TE-004, TE-005, TE-006)
- **After**: Add tests that validate native-loading/provider attach behavior for BTF address copying into the existing runtime-context field and creation of provider-binding state.
- **Rationale**: The remaining gap is native-loading/provider-binding coverage, not basic existence of the BTF runtime-context field.

### VD-004

- **Upstream REQ-ID**: REQ-LOAD-004
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005
- **Expected test change locations**: `[UNKNOWN: BTF provider attach tests]`
- **Before**: No current native-loading test asserts `STATUS_NOINTERFACE` behavior for unrelated BTF providers. (Evidence: TE-005)
- **After**: Add tests that explicitly verify `STATUS_NOINTERFACE` on mismatched provider-module GUIDs.
- **Rationale**: The source specifies a concrete error path that needs direct coverage.

### VD-005

- **Upstream REQ-ID**: REQ-LOAD-005
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005
- **Expected test change locations**: `[UNKNOWN: BTF provider detach tests]`
- **Before**: Current tests do not cover BTF detach-driven address clearing or detached-state updates. (Evidence: TE-005)
- **After**: Add detach tests that verify addresses are nulled and provider bindings are marked detached.
- **Rationale**: Current native-load tests focus on module load/unload, not BTF provider detach semantics.

### VD-006

- **Upstream REQ-ID**: REQ-LOAD-006
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005
- **Expected test change locations**: `[UNKNOWN: BTF callback/detach coordination tests]`
- **Before**: Current tests do not cover `btf_resolved_function_addresses_changed_callback` or wait-for-current-execution behavior. (Evidence: TE-005)
- **After**: Add tests for callback invocation and detach timing/coordination once the BTF callback contract exists.
- **Rationale**: The current helper-address callback tests are not BTF-specific and do not prove this contract.

### VD-007

- **Upstream REQ-ID**: REQ-LOAD-007
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-003, TE-004, TE-005
- **Expected test change locations**: `[UNKNOWN: BTF multi-provider integration tests]`
- **Before**: Current tests validate native-module load/reload/module-handle behavior, but none validate multiple BTF providers or gating execution on all required providers being attached. (Evidence: TE-002, TE-003, TE-005)
- **After**: Add multi-provider tests that keep execution blocked until all required providers are attached.
- **Rationale**: This is a new readiness rule absent from current tests.

### VD-008

- **Upstream REQ-ID**: REQ-LOAD-008
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005
- **Expected test change locations**: `[UNKNOWN: BTF state-structure tests]`
- **Before**: No current test distinguishes provider-binding state from per-function BTF binding state because no BTF native-loading state exists in scope. (Evidence: TE-005)
- **After**: Add tests that verify provider-level state remains separate from any per-function binding state and from helper-resolution state.
- **Rationale**: This requirement is about internal structure boundaries and needs targeted validation once implemented.

### VD-009

- **Upstream REQ-ID**: REQ-LOAD-009
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-003
- **Expected test change locations**: None
- **Before**: Existing unit, API, end-to-end, and plugin tests already define the current native-module validation architecture. (Evidence: TE-001, TE-002, TE-003)
- **After**: No new validation architecture is required; extend the existing native-load and runtime-context tests with BTF-aware cases.
- **Rationale**: The current validation model is already the right extension point.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-LOAD-001 | MISSING | VD-001 | `[UNKNOWN: BTF client/provider integration tests]`; possibly `tests\end_to_end` | No BTF client-registration test exists. |
| REQ-LOAD-002 | MISSING | VD-002 | `[UNKNOWN: BTF provider attach tests]` | No BTF GUID/import-table matching test exists. |
| REQ-LOAD-003 | PARTIAL | VD-003 | `[UNKNOWN: native-loading/provider-binding tests]`; `tests\bpf2c_plugin`; `tests\bpf2c_tests` | Existing harness tests cover `btf_resolved_function_data`, but not native-loading/provider-binding behavior. |
| REQ-LOAD-004 | MISSING | VD-004 | `[UNKNOWN: BTF provider attach tests]` | No BTF-specific `STATUS_NOINTERFACE` test exists. |
| REQ-LOAD-005 | MISSING | VD-005 | `[UNKNOWN: BTF provider detach tests]` | No BTF detach-state/address-clearing test exists. |
| REQ-LOAD-006 | MISSING | VD-006 | `[UNKNOWN: BTF callback/detach coordination tests]` | No BTF callback/wait test exists. |
| REQ-LOAD-007 | MISSING | VD-007 | `[UNKNOWN: BTF multi-provider integration tests]` | No multi-provider BTF readiness test exists. |
| REQ-LOAD-008 | MISSING | VD-008 | `[UNKNOWN: BTF state-structure tests]` | No test covers distinct BTF provider-binding state. |
| REQ-LOAD-009 | SATISFIED | No-Impact | None | Existing native-load/runtime tests are already the right extension point. |

## 5. Invariant Impact

- [KNOWN] Existing validation already covers native-module IOCTL loading, authorization, reload prevention, and user-mode/runtime BTF address population; the proposed deltas preserve that architecture. (Evidence: TE-001, TE-002, TE-003, TE-004, TE-005)
- [KNOWN] Existing plugin/runtime tests already treat both `helper_data` and `btf_resolved_function_data` as callable-address channels in harnesses; the proposed deltas extend that public contract into native-loading coverage rather than replacing the existing tests outright. (Evidence: TE-004, TE-005)
- [KNOWN] No current test references the actual BTF-resolved native-loading client/provider attach-detach contract, so the proposed deltas add new feature-specific coverage rather than revising established BTF runtime-harness assertions. (Evidence: TE-006)

## 6. Application Notes

1. [KNOWN] No existing validation plan was provided, so these deltas are synthesized additions rather than edits to a prior plan.
2. [KNOWN] The main validation gap is total absence of BTF-specific native-loading client/provider fixtures and callback tests, not absence of user-mode BTF runtime-context harnesses.
3. [KNOWN] Several future test locations remain `[UNKNOWN]` because the BTF client-side native-module implementation is not present in the examined code.

## Coverage
- **Examined**: `libs\execution_context\unit\execution_context_unit_test.cpp`; `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `tests\bpf2c_plugin\bpf2c_test.cpp`; `tests\bpf2c_tests\bpf_test.cpp`
- **Method**: targeted `view` on native-module load/reload tests and BTF-aware runtime-context harness tests; targeted `rg` for BTF-resolved symbols, native-load entry points, and runtime-context fields
- **Excluded**: runtime execution semantics after successful BTF provider attachment, because no such path exists in the examined tests
- **Limitations**: no BTF-resolved native-loading tests currently exist, so several future test files remain `[UNKNOWN]`

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test.cpp:2147-2160`, `libs\execution_context\unit\execution_context_unit_test.cpp:2474-2509` | Unit tests cover negative IOCTL shapes for `EBPF_OPERATION_LOAD_NATIVE_MODULE`. | Establishes the low-level native-load validation baseline. |
| TE-002 | `tests\api_test\api_test.cpp:1251-1265` | API tests verify that reloading the same native module fails until the prior native module handle is closed. | Establishes current reload/unload behavior coverage. |
| TE-003 | `tests\end_to_end\end_to_end.cpp:2252-2289`, `tests\end_to_end\end_to_end.cpp:2310-2406` | End-to-end tests cover native-module load success, reload failure, and load-programs sequencing. | Establishes current native-module load integration coverage. |
| TE-004 | `tests\bpf2c_plugin\bpf2c_test.cpp:191-222` | The plugin runtime harness allocates and populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes existing user-mode/runtime coverage for BTF address population. |
| TE-005 | `tests\bpf2c_tests\bpf_test.cpp:85-116` | The standalone bpf2c runtime harness also allocates and populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes additional BTF runtime-context coverage outside the plugin harness. |
| TE-006 | Searches over `libs\execution_context` and `tests` for `btf_resolved_function_addresses_changed_callback`, wildcard BTF client registration, `STATUS_NOINTERFACE` BTF attach handling, and BTF provider-binding logic returned no matches in the examined scope. | No BTF-resolved native-loading validation exists in the examined code/test tree for the actual client/provider attach-detach path. | Establishes the remaining feature-specific validation gap. |

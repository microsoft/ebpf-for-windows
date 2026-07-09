<!-- Delta artifact: Runtime Execution alignment set -->

# Runtime Execution — Validation Delta

## 1. Change Context

- **Area**: Runtime Execution
- **Requirements source**: `docs\specs\btfid\08-runtime-execution.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this run
- **Code scope**: `libs\execution_context`
- **Test scope**: `libs\execution_context\unit`; selected runtime tests under `tests\`
- **Goal**: identify the minimal validation-spec deltas needed to align test coverage with the runtime-execution requirements

[KNOWN] Current tests already exercise the runtime baseline and some standalone BTF call-indirection behavior: unit tests cover successful `ebpf_program_invoke(...)` and `ebpf_program_execute_test_run(...)`, link attach failures already surface `EBPF_EXTENSION_FAILED_TO_LOAD` for mismatched providers, and the plugin/standalone bpf2c harnesses allocate and populate `runtime_context->btf_resolved_function_data`. [KNOWN] No current test covers execution_context-managed native BTF provider readiness, native BTF rundown acquisition, explicit BTF callback behavior, or BTF detach-during-execution semantics. (Evidence: TE-001, TE-002, TE-003, TE-004, TE-005, TE-006)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-RUN-001 | Add | Required | Add tests for execution_context-managed provider-complete native BTF readiness checks before invocation. | TE-001, TE-002, TE-006 |
| VD-002 | REQ-RUN-002 | Add | Required | Add tests that return `EBPF_EXTENSION_FAILED_TO_LOAD` when any required native BTF provider is unavailable at invoke time. | TE-002, TE-006 |
| VD-003 | REQ-RUN-003 | Add | Required | Add tests for acquisition/release of rundown protection across all required native BTF bindings. | TE-001, TE-006 |
| VD-004 | REQ-RUN-004 | Modify | Required | Extend existing standalone `btf_resolved_function_data` harness coverage into execution_context-managed native runtime coverage. | TE-004, TE-005, TE-006 |
| VD-005 | REQ-RUN-005 | Add | Required | Add tests for native BTF address clearing/update behavior and any future explicit BTF callback/JIT propagation path. | TE-004, TE-005, TE-006 |
| VD-006 | REQ-RUN-006 | Add | Required | Add tests for detach-during-execution completion followed by failure of later invocations until reattach. | TE-003, TE-006 |
| VD-007 | REQ-RUN-007 | Add | Required | Add tests that distinguish the three documented BTF runtime failure scenarios. | TE-002, TE-006 |
| VD-008 | REQ-RUN-008 | No-Impact | Not required | Extend the existing invoke/test-run/native-runtime test model rather than creating a separate validation architecture. | TE-001, TE-002, TE-004, TE-005 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-RUN-001
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-006
- **Expected test change locations**: `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; `[UNKNOWN: any BTF runtime integration tests]`
- **Before**: Current tests validate general invoke success and some extension/provider failure paths, but no test checks execution_context-managed provider-complete BTF readiness before native invocation. (Evidence: TE-001, TE-002, TE-006)
- **After**: Add tests that fail native invocation when any required BTF provider is unattached and succeed only when all required BTF providers are attached.
- **Rationale**: The current generic readiness tests and standalone harnesses do not prove the execution_context native path.

### VD-002

- **Upstream REQ-ID**: REQ-RUN-002
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-006
- **Expected test change locations**: `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; `[UNKNOWN: BTF runtime integration tests]`
- **Before**: `EBPF_EXTENSION_FAILED_TO_LOAD` is already observed for some mismatched/absent provider scenarios, but not for execution_context-managed native BTF invoke readiness. (Evidence: TE-002, TE-006)
- **After**: Add tests that specifically assert `EBPF_EXTENSION_FAILED_TO_LOAD` for missing or detached required native BTF providers at invocation time.
- **Rationale**: The source reuses the failure code, but this native runtime path is still untested.

### VD-003

- **Upstream REQ-ID**: REQ-RUN-003
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-006
- **Expected test change locations**: `[UNKNOWN: BTF rundown/invocation tests]`
- **Before**: Current tests prove invocation and test-run success, but do not verify native BTF binding-complete rundown acquisition/release. (Evidence: TE-001, TE-006)
- **After**: Add tests that observe or simulate rundown acquisition on all required native BTF bindings before invocation and release afterward.
- **Rationale**: The native implementation now has this path, but no test covers it.

### VD-004

- **Upstream REQ-ID**: REQ-RUN-004
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005, TE-006
- **Expected test change locations**: `[UNKNOWN: execution_context-managed native BTF runtime tests]`; `tests\bpf2c_plugin`; `tests\bpf2c_tests`
- **Before**: Standalone runtime harnesses already populate `runtime_context->btf_resolved_function_data`, but no execution_context-managed native test proves that the real native runtime path wires and executes through that storage. (Evidence: TE-004, TE-005, TE-006)
- **After**: Add tests that extend existing harness coverage into execution_context-managed native runtime-context execution.
- **Rationale**: The remaining gap is no longer standalone indirection coverage; it is absence of real runtime-path coverage.

### VD-005

- **Upstream REQ-ID**: REQ-RUN-005
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005, TE-006
- **Expected test change locations**: `[UNKNOWN: BTF callback/native-update tests]`
- **Before**: Current tests do not cover native BTF address clearing/update behavior in execution_context, and they also do not cover any explicit BTF-resolved callback type or JIT propagation behavior. (Evidence: TE-004, TE-005, TE-006)
- **After**: Add tests for native BTF address clearing/update behavior now, and extend them for the explicit callback/JIT path if and when that contract is added.
- **Rationale**: The standalone harnesses and helper callback tests are not sufficient proxies for the execution_context native path.

### VD-006

- **Upstream REQ-ID**: REQ-RUN-006
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-003, TE-006
- **Expected test change locations**: `[UNKNOWN: BTF detach-during-execution tests]`
- **Before**: Current tests cover general runtime behavior and some synchronization scenarios, but none cover BTF provider detach during execution. (Evidence: TE-003, TE-006)
- **After**: Add tests that detach a BTF provider during execution, verify the in-flight execution completes, and then verify later invocations fail until reattach.
- **Rationale**: This is a feature-specific scenario absent from the current test tree.

### VD-007

- **Upstream REQ-ID**: REQ-RUN-007
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-006
- **Expected test change locations**: `[UNKNOWN: BTF runtime error-scenario tests]`
- **Before**: Current tests do not distinguish the three documented BTF runtime failure scenarios. (Evidence: TE-006)
- **After**: Add tests for: provider not registered, provider detached while loaded, and provider detached during execution.
- **Rationale**: The source requires deterministic distinction among those scenarios.

### VD-008

- **Upstream REQ-ID**: REQ-RUN-008
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-004, TE-005
- **Expected test change locations**: None
- **Before**: Existing unit/runtime tests and standalone BTF harnesses already define the current validation architecture. (Evidence: TE-001, TE-002, TE-004, TE-005)
- **After**: No new validation architecture is required; extend the existing runtime tests and standalone harnesses with execution_context-aware BTF cases.
- **Rationale**: The current validation model is already the right extension point.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-RUN-001 | MISSING | VD-001 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; `[UNKNOWN: BTF runtime integration tests]` | No execution_context-native BTF readiness test exists. |
| REQ-RUN-002 | MISSING | VD-002 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; `[UNKNOWN: BTF runtime integration tests]` | No execution_context-native BTF invoke failure-code test exists. |
| REQ-RUN-003 | MISSING | VD-003 | `[UNKNOWN: BTF rundown/invocation tests]` | No native BTF rundown-binding-set test exists. |
| REQ-RUN-004 | PARTIAL | VD-004 | `[UNKNOWN: execution_context-managed native BTF runtime tests]`; `tests\bpf2c_plugin`; `tests\bpf2c_tests` | Standalone harnesses cover `btf_resolved_function_data`, but the real native runtime path is untested. |
| REQ-RUN-005 | MISSING | VD-005 | `[UNKNOWN: BTF callback/native-update tests]` | No execution_context-native BTF address-update or callback test exists. |
| REQ-RUN-006 | MISSING | VD-006 | `[UNKNOWN: BTF detach-during-execution tests]` | No BTF detach-during-execution test exists. |
| REQ-RUN-007 | MISSING | VD-007 | `[UNKNOWN: BTF runtime error-scenario tests]` | No three-scenario BTF runtime failure test exists. |
| REQ-RUN-008 | SATISFIED | No-Impact | None | Existing runtime test model is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] Existing validation already covers successful invocation/test-run and explicit failure behavior for current extension/provider scenarios; the proposed deltas preserve that structure. (Evidence: TE-001, TE-002)
- [KNOWN] Existing standalone BTF harness tests already treat `btf_resolved_function_data` as an updatable runtime-address channel; the proposed deltas extend that contract into execution_context-managed native coverage rather than replacing the harnesses. (Evidence: TE-004, TE-005)
- [KNOWN] No current test references execution_context-managed native BTF readiness, detach, or callback behavior, so the proposed deltas add missing feature-specific coverage rather than revising established standalone BTF assertions. (Evidence: TE-006)

## 6. Application Notes

1. [KNOWN] No existing validation plan was provided, so these deltas are synthesized additions rather than edits to a prior plan.
2. [KNOWN] The main validation gap is no longer total absence of BTF call-indirection coverage; it is absence of execution_context-managed native BTF runtime readiness, rundown, update, and detach tests.
3. [KNOWN] Several future test locations remain `[UNKNOWN]` because the execution_context native BTF runtime path is implemented but not yet represented in dedicated tests.

## Coverage
- **Examined**: `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; `libs\execution_context\unit\execution_context_unit_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `tests\bpf2c_plugin\bpf2c_test.cpp`; `tests\bpf2c_tests\bpf_test.cpp`
- **Method**: targeted `view` on invoke/test-run success, explicit `EBPF_EXTENSION_FAILED_TO_LOAD` cases, long-running synchronization tests, and standalone BTF runtime-context harness tests; targeted `rg` for BTF runtime symbols and runtime-failure terms
- **Excluded**: tests outside the examined runtime paths that do not exercise execution or runtime address updates
- **Limitations**: no execution_context-managed native BTF runtime tests currently exist, so several future test files remain `[UNKNOWN]`

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp:338-376` | Unit tests cover successful `ebpf_program_invoke(...)` and `ebpf_program_execute_test_run(...)`. | Establishes the current runtime invocation/test-run baseline. |
| TE-002 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp:393-410`, `tests\end_to_end\end_to_end.cpp:1768-1771` | Existing tests already observe `EBPF_EXTENSION_FAILED_TO_LOAD` for current mismatched/unsupported provider scenarios. | Establishes the current explicit failure-behavior baseline. |
| TE-003 | `tests\end_to_end\end_to_end.cpp:3474-3507` | End-to-end tests exercise long-running repeated execution plus explicit synchronization. | Establishes a nearby in-flight execution/synchronization baseline, even though it is not BTF-specific. |
| TE-004 | `tests\bpf2c_plugin\bpf2c_test.cpp:191-222` | The plugin runtime harness allocates and populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes standalone BTF runtime-context coverage. |
| TE-005 | `tests\bpf2c_tests\bpf_test.cpp:82-116` | The standalone bpf2c runtime harness also allocates and populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes additional standalone BTF runtime-context coverage. |
| TE-006 | Exact searches over `libs\execution_context`, `include`, and `tests` for execution_context-native BTF runtime invoke/detach tests returned no matches. | No execution_context-managed native BTF runtime validation exists in the examined tree. | Establishes the remaining feature-specific validation gap. |

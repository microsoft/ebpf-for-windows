<!-- Delta artifact: Runtime Execution alignment set -->

# Runtime Execution — Requirements / Code / Test Traceability

## Coverage

- **Target**: runtime-execution requirements for BTF-resolved functions, joined against `libs\execution_context` code and related runtime tests
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\08-runtime-execution.md`
  - `view` on `libs\execution_context\ebpf_program.h`, `libs\execution_context\ebpf_program.c`, `libs\execution_context\ebpf_native.c`, `include\bpf2c.h`
  - `view` on `libs\execution_context\unit\execution_context_unit_test_jit.cpp`, `libs\execution_context\unit\execution_context_unit_test.cpp`, `tests\end_to_end\end_to_end.cpp`, `tests\bpf2c_plugin\bpf2c_test.cpp`, `tests\bpf2c_tests\bpf_test.cpp`, and `tests\bpf2c_tests\expected\btf_resolved_sys.c`
  - `rg "ebpf_native_acquire_btf_references|ebpf_native_release_btf_references|ebpf_btf_resolved_function_addresses_changed_callback_t|btf_resolved_function_data|EBPF_EXTENSION_FAILED_TO_LOAD|program_invoke"` over `libs\execution_context`, `include`, and relevant `tests`
- **Excluded**: load-time provider attach mechanics; internal `ebpf_program_t` design beyond runtime-accessible behavior
- **Limitations**: the examined code still lacks an explicit BTF callback/JIT propagation path and still lacks end-to-end tests for execution_context-managed native BTF runtime behavior, so several future change locations remain `[UNKNOWN]`

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\08-runtime-execution.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-RUN-001 through REQ-RUN-008 |
| `libs\execution_context\ebpf_program.h` | Code | Implementation baseline | Current invoke and helper-callback contract |
| `libs\execution_context\ebpf_program.c` | Code | Implementation baseline | Current invoke gate plus native BTF invoke hook |
| `libs\execution_context\ebpf_native.c` | Code | Implementation baseline | Current native BTF address update and rundown logic |
| `include\bpf2c.h` | Code | Public contract baseline | Current native runtime-context declaration including `btf_resolved_function_data` |
| `libs\execution_context\unit\execution_context_unit_test_jit.cpp` | Test code | Validation baseline | Current invoke/test-run and extension failure tests |
| `libs\execution_context\unit\execution_context_unit_test.cpp` | Test code | Validation baseline | Current native-load failure-path tests |
| `tests\end_to_end\end_to_end.cpp` | Test code | Validation baseline | Current long-running runtime execution/synchronization tests |
| `tests\bpf2c_plugin\bpf2c_test.cpp` | Test code | Validation baseline | Current runtime-context harness including BTF-resolved address population |
| `tests\bpf2c_tests\bpf_test.cpp` | Test code | Validation baseline | Current standalone BTF-resolved runtime-context harness |
| `tests\bpf2c_tests\expected\btf_resolved_sys.c` | Generated code fixture | Implementation baseline | Current generated native BTF call-indirection behavior |
| Existing design document | Design doc | None provided | Recorded as absent for this run |
| Existing validation document | Validation doc | None provided | Recorded as absent for this run |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-RUN-001 | Check that all required BTF providers are attached before invocation. | PARTIAL | MISSING | Native invocation now checks all required BTF provider bindings, but there is no shared runtime abstraction or direct test coverage. |
| REQ-RUN-002 | Return `EBPF_EXTENSION_FAILED_TO_LOAD` when any required BTF provider is detached/unavailable. | PARTIAL | MISSING | Native invoke now returns the failure code on BTF-provider acquire failure, but the scenario is not directly tested. |
| REQ-RUN-003 | Take and release rundown protection on all BTF bindings around execution. | PARTIAL | MISSING | Native invoke now acquires/releases all required BTF provider rundowns, but there is no direct test coverage. |
| REQ-RUN-004 | Execute BTF-resolved functions through runtime-context indirection. | SATISFIED | PARTIAL | The public native contract, generated code, and standalone harnesses already use `runtime_context->btf_resolved_function_data`, but execution_context-managed native tests are still missing. |
| REQ-RUN-005 | Propagate BTF address changes via `ebpf_btf_resolved_function_addresses_changed_callback_t`. | PARTIAL | MISSING | Native direct address updates exist, but the explicit callback/JIT path is absent and untested. |
| REQ-RUN-006 | If a provider detaches during execution, current execution completes and later invocations fail until reattach. | SATISFIED | MISSING | Native detach now waits for rundown and later invoke fails, but there is no direct test coverage. |
| REQ-RUN-007 | Runtime failure behavior for unavailable BTF providers is explicit and deterministic across the three scenarios. | PARTIAL | MISSING | Native failure behavior is partly implemented, but the three scenarios are not explicitly validated. |
| REQ-RUN-008 | Extend the existing invoke/rundown/address-update pipeline rather than invent a second runtime path. | SATISFIED | SATISFIED | Current runtime architecture is already the right extension point. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-RUN-001 | Check that all required BTF providers are attached before invocation. | CE-001, CE-003, CE-006 | PARTIAL | DD-001 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | TE-001, TE-002, TE-006 | MISSING | VD-001 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; `[UNKNOWN: BTF runtime integration tests]` | Native invoke now enforces provider-complete BTF readiness, but there is no direct runtime test. |
| REQ-RUN-002 | Return `EBPF_EXTENSION_FAILED_TO_LOAD` when any required BTF provider is detached/unavailable. | CE-001, CE-003 | PARTIAL | DD-002 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | TE-002, TE-006 | MISSING | VD-002 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp`; `[UNKNOWN: BTF runtime integration tests]` | Native invoke now returns the failure code on BTF-provider acquire failure, but no direct test covers that path. |
| REQ-RUN-003 | Take and release rundown protection on all BTF bindings around execution. | CE-001, CE-003 | PARTIAL | DD-003 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | TE-001, TE-006 | MISSING | VD-003 | `[UNKNOWN: BTF rundown/invocation tests]` | Native invoke now acquires/releases all required BTF provider rundowns. |
| REQ-RUN-004 | Execute BTF-resolved functions through runtime-context indirection. | CE-004, CE-005 | SATISFIED | No-Impact | None | TE-004, TE-005 | PARTIAL | VD-004 | `[UNKNOWN: execution_context-managed native BTF runtime tests]`; `tests\bpf2c_plugin`; `tests\bpf2c_tests` | The public contract and generated code already use `btf_resolved_function_data`, and standalone harnesses populate it. |
| REQ-RUN-005 | Propagate BTF address changes via `ebpf_btf_resolved_function_addresses_changed_callback_t`. | CE-002, CE-003, CE-004, CE-006 | PARTIAL | DD-005 | `libs\execution_context\ebpf_program.h`; `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | TE-004, TE-005, TE-006 | MISSING | VD-005 | `[UNKNOWN: BTF callback/native-update tests]` | Native direct address updates exist, but the explicit callback/JIT path does not. |
| REQ-RUN-006 | If a provider detaches during execution, current execution completes and later invocations fail until reattach. | CE-001, CE-003 | SATISFIED | No-Impact | None | TE-003, TE-006 | MISSING | VD-006 | `[UNKNOWN: BTF detach-during-execution tests]` | Native detach now waits for rundown release and later invoke fails, but the path is untested. |
| REQ-RUN-007 | Runtime failure behavior for unavailable BTF providers is explicit and deterministic across the three scenarios. | CE-001, CE-003, CE-006 | PARTIAL | DD-007 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | TE-002, TE-006 | MISSING | VD-007 | `[UNKNOWN: BTF runtime error-scenario tests]` | Native failure behavior is partly present, but the three scenarios are not yet explicitly validated. |
| REQ-RUN-008 | Extend the existing invoke/rundown/address-update pipeline rather than invent a second runtime path. | CE-001, CE-002, CE-003, CE-004 | SATISFIED | No-Impact | None | TE-001, TE-002, TE-004 | SATISFIED | No-Impact | None | Existing runtime architecture is already the right extension point. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The source requires provider-complete BTF readiness and binding-complete rundown. Native execution now implements those behaviors, but only through a native-specific path rather than a shared runtime abstraction. | CE-001, CE-003 | Apply DD-001 through DD-003. |
| CR-002 | Upstream-downstream | The source requires an explicit BTF callback/JIT-native propagation contract. The current native path already updates `btf_resolved_function_data` directly, but the explicit callback/JIT side is still missing. | CE-002, CE-003, CE-004, CE-006 | Apply DD-005. |
| CR-003 | Coverage gap | The current test suite now includes standalone harness coverage for `btf_resolved_function_data`, but it still contains no execution_context-managed native BTF runtime coverage. | TE-001, TE-002, TE-003, TE-004, TE-005, TE-006 | Apply VD-001 through VD-007. |

## Open Questions

1. [UNKNOWN: whether BTF provider-complete readiness and rundown should remain native-path-specific or be surfaced through a shared runtime helper.]
2. [UNKNOWN: which exact JIT update mechanism will be used for BTF-resolved function address changes once the explicit BTF callback contract is added.]
3. [KNOWN] No existing design or validation document was provided, so these delta artifacts are synthesized from requirements plus code/test evidence only.

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_program.h:200-214` | Current invoke path still checks `extension_program_data`, returns `EBPF_EXTENSION_FAILED_TO_LOAD`, and in the native branch calls `ebpf_native_acquire_btf_references(...)` / `ebpf_native_release_btf_references(...)`. | Establishes the generic invoke baseline plus the native BTF invoke gate. |
| CE-002 | `libs\execution_context\ebpf_program.h:389-407`, `libs\execution_context\ebpf_program.c:1154-1238` | The current explicit callback/update surface is helper-address based for JIT/interpreter execution. | Establishes the remaining helper-specific callback baseline. |
| CE-003 | `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_native.c:1051-1095` | Native BTF provider attach/detach updates `runtime_context.btf_resolved_function_data`, detach waits for rundown release, and native invoke acquires/releases all required BTF provider rundowns. | Establishes the implemented native BTF runtime path. |
| CE-004 | `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170` | `include\bpf2c.h` defines `btf_resolved_function_data_t` and includes `btf_resolved_function_data` in `program_runtime_context_t`. | Establishes the current public native runtime contract. |
| CE-005 | `tests\bpf2c_tests\expected\btf_resolved_sys.c:245-247` | Generated native code already calls through `runtime_context->btf_resolved_function_data[0].address`. | Establishes the current native BTF call-indirection behavior. |
| CE-006 | Exact searches over `libs\execution_context`, `include`, and `tests` for `ebpf_btf_resolved_function_addresses_changed_callback_t` returned no implementation matches. | No explicit BTF-resolved runtime callback/JIT propagation contract exists in the examined scope. | Establishes the remaining callback/JIT gap. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp:338-376` | Unit tests cover successful `ebpf_program_invoke(...)` and `ebpf_program_execute_test_run(...)`. | Establishes the current runtime invocation/test-run baseline. |
| TE-002 | `libs\execution_context\unit\execution_context_unit_test_jit.cpp:393-410`, `tests\end_to_end\end_to_end.cpp:1768-1771` | Existing tests already observe `EBPF_EXTENSION_FAILED_TO_LOAD` for current mismatched/unsupported provider scenarios. | Establishes the current explicit failure-behavior baseline. |
| TE-003 | `tests\end_to_end\end_to_end.cpp:3474-3507` | End-to-end tests exercise long-running repeated execution plus explicit synchronization. | Establishes a nearby in-flight execution/synchronization baseline. |
| TE-004 | `tests\bpf2c_plugin\bpf2c_test.cpp:191-222` | The plugin runtime harness allocates and populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes standalone runtime-context coverage for BTF call indirection. |
| TE-005 | `tests\bpf2c_tests\bpf_test.cpp:82-116` | The standalone bpf2c runtime harness also allocates and populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes additional standalone BTF call-indirection coverage. |
| TE-006 | Exact searches over `libs\execution_context`, `include`, and `tests` for execution_context-native BTF runtime invoke/detach tests returned no matches. | No execution_context-managed native BTF runtime validation exists in the examined tree. | Establishes the remaining feature-specific validation gap. |

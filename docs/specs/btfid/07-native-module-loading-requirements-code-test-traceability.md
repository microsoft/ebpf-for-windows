<!-- Delta artifact: Native Module Loading alignment set -->

# Native Module Loading — Requirements / Code / Test Traceability

## Coverage

- **Target**: native-module-loading requirements for BTF-resolved functions, joined against `libs\execution_context` code and related native-module/runtime tests
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\07-native-module-loading.md`
  - `view` on `include\bpf2c.h`, `libs\execution_context\ebpf_native.c`, `libs\execution_context\ebpf_program.h`, `libs\execution_context\ebpf_program.c`
  - `view` on `libs\execution_context\unit\execution_context_unit_test.cpp`, `tests\api_test\api_test.cpp`, `tests\end_to_end\end_to_end.cpp`, `tests\bpf2c_plugin\bpf2c_test.cpp`, `tests\bpf2c_tests\bpf_test.cpp`, and `tests\bpf2c_tests\expected\btf_resolved_sys.c`
  - `rg "btf_resolved_function_data|btf_resolved_function_addresses_changed_callback|STATUS_NOINTERFACE|wildcard module ID|provider binding list|load_native_module|helper_data"` over `include\`, `libs\execution_context`, and relevant `tests\`
- **Excluded**: runtime invocation after successful provider attachment; native module skeleton/client code outside the examined execution-context scope
- **Limitations**: the BTF client-side native-loading implementation required by the source is not present in the examined code or tests, so several future change locations remain `[UNKNOWN]`

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\07-native-module-loading.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-LOAD-001 through REQ-LOAD-009 |
| `include\bpf2c.h` | Code | Public contract baseline | Current native runtime-context and metadata-table declarations |
| `libs\execution_context\ebpf_native.c` | Code | Implementation baseline | Current native load/provider attach, helper resolution, and callback wiring |
| `libs\execution_context\ebpf_program.h` | Code | Implementation baseline | Current helper-address change callback contract |
| `libs\execution_context\ebpf_program.c` | Code | Implementation baseline | Current helper-address callback invocation/registration path |
| `libs\execution_context\unit\execution_context_unit_test.cpp` | Test code | Validation baseline | Current native-load IOCTL negative tests |
| `tests\api_test\api_test.cpp` | Test code | Validation baseline | Current native-module reload behavior tests |
| `tests\end_to_end\end_to_end.cpp` | Test code | Validation baseline | Current native-module load/reload sequencing tests |
| `tests\bpf2c_plugin\bpf2c_test.cpp` | Test code | Validation baseline | Current runtime-context harness including BTF-resolved address population |
| `tests\bpf2c_tests\bpf_test.cpp` | Test code | Validation baseline | Current standalone bpf2c runtime harness including BTF-resolved address population |
| `tests\bpf2c_tests\expected\btf_resolved_sys.c` | Generated code fixture | Implementation baseline | Current generated native scaffolding for BTF imports and runtime-context use |
| Existing design document | Design doc | None provided | Recorded as absent for this run |
| Existing validation document | Validation doc | None provided | Recorded as absent for this run |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-LOAD-001 | Register the native module as an NMR client for the BTF-resolved-function NPI with wildcard module ID. | MISSING | MISSING | In-scope code is provider-side for the private native NPI, not a BTF client-registration path. |
| REQ-LOAD-002 | Match provider module GUIDs against the BTF import table during attach. | MISSING | MISSING | Current native load path resolves helpers, not BTF provider GUIDs. |
| REQ-LOAD-003 | Store binding state and copy provider addresses into `btf_resolved_function_data`. | PARTIAL | PARTIAL | Public/runtime scaffolding and user-mode harness population exist, but kernel native loading still lacks provider binding and address-copy behavior and currently fails closed. |
| REQ-LOAD-004 | Decline unrelated providers with `STATUS_NOINTERFACE`. | MISSING | MISSING | No BTF attach callback path exists in scope. |
| REQ-LOAD-005 | Clear BTF-resolved addresses and mark bindings detached on provider detach. | MISSING | MISSING | No BTF detach path exists in scope. |
| REQ-LOAD-006 | Wait for current execution and invoke `btf_resolved_function_addresses_changed_callback` on detach. | MISSING | MISSING | Current callback surface is helper-address based only. |
| REQ-LOAD-007 | Support multiple BTF providers and require all required providers before execution. | MISSING | MISSING | No BTF provider-binding list or readiness gate exists in scope. |
| REQ-LOAD-008 | Keep provider-binding state distinct from per-function binding state. | MISSING | MISSING | No BTF provider-binding state exists in scope. |
| REQ-LOAD-009 | Extend the existing native loader/runtime contract rather than inventing a second path. | SATISFIED | SATISFIED | Current native load pipeline/public contract are already the right extension points. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-LOAD-001 | Register the native module as an NMR client for the BTF-resolved-function NPI with wildcard module ID. | CE-001, CE-002, CE-006 | MISSING | DD-001 | `[UNKNOWN: native module client registration site]`; `06-nmr-provider-registration` touch points | TE-001, TE-002, TE-005 | MISSING | VD-001 | `[UNKNOWN: BTF client/provider integration tests]`; possibly `tests\end_to_end` | Current code is provider-side for the private native NPI only. |
| REQ-LOAD-002 | Match provider module GUIDs against the BTF import table during attach. | CE-004, CE-006 | MISSING | DD-002 | `[UNKNOWN: native module client attach callback site]`; possibly `include\bpf2c.h` | TE-004, TE-005 | MISSING | VD-002 | `[UNKNOWN: BTF provider attach tests]` | Current load path resolves helpers, not BTF provider GUIDs. |
| REQ-LOAD-003 | Store binding state and copy provider addresses into `btf_resolved_function_data`. | CE-003, CE-004, CE-005, CE-007, CE-008 | PARTIAL | DD-003 | `[UNKNOWN: native module attach/load code]` | TE-004, TE-005, TE-006 | PARTIAL | VD-003 | `[UNKNOWN: native-loading/provider-binding tests]`; `tests\bpf2c_plugin`; `tests\bpf2c_tests` | Public/runtime scaffolding exists, but execution-context native loading still rejects BTF-importing native modules. |
| REQ-LOAD-004 | Decline unrelated providers with `STATUS_NOINTERFACE`. | CE-006 | MISSING | DD-004 | `[UNKNOWN: native module client attach callback site]` | TE-004, TE-005 | MISSING | VD-004 | `[UNKNOWN: BTF provider attach tests]` | No BTF-specific `STATUS_NOINTERFACE` path exists in scope. |
| REQ-LOAD-005 | Clear BTF-resolved addresses and mark bindings detached on provider detach. | CE-005, CE-006 | MISSING | DD-005 | `[UNKNOWN: native module client detach callback site]`; `[ASSUMPTION] include\bpf2c.h` | TE-004, TE-005 | MISSING | VD-005 | `[UNKNOWN: BTF provider detach tests]` | No BTF detach path exists in scope. |
| REQ-LOAD-006 | Wait for current execution and invoke `btf_resolved_function_addresses_changed_callback` on detach. | CE-005, CE-006 | MISSING | DD-006 | `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: detach/runtime coordination code]` | TE-004, TE-005 | MISSING | VD-006 | `[UNKNOWN: BTF callback/detach coordination tests]` | Current callback contract is helper-address based only. |
| REQ-LOAD-007 | Support multiple BTF providers and require all required providers before execution. | CE-003, CE-006 | MISSING | DD-007 | `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: provider-binding state owner]` | TE-002, TE-003, TE-004, TE-005 | MISSING | VD-007 | `[UNKNOWN: BTF multi-provider integration tests]` | No BTF readiness gating exists in current load tests or code. |
| REQ-LOAD-008 | Keep provider-binding state distinct from per-function binding state. | CE-003, CE-004, CE-006 | MISSING | DD-008 | `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: provider-binding state owner]` | TE-004, TE-005 | MISSING | VD-008 | `[UNKNOWN: BTF state-structure tests]` | No BTF provider-binding structure exists in scope. |
| REQ-LOAD-009 | Extend the existing native loader/runtime contract rather than inventing a second path. | CE-001, CE-003, CE-004, CE-005 | SATISFIED | No-Impact | None | TE-001, TE-002, TE-003 | SATISFIED | No-Impact | None | Existing native-loader/public-contract architecture is already the right extension point. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The source requires BTF-provider client registration and provider attach/detach behavior, but the current in-scope code implements only the provider side of the private native-module NPI and helper-centric address wiring. | CE-001, CE-002, CE-004, CE-006 | Apply DD-001 through DD-008. |
| CR-002 | Upstream-downstream | The source requires attach-time provider binding, `btf_resolved_function_data` population, and a BTF-resolved address-change callback; the current public contract already exposes BTF runtime/import scaffolding, but execution-context still exposes only the helper-address callback path and rejects native loads with BTF imports. | CE-003, CE-005, CE-008 | Apply DD-003, DD-005, and DD-006. |
| CR-003 | Coverage gap | The current test suite covers native-module load/reload and helper-centric runtime state, but contains no BTF-resolved native-loading coverage. | TE-001, TE-002, TE-003, TE-004, TE-005 | Apply VD-001 through VD-008. |

## Open Questions

1. [UNKNOWN: where the native module skeleton/client code for BTF-resolved provider registration will live, since it is not present in the examined execution-context scope.]
2. [UNKNOWN: which exact additional public `include\bpf2c.h` declarations beyond the existing BTF import/runtime fields will carry provider-binding state and BTF address-change callback registration.]
3. [KNOWN] No existing design or validation document was provided, so these delta artifacts are synthesized from requirements plus code/test evidence only.

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\execution_context\ebpf_native.c:107-144`, `libs\execution_context\ebpf_native.c:1068-1073` | Execution-context registers a provider for the private native-module NPI `_ebpf_native_npi_id`. | Establishes the current native provider baseline. |
| CE-002 | `libs\execution_context\ebpf_native.c:800-977` | The native attach callback in scope validates and authorizes native modules from the provider side. | Establishes the provider-side scope boundary. |
| CE-003 | `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170`, `include\bpf2c.h:190-193`, `include\bpf2c.h:220-238` | `include\bpf2c.h` defines BTF import metadata and `program_runtime_context_t::btf_resolved_function_data`, but `metadata_table_t` still has no BTF-specific callback field. | Establishes the current public native contract baseline. |
| CE-004 | `libs\execution_context\ebpf_native.c:1658-1744`, `libs\execution_context\ebpf_native.c:1917-1970` | The loader allocates `runtime_context.helper_data`, resolves helpers, and writes helper addresses into runtime context; when `btf_resolved_function_count > 0`, the loader returns `EBPF_EXTENSION_FAILED_TO_LOAD`. | Establishes the helper-centric runtime wiring baseline and current fail-closed BTF behavior. |
| CE-005 | `libs\execution_context\ebpf_program.h:389-407`, `libs\execution_context\ebpf_native.c:1971-2005`, `libs\execution_context\ebpf_native.c:2407-2452` | The current callback/update path is helper-address based via `ebpf_program_register_for_helper_changes` and `_ebpf_native_helper_address_changed`. | Establishes the current callback/update contract. |
| CE-006 | `libs\execution_context` search using `rg "btf_resolved_function_data|btf_resolved_function_addresses_changed_callback|STATUS_NOINTERFACE|wildcard module ID|provider binding list"` returned no native-loading implementation matches for the BTF-specific client-side contract. | No BTF-resolved native-loading path is visible in the examined code scope. | Establishes the BTF loading gap. |
| CE-007 | `tests\bpf2c_tests\expected\btf_resolved_sys.c:106-107`, `tests\bpf2c_tests\expected\btf_resolved_sys.c:187-247` | Generated native code already emits a BTF import table and dereferences `runtime_context->btf_resolved_function_data[0].address`. | Establishes that generated/native scaffolding is ahead of the execution-context consumer implementation. |
| CE-008 | `libs\execution_context\ebpf_native.c:1963-1970` | The native loader explicitly rejects native programs that declare BTF imports with `EBPF_EXTENSION_FAILED_TO_LOAD`. | Establishes the current temporary kernel behavior for BTF-importing native modules. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test.cpp:2147-2160`, `libs\execution_context\unit\execution_context_unit_test.cpp:2474-2509` | Unit tests cover negative request-shape handling for `EBPF_OPERATION_LOAD_NATIVE_MODULE`. | Establishes the low-level native-load validation baseline. |
| TE-002 | `tests\api_test\api_test.cpp:1251-1265` | API tests verify native-module reload failure until the original module handle is closed. | Establishes current reload/unload behavior coverage. |
| TE-003 | `tests\end_to_end\end_to_end.cpp:2252-2289`, `tests\end_to_end\end_to_end.cpp:2310-2406` | End-to-end tests cover native-module load success, reload failure, and load-program sequencing. | Establishes current native-module integration coverage. |
| TE-004 | `tests\bpf2c_plugin\bpf2c_test.cpp:191-222` | The plugin runtime harness populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes existing user-mode/runtime coverage for BTF address population. |
| TE-005 | `tests\bpf2c_tests\bpf_test.cpp:85-116` | The standalone bpf2c runtime harness also populates `runtime_context->btf_resolved_function_data` from emitted BTF import metadata. | Establishes existing BTF runtime-context coverage outside the plugin harness. |
| TE-006 | Searches over `libs\execution_context` and `tests` for wildcard BTF client registration, BTF provider-binding state, `STATUS_NOINTERFACE` BTF attach handling, and BTF detach callbacks returned no native-loading validation matches in the examined scope. | No BTF-resolved native-loading validation exists in the examined tree for the actual client/provider attach-detach path. | Establishes the remaining feature-specific validation gap. |

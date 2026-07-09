<!-- Delta artifact: NMR Provider Registration alignment set -->

# NMR Provider Registration — Requirements / Code / Test Traceability

## Coverage

- **Target**: NMR-provider-registration requirements for BTF-resolved functions, joined against the current
  execution-context code plus adjacent BTF registry/verifier/native-codegen coverage
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\06-nmr-provider-registration.md`
  - `view` on `include\ebpf_extension_uuids.h`, `include\ebpf_extension.h`, `include\ebpf_store_helper.h`, `include\bpf2c.h`
  - `view` on `libs\execution_context\ebpf_core.c`, `libs\execution_context\ebpf_program.c`, `tools\bpf2c\bpf_code_generator.cpp`
  - `view` on `libs\execution_context\unit\execution_context_unit_test.cpp`, `tests\end_to_end\helpers.h`, `tests\netebpfext_unit\netebpf_ext_helper.h`
  - `view` on `tests\unit\export_program_info_test.cpp`, `tests\unit\btf_verifier_test.cpp`, `tests\bpf2c_tests\bpf_test.cpp`, `tests\bpf2c_plugin\bpf2c_test.cpp`, and `tests\sample\unsafe\btf_resolved.c`
  - `rg "EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID|ebpf_btf_resolved_function_provider_data_t|NmrRegisterProvider"` over `include\`, `libs\execution_context`, and `tests\`
- **Excluded**: detailed native-module attach/detach behavior after provider registration; runtime execution after successful binding
- **Limitations**: the examined repository contains adjacent BTF groundwork, but still no BTF-resolved NMR provider implementation or NMR-specific tests, so some future change locations remain `[UNKNOWN]`

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\06-nmr-provider-registration.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-NMR-001 through REQ-NMR-007 |
| `include\ebpf_extension_uuids.h` | Code | Public contract baseline | Current extension IID definitions |
| `include\ebpf_extension.h` | Code | Public contract baseline | Existing extension provider-data type declarations |
| `include\ebpf_store_helper.h` | Code | Adjacent BTF baseline | Current BTF registry-publication contract |
| `include\bpf2c.h` | Code | Adjacent BTF baseline | Current native BTF import/runtime metadata contract |
| `libs\execution_context\ebpf_core.c` | Code | Implementation baseline | Current NMR provider registration baseline |
| `libs\execution_context\ebpf_program.c` | Code | Implementation baseline | Current provider-data matching and validation baseline |
| `tools\bpf2c\bpf_code_generator.cpp` | Code | Adjacent BTF baseline | Current native metadata emission baseline |
| `libs\execution_context\unit\execution_context_unit_test.cpp` | Test code | Validation baseline | Current provider registration / provider-data validation tests |
| `tests\end_to_end\helpers.h` | Test code | Validation baseline | Current provider helper baseline |
| `tests\netebpfext_unit\netebpf_ext_helper.h` | Test code | Validation baseline | Current program-info client baseline |
| `tests\unit\export_program_info_test.cpp` | Test code | Adjacent BTF baseline | Current BTF registry-publication tests |
| `tests\unit\btf_verifier_test.cpp` | Test code | Adjacent BTF baseline | Current BTF verifier / module-guid lineage tests |
| `tests\bpf2c_tests\bpf_test.cpp` | Test code | Adjacent BTF baseline | Current native test harness for BTF runtime data |
| `tests\bpf2c_plugin\bpf2c_test.cpp` | Test code | Adjacent BTF baseline | Current plugin/native test harness for BTF runtime data |
| `tests\sample\unsafe\btf_resolved.c` | Test code | Adjacent BTF baseline | Sample BTF import using a `module_id:` declaration tag |
| Existing design document | Design doc | None provided | Recorded as absent for this run |
| Existing validation document | Validation doc | None provided | Recorded as absent for this run |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-NMR-001 | Register BTF providers against a BTF-resolved-function NPI. | PARTIAL | MISSING | Adjacent BTF metadata exists, but NMR provider registration still exists only for `EBPF_PROGRAM_INFO_EXTENSION_IID`. |
| REQ-NMR-002 | Use the driver's module GUID as `ModuleId`. | PARTIAL | PARTIAL | Module-GUID lineage already exists across declaration tags, store publication, verifier lookup, and generated native metadata, but not yet as a BTF NMR `ModuleId`. |
| REQ-NMR-003 | Publish `ebpf_btf_resolved_function_provider_data_t` via `NpiSpecificCharacteristics`. | MISSING | MISSING | Current code/tests use registry-publication types and `ebpf_program_data_t`, not a BTF NMR payload. |
| REQ-NMR-004 | Include count, prototype array, and address array in provider data. | MISSING | MISSING | Native/runtime code already has address slots, but no NMR provider-data type or validator exists. |
| REQ-NMR-005 | Do not require a provider dispatch table. | PARTIAL | PARTIAL | Existing data-provider patterns already use `provider_dispatch = NULL`, and current BTF runtime tests consume direct addresses, but not through a BTF provider. |
| REQ-NMR-006 | Preserve the same module GUID across phases. | PARTIAL | PARTIAL | Cross-phase identity is largely present outside NMR; the NMR hop is still missing. |
| REQ-NMR-007 | Extend the existing execution-context NMR provider pattern. | SATISFIED | SATISFIED | The current execution-context/provider helper architecture remains the right extension point. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-NMR-001 | Register BTF providers against a BTF-resolved-function NPI. | CE-001, CE-002, CE-008 | PARTIAL | DD-001 | `include\ebpf_extension_uuids.h`; `[UNKNOWN: BTF provider registration site]` | TE-001, TE-002, TE-003, TE-007 | MISSING | VD-001 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `tests\end_to_end\helpers.h` | Provider registration exists, but only for the current program-info NPI. |
| REQ-NMR-002 | Use the driver's module GUID as `ModuleId`. | CE-002, CE-004, CE-005, CE-006, CE-007 | PARTIAL | DD-002 | `[UNKNOWN: BTF provider registration site]`; consumer-side match helper | TE-004, TE-005, TE-006 | PARTIAL | VD-002 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: BTF consumer helper]` | Module-GUID lineage exists outside NMR, but no BTF provider path uses it as `ModuleId` yet. |
| REQ-NMR-003 | Publish `ebpf_btf_resolved_function_provider_data_t` via `NpiSpecificCharacteristics`. | CE-003, CE-004, CE-005, CE-008 | MISSING | DD-003 | `[ASSUMPTION] include\ebpf_extension.h`; `[UNKNOWN: BTF provider publisher]` | TE-001, TE-002, TE-007 | MISSING | VD-003 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: helper header]` | No BTF NMR provider-data type or usage exists. |
| REQ-NMR-004 | Include count, prototype array, and address array in provider data. | CE-004, CE-006, CE-008 | MISSING | DD-004 | `libs\execution_context\ebpf_program.c` or sibling validator; `[UNKNOWN: BTF consumer attach path]` | TE-006, TE-007 | MISSING | VD-004 | `libs\execution_context\unit\execution_context_unit_test.cpp` | Current validation only understands program-info/helper data; runtime BTF address slots exist separately. |
| REQ-NMR-005 | Do not require a provider dispatch table. | CE-002 | PARTIAL | DD-005 | None | TE-002, TE-003, TE-006 | PARTIAL | VD-005 | Minimal or none beyond BTF-specific cases | The no-dispatch pattern exists already, but no BTF-specific case exists. |
| REQ-NMR-006 | Preserve the same module GUID across phases. | CE-004, CE-005, CE-006, CE-007 | PARTIAL | DD-006 | `[UNKNOWN: BTF provider registration site]`; possibly `tools\bpf2c` for ordering guarantees | TE-004, TE-005, TE-006 | PARTIAL | VD-006 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: lineage integration test]` | Existing header/registry/native metadata lineage is reusable, but not yet threaded through NMR. |
| REQ-NMR-007 | Extend the existing execution-context NMR provider pattern. | CE-002, CE-004 | SATISFIED | No-Impact | None | TE-001, TE-002, TE-003 | SATISFIED | No-Impact | None | Existing execution-context/provider helper structure is already the right extension point. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The source requires a dedicated BTF-resolved-function NPI and NMR provider-data contract, but the current implementation only exposes the existing program-info NMR provider contract plus adjacent registry/native metadata contracts. | CE-001, CE-002, CE-005, CE-006, CE-008 | Apply DD-001 and DD-003. |
| CR-002 | Upstream-downstream | The source requires BTF-specific provider data with function count/prototype/address arrays, but the current execution-context validator only understands `ebpf_program_data_t`. | CE-004, CE-006, CE-008 | Apply DD-004. |
| CR-003 | Coverage gap | Current tests cover adjacent BTF phases (registry publication, verifier lookup, native runtime metadata) but contain no BTF-resolved NMR provider registration or attach cases. | TE-004, TE-005, TE-006, TE-007 | Apply VD-001 through VD-006. |

## Open Questions

1. [UNKNOWN: which specific execution-context source file should own the future BTF-resolved provider registration implementation.]
2. [UNKNOWN: which specific consumer-side attach path will validate and consume `ebpf_btf_resolved_function_provider_data_t` once the BTF NPI is introduced.]
3. [UNKNOWN: whether the final public declaration site for `ebpf_btf_resolved_function_provider_data_t` should mirror other extension provider-data types in `include\ebpf_extension.h` or intentionally diverge.]
4. [KNOWN] No existing design or validation document was provided, so these delta artifacts are synthesized from requirements plus code/test evidence only.

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `include\ebpf_extension_uuids.h:11-27` | The current public UUID header defines no BTF-resolved-function NPI identifier. | Establishes the missing public NPI contract. |
| CE-002 | `libs\execution_context\ebpf_core.c:195-208`, `libs\execution_context\ebpf_core.c:213-242`, `libs\execution_context\ebpf_core.c:323-349` | Execution-context registers the existing program-info provider with GUID-typed `ModuleId`, typed `NpiSpecificCharacteristics`, and `provider_dispatch = NULL`. | Establishes the current provider-registration baseline and the no-dispatch pattern. |
| CE-003 | `include\ebpf_extension.h:494-501` | Existing extension provider-data types live in `include\ebpf_extension.h`, but no BTF-resolved NMR provider payload is declared there. | Establishes the likely public-header extension point without guessing the final declaration site. |
| CE-004 | `libs\execution_context\ebpf_program.c:217-310` | Consumer-side code requires GUID `ModuleId` and validates `ebpf_program_data_t` from `NpiSpecificCharacteristics`. | Establishes the current matching/validation baseline. |
| CE-005 | `include\ebpf_store_helper.h:23-39`, `include\ebpf_store_helper.h:103-111` | The current BTF registry-publication contract uses `module_guid`, function count, and a prototype array. | Establishes that BTF provider identity and prototype metadata already exist outside NMR. |
| CE-006 | `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170`, `include\bpf2c.h:176-200` | Native metadata already includes `btf_resolved_function_entry_t::module_guid`, `program_runtime_context_t::btf_resolved_function_data`, and `program_entry_t::btf_resolved_function_count`. | Establishes that the native side already carries BTF dependency identity, counts, and address slots. |
| CE-007 | `tools\bpf2c\bpf_code_generator.cpp:2557-2625` | `bpf2c` emits per-program BTF dependency arrays and counts from module-guid keyed dependency state. | Establishes deterministic native metadata emission adjacent to the missing NMR contract. |
| CE-008 | Searches over `include\` and `libs\execution_context` for `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID`, `ebpf_btf_resolved_function_provider_data_t`, and BTF-specific `NmrRegisterProvider` usage returned no implementation matches. | No BTF-resolved provider contract exists in the in-scope implementation. | Establishes the remaining feature gap. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test.cpp:2516-2694` | Unit tests validate provider registration using `EBPF_PROGRAM_INFO_EXTENSION_IID` and malformed `ebpf_program_data_t` cases. | Establishes the current execution-context provider-data validation baseline. |
| TE-002 | `tests\end_to_end\helpers.h:1527-1560` | End-to-end provider helper uses `EBPF_PROGRAM_INFO_EXTENSION_IID`, GUID-typed `ModuleId`, and `provider_dispatch = NULL`. | Establishes the current provider-helper baseline. |
| TE-003 | `tests\netebpfext_unit\netebpf_ext_helper.h:185-199` | Program-info client helper subscribes to `EBPF_PROGRAM_INFO_EXTENSION_IID`. | Establishes the current consumer-side NPI baseline. |
| TE-004 | `tests\unit\export_program_info_test.cpp:155-204` | Tests validate BTF provider registry publication and invalid-input rejection via `ebpf_store_update_btf_resolved_function_provider_information`. | Establishes current BTF publication coverage outside NMR. |
| TE-005 | `tests\unit\btf_verifier_test.cpp:141-220` | Tests publish BTF provider metadata keyed by module GUID and resolve verifier metadata via matching `module_id:` declaration tags. | Establishes current header/registry/verifier GUID-lineage coverage outside NMR. |
| TE-006 | `tests\sample\unsafe\btf_resolved.c:6-17`; `tests\bpf2c_tests\bpf_test.cpp:82-117`; `tests\bpf2c_plugin\bpf2c_test.cpp:188-223` | The sample program uses a `module_id:` declaration tag, and the native test harnesses populate `runtime_context->btf_resolved_function_data` directly from generated BTF dependency metadata. | Establishes current header/native-runtime lineage and shows that BTF address consumption exists without NMR attach coverage. |
| TE-007 | Searches over `include\`, `libs\execution_context`, and `tests\` for `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID`, `ebpf_btf_resolved_function_provider_data_t`, and BTF-specific `NmrRegisterProvider` usage returned no BTF NMR provider fixtures. | No BTF-resolved NMR provider tests exist in the examined test tree. | Establishes the feature-specific validation gap. |

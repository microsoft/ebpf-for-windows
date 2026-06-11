<!-- Delta artifact: NMR Provider Registration alignment set -->

# NMR Provider Registration — Validation Delta

## 1. Change Context

- **Area**: NMR Provider Registration
- **Requirements source**: `docs\specs\btfid\06-nmr-provider-registration.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this run
- **Code scope**: `libs\execution_context`
- **Test scope**: `libs\execution_context\unit`; selected provider/client helpers plus adjacent BTF registry/verifier/native-codegen tests under `tests\`
- **Goal**: identify the minimal validation-spec deltas needed to align test coverage with the NMR-provider-registration requirements

[KNOWN] Current tests already cover adjacent BTF-resolved-function phases: `export_program_info_test` validates registry
publication, `btf_verifier_test` validates module-GUID / declaration-tag lookup against published metadata, and the
`bpf2c` native harnesses populate `runtime_context->btf_resolved_function_data` directly from generated metadata.
[KNOWN] No current test covers a dedicated BTF-resolved-function NPI, BTF `ModuleId` handling through NMR, or a
BTF-specific provider-data payload attached through `NpiSpecificCharacteristics`. (Evidence: TE-001, TE-002, TE-003,
TE-004, TE-005, TE-006, TE-007)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-NMR-001 | Add | Required | Add tests for registration against a dedicated BTF-resolved-function NPI. | TE-001, TE-002, TE-003, TE-007 |
| VD-002 | REQ-NMR-002 | Add | Required | Add tests that verify BTF provider `ModuleId` reuses the same module-GUID lineage already exercised by the current BTF fixtures. | TE-004, TE-005, TE-006 |
| VD-003 | REQ-NMR-003 | Add | Required | Add tests that publish and consume `ebpf_btf_resolved_function_provider_data_t` through `NpiSpecificCharacteristics`. | TE-001, TE-002, TE-007 |
| VD-004 | REQ-NMR-004 | Add | Required | Add validation tests for BTF-resolved function count/prototype/address array shape and correspondence. | TE-001, TE-006, TE-007 |
| VD-005 | REQ-NMR-005 | No-Impact/Constrain | Partially satisfied | Preserve the existing `provider_dispatch = NULL` validation pattern and direct-address consumption model for the BTF provider. | TE-002, TE-003, TE-006 |
| VD-006 | REQ-NMR-006 | Add | Required | Add tests that bridge the existing header/registry/native metadata GUID lineage into BTF NMR attachment. | TE-004, TE-005, TE-006 |
| VD-007 | REQ-NMR-007 | No-Impact | Not required | Extend the existing provider/helper test infrastructure and reuse current BTF fixtures instead of creating a separate validation architecture. | TE-001, TE-002, TE-003, TE-004, TE-005, TE-006 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-NMR-001
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-003, TE-007
- **Expected test change locations**: `libs\execution_context\unit\execution_context_unit_test.cpp`; `tests\end_to_end\helpers.h`; `[UNKNOWN: any additional BTF consumer/provider integration test helper]`
- **Before**: Current tests register only the existing program-info providers and clients; no test registers a
  BTF-resolved-function provider or uses a BTF-resolved NPI. (Evidence: TE-001, TE-002, TE-003, TE-007)
- **After**: Add tests that register a BTF-resolved provider against the dedicated BTF NPI and verify consumer
  attachment behavior.
- **Rationale**: The new NPI identity is a core contract change and needs direct coverage rather than inference from
  adjacent BTF tests.

### VD-002

- **Upstream REQ-ID**: REQ-NMR-002
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005, TE-006
- **Expected test change locations**: `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: any BTF consumer-side test helper]`
- **Before**: Current adjacent BTF tests already reuse the same module GUID across registry publication, verifier lookup,
  declaration tags, and generated native metadata, but none validate that the same GUID is used as the provider's NMR
  `ModuleId`. (Evidence: TE-004, TE-005, TE-006)
- **After**: Add tests that verify BTF provider registration or attach fails when the NMR `ModuleId` does not match the
  expected driver module GUID.
- **Rationale**: GUID continuity is already a tested adjacent invariant; this delta extends that invariant into the
  currently untested NMR stage.

### VD-003

- **Upstream REQ-ID**: REQ-NMR-003
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-007
- **Expected test change locations**: `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: any reusable test helper header]`
- **Before**: Current execution-context tests only publish `ebpf_program_data_t` through `NpiSpecificCharacteristics`.
  No test publishes or consumes a BTF-resolved NMR provider-data payload. (Evidence: TE-001, TE-002, TE-007)
- **After**: Add tests that publish and consume `ebpf_btf_resolved_function_provider_data_t` through
  `NpiSpecificCharacteristics`.
- **Rationale**: The provider-data type is the central new NMR payload contract and needs explicit positive coverage.

### VD-004

- **Upstream REQ-ID**: REQ-NMR-004
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-006, TE-007
- **Expected test change locations**: `libs\execution_context\unit\execution_context_unit_test.cpp`
- **Before**: Current negative tests validate malformed `ebpf_program_data_t`, and current BTF native harnesses only
  populate address slots directly. There is no equivalent validation coverage for BTF-resolved function
  count/prototype/address arrays. (Evidence: TE-001, TE-006, TE-007)
- **After**: Add positive and negative tests for mismatched function count, missing prototype array, missing address
  array, and any ordering/correspondence rules adopted for the BTF provider data.
- **Rationale**: The current validation suite already proves the pattern for typed provider-data validation; it should be
  extended rather than duplicated.

### VD-005

- **Upstream REQ-ID**: REQ-NMR-005
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-003, TE-006
- **Expected test change locations**: Minimal or none beyond new BTF-specific cases
- **Before**: Existing provider helper code already sets `provider_dispatch = NULL` for data-driven NMR providers, and
  existing BTF native harnesses already consume direct addresses through `btf_resolved_function_data`. (Evidence: TE-002,
  TE-003, TE-006)
- **After**: Reuse those same assertion patterns for the BTF-resolved provider path.
- **Rationale**: This requirement is already aligned as a pattern; it only needs feature-specific carry-forward.

### VD-006

- **Upstream REQ-ID**: REQ-NMR-006
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-004, TE-005, TE-006
- **Expected test change locations**: `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: any lineage integration test that reuses current BTF fixtures]`
- **Before**: Current adjacent BTF tests already tie the same module GUID across registry publication, verifier lookup,
  declaration tags, and generated native metadata, but no test ties that lineage to BTF provider registration and
  attachment. (Evidence: TE-004, TE-005, TE-006)
- **After**: Add tests that verify the same module GUID is required end-to-end for BTF provider registration and
  consumption through NMR.
- **Rationale**: Cross-phase identity is already partially proven outside NMR; this delta closes the last untested hop.

### VD-007

- **Upstream REQ-ID**: REQ-NMR-007
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-003, TE-004, TE-005, TE-006
- **Expected test change locations**: None
- **Before**: Existing unit and helper tests already provide the NMR test architecture for data-driven providers, and the
  current BTF tests already provide reusable module-guid / prototype / runtime-address fixtures. (Evidence: TE-001,
  TE-002, TE-003, TE-004, TE-005, TE-006)
- **After**: No new validation architecture is required; extend the existing provider/helper tests and reuse current BTF
  fixtures where practical.
- **Rationale**: The current test pattern and adjacent BTF fixtures are already the correct extension points.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-NMR-001 | MISSING | VD-001 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `tests\end_to_end\helpers.h`; `[UNKNOWN: BTF integration helper]` | No BTF-resolved NPI registration test exists. |
| REQ-NMR-002 | PARTIAL | VD-002 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: BTF consumer helper]` | Adjacent module-GUID lineage tests exist, but none validate NMR `ModuleId`. |
| REQ-NMR-003 | MISSING | VD-003 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: helper header]` | No BTF provider-data payload test exists. |
| REQ-NMR-004 | MISSING | VD-004 | `libs\execution_context\unit\execution_context_unit_test.cpp` | No BTF provider-data field validation test exists. |
| REQ-NMR-005 | PARTIAL | VD-005 | Minimal or none beyond BTF-specific cases | Existing no-dispatch and direct-address patterns are already covered for adjacent providers / runtimes. |
| REQ-NMR-006 | PARTIAL | VD-006 | `libs\execution_context\unit\execution_context_unit_test.cpp`; `[UNKNOWN: lineage integration test]` | Cross-phase GUID lineage is partially tested outside NMR only. |
| REQ-NMR-007 | SATISFIED | No-Impact | None | Existing NMR/provider helper infrastructure is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] Existing validation already relies on unit-level NMR provider registration tests and reusable provider/client
  helpers; the proposed deltas preserve that architecture. (Evidence: TE-001, TE-002, TE-003)
- [KNOWN] Existing adjacent BTF tests already supply reusable fixtures for module GUIDs, declaration tags, published
  prototypes, and runtime-address slots; the proposed deltas preserve those fixtures and extend them into NMR coverage.
  (Evidence: TE-004, TE-005, TE-006)
- [KNOWN] Existing data-provider helpers already treat `provider_dispatch = NULL` as normal for data-driven NPIs, and
  current BTF native harnesses already consume direct addresses. The proposed deltas preserve those invariants. (Evidence:
  TE-002, TE-003, TE-006)

## 6. Application Notes

1. [KNOWN] No existing validation plan was provided, so these deltas are synthesized additions rather than edits to a
   prior plan.
2. [KNOWN] The main testing gap is no longer “no BTF coverage at all”; it is specifically the absence of BTF-specific
   NMR provider-registration, `ModuleId`, and provider-data tests.
3. [KNOWN] Some future test locations remain `[UNKNOWN]` because no BTF-resolved consumer/provider helper exists in the
   current execution-context test tree.

## Coverage
- **Examined**: `libs\execution_context\unit\execution_context_unit_test.cpp`; `tests\end_to_end\helpers.h`; `tests\netebpfext_unit\netebpf_ext_helper.h`; `tests\unit\export_program_info_test.cpp`; `tests\unit\btf_verifier_test.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_plugin\bpf2c_test.cpp`; `tests\sample\unsafe\btf_resolved.c`; repo-wide test searches for BTF-resolved NMR symbols
- **Method**: targeted `view` on provider registration helpers, BTF registry/verifier/native fixtures, and negative validation tests; targeted `rg` for BTF-resolved provider symbols and NMR provider registration usage
- **Excluded**: runtime execution tests after successful NMR attachment
- **Limitations**: no BTF-resolved NMR provider tests currently exist, so several future test files remain `[UNKNOWN]`

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `libs\execution_context\unit\execution_context_unit_test.cpp:2516-2694` | Unit tests register providers against `EBPF_PROGRAM_INFO_EXTENSION_IID` and validate malformed `ebpf_program_data_t` through negative cases. | Establishes the current provider-data validation test baseline. |
| TE-002 | `tests\end_to_end\helpers.h:1527-1560` | End-to-end provider helper uses `EBPF_PROGRAM_INFO_EXTENSION_IID`, GUID-typed `ModuleId`, and `provider_dispatch = NULL`. | Establishes the current provider-helper baseline. |
| TE-003 | `tests\netebpfext_unit\netebpf_ext_helper.h:185-199` | The netebpfext unit test helper registers a program-info client against `EBPF_PROGRAM_INFO_EXTENSION_IID`. | Establishes the current consumer-side NPI baseline. |
| TE-004 | `tests\unit\export_program_info_test.cpp:155-204` | Tests validate BTF provider registry publication and invalid-input rejection via `ebpf_store_update_btf_resolved_function_provider_information`. | Establishes current BTF publication coverage outside NMR. |
| TE-005 | `tests\unit\btf_verifier_test.cpp:141-220` | Tests publish BTF provider metadata keyed by module GUID and resolve verifier metadata via matching `module_id:` declaration tags. | Establishes current header/registry/verifier GUID-lineage coverage outside NMR. |
| TE-006 | `tests\sample\unsafe\btf_resolved.c:6-17`; `tests\bpf2c_tests\bpf_test.cpp:82-117`; `tests\bpf2c_plugin\bpf2c_test.cpp:188-223` | The sample program uses a `module_id:` declaration tag, and the native test harnesses populate `runtime_context->btf_resolved_function_data` directly from generated BTF dependency metadata. | Establishes current header/native-runtime lineage and shows that BTF address consumption exists without NMR attach coverage. |
| TE-007 | Searches over `include\`, `libs\execution_context`, and `tests\` for `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID`, `ebpf_btf_resolved_function_provider_data_t`, and BTF-specific `NmrRegisterProvider` usage returned no BTF NMR provider fixtures. | No BTF-resolved provider test coverage exists for the NMR contract itself. | Establishes the feature-specific validation gap. |

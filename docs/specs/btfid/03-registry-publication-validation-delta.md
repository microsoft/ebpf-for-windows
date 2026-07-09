<!-- Delta artifact: Registry Publication alignment set -->

# Registry Publication — Validation Delta

## 1. Change Context

- **Area**: Registry Publication
- **Requirements source**: `docs\specs\btfid\03-registry-publication.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this run
- **Code scope**: `libs\store_helper`
- **Test scope**: `tests`
- **Goal**: identify the minimal validation-spec deltas needed to align test coverage with the registry-publication requirements

[KNOWN] The examined tests use existing section/program store-helper APIs as setup utilities, but no examined test asserts BTF-resolved-function publication behavior, registry layout, schema, or dual-root error-handling. (Evidence: TE-001, TE-002, TE-003)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-REG-001 | Add | Required | Add tests for the BTF provider registry subtree under `Providers\BtfResolvedFunctions\{module_guid}`. | TE-001, TE-002, TE-003 |
| VD-002 | REQ-REG-002 | Add | Required | Add tests that verify `Version` and `Size` values are written on the provider GUID node. | TE-001, TE-003 |
| VD-003 | REQ-REG-003 | Add | Required | Add tests that verify the `Functions` child collection and function-name keyed records. | TE-001, TE-003 |
| VD-004 | REQ-REG-004 | Add | Required | Add tests that verify discrete `Prototype`, `ReturnType`, `Arguments`, and `Flags` values instead of helper-style binary serialization. | TE-001, TE-003 |
| VD-005 | REQ-REG-005 | Add | Required | Add API-focused tests for the new BTF publication entry point, invalid input handling, and cleanup. | TE-001, TE-002, TE-003 |
| VD-006 | REQ-REG-006 | Add | Required | Add tests that confirm published metadata is observable immediately after publication returns, before any dependent verification path is invoked. | TE-002, TE-003 |
| VD-007 | REQ-REG-007 | Add | Required | Add tests for HKCU/HKLM wrapper behavior, including HKLM access-denied suppression if the test harness can simulate it. | TE-001, TE-003 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-REG-001
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-003
- **Expected test change locations**: `tests\export_program_info_test\`; `[UNKNOWN: any new dedicated BTF store-helper test file name]`
- **Before**: The examined tests call existing section/program store-helper APIs but do not assert the existence of a BTF provider subtree rooted at `Providers\BtfResolvedFunctions\{module_guid}`. (Evidence: TE-001, TE-002, TE-003)
- **After**: Add a validation case that publishes one BTF provider and asserts the provider GUID node appears beneath the BTF-specific registry subtree in the selected root.
- **Rationale**: This is the minimal validation needed to prove the new design delta for REQ-REG-001 is visible in the registry.

### VD-002

- **Upstream REQ-ID**: REQ-REG-002
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003
- **Expected test change locations**: `tests\export_program_info_test\`
- **Before**: No examined test asserts provider-node metadata values such as `Version` or `Size`. (Evidence: TE-001, TE-003)
- **After**: Add assertions that the BTF provider GUID node contains the required `Version` and `Size` values and that they match the published provider metadata.
- **Rationale**: REQ-REG-002 is not covered by setup-only tests; direct registry assertions are required.

### VD-003

- **Upstream REQ-ID**: REQ-REG-003
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003
- **Expected test change locations**: `tests\export_program_info_test\`
- **Before**: No examined test asserts that a BTF `Functions` collection exists or that functions are keyed by name. (Evidence: TE-001, TE-003)
- **After**: Add assertions that publication creates a `Functions` child collection and one child record per BTF function name.
- **Rationale**: This validates the lookup topology the verifier depends on.

### VD-004

- **Upstream REQ-ID**: REQ-REG-004
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003
- **Expected test change locations**: `tests\export_program_info_test\`
- **Before**: No examined test distinguishes discrete per-field BTF metadata values from the helper binary-serialization pattern. (Evidence: TE-001, TE-003)
- **After**: Add assertions that each published BTF function record contains discrete `Prototype`, `ReturnType`, `Arguments`, and `Flags` values and that no helper-style binary prototype blob is treated as sufficient coverage for this requirement.
- **Rationale**: This closes the explicit schema conflict between the BTF requirements and the nearest existing helper pattern.

### VD-005

- **Upstream REQ-ID**: REQ-REG-005
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-003
- **Expected test change locations**: `tests\export_program_info_test\`; `[UNKNOWN: any dedicated negative-input test file name]`
- **Before**: The examined tests use existing APIs but do not exercise a BTF-resolved-function publication API because none exists in the current baseline. (Evidence: TE-001, TE-002, TE-003)
- **After**: Add API-level tests for successful publication, invalid input rejection, and cleanup behavior for the new BTF publication entry point.
- **Rationale**: A new store API needs direct API-level validation instead of only indirect end-to-end consumption.

### VD-006

- **Upstream REQ-ID**: REQ-REG-006
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-002, TE-003
- **Expected test change locations**: `tests\export_program_info_test\`; `tests\cilium\cilium_tests.cpp` only if reused for sequencing coverage
- **Before**: `tests\cilium\cilium_tests.cpp` demonstrates that section/program information is written before verification is invoked, but no examined test proves the same sequencing for BTF-resolved-function metadata. (Evidence: TE-002, TE-003)
- **After**: Add a sequencing test that publishes BTF metadata and confirms it is observable immediately after the API returns, before any dependent verification step is attempted.
- **Rationale**: This is the closest validation analogue available within the current test scope for the verification-time availability requirement.

### VD-007

- **Upstream REQ-ID**: REQ-REG-007
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003
- **Expected test change locations**: `tests\export_program_info_test\`; `[UNKNOWN: any harness required to simulate HKLM access denial]`
- **Before**: No examined test asserts dual-root write behavior or HKLM `EBPF_ACCESS_DENIED` suppression. (Evidence: TE-001, TE-003)
- **After**: Add tests that verify HKCU publication occurs first and that the HKLM pass either succeeds or is explicitly tolerated when it returns `EBPF_ACCESS_DENIED`, if the available test harness can force that condition.
- **Rationale**: REQ-REG-007 is derived from an implementation convention, so it requires direct behavioral validation rather than indirect registry-layout assertions.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-REG-001 | MISSING | VD-001 | `tests\export_program_info_test\` | No BTF subtree assertions exist. |
| REQ-REG-002 | MISSING | VD-002 | `tests\export_program_info_test\` | No provider-node value assertions exist. |
| REQ-REG-003 | MISSING | VD-003 | `tests\export_program_info_test\` | No `Functions` collection assertions exist. |
| REQ-REG-004 | MISSING | VD-004 | `tests\export_program_info_test\` | No BTF per-field schema assertions exist. |
| REQ-REG-005 | MISSING | VD-005 | `tests\export_program_info_test\` | No BTF publication API exists, so no API tests exist. |
| REQ-REG-006 | PARTIAL | VD-006 | `tests\export_program_info_test\`; `tests\cilium\cilium_tests.cpp` | Current tests show publication-before-verification only for section/program metadata. |
| REQ-REG-007 | MISSING | VD-007 | `tests\export_program_info_test\` | No dual-root or HKLM access-denied assertions exist. |

## 5. Invariant Impact

- [KNOWN] Existing tests use store-helper APIs primarily as setup/teardown utilities; the proposed validation deltas preserve that role but add direct registry assertions where the requirements demand them. (Evidence: TE-001, TE-002)
- [KNOWN] No examined test currently validates dual-root wrapper behavior, so VD-007 introduces new behavioral coverage rather than changing an existing asserted invariant. (Evidence: TE-001, TE-003)
- [KNOWN] No examined test currently validates the helper binary-serialization format itself, so VD-004 can assert a different BTF-specific schema without conflicting with existing test intent. (Evidence: TE-001, TE-003)

## 6. Application Notes

1. [KNOWN] No existing validation plan was provided, so these deltas are synthesized additions rather than edits to a prior plan.
2. [KNOWN] The most important missing validation is direct registry inspection for the BTF path and per-function values; setup-only API calls are not sufficient to prove the registry contract.
3. [KNOWN] HKLM access-denied simulation may require additional test harness support that is not visible in the provided test scope; this remains an explicit open question rather than an assumed existing capability.

## Coverage
- **Examined**: `tests\export_program_info_test\export_program_info_test.cpp`; `tests\cilium\cilium_tests.cpp`; `docs\specs\btfid\03-registry-publication.md`
- **Method**: `view` on relevant test files; `rg "ebpf_store_update_global_helper_information|ebpf_store_update_section_information|ebpf_store_update_program_information_array|ebpf_store_delete_program_information|ebpf_store_delete_section_information" Q:\ebpf-for-windows\tests`; `rg "BtfResolvedFunctions|btf_resolved_function|btf_resolved" Q:\ebpf-for-windows\tests`; `rg "ebpf_open_registry_key|ebpf_create_registry_key|Registry|HKCU|HKLM|ebpf_delete_registry_tree|ebpf_read_registry|ebpf_write_registry" Q:\ebpf-for-windows\tests`
- **Excluded**: generated expected files under `tests\bpf2c_tests\expected` as direct validation evidence for this area, because they are generated outputs unrelated to `store_helper` registry-publication tests; code outside `tests` was not used as test evidence
- **Limitations**: no examined test file in the provided scope references BTF-resolved-function publication directly

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\export_program_info_test\export_program_info_test.cpp:75-127` | Utility-style test code calls `ebpf_store_update_program_information_array`, `ebpf_store_update_section_information`, and matching delete APIs, but contains no registry assertions and no BTF publication flow. | Shows current test usage of store-helper APIs without requirement-level coverage for BTF registry publication. |
| TE-002 | `tests\cilium\cilium_tests.cpp:93-200` | `register_xdp_program_information()` publishes program/section metadata before verifier calls, then verification proceeds against XDP objects. | Shows partial sequencing coverage analogous to REQ-REG-006, but not for BTF metadata. |
| TE-003 | `tests\` search using `rg "BtfResolvedFunctions|btf_resolved_function|btf_resolved"` returned no matches. | No BTF-resolved-function-specific test evidence exists in the provided test scope. | Establishes that all BTF registry-publication validation is currently missing. |

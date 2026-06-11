<!-- Delta artifact: Registry Publication alignment set -->

# Registry Publication — Requirements / Code / Test Traceability

## Coverage

- **Target**: Registry-publication requirements for BTF-resolved functions, joined against `libs\store_helper` code and `tests` coverage
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\03-registry-publication.md`
  - `view Q:\ebpf-for-windows\libs\store_helper\ebpf_store_helper.c` on relevant line ranges
  - `view Q:\ebpf-for-windows\tests\export_program_info_test\export_program_info_test.cpp`
  - `view Q:\ebpf-for-windows\tests\cilium\cilium_tests.cpp`
  - `rg "ebpf_store_update_global_helper_information|ebpf_store_update_section_information|ebpf_store_update_program_information_array|ebpf_store_delete_program_information|ebpf_store_delete_section_information" Q:\ebpf-for-windows\tests`
  - `rg "BtfResolvedFunctions|btf_resolved_function|btf_resolved" Q:\ebpf-for-windows\tests`
  - `rg "ebpf_open_registry_key|ebpf_create_registry_key|Registry|HKCU|HKLM|ebpf_delete_registry_tree|ebpf_read_registry|ebpf_write_registry" Q:\ebpf-for-windows\tests`
- **Excluded**: code outside `libs\store_helper`; tests unrelated to store-helper publication semantics; generated expected files under `tests\bpf2c_tests\expected` as direct validation evidence
- **Limitations**: the provided code scope contains no BTF-resolved-function publication implementation, and the provided test scope contains no BTF-resolved-function publication tests

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\03-registry-publication.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-REG-001 through REQ-REG-007 |
| `libs\store_helper\ebpf_store_helper.c` | Code | Implementation baseline | Contains adjacent store-helper publication and deletion patterns |
| `tests\export_program_info_test\export_program_info_test.cpp` | Test code | Existing validation baseline | Uses existing program/section store APIs as setup utilities |
| `tests\cilium\cilium_tests.cpp` | Test code | Existing validation baseline | Demonstrates pre-verification publication sequencing for non-BTF metadata |
| Existing design document | Design doc | None provided | Recorded as absent for this run |
| Existing validation document | Validation doc | None provided | Recorded as absent for this run |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-REG-001 | Publish BTF metadata under `Providers\BtfResolvedFunctions\{module_guid}`. | PARTIAL | MISSING | Common provider root exists; BTF subtree does not. |
| REQ-REG-002 | Publish `Version` and `Size` on the provider node. | PARTIAL | MISSING | Existing extension-header writer exists; no BTF provider-node writer exists. |
| REQ-REG-003 | Publish a `Functions` child collection keyed by function name. | MISSING | MISSING | No examined BTF function collection exists. |
| REQ-REG-004 | Publish per-function `Prototype`, `ReturnType`, `Arguments`, and `Flags` values. | CONFLICT | MISSING | Closest existing schema serializes helper data into a binary blob. |
| REQ-REG-005 | Support provider-level publication through a BTF store API. | MISSING | MISSING | Existing update APIs cover other metadata only. |
| REQ-REG-006 | Make provider metadata available before verification depends on it. | PARTIAL | PARTIAL | Current synchronous writers and cilium setup show the pattern for non-BTF metadata only. |
| REQ-REG-007 | Follow the existing dual-root store-helper publication convention. | PARTIAL | MISSING | Convention exists in adjacent flows; no BTF flow or tests apply it yet. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-REG-001 | Publish BTF metadata under `Providers\BtfResolvedFunctions\{module_guid}`. | CE-001, CE-004, CE-005, CE-006 | PARTIAL | DD-001 | `libs\store_helper\ebpf_store_helper.c` | TE-001, TE-002, TE-003 | MISSING | VD-001 | `tests\export_program_info_test\` | Existing flows only reach sibling subtrees (`GlobalHelpers`, `Sections`, `ProgramData`). |
| REQ-REG-002 | Publish `Version` and `Size` on the provider node. | CE-002 | PARTIAL | DD-002 | `libs\store_helper\ebpf_store_helper.c` | TE-001, TE-003 | MISSING | VD-002 | `tests\export_program_info_test\` | Existing writer is reusable, but no BTF provider-node call site exists. |
| REQ-REG-003 | Publish a `Functions` child collection keyed by function name. | CE-003, CE-005, CE-006 | MISSING | DD-003 | `libs\store_helper\ebpf_store_helper.c` | TE-001, TE-003 | MISSING | VD-003 | `tests\export_program_info_test\` | Keyed-child patterns exist elsewhere but not for BTF functions. |
| REQ-REG-004 | Publish per-function `Prototype`, `ReturnType`, `Arguments`, and `Flags` values. | CE-003 | CONFLICT | DD-004 | `libs\store_helper\ebpf_store_helper.c` | TE-001, TE-003 | MISSING | VD-004 | `tests\export_program_info_test\` | The closest existing schema is helper binary serialization, which conflicts with the required per-field values. |
| REQ-REG-005 | Support provider-level publication through a BTF store API. | CE-004, CE-005, CE-006 | MISSING | DD-005 | `libs\store_helper\ebpf_store_helper.c`; `[UNKNOWN: declaration site outside scope]` | TE-001, TE-002, TE-003 | MISSING | VD-005 | `tests\export_program_info_test\` | No examined BTF publication API exists. |
| REQ-REG-006 | Make provider metadata available before verification depends on it. | CE-001, CE-002, CE-004, CE-005, CE-006 | PARTIAL | DD-006 | `libs\store_helper\ebpf_store_helper.c` | TE-002, TE-003 | PARTIAL | VD-006 | `tests\export_program_info_test\`; `tests\cilium\cilium_tests.cpp` | Current sequencing is demonstrated only for program/section metadata. |
| REQ-REG-007 | Follow the existing dual-root store-helper publication convention. | CE-004, CE-005, CE-006, CE-007 | PARTIAL | DD-007 | `libs\store_helper\ebpf_store_helper.c` | TE-001, TE-003 | MISSING | VD-007 | `tests\export_program_info_test\` | Existing dual-root convention is established but not yet applied to BTF publication. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The registry-publication requirements call for a BTF subtree under `BtfResolvedFunctions`, but the examined implementation only publishes `GlobalHelpers`, `Sections`, and `ProgramData`. | CE-001, CE-004, CE-005, CE-006 | Apply DD-001 and DD-005. |
| CR-002 | Upstream-downstream | The requirements call for discrete per-function values, while the nearest existing implementation pattern serializes helper prototype data into a binary blob. | CE-003 | Apply DD-004 and validate with VD-004. |
| CR-003 | Coverage gap | No examined tests reference BTF-resolved-function publication or assert registry layout for this area. | TE-001, TE-002, TE-003 | Apply VD-001 through VD-007. |

## Open Questions

1. [UNKNOWN: any public declaration site for a new BTF publication API was outside the provided code scope for this run.]
2. [UNKNOWN: the provided test scope does not reveal an existing harness for deterministically forcing HKLM `EBPF_ACCESS_DENIED` during store publication.]
3. [KNOWN] No existing design or validation document was provided, so these delta artifacts are synthesized from requirements plus code/test evidence only.

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\store_helper\ebpf_store_helper.c:25-46` | `_ebpf_store_open_or_create_provider_registry_key` creates the common store root and `Providers` key. | Shared basis for BTF subtree creation. |
| CE-002 | `libs\store_helper\ebpf_store_helper.c:13-21` | `_ebpf_store_update_extension_header_information` writes `version` and `size`. | Reusable pattern for provider-node metadata. |
| CE-003 | `libs\store_helper\ebpf_store_helper.c:50-100` | `_ebpf_store_update_helper_prototype` creates name-keyed helper records and serializes prototype data into a binary value. | Closest existing schema pattern and the main conflict for REQ-REG-004. |
| CE-004 | `libs\store_helper\ebpf_store_helper.c:109-173` | Global-helper publication validates arrays, creates `GlobalHelpers`, and wraps HKCU/HKLM writes. | Establishes sibling API and dual-root convention. |
| CE-005 | `libs\store_helper\ebpf_store_helper.c:177-288` | Section publication creates `Sections`, creates child records by name, and wraps HKCU/HKLM writes. | Establishes keyed-child and dual-root conventions. |
| CE-006 | `libs\store_helper\ebpf_store_helper.c:402-499` | Program-info publication creates `ProgramData`, keys records by GUID, and wraps HKCU/HKLM writes. | Establishes GUID-keyed publication and sibling API shape. |
| CE-007 | `libs\store_helper\ebpf_store_helper.c:502-611` | Delete flows mirror the dual-root convention used by update flows. | Establishes the broader store-helper invariant preserved by DD-007. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\export_program_info_test\export_program_info_test.cpp:75-127` | Calls section/program store-helper update/delete APIs, but performs no registry assertions and no BTF publication. | Shows current setup-style test usage without area coverage. |
| TE-002 | `tests\cilium\cilium_tests.cpp:93-200` | Publishes program/section metadata before verifier calls. | Shows partial sequencing coverage analogous to REQ-REG-006. |
| TE-003 | `tests\` search using `rg "BtfResolvedFunctions|btf_resolved_function|btf_resolved"` returned no matches. | No BTF-resolved-function publication tests exist in the provided scope. | Shows the validation gap is feature-wide within the current test scope. |

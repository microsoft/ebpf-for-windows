<!-- Derived artifact: Stable sample BTF provider alignment set -->

# Sample BTF Provider — Requirements / Code / Test Traceability

## Coverage

- **Target**: derived sample-provider requirements for a stable in-tree BTF-resolved-function provider, joined against current sample-extension code and sample/native-load tests
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\12-sample-btf-provider.md`
  - `view` on `undocked\tests\sample\ext\inc\sample_ext_helpers.h`, `undocked\tests\sample\ext\inc\sample_ext_program_info.h`, `undocked\tests\sample\ext\drv\sample_ext.c`, `undocked\tests\sample\ext\drv\sample_ext.h`, `undocked\tests\sample\ext\drv\sample_ext_drv.c`
  - `view` on `tests\sample\unsafe\btf_resolved.c` and `tests\sample\sample.vcxproj`
  - `rg "btf_resolved|EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID|ebpf_btf_resolved_function_provider_data_t|sample_ebpf_extension_.*provider_(register|unregister)"` over the sample-extension and sample-test trees
- **Excluded**: deep runtime implementation inside `libs\execution_context`; generic non-sample provider code outside the sample/test trees
- **Limitations**: the examined sample-tree code does not yet implement a BTF provider, so several change locations are future-facing and remain `[UNKNOWN]`

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\12-sample-btf-provider.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-SAMP-001 through REQ-SAMP-008 |
| `undocked\tests\sample\ext\inc\sample_ext_helpers.h` | Code | Declaration baseline | Current shared sample-extension include surface |
| `undocked\tests\sample\ext\inc\sample_ext_program_info.h` | Code | Declaration baseline | Current sample helper/program-info metadata pattern |
| `undocked\tests\sample\ext\drv\sample_ext.c` | Code | Implementation baseline | Current sample provider implementations and NMR registration pattern |
| `undocked\tests\sample\ext\drv\sample_ext.h` | Code | Implementation baseline | Current sample driver registration declarations |
| `undocked\tests\sample\ext\drv\sample_ext_drv.c` | Code | Lifecycle baseline | Current sample-driver startup/shutdown provider wiring |
| `tests\sample\unsafe\btf_resolved.c` | Test/sample code | Placeholder baseline | Current placeholder BTF sample contract |
| `tests\sample\sample.vcxproj` | Build/test code | Validation baseline | Current special-case build path for `btf_resolved` |
| Existing design document | Design doc | None provided | Recorded as absent for this derived area |
| Existing validation document | Validation doc | None provided | Recorded as absent for this derived area |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-SAMP-001 | Expose a canonical sample BTF declaration with sample-owned GUID and prototype. | MISSING | MISSING | No such declaration exists in the shared sample include tree. |
| REQ-SAMP-002 | Back the canonical sample BTF contract with `sample_ebpf_ext`. | MISSING | MISSING | No sample-extension BTF provider implementation exists. |
| REQ-SAMP-003 | Publish matching registry metadata before verification. | MISSING | MISSING | No sample-owned BTF publication path exists in scope. |
| REQ-SAMP-004 | Register a matching BTF NMR provider. | MISSING | MISSING | Existing sample provider registration covers only map/program-info/hook. |
| REQ-SAMP-005 | Wire registration/unregistration into the sample driver lifecycle. | MISSING | MISSING | Driver startup/shutdown omits BTF provider handling. |
| REQ-SAMP-006 | Retarget at least one sample program/fixture away from the placeholder GUID/symbol. | MISSING | MISSING | `btf_resolved.c` still uses placeholder metadata and special-case build plumbing. |
| REQ-SAMP-007 | Keep the first contract deterministic and test-oriented. | PARTIAL | PARTIAL | The placeholder contract is simple, but no real sample provider exists yet. |
| REQ-SAMP-008 | Extend existing sample-extension patterns instead of creating a disconnected test-only contract. | SATISFIED | SATISFIED | The sample-extension include/provider model is already the right extension point. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-SAMP-001 | Expose a canonical sample BTF declaration with sample-owned GUID and prototype. | CE-001, CE-004 | MISSING | DD-001 | `undocked\tests\sample\ext\inc\sample_ext_helpers.h`; `[ASSUMPTION] sibling header` | TE-001, TE-002 | MISSING | VD-001 | `tests\sample\unsafe\btf_resolved.c`; any new sample declaration consumer | Only the placeholder fixture defines a BTF declaration today. |
| REQ-SAMP-002 | Back the canonical sample BTF contract with `sample_ebpf_ext`. | CE-002, CE-003, CE-005 | MISSING | DD-002 | `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h` | TE-002, TE-004 | MISSING | VD-002 | `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: sample-provider-specific test helper]` | No sample-extension BTF function/provider exists in scope. |
| REQ-SAMP-003 | Publish matching registry metadata before verification. | CE-005 | MISSING | DD-003 | `[UNKNOWN: sample publication helper or driver-owned publication code]` | TE-003, TE-004 | MISSING | VD-003 | `[UNKNOWN: registry publication validation]` | No sample-owned BTF publication path is visible. |
| REQ-SAMP-004 | Register a matching BTF NMR provider. | CE-002, CE-003 | MISSING | DD-004 | `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h` | TE-003, TE-004 | MISSING | VD-004 | `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: provider attach fixture]` | Existing NMR pattern exists but is not used for BTF. |
| REQ-SAMP-005 | Wire registration/unregistration into the sample driver lifecycle. | CE-003 | MISSING | DD-005 | `undocked\tests\sample\ext\drv\sample_ext_drv.c` | TE-004 | MISSING | VD-005 | `tests\end_to_end\end_to_end.cpp` | Driver lifecycle currently omits BTF provider registration. |
| REQ-SAMP-006 | Retarget at least one sample program/fixture away from the placeholder GUID/symbol. | CE-004, CE-005 | MISSING | DD-006 | `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj` | TE-001, TE-002 | MISSING | VD-001, VD-006 | `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj` | Current sample source/build path is still placeholder-oriented. |
| REQ-SAMP-007 | Keep the first contract deterministic and test-oriented. | CE-002, CE-004 | PARTIAL | DD-007 | `undocked\tests\sample\ext\drv\sample_ext.c` | TE-001, TE-002 | PARTIAL | VD-002, VD-006 | `tests\sample\unsafe\btf_resolved.c`; `tests\end_to_end\end_to_end.cpp` | The intent is visible in the placeholder contract and existing sample helpers, but no real provider proves it yet. |
| REQ-SAMP-008 | Extend existing sample-extension patterns instead of creating a disconnected test-only contract. | CE-001, CE-002, CE-003 | SATISFIED | DD-008 | None | TE-002 | SATISFIED | No-Impact | None | Existing sample-extension structure is already the preferred extension point. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The derived sample-provider requirements need a real in-tree provider contract, but the current sample tree exposes only placeholder `.ksyms` metadata for `btf_resolved`. | CE-004, TE-001 | Apply DD-001, DD-002, and DD-006. |
| CR-002 | Upstream-downstream | The sample driver already has a stable provider-registration lifecycle, but it does not publish or register any BTF-resolved-function provider. | CE-002, CE-003, TE-004 | Apply DD-003, DD-004, and DD-005. |
| CR-003 | Coverage gap | The current tests/build only prove the placeholder sample fixture path, not a sample-driver-owned registry/NMR/runtime path. | TE-001, TE-002, TE-003, TE-004 | Apply VD-001 through VD-006. |

## Open Questions

1. [UNKNOWN: whether the canonical sample BTF declaration should extend `sample_ext_helpers.h` directly or move to a sibling sample-extension header.]
2. [UNKNOWN: which concrete sample publication mechanism will be used to satisfy `03-registry-publication.md` for the sample driver.]
3. [UNKNOWN: whether the existing checked-in generated `btf_resolved` fixtures remain necessary once a real sample provider exists.]

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `undocked\tests\sample\ext\inc\sample_ext_program_info.h:24-103` | The sample-extension include tree already defines shared helper/program-info contracts for sample programs. | Establishes the declaration-pattern baseline. |
| CE-002 | `undocked\tests\sample\ext\drv\sample_ext.c:212-225`, `undocked\tests\sample\ext\drv\sample_ext.c:301-313`, `undocked\tests\sample\ext\drv\sample_ext.c:386-398`, `undocked\tests\sample\ext\drv\sample_ext.c:504-770` | The sample driver already implements and registers map, program-info, and hook providers through NMR. | Establishes the provider-registration baseline. |
| CE-003 | `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170` | Driver unload/startup only unregister/register the existing three sample providers. | Establishes the lifecycle gap. |
| CE-004 | `tests\sample\unsafe\btf_resolved.c:6-17` | The current BTF sample fixture uses a placeholder module GUID and symbol. | Establishes the placeholder-contract gap. |
| CE-005 | `tests\sample\sample.vcxproj:271-276` | The current `btf_resolved` sample uses special-case build plumbing and checked-in generated fixture C. | Establishes the current test/build baseline. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\sample\unsafe\btf_resolved.c:6-17` | The current sample test input for BTF-resolved functions is a placeholder `.ksyms` declaration, not a canonical sample-driver contract. | Establishes the current sample-fixture baseline. |
| TE-002 | `tests\sample\sample.vcxproj:271-276` | The sample build has a dedicated `btf_resolved` path, so existing validation already has a place to host a retargeted canonical sample fixture. | Establishes the immediate build/test extension point. |
| TE-003 | Searches over `undocked\tests\sample\ext`, `tests\sample`, and `tests\end_to_end` for `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID`, `ebpf_btf_resolved_function_provider_data_t`, and `btf_resolved` returned no sample-extension BTF provider implementation or end-to-end sample-provider validation matches. | No current test validates a real sample-provider-backed BTF contract. | Establishes the remaining validation gap. |
| TE-004 | `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170` | Existing sample-driver lifecycle already defines where provider registration and teardown are validated conceptually. | Establishes the lifecycle-oriented validation extension point. |

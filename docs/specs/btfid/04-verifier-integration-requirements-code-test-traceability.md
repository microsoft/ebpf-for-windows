<!-- Delta artifact: Verifier Integration alignment set -->

# Verifier Integration — Requirements / Code / Test Traceability

## Coverage

- **Target**: Verifier-integration requirements for BTF-resolved functions, joined against `libs\api`, `libs\api_common`, and verifier-related tests under `tests`
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\04-verifier-integration.md`
  - `view` on `libs\api\Verifier.cpp`, `libs\api\windows_platform.cpp`, `libs\api\ebpf_api.cpp`
  - `view` on `libs\api_common\api_common.cpp`, `libs\api_common\windows_platform_common.cpp`, `libs\api_common\windows_helpers.cpp`
  - `rg "call_btf|resolve_kfunc_call|kfunc|ksyms|decl_tag|BTF_KIND_DECL_TAG|btf_id|external call|verify|verifier" Q:\ebpf-for-windows\libs\api Q:\ebpf-for-windows\libs\api_common`
  - `view` on `tests\api_test\api_test.cpp`, `tests\end_to_end\end_to_end.cpp`, `tests\cilium\cilium_tests.cpp`
  - `rg "call_btf|kfunc|resolve_kfunc_call|resolve_ksym_btf_id|ksyms|decl_tag|BTF_KIND_DECL_TAG" Q:\ebpf-for-windows\tests`
- **Excluded**: external verifier-library internals outside `libs\api` / `libs\api_common`; runtime/native-code-generation areas outside verifier integration
- **Limitations**: some parser/unmarshal behavior is delegated to out-of-scope libraries, so exact preprocessing internals are not fully observable from the provided code scope

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\04-verifier-integration.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-VER-001 through REQ-VER-007 |
| `libs\api\Verifier.cpp` | Code | Implementation baseline | Verifier entry points, ELF loading, and generic verification flow |
| `libs\api\windows_platform.cpp` | Code | Implementation baseline | Windows verifier platform callback table |
| `libs\api\ebpf_api.cpp` | Code | Implementation baseline | Public verifier-related API surface |
| `libs\api_common\api_common.cpp` | Code | Implementation baseline | Verification/TLS lifecycle |
| `libs\api_common\windows_platform_common.cpp` | Code | Implementation baseline | Program-type and TLS program-info caches |
| `libs\api_common\windows_helpers.cpp` | Code | Implementation baseline | Helper resolution against program-info cache |
| `tests\api_test\api_test.cpp` | Test code | Existing validation baseline | Generic verifier API coverage |
| `tests\end_to_end\end_to_end.cpp` | Test code | Existing validation baseline | End-to-end verifier coverage |
| `tests\cilium\cilium_tests.cpp` | Test code | Existing validation baseline | Repeated verifier API usage over cilium objects |
| Existing design document | Design doc | None provided | Recorded as absent for this run |
| Existing validation document | Validation doc | None provided | Recorded as absent for this run |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-VER-001 | Enumerate BTF-resolved `.ksyms` symbols before verification. | PARTIAL | MISSING | Generic ELF verification path exists, but no explicit Windows-side `.ksyms` handling is visible. |
| REQ-VER-002 | Parse top-level declaration tags and build module-to-function mappings. | MISSING | MISSING | No in-scope decl-tag parsing appears. |
| REQ-VER-003 | Allocate deterministic session-local BTF IDs and reversible mappings. | MISSING | MISSING | No visible BTF ID mapping state exists in scope. |
| REQ-VER-004 | Resolve `call_btf` through `resolve_kfunc_call`. | CONFLICT | MISSING | The Windows platform callback slot is explicitly null today. |
| REQ-VER-005 | Rewrite extern BTF calls into `call_btf`. | PARTIAL | MISSING | `CallBtf` is recognized by the verifier pipeline, but no Windows-side rewrite path is visible. |
| REQ-VER-006 | Keep verifier-assigned BTF IDs ephemeral and non-public. | SATISFIED | SATISFIED | Current public verifier APIs do not expose BTF IDs. |
| REQ-VER-007 | Integrate BTF support through existing verifier entry points and platform table. | PARTIAL | PARTIAL | Existing surface exists, but BTF support is not yet integrated into it. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-VER-001 | Enumerate BTF-resolved `.ksyms` symbols before verification. | CE-002, CE-003 | PARTIAL | DD-001 | `libs\api\Verifier.cpp`; `[UNKNOWN: out-of-scope reader internals]` | TE-001, TE-003, TE-004, TE-005 | MISSING | VD-001 | `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: BTF fixtures]` | Generic verification exists, but no explicit `.ksyms` coverage or Windows-side handling is visible. |
| REQ-VER-002 | Parse top-level declaration tags and build module-to-function mappings. | CE-002, CE-003 | MISSING | DD-002 | `libs\api\Verifier.cpp`; `[UNKNOWN: out-of-scope reader internals]` | TE-001, TE-003, TE-004, TE-005 | MISSING | VD-002 | `tests\api_test\api_test.cpp`; `[UNKNOWN: BTF fixtures]` | No in-scope decl-tag logic or tests exist. |
| REQ-VER-003 | Allocate deterministic session-local BTF IDs and reversible mappings. | CE-001, CE-004, CE-005, CE-006 | MISSING | DD-003 | `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp`; `libs\api_common\windows_platform_common.hpp` | TE-001, TE-005 | MISSING | VD-003 | `tests\api_test\api_test.cpp`; `[UNKNOWN: verifier-state fixture]` | Existing TLS state exists, but no BTF mapping state exists. |
| REQ-VER-004 | Resolve `call_btf` through `resolve_kfunc_call`. | CE-001, CE-004, CE-005, CE-006, CE-008 | CONFLICT | DD-004 | `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp`; `libs\api_common\windows_platform_common.hpp` | TE-001, TE-003, TE-004, TE-005 | MISSING | VD-004 | `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: metadata fixtures]` | The required callback is explicitly null. |
| REQ-VER-005 | Rewrite extern BTF calls into `call_btf`. | CE-002, CE-003 | PARTIAL | DD-005 | `libs\api\Verifier.cpp`; `libs\api\windows_platform.cpp`; `[UNKNOWN: out-of-scope reader/unmarshal internals]` | TE-001, TE-003, TE-004, TE-005 | MISSING | VD-005 | `tests\api_test\api_test.cpp`; `[UNKNOWN: BTF-capable ELF fixtures]` | `CallBtf` is recognized after parsing, but no Windows-side rewrite path is visible. |
| REQ-VER-006 | Keep verifier-assigned BTF IDs ephemeral and non-public. | CE-002, CE-007 | SATISFIED | No-Impact | None | TE-001, TE-002 | SATISFIED | No-Impact | None | Current public verifier APIs expose file/memory verification and program info, not BTF IDs. |
| REQ-VER-007 | Integrate BTF support through existing verifier entry points and platform table. | CE-001, CE-002, CE-006, CE-007 | PARTIAL | DD-006 | `libs\api\Verifier.cpp`; `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp` | TE-001, TE-002, TE-003, TE-004 | PARTIAL | VD-007 | `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `tests\cilium\cilium_tests.cpp` | The current public surface is the right integration point, but BTF support is not yet present there. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The source requires Windows-side BTF callback support, but the current Windows platform table wires both BTF-related callback slots as `nullptr`. | CE-001 | Apply DD-003 and DD-004. |
| CR-002 | Coverage gap | The provided test scope contains generic verifier API coverage but no BTF-verifier coverage for `.ksyms`, declaration tags, BTF ID mapping, or `call_btf`. | TE-001, TE-002, TE-003, TE-004, TE-005 | Apply VD-001 through VD-005 and VD-007. |
| CR-003 | Scope visibility | Some preprocessing behavior is delegated to out-of-scope verifier reader/unmarshal internals, so not every BTF preprocessing detail can be confirmed directly from the provided code scope. | CE-002 | Keep `[UNKNOWN]` placeholders where out-of-scope reader internals may also need change. |

## Open Questions

1. [UNKNOWN: whether `read_elf(...)` or unmarshal internals outside the provided code scope already implement any portion of BTF `.ksyms` / declaration-tag parsing.]
2. [UNKNOWN: where new BTF-verifier ELF/object fixtures should live under `tests` if new samples are required.]
3. [KNOWN] No existing design or validation document was provided, so these delta artifacts are synthesized from requirements plus code/test evidence only.

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\api\windows_platform.cpp:100-113` | `g_ebpf_platform_windows` wires `resolve_ksym_btf_id` and `resolve_kfunc_call` as `nullptr`. | Direct evidence of the current BTF callback gap. |
| CE-002 | `libs\api\Verifier.cpp:802-988` | File/memory verification entry points route ELF input through `read_elf(...)`, `unmarshal(...)`, and `ebpf_verify_program(...)`. | Establishes the current verifier entry-point surface. |
| CE-003 | `libs\api\Verifier.cpp:57-106` | `_instype(...)` recognizes `prevail::CallBtf` as `call_btf`. | Shows existing post-parse recognition of `call_btf`. |
| CE-004 | `libs\api_common\api_common.cpp:195-279` | Verification clears TLS state, sets verification program type, and runs PREVAIL analysis. | Shows current verifier-side TLS/request behavior. |
| CE-005 | `libs\api_common\windows_platform_common.cpp:236-286` | `get_program_type_windows(...)` loads/caches program info and descriptors. | Shows existing cache patterns adjacent to the missing BTF mapping state. |
| CE-006 | `libs\api_common\windows_platform_common.cpp:792-847` | TLS-backed program-info retrieval and cache-clearing helpers exist for verifier state. | Shows the current verifier-side TLS support. |
| CE-007 | `libs\api\ebpf_api.cpp:4847-4873` | Public verifier-related APIs cover program-type lookup and `ebpf_get_program_info_from_verifier(...)`. | Shows the current public verifier surface is BTF-ID free. |
| CE-008 | `libs\api_common\windows_helpers.cpp:27-75` | Helper usability and prototype resolution are implemented against cached program info. | Shows current verifier integration supports helper IDs but not BTF-resolved functions. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\api_test\api_test.cpp:3256-3335` | Exercises generic verifier file/memory APIs and invalid-ELF failure handling. | Establishes current verifier API coverage. |
| TE-002 | `tests\api_test\api_test.cpp:3756-3820` | Exercises verifier success plus `ebpf_get_program_info_from_verifier(...)`. | Establishes current verifier-side TLS/program-info and public-surface coverage. |
| TE-003 | `tests\end_to_end\end_to_end.cpp:1040-1165` | Exercises end-to-end verifier success with registered program info. | Establishes current end-to-end verifier coverage. |
| TE-004 | `tests\cilium\cilium_tests.cpp:143-190` | Exercises repeated file-based verifier calls for cilium objects. | Establishes current verifier API extension-point coverage. |
| TE-005 | `tests\` search using `rg "call_btf|kfunc|resolve_kfunc_call|resolve_ksym_btf_id|ksyms|decl_tag|BTF_KIND_DECL_TAG"` returned no matches. | No BTF-verifier-specific tests exist in the provided scope. | Establishes the feature-specific validation gap. |

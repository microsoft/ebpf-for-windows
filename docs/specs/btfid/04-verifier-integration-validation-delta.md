<!-- Delta artifact: Verifier Integration alignment set -->

# Verifier Integration — Validation Delta

## 1. Change Context

- **Area**: Verifier Integration
- **Requirements source**: `docs\specs\btfid\04-verifier-integration.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this run
- **Code scope**: `libs\api_common`; `libs\api`
- **Test scope**: `tests`
- **Goal**: identify the minimal validation-spec deltas needed to align test coverage with the verifier-integration requirements

[KNOWN] The examined tests already exercise generic verifier file/memory APIs, end-to-end verification success, cilium verification flows, and TLS-backed `ebpf_get_program_info_from_verifier(...)`. [KNOWN] The provided test scope contains no BTF-verifier coverage for `.ksyms`, declaration tags, BTF ID mapping, `call_btf`, or Windows kfunc resolution. (Evidence: TE-001, TE-002, TE-003, TE-004, TE-005)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-VER-001 | Add | Required | Add tests for Windows-side verification of ELF inputs containing BTF-resolved `.ksyms` symbols. | TE-001, TE-003, TE-004, TE-005 |
| VD-002 | REQ-VER-002 | Add | Required | Add tests for declaration-tag-to-module mapping behavior during verification. | TE-001, TE-003, TE-004, TE-005 |
| VD-003 | REQ-VER-003 | Add | Required | Add tests for deterministic session-local BTF ID allocation and reverse lookup behavior. | TE-001, TE-005 |
| VD-004 | REQ-VER-004 | Add | Required | Add tests for `resolve_kfunc_call`-driven verification success/failure against provider metadata. | TE-001, TE-003, TE-004, TE-005 |
| VD-005 | REQ-VER-005 | Add | Required | Add tests that verify Windows-side BTF extern-call inputs are accepted/rejected based on rewrite-to-`call_btf` behavior. | TE-001, TE-003, TE-004, TE-005 |
| VD-006 | REQ-VER-006 | No-Impact | Not required | No new test change required so long as the public verifier API surface remains BTF-ID free. | TE-001, TE-002 |
| VD-007 | REQ-VER-007 | Add | Required | Extend existing verifier API tests, not a new API surface, when BTF verifier support is added. | TE-001, TE-002, TE-003, TE-004 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-VER-001
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003, TE-004, TE-005
- **Expected test change locations**: `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: any new BTF verifier sample/object fixtures under tests]`
- **Before**: Existing verifier tests prove generic file-based and end-to-end verification success, but the provided test scope contains no BTF-resolved `.ksyms` verification coverage. (Evidence: TE-001, TE-003, TE-004, TE-005)
- **After**: Add verification tests that load BTF-resolved ELF inputs and assert Windows-side verifier behavior when `.ksyms` symbols are present.
- **Rationale**: The current tests demonstrate the generic verification surface only; BTF-specific preprocessing needs direct coverage.

### VD-002

- **Upstream REQ-ID**: REQ-VER-002
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003, TE-004, TE-005
- **Expected test change locations**: `tests\api_test\api_test.cpp`; `[UNKNOWN: fixture location for decl-tag-bearing ELF inputs]`
- **Before**: No examined test asserts declaration-tag parsing or module-to-function association during verification. (Evidence: TE-005)
- **After**: Add positive and negative tests that verify declaration-tag inputs either map to the expected provider module or fail verification when missing/malformed.
- **Rationale**: This is the only direct way to validate the declaration-tag preprocessing contract.

### VD-003

- **Upstream REQ-ID**: REQ-VER-003
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-005
- **Expected test change locations**: `tests\api_test\api_test.cpp`; `[UNKNOWN: any specialized verifier-state test fixture]`
- **Before**: No examined test covers deterministic session-local BTF ID allocation or reverse lookup behavior. (Evidence: TE-005)
- **After**: Add tests that verify a stable mapping exists within one verification session and that lookup by assigned BTF ID resolves the intended BTF-resolved function.
- **Rationale**: Mapping determinism and reversibility are central to the area requirements and are completely uncovered today.

### VD-004

- **Upstream REQ-ID**: REQ-VER-004
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003, TE-004, TE-005
- **Expected test change locations**: `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: metadata fixture location]`
- **Before**: Existing verifier tests do not exercise any Windows-side `resolve_kfunc_call` behavior because the current test scope contains no BTF-resolved verification inputs. (Evidence: TE-001, TE-003, TE-004, TE-005)
- **After**: Add tests that verify successful verification when provider metadata exists and explicit failure when required BTF-resolved metadata or callbacks are missing.
- **Rationale**: The callback gap is the strongest direct code conflict in this area.

### VD-005

- **Upstream REQ-ID**: REQ-VER-005
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003, TE-004, TE-005
- **Expected test change locations**: `tests\api_test\api_test.cpp`; `tests\cilium\cilium_tests.cpp` only if reused as a verifier API pattern; `[UNKNOWN: BTF-capable ELF fixture location]`
- **Before**: No examined test proves that Windows verifier preprocessing rewrites BTF extern-call inputs into `call_btf` semantics before verification. (Evidence: TE-005)
- **After**: Add tests that verify BTF-specific inputs are either accepted only after rewrite or rejected when rewrite prerequisites are not met.
- **Rationale**: The existing tests cover verifier success/failure generically, but not this rewrite-specific behavior.

### VD-006

- **Upstream REQ-ID**: REQ-VER-006
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002
- **Expected test change locations**: None
- **Before**: The current verifier API tests already exercise the exposed public verification entry points and `ebpf_get_program_info_from_verifier(...)`, and none of those surfaces expose BTF IDs. (Evidence: TE-001, TE-002)
- **After**: No test change required unless future code adds a new public verifier API that exposes BTF IDs.
- **Rationale**: This requirement is already satisfied by the current API surface and does not require a new validation delta under the current code baseline.

### VD-007

- **Upstream REQ-ID**: REQ-VER-007
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-003, TE-004
- **Expected test change locations**: `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `tests\cilium\cilium_tests.cpp`
- **Before**: Existing tests already target the current verifier entry points and end-to-end verification flows; no separate BTF-specific verifier API tests exist. (Evidence: TE-001, TE-002, TE-003, TE-004)
- **After**: Extend those existing verification test suites with BTF-specific cases instead of creating a new public-surface test family for a separate verifier API.
- **Rationale**: This preserves the current test topology and matches the design constraint that BTF verifier support should stay inside the existing API surface.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-VER-001 | MISSING | VD-001 | `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: BTF fixtures]` | Generic verification tests exist, but no `.ksyms` coverage exists. |
| REQ-VER-002 | MISSING | VD-002 | `tests\api_test\api_test.cpp`; `[UNKNOWN: BTF fixtures]` | No decl-tag coverage exists. |
| REQ-VER-003 | MISSING | VD-003 | `tests\api_test\api_test.cpp`; `[UNKNOWN: verifier-state fixture]` | No BTF ID determinism coverage exists. |
| REQ-VER-004 | MISSING | VD-004 | `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: metadata fixtures]` | No `resolve_kfunc_call` coverage exists. |
| REQ-VER-005 | MISSING | VD-005 | `tests\api_test\api_test.cpp`; `[UNKNOWN: BTF-capable ELF fixtures]` | No rewrite-to-`call_btf` coverage exists. |
| REQ-VER-006 | SATISFIED | No-Impact | None | Current verifier API tests already exercise the exposed public verifier surface, which is BTF-ID free. |
| REQ-VER-007 | PARTIAL | VD-007 | `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `tests\cilium\cilium_tests.cpp` | Existing verifier suites are the right extension point, but they contain no BTF-specific cases yet. |

## 5. Invariant Impact

- [KNOWN] Existing tests treat `ebpf_api_elf_verify_program_from_file(...)` / memory / end-to-end verification as the stable public surface; the proposed validation deltas preserve that invariant. (Evidence: TE-001, TE-002, TE-003, TE-004)
- [KNOWN] No examined tests reference BTF-specific verifier symbols such as `call_btf`, `kfunc`, `.ksyms`, or declaration tags, so the proposed deltas add new coverage rather than modifying established BTF-specific assertions. (Evidence: TE-005)
- [KNOWN] The no-impact treatment for REQ-VER-006 preserves the current public verifier API expectations instead of expanding the public surface under test. (Evidence: TE-001, TE-002)

## 6. Application Notes

1. [KNOWN] No existing validation plan was provided, so these deltas are synthesized additions rather than edits to a prior plan.
2. [KNOWN] The largest current validation gap is the absence of any BTF-verifier fixtures or assertions in the provided test scope.
3. [KNOWN] Several proposed test cases depend on new BTF-capable ELF fixtures or metadata fixtures whose exact locations cannot be determined from the current test scope alone.

## Coverage
- **Examined**: `tests\api_test\api_test.cpp`; `tests\end_to_end\end_to_end.cpp`; `tests\cilium\cilium_tests.cpp`; `docs\specs\btfid\04-verifier-integration.md`
- **Method**: targeted `view` on verifier-related test sections; `rg "ebpf_api_elf_verify_program_from_file|ebpf_api_elf_verify_program_from_memory|ebpf_verify_program\\(|load_byte_code\\(" Q:\ebpf-for-windows\tests`; `rg "call_btf|kfunc|resolve_kfunc_call|resolve_ksym_btf_id|ksyms|decl_tag|BTF_KIND_DECL_TAG" Q:\ebpf-for-windows\tests`
- **Excluded**: tests unrelated to verifier APIs; generated artifacts outside normal verifier test flows
- **Limitations**: the provided test scope contains no BTF-verifier fixtures, so future test-file locations are partially `[UNKNOWN]`

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\api_test\api_test.cpp:3256-3335` | Exercises generic verifier file/memory APIs and invalid-ELF failure handling. | Establishes current verifier API coverage. |
| TE-002 | `tests\api_test\api_test.cpp:3756-3820` | Exercises `ebpf_api_elf_verify_program_from_file(...)`, `ebpf_get_program_info_from_verifier(...)`, and memory-verification behavior. | Establishes current verifier-side TLS/program-info and public-surface coverage. |
| TE-003 | `tests\end_to_end\end_to_end.cpp:1040-1165` | Exercises end-to-end verifier success with registered program info. | Establishes current end-to-end verifier coverage. |
| TE-004 | `tests\cilium\cilium_tests.cpp:143-190` | Exercises repeated file-based verifier calls over cilium test objects. | Establishes another current verifier API extension point. |
| TE-005 | `tests\` search using `rg "call_btf|kfunc|resolve_kfunc_call|resolve_ksym_btf_id|ksyms|decl_tag|BTF_KIND_DECL_TAG"` returned no matches. | No BTF-verifier-specific coverage exists in the provided test scope. | Establishes the feature-specific validation gap. |

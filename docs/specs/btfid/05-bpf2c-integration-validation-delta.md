<!-- Delta artifact: bpf2c Integration alignment set -->

# bpf2c Integration — Validation Delta

## 1. Change Context

- **Area**: bpf2c Integration
- **Requirements source**: `docs\specs\btfid\05-bpf2c-integration.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this run
- **Code scope**: `tools\bpf2c`
- **Test scope**: `tests\bpf2c_tests`
- **Goal**: identify the minimal validation-spec deltas needed to align test coverage with the bpf2c-integration requirements

[KNOWN] The current bpf2c tests already snapshot generated C output, compile generated code against `bpf_test.cpp`, and exercise helper-only runtime indirection and helper-only hash options. [KNOWN] The current test scope contains no BTF-resolved bpf2c coverage, no BTF import-table snapshots, and no BTF-specific runtime-context or hash assertions. (Evidence: TE-001, TE-002, TE-003, TE-004, TE-005)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-B2C-001 | Add | Required | Add expected-output tests that verify BTF-resolved import-table emission alongside helper tables. | TE-001, TE-002, TE-005 |
| VD-002 | REQ-B2C-002 | Add | Required | Add expected-output tests for `zero_marker`-first BTF-resolved entry layout. | TE-001, TE-002, TE-005 |
| VD-003 | REQ-B2C-003 | Add | Required | Add expected-output tests for BTF-resolved entry fields containing function name and module GUID. | TE-001, TE-002, TE-005 |
| VD-004 | REQ-B2C-004 | Add | Required | Add expected-output and compile/run tests for `program_runtime_context_t` BTF address storage use. | TE-001, TE-003, TE-004, TE-005 |
| VD-005 | REQ-B2C-005 | Add | Required | Add codegen tests for BTF-resolved call-site indirection through `btf_resolved_function_data[index].address`. | TE-001, TE-003, TE-005 |
| VD-006 | REQ-B2C-006 | Add | Required | Add tests that verify BTF dependency count and ordering affect generated program-info hashes. | TE-001, TE-002, TE-005 |
| VD-007 | REQ-B2C-007 | Add | Required | Add tests that verify BTF dependency fields contribute to program-info hash material. | TE-001, TE-002, TE-005 |
| VD-008 | REQ-B2C-009 | No-Impact | Not required | Keep using the existing expected-output snapshot harness rather than creating a separate validation path. | TE-001, TE-002 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-B2C-001
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-005
- **Expected test change locations**: `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\`
- **Before**: The current expected-output snapshots validate helper import arrays and program entries, but the provided test scope contains no BTF-resolved import-table output at all. (Evidence: TE-001, TE-002, TE-005)
- **After**: Add BTF-capable bpf2c snapshot tests that verify emitted BTF-resolved import arrays appear alongside helper arrays.
- **Rationale**: The current snapshot harness is already the direct validation mechanism for generated C output.

### VD-002

- **Upstream REQ-ID**: REQ-B2C-002
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-005
- **Expected test change locations**: `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\`
- **Before**: No expected-output test asserts a BTF-resolved import-entry layout or `zero_marker` field ordering. (Evidence: TE-005)
- **After**: Add snapshot assertions for the emitted BTF import-entry structure, including `zero_marker` preceding the version header.
- **Rationale**: Layout-sensitive output belongs in the existing expected-output snapshots.

### VD-003

- **Upstream REQ-ID**: REQ-B2C-003
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-005
- **Expected test change locations**: `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\`
- **Before**: No current expected-output test includes BTF import records carrying function name and module GUID. (Evidence: TE-005)
- **After**: Add expected-output assertions for the emitted BTF name/GUID fields.
- **Rationale**: This directly validates the generated import-entry payload.

### VD-004

- **Upstream REQ-ID**: REQ-B2C-004
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003, TE-004, TE-005
- **Expected test change locations**: `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\expected\`
- **Before**: The current runtime harness populates `runtime_context->helper_data` only, and the expected-output baseline references helper-data only. (Evidence: TE-003, TE-004)
- **After**: Extend snapshot and runtime harness validation so BTF-resolved address storage is represented and consumable in generated test code.
- **Rationale**: Runtime-context changes need both emitted-code validation and runnable-harness validation.

### VD-005

- **Upstream REQ-ID**: REQ-B2C-005
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-003, TE-005
- **Expected test change locations**: `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\expected\`
- **Before**: No current expected-output or runtime harness test validates BTF-resolved call-site indirection. (Evidence: TE-005)
- **After**: Add snapshot and compile/run tests that verify generated call sites use `runtime_context->btf_resolved_function_data[index].address`.
- **Rationale**: The requirement is about emitted call shape, so both source snapshots and runtime compilation should validate it.

### VD-006

- **Upstream REQ-ID**: REQ-B2C-006
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-005
- **Expected test change locations**: `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: any BTF-aware hash fixture inputs]`
- **Before**: Current hash-related tests cover hash-option behavior generally, but no test validates BTF dependency count or deterministic BTF ordering in generated program-info hashes. (Evidence: TE-001, TE-005)
- **After**: Add tests that compare generated output or metadata for BTF-capable inputs with reordered declarations and confirm deterministic hash behavior.
- **Rationale**: Hash determinism for BTF dependencies is not implied by current helper-only hash coverage.

### VD-007

- **Upstream REQ-ID**: REQ-B2C-007
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002, TE-005
- **Expected test change locations**: `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: any BTF-aware hash fixture inputs]`
- **Before**: No current test validates that BTF function name, module GUID, return type, arguments, and non-default flags contribute to hash material. (Evidence: TE-005)
- **After**: Add hash-oriented tests that vary those BTF dependency fields and verify the generated program-info hash changes only when the required fields differ.
- **Rationale**: This is the only direct way to validate the new BTF-specific hash field set.

### VD-008

- **Upstream REQ-ID**: REQ-B2C-009
- **Existing validation location**: N/A — no existing validation doc
- **Related test evidence IDs**: TE-001, TE-002
- **Expected test change locations**: None
- **Before**: The current `elf_bpf.cpp` harness already snapshots generated output for `--raw`, `--dll`, and `--sys`. (Evidence: TE-001)
- **After**: No new validation architecture is required; extend the existing snapshot harness with BTF-aware fixtures.
- **Rationale**: The current validation model is already the correct extension point for generated-code changes.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-B2C-001 | MISSING | VD-001 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\` | No BTF import-table snapshots exist. |
| REQ-B2C-002 | MISSING | VD-002 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\` | No BTF entry-layout snapshots exist. |
| REQ-B2C-003 | MISSING | VD-003 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\` | No BTF name/GUID snapshot coverage exists. |
| REQ-B2C-004 | MISSING | VD-004 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\expected\` | Runtime harness and expected outputs are helper-data only. |
| REQ-B2C-005 | MISSING | VD-005 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\expected\` | No BTF call-indirection coverage exists. |
| REQ-B2C-006 | MISSING | VD-006 | `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: BTF hash fixtures]` | Current hash tests are not BTF-specific. |
| REQ-B2C-007 | MISSING | VD-007 | `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: BTF hash fixtures]` | No BTF field-to-hash coverage exists. |
| REQ-B2C-008 | MISSING | VD-006, VD-007 | `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: BTF hash fixtures]` | Deterministic BTF ordering is untested. |
| REQ-B2C-009 | SATISFIED | No-Impact | None | Existing snapshot/expected-output model is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] Existing bpf2c tests treat expected generated C files as the primary validation artifact for codegen changes; the proposed deltas preserve that invariant. (Evidence: TE-001, TE-002)
- [KNOWN] Existing runtime harness behavior is helper-centric; the proposed deltas extend that harness rather than replace it. (Evidence: TE-003, TE-004)
- [KNOWN] No current bpf2c test references BTF-resolved output, so the proposed deltas add new BTF-specific coverage rather than modifying established BTF assertions. (Evidence: TE-005)

## 6. Application Notes

1. [KNOWN] No existing validation plan was provided, so these deltas are synthesized additions rather than edits to a prior plan.
2. [KNOWN] The largest validation gap is the complete absence of BTF-resolved fixtures and expected outputs in `tests\bpf2c_tests`.
3. [KNOWN] Some future tests may require new BTF-aware ELF fixtures whose exact source location is not derivable from the current test scope alone.

## Coverage
- **Examined**: `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\raw_bpf.cpp`; `tests\bpf2c_tests\expected\`
- **Method**: targeted `view` on the bpf2c snapshot harness and runtime harness; targeted `rg` for `helper_function_entry_t`, `program_runtime_context_t`, `helper_data`, `program_info_hash`, `call_btf`, and `btf_resolved`
- **Excluded**: tests outside `tests\bpf2c_tests`
- **Limitations**: the current test scope contains no BTF-resolved fixtures or expected outputs, so some future test-file names remain `[UNKNOWN]`

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\bpf2c_tests\elf_bpf.cpp:99-193` | The snapshot harness runs bpf2c and compares generated `--raw`, `--dll`, and `--sys` output against files under `expected\`. | Establishes the current generated-output validation model. |
| TE-002 | `tests\bpf2c_tests\expected\atomic_instruction_fetch_add_dll.c:85-187` | Expected generated output contains helper import arrays, helper-data call indirection, and program entries without BTF-resolved fields. | Establishes the helper-only expected-output baseline. |
| TE-003 | `tests\bpf2c_tests\bpf_test.cpp:42-84` | The runtime harness allocates helper-function arrays and populates `runtime_context->helper_data` only. | Establishes the helper-only runtime harness baseline. |
| TE-004 | `tests\bpf2c_tests\raw_bpf.cpp:206-233` | Generated-code compile/run tests use `bpf_test.cpp` as the execution harness. | Shows where runtime-harness changes would need to be exercised. |
| TE-005 | `tests\bpf2c_tests` search using `rg "btf_resolved|call_btf"` returned no matches in the expected-output baseline for BTF-resolved integration. | No BTF-resolved bpf2c validation exists in the provided test scope. | Establishes the feature-specific validation gap. |

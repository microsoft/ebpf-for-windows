<!-- Delta artifact: bpf2c Integration alignment set -->

# bpf2c Integration — Requirements / Code / Test Traceability

## Coverage

- **Target**: bpf2c-integration requirements for BTF-resolved functions, joined against `tools\bpf2c` code and `tests\bpf2c_tests` coverage
- **Method**:
  - `view Q:\ebpf-for-windows\docs\specs\btfid\05-bpf2c-integration.md`
  - `view` on `tools\bpf2c\bpf2c.cpp`, `tools\bpf2c\bpf_code_generator.cpp`, `tools\bpf2c\bpf_code_generator.h`
  - `view` on `tests\bpf2c_tests\bpf_test.cpp`, `tests\bpf2c_tests\elf_bpf.cpp`, `tests\bpf2c_tests\raw_bpf.cpp`, and representative files under `tests\bpf2c_tests\expected\`
  - `rg "helper_function_entry_t|program_info_hash|runtime_context->helper_data|call_btf|btf_resolved"` over `tools\bpf2c` and `tests\bpf2c_tests`
- **Excluded**: code outside `tools\bpf2c`, including external declarations consumed from `bpf2c.h`; tests outside `tests\bpf2c_tests`
- **Limitations**: structural declarations consumed from outside `tools\bpf2c` were not examined, so a few required code locations remain `[UNKNOWN]`

## Input Inventory

| Input | Type | Scope Role | Notes |
| --- | --- | --- | --- |
| `docs\specs\btfid\05-bpf2c-integration.md` | Requirements doc | Upstream requirements | Area-scoped source of REQ-B2C-001 through REQ-B2C-009 |
| `tools\bpf2c\bpf2c.cpp` | Code | Implementation baseline | Hash computation and main bpf2c integration path |
| `tools\bpf2c\bpf_code_generator.cpp` | Code | Implementation baseline | Import-table emission, program-entry emission, runtime-context use |
| `tools\bpf2c\bpf_code_generator.h` | Code | Implementation baseline | Generator state and interfaces |
| `tests\bpf2c_tests\elf_bpf.cpp` | Test code | Existing validation baseline | Expected-output snapshot harness |
| `tests\bpf2c_tests\bpf_test.cpp` | Test code | Existing validation baseline | Runtime harness for generated code |
| `tests\bpf2c_tests\raw_bpf.cpp` | Test code | Existing validation baseline | Compile/run generated-code tests |
| `tests\bpf2c_tests\expected\*` | Test artifact | Existing validation baseline | Snapshot baseline for generated C output |
| Existing design document | Design doc | None provided | Recorded as absent for this run |
| Existing validation document | Validation doc | None provided | Recorded as absent for this run |

## Requirement Join Summary

| REQ-ID | Requirement Summary | Code Status | Test Status | Notes |
| --- | --- | --- | --- | --- |
| REQ-B2C-001 | Emit a BTF-resolved import table alongside the helper table. | PARTIAL | MISSING | Import-table machinery exists, but only for helpers. |
| REQ-B2C-002 | Place `zero_marker` before the BTF entry header. | MISSING | MISSING | No BTF entry layout exists in scope. |
| REQ-B2C-003 | Include function name and module GUID in each BTF entry. | MISSING | MISSING | No BTF entry fields exist in scope. |
| REQ-B2C-004 | Extend `program_runtime_context_t` with BTF-resolved address storage. | MISSING | MISSING | Generated code references `helper_data` only. |
| REQ-B2C-005 | Generate BTF call sites through `btf_resolved_function_data[index].address`. | MISSING | MISSING | Generated call sites use helper-data indirection only. |
| REQ-B2C-006 | Include BTF dependency count and deterministic ordering in program-info hashes. | PARTIAL | MISSING | Hash machinery exists, but only for helpers. |
| REQ-B2C-007 | Include BTF dependency fields in program-info hashes. | PARTIAL | MISSING | Hash field appends exist, but only for helpers. |
| REQ-B2C-008 | Make BTF dependency hashing deterministic. | PARTIAL | MISSING | Deterministic helper ordering exists; BTF ordering does not. |
| REQ-B2C-009 | Extend the existing bpf2c codegen/test pipeline rather than create a second output path. | SATISFIED | SATISFIED | Current generator and expected-output model are already the right extension point. |

## Detailed Traceability Matrix

| REQ-ID | Requirement Summary | Code Evidence IDs | Code Status | Design Delta IDs | Expected Code Change Locations | Test Evidence IDs | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REQ-B2C-001 | Emit a BTF-resolved import table alongside the helper table. | CE-002, CE-003, CE-006 | PARTIAL | DD-001 | `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h` | TE-001, TE-002, TE-005 | MISSING | VD-001 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\` | Helper import-table emission exists; BTF import-table emission does not. |
| REQ-B2C-002 | Place `zero_marker` before the BTF entry header. | CE-006 | MISSING | DD-002 | `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h`; `[UNKNOWN: out-of-scope struct declarations]` | TE-001, TE-002, TE-005 | MISSING | VD-002 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\` | No BTF entry layout exists today. |
| REQ-B2C-003 | Include function name and module GUID in each BTF entry. | CE-006 | MISSING | DD-003 | `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h` | TE-001, TE-002, TE-005 | MISSING | VD-003 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\` | No emitted BTF entry fields exist today. |
| REQ-B2C-004 | Extend `program_runtime_context_t` with BTF-resolved address storage. | CE-002, CE-006 | MISSING | DD-004 | `tools\bpf2c\bpf_code_generator.cpp`; `[UNKNOWN: out-of-scope runtime-context declarations]` | TE-001, TE-003, TE-004, TE-005 | MISSING | VD-004 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\expected\` | Generated code and runtime harness are helper-data only. |
| REQ-B2C-005 | Generate BTF call sites through `btf_resolved_function_data[index].address`. | CE-002, CE-006 | MISSING | DD-005 | `tools\bpf2c\bpf_code_generator.cpp` | TE-001, TE-003, TE-005 | MISSING | VD-005 | `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\expected\` | Generated call sites currently use helper-data indirection only. |
| REQ-B2C-006 | Include BTF dependency count and deterministic ordering in program-info hashes. | CE-001, CE-005 | PARTIAL | DD-006 | `tools\bpf2c\bpf2c.cpp` | TE-001, TE-002, TE-005 | MISSING | VD-006 | `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: BTF hash fixtures]` | Hash pipeline exists, but only for helper dependencies. |
| REQ-B2C-007 | Include BTF dependency fields in program-info hashes. | CE-001, CE-005 | PARTIAL | DD-007 | `tools\bpf2c\bpf2c.cpp` | TE-001, TE-002, TE-005 | MISSING | VD-007 | `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: BTF hash fixtures]` | Hash field appends exist, but only for helper metadata. |
| REQ-B2C-008 | Make BTF dependency hashing deterministic. | CE-001, CE-005 | PARTIAL | DD-006, DD-007 | `tools\bpf2c\bpf2c.cpp` | TE-001, TE-002, TE-005 | MISSING | VD-006, VD-007 | `tests\bpf2c_tests\elf_bpf.cpp`; `[UNKNOWN: BTF hash fixtures]` | Helper-order determinism exists, but not BTF-order determinism. |
| REQ-B2C-009 | Extend the existing bpf2c codegen/test pipeline rather than create a second output path. | CE-003, CE-004, CE-006 | SATISFIED | No-Impact | None | TE-001, TE-002 | SATISFIED | No-Impact | None | Existing generator and expected-output snapshot harness are already the right extension point. |

## Conflict Register

| Conflict ID | Type | Description | Evidence | Recommended Resolution |
| --- | --- | --- | --- | --- |
| CR-001 | Upstream-downstream | The source requires BTF-resolved import tables and runtime-context fields, but the current generator emits only helper import arrays and helper-data indirection. | CE-002, CE-003, CE-006 | Apply DD-001 through DD-005. |
| CR-002 | Upstream-downstream | The source requires BTF-resolved dependency hashing, but the current hash path only covers helper dependencies. | CE-001, CE-005 | Apply DD-006 and DD-007. |
| CR-003 | Coverage gap | The current bpf2c test scope contains no BTF-resolved codegen or hash validation. | TE-001, TE-002, TE-003, TE-004, TE-005 | Apply VD-001 through VD-007. |

## Open Questions

1. [UNKNOWN: which out-of-scope declaration file should carry any required `program_runtime_context_t` or BTF entry-type changes.]
2. [UNKNOWN: where new BTF-capable ELF fixtures for bpf2c tests should live if they are not already present elsewhere in the repository.]
3. [KNOWN] No existing design or validation document was provided, so these delta artifacts are synthesized from requirements plus code/test evidence only.

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `tools\bpf2c\bpf2c.cpp:73-129` | `get_program_info_type_hash(...)` hashes program type data and actually-called helper metadata only. | Establishes the helper-only hash baseline. |
| CE-002 | `tools\bpf2c\bpf_code_generator.cpp:1077-1085` | Instruction encoding uses `runtime_context->helper_data[{}]` as the callable import-address prefix. | Establishes current helper-only runtime-context indirection. |
| CE-003 | `tools\bpf2c\bpf_code_generator.cpp:1951-1975` | The generator emits `helper_function_entry_t` arrays for each program. | Establishes the helper-only import-table baseline. |
| CE-004 | `tools\bpf2c\bpf_code_generator.cpp:2107-2155` | Program entries carry helper arrays/counts and optional program-info hashes. | Establishes current per-program metadata emission. |
| CE-005 | `tools\bpf2c\bpf2c.cpp:343-360` | Main bpf2c flow gets verifier program info and computes/stores program-info hashes from helper IDs. | Establishes the current helper-only hash integration point. |
| CE-006 | `tools\bpf2c` search using `rg "btf_resolved|call_btf"` returned no implementation matches for BTF-resolved import-table or runtime-context generation. | No BTF-resolved generation path is visible in the provided code scope. | Establishes the BTF generation gap. |

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\bpf2c_tests\elf_bpf.cpp:99-193` | The snapshot harness compares generated `--raw`, `--dll`, and `--sys` output against `expected\*`. | Establishes the current generated-output validation model. |
| TE-002 | `tests\bpf2c_tests\expected\atomic_instruction_fetch_add_dll.c:85-187` | Representative expected output contains helper arrays, helper-data indirection, and program entries with no BTF-resolved fields. | Establishes the helper-only expected-output baseline. |
| TE-003 | `tests\bpf2c_tests\bpf_test.cpp:42-84` | The runtime harness populates `runtime_context->helper_data` only and rejects helper resolution by name. | Establishes the helper-only runtime harness baseline. |
| TE-004 | `tests\bpf2c_tests\raw_bpf.cpp:206-233` | Generated-code compile/run tests execute generated output through `bpf_test.cpp`. | Shows where runtime-harness changes would need to be exercised. |
| TE-005 | `tests\bpf2c_tests` search using `rg "btf_resolved|call_btf"` returned no matches for BTF-resolved integration in the provided test scope. | No BTF-resolved bpf2c validation exists in the provided test scope. | Establishes the feature-specific validation gap. |

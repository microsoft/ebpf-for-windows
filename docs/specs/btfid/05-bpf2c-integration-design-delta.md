<!-- Delta artifact: bpf2c Integration alignment set -->

# bpf2c Integration — Design Delta

## 1. Change Context

- **Area**: bpf2c Integration
- **Requirements source**: `docs\specs\btfid\05-bpf2c-integration.md`
- **Existing design doc**: N/A — no existing design document was provided for this run
- **Code scope**: `tools\bpf2c`
- **Test scope**: `tests\bpf2c_tests`
- **Goal**: identify the minimal design deltas needed to align the bpf2c-integration requirements with the current `tools\bpf2c` implementation and its test baseline

[KNOWN] The current `tools\bpf2c` implementation already emits helper import arrays, helper-data runtime indirection, program-entry metadata, and helper-only program-info hashes. [KNOWN] The current code scope does not emit any BTF-resolved import structures, BTF runtime-context references, or BTF-specific hash data. (Evidence: CE-001, CE-002, CE-003, CE-004, CE-005, CE-006)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-B2C-001 | Modify | Required | Extend import-table emission with a BTF-resolved-function import table alongside the existing helper table. | CE-002, CE-003, CE-006 |
| DD-002 | REQ-B2C-002 | Add | Required | Define and emit a BTF-resolved-function entry layout whose first field is `zero_marker`. | CE-006 |
| DD-003 | REQ-B2C-003 | Add | Required | Include function name and module GUID in each emitted BTF-resolved import entry. | CE-006 |
| DD-004 | REQ-B2C-004 | Modify | Required | Extend generated runtime-context usage to reference BTF-resolved-function address storage in addition to helper data. | CE-002, CE-006 |
| DD-005 | REQ-B2C-005 | Modify | Required | Generate BTF-resolved call sites through `runtime_context->btf_resolved_function_data[index].address`. | CE-002, CE-006 |
| DD-006 | REQ-B2C-006 | Modify | Required | Extend the current program-info hash path to incorporate a deterministic BTF-resolved dependency list and count. | CE-001, CE-005 |
| DD-007 | REQ-B2C-007 | Modify | Required | Extend hash material to include BTF-resolved function name, module GUID, return type, arguments, and non-default flags. | CE-001, CE-005 |
| DD-008 | REQ-B2C-009 | No-Impact/Constrain | Required | Keep BTF-resolved support inside the existing bpf2c generator and expected-output pipeline. | CE-003, CE-004, CE-006 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-B2C-001
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-003, CE-006
- **Expected code change locations**: `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h`
- **Before**: The current generator emits only `helper_function_entry_t` import arrays for each program and threads those arrays into `program_entry_t`. No BTF-resolved import table is emitted in the provided code scope. (Evidence: CE-002, CE-003, CE-006)
- **After**: Extend the current import-table emission path with a BTF-resolved-function import array emitted alongside the existing helper array and referenced from generated program metadata.
- **Rationale**: The helper import pipeline already exists; the minimal aligned change is to add a parallel BTF-resolved import path rather than redesign the entire generator.

### DD-002

- **Upstream REQ-ID**: REQ-B2C-002
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-006
- **Expected code change locations**: `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h`; `[UNKNOWN: any supporting struct declaration outside the provided code scope]`
- **Before**: No BTF-resolved import entry type or BTF-resolved emitted record exists in the provided code scope. (Evidence: CE-006)
- **After**: Define the BTF-resolved import entry layout and emit records with `zero_marker` as the leading field before the version header.
- **Rationale**: The current code has no BTF entry shape at all, so a concrete layout is the minimal missing design element.

### DD-003

- **Upstream REQ-ID**: REQ-B2C-003
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-006
- **Expected code change locations**: `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h`
- **Before**: Existing helper import records carry helper ID and helper name only; there is no emitted BTF import record carrying function name and module GUID. (Evidence: CE-006)
- **After**: Add function name and module GUID fields to the emitted BTF-resolved import records.
- **Rationale**: Load-time BTF binding requires provider identity, which the current helper-only import model does not carry.

### DD-004

- **Upstream REQ-ID**: REQ-B2C-004
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-006
- **Expected code change locations**: `tools\bpf2c\bpf_code_generator.cpp`; [UNKNOWN: any `program_runtime_context_t` declaration outside the provided code scope]
- **Before**: Generated code currently assumes `runtime_context->helper_data[...]` as the only callable import-address store used by bpf2c-generated call sites. (Evidence: CE-002, CE-006)
- **After**: Extend generated runtime-context usage to support `btf_resolved_function_data` in addition to `helper_data`.
- **Rationale**: The source requirement is a runtime-context contract change; the current helper-only code path is insufficient.

### DD-005

- **Upstream REQ-ID**: REQ-B2C-005
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-006
- **Expected code change locations**: `tools\bpf2c\bpf_code_generator.cpp`
- **Before**: Generated call sites currently go through `runtime_context->helper_data[index].address(...)`, and the expected-output baseline confirms that helper-only call shape. (Evidence: CE-002, CE-006)
- **After**: Add code-generation logic for BTF-resolved call sites that uses `runtime_context->btf_resolved_function_data[index].address`.
- **Rationale**: The call-shape requirement is distinct from the import-table requirement and needs its own generator change.

### DD-006

- **Upstream REQ-ID**: REQ-B2C-006
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-005
- **Expected code change locations**: `tools\bpf2c\bpf2c.cpp`
- **Before**: `get_program_info_type_hash(...)` includes program type data, helper count, and actually-called helper metadata, but it has no BTF-resolved dependency count or ordering rules. (Evidence: CE-001)
- **After**: Extend the existing hash path to append the count of BTF-resolved functions used and a deterministic BTF dependency list ordered by module GUID and then function name.
- **Rationale**: The current hash machinery already exists and should be extended rather than replaced.

### DD-007

- **Upstream REQ-ID**: REQ-B2C-007
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-005
- **Expected code change locations**: `tools\bpf2c\bpf2c.cpp`
- **Before**: The current hash path appends helper ID, name, return type, arguments, and sometimes helper flags, but it has no emitted BTF dependency fields at all. (Evidence: CE-001)
- **After**: Extend hash material to include BTF-resolved function name, module GUID, return type, argument elements, and non-default flags.
- **Rationale**: This is the minimal extension required to align proof-of-verification hashing with the BTF-resolved requirements.

### DD-008

- **Upstream REQ-ID**: REQ-B2C-009
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-004, CE-006
- **Expected code change locations**: `tools\bpf2c\bpf_code_generator.cpp`; `tests\bpf2c_tests\elf_bpf.cpp`; `tests\bpf2c_tests\expected\`
- **Before**: The current bpf2c output model is centralized in one code generator and one expected-output snapshot harness. (Evidence: CE-003, CE-004)
- **After**: Keep BTF-resolved support inside that same codegen and expected-output model instead of inventing a separate BTF-only generation path or test family.
- **Rationale**: This preserves current tool structure and minimizes churn to both implementation and validation flow.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-B2C-001 | PARTIAL | DD-001 | `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h` | Import-table infrastructure exists, but only for helpers. |
| REQ-B2C-002 | MISSING | DD-002 | `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h`; `[UNKNOWN: out-of-scope struct declarations]` | No BTF-resolved entry layout is emitted today. |
| REQ-B2C-003 | MISSING | DD-003 | `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h` | No emitted BTF name/GUID entry exists. |
| REQ-B2C-004 | MISSING | DD-004 | `tools\bpf2c\bpf_code_generator.cpp`; `[UNKNOWN: out-of-scope runtime-context declarations]` | Generated code references only `helper_data`. |
| REQ-B2C-005 | MISSING | DD-005 | `tools\bpf2c\bpf_code_generator.cpp` | Generated call sites use helper-data indirection only. |
| REQ-B2C-006 | PARTIAL | DD-006 | `tools\bpf2c\bpf2c.cpp` | Hash machinery exists, but only for helper dependencies. |
| REQ-B2C-007 | PARTIAL | DD-007 | `tools\bpf2c\bpf2c.cpp` | Hash field appends exist, but only for helper metadata. |
| REQ-B2C-008 | PARTIAL | DD-006, DD-007 | `tools\bpf2c\bpf2c.cpp` | Deterministic helper ordering exists; BTF deterministic ordering does not. |
| REQ-B2C-009 | SATISFIED | No-Impact/Constrain | None | Existing bpf2c generator and expected-output model are already the right extension point. |

## 5. Invariant Impact

- [KNOWN] The current generator emits one consolidated program-entry structure per program and one consolidated expected-output snapshot per test case; the deltas preserve that structure. (Evidence: CE-003, CE-004, CE-006)
- [KNOWN] The current hash path is centralized in `get_program_info_type_hash(...)`; the deltas preserve that single hash pipeline and extend it rather than adding a second hash mechanism. (Evidence: CE-001, CE-005)
- [KNOWN] The helper import model remains intact; the deltas add BTF-resolved support alongside it rather than replacing it. (Evidence: CE-002, CE-006)

## 6. Application Notes

1. [KNOWN] No existing design document was provided, so these deltas are synthesized additions rather than edits against a prior design artifact.
2. [KNOWN] The strongest current gap is that bpf2c is still helper-centric in both import-table emission and program-info hashing.
3. [KNOWN] Some required structural changes, especially to `program_runtime_context_t`, may also touch declarations outside `tools\bpf2c`; those locations remain `[UNKNOWN]` because they are outside the provided code scope.

## Coverage
- **Examined**: `docs\specs\btfid\05-bpf2c-integration.md`; `tools\bpf2c\bpf2c.cpp`; `tools\bpf2c\bpf_code_generator.cpp`; `tools\bpf2c\bpf_code_generator.h`
- **Method**: targeted `view` on hash computation, helper-array emission, program-entry emission, and runtime-context use; targeted `rg` for `helper_function_entry_t`, `program_info_hash`, `runtime_context->helper_data`, `call_btf`, and `btf_resolved`
- **Excluded**: code outside `tools\bpf2c`, including header declarations consumed from elsewhere; runtime and verifier internals outside bpf2c integration
- **Limitations**: some required structural declarations appear to live outside the provided code scope, so a few code-change locations remain `[UNKNOWN]`

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `tools\bpf2c\bpf2c.cpp:73-129` | `get_program_info_type_hash(...)` hashes program type data plus actually-called helper metadata only. | Establishes the helper-only hash baseline. |
| CE-002 | `tools\bpf2c\bpf_code_generator.cpp:1077-1085` | Instruction encoding uses `runtime_context->helper_data[{}]` as the callable import-address prefix. | Establishes current helper-only runtime-context indirection. |
| CE-003 | `tools\bpf2c\bpf_code_generator.cpp:1951-1975` | The generator emits per-program `helper_function_entry_t` arrays only. | Establishes the helper-only import-table baseline. |
| CE-004 | `tools\bpf2c\bpf_code_generator.cpp:2107-2155` | Program entries carry map arrays, helper arrays, helper counts, GUID metadata, and optional program-info hashes. | Establishes current per-program metadata emission. |
| CE-005 | `tools\bpf2c\bpf2c.cpp:343-360` | Main bpf2c flow gets verifier program info, parses it into the generator, and computes/stores program-info hashes from helper IDs. | Establishes the current helper-only hash integration point. |
| CE-006 | `tools\bpf2c` search using `rg "btf_resolved|call_btf"` returned no implementation matches for BTF-resolved import-table or runtime-context generation. | No BTF-resolved generation path is visible in the provided code scope. | Establishes the code gap for BTF-specific output. |

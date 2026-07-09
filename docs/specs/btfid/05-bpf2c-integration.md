# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source specifies a structural convention that `zero_marker` must precede the header, but it does not define the generic bpf2c section-parsing rules that make this field-order constraint necessary. (Source: `docs/BtfResolvedFunctions.md:251-258`)
- [KNOWN] The source specifies that flags are included in the program-info hash, but it does not separately define any flag-normalization rules beyond the stored value itself. (Source: `docs/BtfResolvedFunctions.md:313-317`)
- [KNOWN] The current `tools\bpf2c` code computes program-info hashes using both helper metadata from `ebpf_get_program_info_from_verifier(...)` and BTF-resolved-function dependency metadata supplied by the verifier/code-generator pipeline. (Source: `tools/bpf2c/bpf2c.cpp:73-145`, `tools/bpf2c/bpf2c.cpp:362-379`)
- [KNOWN] The current code generator emits both helper-function import tables and BTF-resolved-function import tables, including the native runtime indirection needed for generated BTF calls. (Source: `tools/bpf2c/bpf_code_generator.cpp:2343-2411`, `tests\bpf2c_tests\expected\btf_resolved_sys.c:237-247`)

## Implicit requirements in this area

- [INFERRED] Generated native artifacts must preserve the verifier-resolved provider identity and prototype information, because load-time binding and proof-of-verification hashing both consume generated bpf2c outputs. (Source: `docs/BtfResolvedFunctions.md:247-310`)
- [INFERRED] Any future BTF-resolved bpf2c support should extend the existing helper/program-entry emission pipeline rather than introduce a parallel output format, because the current code generator already centralizes import-table emission, runtime-context references, and per-program hash metadata in one path. (Source: `tools/bpf2c/bpf_code_generator.cpp:1951-2155`)

## Actual or possible conflicts

- [KNOWN] The source requires the emitted BTF-resolved import table to preserve verifier-approved signature metadata as well as provider identity, because proof-of-verification hashing consumes return type, argument types, and flags in addition to name and module GUID. (Source: `docs/BtfResolvedFunctions.md:313-317`, `tools/bpf2c/bpf2c.cpp:132-141`, `tools/bpf2c/bpf_code_generator.cpp:2353-2372`)

## Coverage statement

- **Examined:** Section 6 bpf2c Integration; `tools/bpf2c/bpf2c.cpp`; `tools/bpf2c/bpf_code_generator.cpp`; `tools/bpf2c/bpf_code_generator.h`; `tests/bpf2c_tests/bpf_test.cpp`; `tests/bpf2c_tests/elf_bpf.cpp`; expected bpf2c output under `tests/bpf2c_tests/expected`.
- **Method:** extracted generated-artifact, runtime-context, and hash-computation requirements, then compared them with the current hash path, helper import emission, program-entry emission, and bpf2c expected-output tests.
- **Excluded:** runtime attach/detach logic, verifier-side symbol resolution mechanics, and code outside `tools/bpf2c`.
- **Limitations:** `program_runtime_context_t` is consumed from `bpf2c.h`, which is outside the provided code scope, so direct header changes remain out of scope for this run.

# bpf2c Integration — Requirements Document

## 1. Overview

[KNOWN] This area defines how verifier-resolved BTF-resolved function calls are carried into generated native code. The source adds a BTF-resolved function import table, a runtime-context extension for resolved addresses, generated call indirection, and proof-of-verification hash inputs. (Source: `docs/BtfResolvedFunctions.md:245-310`)

[KNOWN] The requirements in this area are structural rather than policy-based: they control emitted data layout, emitted code shape, and hash material. (Source: `docs/BtfResolvedFunctions.md:247-310`)

[KNOWN] The current `tools\bpf2c` implementation already emits helper-function import tables, helper-data runtime indirection, per-program GUID metadata, and program-info hashes derived from helper metadata returned by the verifier. [KNOWN] The provided code scope does not currently emit any BTF-resolved-function import structures, runtime-context fields, or BTF-specific hash inputs. (Source: `tools/bpf2c/bpf2c.cpp:73-129`, `tools/bpf2c/bpf2c.cpp:343-360`, `tools/bpf2c/bpf_code_generator.cpp:1084`, `tools/bpf2c/bpf_code_generator.cpp:1951-2155`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] Import-table entry structure for BTF-resolved functions. (Source: `docs/BtfResolvedFunctions.md:249-258`)
- [KNOWN] Runtime-context extension for resolved addresses. (Source: `docs/BtfResolvedFunctions.md:261-280`)
- [KNOWN] Generated call-indirection shape. (Source: `docs/BtfResolvedFunctions.md:283-298`)
- [KNOWN] Program-info hash inputs and deterministic ordering. (Source: `docs/BtfResolvedFunctions.md:300-310`)
- [KNOWN] Existing bpf2c helper-import, program-entry, and helper-hash emission behavior relevant to a future BTF-resolved extension. (Source: `tools/bpf2c/bpf2c.cpp:73-129`, `tools/bpf2c/bpf_code_generator.cpp:1951-2155`)

### 2.2 Out of Scope

- [KNOWN] Caller-side BTF ID allocation, because it belongs to `04-verifier-integration.md`. (Source: `docs/BtfResolvedFunctions.md:197-243`)
- [KNOWN] NMR registration payload shape, because it belongs to `06-nmr-provider-registration.md`. (Source: `docs/BtfResolvedFunctions.md:312-346`)
- [KNOWN] Runtime failure handling when providers detach, because it belongs to `08-runtime-execution.md`. (Source: `docs/BtfResolvedFunctions.md:396-428`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| BTF-resolved function import table | [KNOWN] The generated native array of `btf_resolved_function_entry_t` records emitted alongside the helper import table. (Source: `docs/BtfResolvedFunctions.md:247-258`, `docs/BtfResolvedFunctions.md:287-294`) |
| `zero_marker` | [KNOWN] The leading field in `btf_resolved_function_entry_t` that must precede the header per bpf2c convention. (Source: `docs/BtfResolvedFunctions.md:252-255`) |
| Program-info hash inputs | [KNOWN] The current bpf2c hash path includes program type data, actually-called helper metadata returned by `ebpf_get_program_info_from_verifier(...)`, and BTF-resolved-function dependency metadata. (Source: `tools/bpf2c/bpf2c.cpp:73-145`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-B2C-001: The system MUST emit a BTF-resolved function import table alongside the existing helper import table whenever native code is generated for a program that uses BTF-resolved functions, so that load-time code can enumerate required provider imports. (Source: `docs/BtfResolvedFunctions.md:247-248`, `docs/BtfResolvedFunctions.md:287-294`)

Acceptance Criteria:
- [INFERRED] AC-1: The bpf2c requirements distinguish the BTF-resolved import table from the helper import table instead of merging them. (Source: `docs/BtfResolvedFunctions.md:247-248`)

[KNOWN] REQ-B2C-002: Each `btf_resolved_function_entry_t` record MUST place `zero_marker` before the native-module header, so that the emitted table conforms to the documented bpf2c section-parsing convention. (Source: `docs/BtfResolvedFunctions.md:251-258`)

Acceptance Criteria:
- [INFERRED] AC-1: The entry-structure requirements state that `zero_marker` is the first field in the record. (Source: `docs/BtfResolvedFunctions.md:252-255`)

[KNOWN] REQ-B2C-003: Each `btf_resolved_function_entry_t` record MUST include the function name, module GUID, return type, argument-type array, and flags, so that load-time binding preserves the same callable contract that proof-of-verification hashing approved. (Source: `docs/BtfResolvedFunctions.md:253-262`, `docs/BtfResolvedFunctions.md:313-317`)

Acceptance Criteria:
- [INFERRED] AC-1: The entry-structure requirements preserve both provider identity fields and hashed signature fields in each emitted record. (Source: `docs/BtfResolvedFunctions.md:253-262`, `docs/BtfResolvedFunctions.md:313-317`)

[KNOWN] REQ-B2C-004: The generated `program_runtime_context_t` contract MUST include `btf_resolved_function_data`, so that generated program code has access to resolved BTF-resolved function addresses at runtime. (Source: `docs/BtfResolvedFunctions.md:263-280`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime-context requirements identify `btf_resolved_function_data` as a distinct context field rather than overloading helper or map data. (Source: `docs/BtfResolvedFunctions.md:273-280`)

[KNOWN] REQ-B2C-005: Generated native code MUST invoke each BTF-resolved function through the corresponding `runtime_context->btf_resolved_function_data[index].address` indirection, so that runtime address replacement can occur without regenerating code. (Source: `docs/BtfResolvedFunctions.md:285-298`)

Acceptance Criteria:
- [INFERRED] AC-1: The generated-code requirements describe indirect calls through runtime-context address storage rather than direct calls to provider symbols. (Source: `docs/BtfResolvedFunctions.md:296-298`)

[KNOWN] REQ-B2C-006: The program-info hash MUST include the count of BTF-resolved functions used and MUST include each function dependency in deterministic order by module GUID and then function name, so that proof-of-verification material is stable and resistant to omitted-dependency ambiguity. (Source: `docs/BtfResolvedFunctions.md:302-305`)

Acceptance Criteria:
- [INFERRED] AC-1: Two requirement-review examples with identical dependency sets in different declaration order still produce the same dependency ordering rule for hashing. (Source: `docs/BtfResolvedFunctions.md:304-305`)
- [INFERRED] AC-2: The count of BTF-resolved functions appears as a required hash input independent of the per-function data list. (Source: `docs/BtfResolvedFunctions.md:304`)

[KNOWN] REQ-B2C-007: For each hashed BTF-resolved function dependency, the system MUST include the function name, module GUID, return type, each argument-type element, and flags, so that verification is tied to the callable contract that was approved. (Source: `docs/BtfResolvedFunctions.md:313-317`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements enumerate all five documented classes of hash input for each dependency. (Source: `docs/BtfResolvedFunctions.md:305-310`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-B2C-008: Hash computation for BTF-resolved function dependencies MUST be deterministic with respect to provider GUID and function name ordering, so that proof-of-verification results do not vary with source declaration order. (Source: `docs/BtfResolvedFunctions.md:304-305`)

Acceptance Criteria:
- [INFERRED] AC-1: The deterministic ordering rule is stated as a mandatory property of hash computation rather than as an example. (Source: `docs/BtfResolvedFunctions.md:304-305`)

[INFERRED] REQ-B2C-009: If BTF-resolved-function support is added to bpf2c, it SHOULD extend the existing helper/program-entry code-generation pipeline and expected-output test model rather than introduce a second unrelated output path, so that generated native artifacts remain consistent with current bpf2c structure and tests. (Source: `tools/bpf2c/bpf_code_generator.cpp:1951-2155`, `tests/bpf2c_tests/elf_bpf.cpp:99-193`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify the current helper import emission, program-entry emission, and expected-output snapshot tests as the preferred extension points for future BTF-resolved support. (Source: `tools/bpf2c/bpf_code_generator.cpp:1951-2155`, `tests/bpf2c_tests/elf_bpf.cpp:99-193`)

### 4.3 Constraints

- [KNOWN] CON-001: The documented `program_runtime_context_t` and related types are proposed extensions to `include/bpf2c.h`, not current public-header contracts. (Source: `docs/BtfResolvedFunctions.md:14-16`, `docs/BtfResolvedFunctions.md:263-280`)
- [KNOWN] CON-002: In shared global-array mode, unused BTF-resolved-function slots remain zero-initialized placeholders identified by `name = ""` and `module_guid = GUID_NULL`; generated code and native load must tolerate those sentinels. (Source: `docs/BtfResolvedFunctions.md:265-266`, `tools/bpf2c/bpf_code_generator.cpp:2353-2374`)
- [KNOWN] CON-003: The current program-info hash path in `bpf2c.cpp` derives dependency data from both helper metadata and BTF-resolved-function metadata, so any generated entry shape change must stay hash-compatible. (Source: `tools/bpf2c/bpf2c.cpp:73-145`)

## 5. Dependencies

- DEP-B2C-001: This requirement set depends on `04-verifier-integration.md` for resolved BTF IDs and on `03-registry-publication.md` for prototype metadata. Impact if unavailable: generated native artifacts cannot be tied back to verified callable contracts. (Source: `docs/BtfResolvedFunctions.md:247-310`)
- DEP-B2C-002: This requirement set depends on the current `tools/bpf2c` code-generation and hashing paths because future BTF-resolved support must either extend or intentionally diverge from those existing helper-centric behaviors. Impact if unavailable: the delta between current bpf2c output and the source requirements cannot be stated concretely. (Source: `tools/bpf2c/bpf2c.cpp:73-129`, `tools/bpf2c/bpf_code_generator.cpp:1951-2155`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] The import-table index used by generated code remains aligned with the order used when populating `btf_resolved_function_data`. If this assumption is wrong, an explicit index-mapping requirement must be added. Justification: the source shows index-based address access but does not define a separate mapping structure. (Source: `docs/BtfResolvedFunctions.md:287-298`)
- ASM-002: [ASSUMPTION] Future BTF-resolved-function code generation will reuse the same expected-output snapshot testing model currently used by `tests/bpf2c_tests/elf_bpf.cpp`. If this assumption is wrong, the validation strategy for generated BTF-resolved output will need a separate test harness. (Source: `tests/bpf2c_tests/elf_bpf.cpp:99-193`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-B2C-001 | [KNOWN] Incorrect entry layout can break bpf2c section parsing. (Source: `docs/BtfResolvedFunctions.md:252-255`) | Medium | High | [INFERRED] Keep the `zero_marker` position as its own atomic requirement. |
| RISK-B2C-002 | [KNOWN] Incomplete or non-deterministic hash inputs weaken proof-of-verification guarantees. (Source: `docs/BtfResolvedFunctions.md:302-310`) | Medium | High | [INFERRED] Keep count, ordering, and per-function fields explicit in separate requirements. |
| RISK-B2C-003 | [KNOWN] Leaving bpf2c on a helper-only import and hash model means generated native artifacts cannot carry the BTF-resolved dependency data required by the source design. (Source: `tools/bpf2c/bpf2c.cpp:73-129`, `tools/bpf2c/bpf_code_generator.cpp:1951-2155`) | High | High | [INFERRED] Make the helper-only baseline explicit in the design and validation deltas. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial bpf2c-integration requirements extracted from `docs/BtfResolvedFunctions.md`. |
| 0.2 | 2026-06-02 | Copilot | Added code-backed bpf2c deltas for helper-only import emission, helper-only program-info hashing, and missing BTF-resolved output paths. |

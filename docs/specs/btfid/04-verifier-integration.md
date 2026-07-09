# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source requires deterministic session-local BTF ID allocation, but it does not define the algorithm that produces that determinism. (Source: `docs/BtfResolvedFunctions.md:208-212`)
- [KNOWN] The source names `resolve_kfunc_call` and the PREVAIL `Call` contract, but it does not define the full `Call` structure in this document. (Source: `docs/BtfResolvedFunctions.md:215-227`)
- [KNOWN] The examined verifier entry points call `read_elf(...)`, but the in-scope Windows code does not contain explicit `.ksyms` or declaration-tag parsing logic, so the current division of responsibility between the Windows integration layer and the external verifier reader is not fully visible within this run's code scope. (Source: `libs/api/Verifier.cpp:478`, `libs/api/Verifier.cpp:824`)
- [KNOWN] The Windows verifier platform currently wires both `resolve_ksym_btf_id` and `resolve_kfunc_call` as `nullptr`, so the intended storage location for BTF ID mappings and the callback implementation strategy are not defined by the current in-scope code. (Source: `libs/api/windows_platform.cpp:100-113`)

## Implicit requirements in this area

- [INFERRED] Caller-side preprocessing and verifier callbacks must agree on a reversible `btf_id` mapping, because verification receives only the BTF ID and must recover the original provider/function identity. (Source: `docs/BtfResolvedFunctions.md:202-227`)
- [INFERRED] Any future BTF-resolved verifier support should extend the existing Windows verifier path (`read_elf` → `unmarshal` → `ebpf_verify_program`) rather than introducing a separate verification surface, because the current API already centralizes file-based and memory-based verification through that pipeline. (Source: `libs/api/Verifier.cpp:802-988`)

## Actual or possible conflicts

- [KNOWN] The source requires Windows-side BTF ID resolution and a `resolve_kfunc_call` platform callback, but the current Windows verifier platform passes `nullptr` for both BTF-related callback slots. (Source: `docs/BtfResolvedFunctions.md:215-227`, `libs/api/windows_platform.cpp:100-113`)
- [KNOWN] The source requires caller-side preprocessing of `.ksyms` symbols and top-level declaration tags, but no explicit Windows-side preprocessing for those inputs appears in the examined `libs/api` or `libs/api_common` code. (Source: `docs/BtfResolvedFunctions.md:197-212`, `libs/api/Verifier.cpp:478`, `libs/api/Verifier.cpp:824`)

## Coverage statement

- **Examined:** Section 5 Verifier Integration; `libs/api/Verifier.cpp`; `libs/api/windows_platform.cpp`; `libs/api_common/api_common.cpp`; `libs/api_common/windows_platform_common.cpp`; `libs/api_common/windows_helpers.cpp`; verifier-related tests under `tests`.
- **Method:** extracted caller preprocessing, callback resolution, rewrite semantics, and BTF-ID visibility rules, then compared them with the current Windows verifier platform wiring, verifier entry points, TLS program-info cache, and verifier API tests.
- **Excluded:** code outside `libs/api` and `libs/api_common`, including the external verifier library internals, plus native-code generation and runtime address binding.
- **Limitations:** the in-scope code calls `read_elf(...)` and PREVAIL APIs but does not include their full implementations, so some BTF-specific parser behavior remains outside direct inspection.

# Verifier Integration — Requirements Document

## 1. Overview

[KNOWN] This area defines how BTF-resolved functions are integrated into the PREVAIL verification flow. The source splits the flow into caller-side ELF parsing and symbol resolution, followed by verification-time prototype resolution through a platform callback. (Source: `docs/BtfResolvedFunctions.md:192-227`)

[KNOWN] The verifier then rewrites external calls into `call_btf` instructions whose BTF IDs are session-local and ephemeral to the verification and bpf2c pipeline. (Source: `docs/BtfResolvedFunctions.md:229-243`)

[KNOWN] The current Windows verifier implementation already exposes file-based and memory-based verification entry points that route ELF input through `read_elf(...)`, `unmarshal(...)`, and `ebpf_verify_program(...)`, and it maintains thread-local program-type information for helper resolution and post-verification program-info retrieval. [KNOWN] However, the current Windows platform callback table leaves both BTF-resolved callback slots unset. (Source: `libs/api/Verifier.cpp:802-988`, `libs/api_common/api_common.cpp:195-204`, `libs/api_common/windows_platform_common.cpp:798-847`, `libs/api/windows_platform.cpp:100-113`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] `.ksyms` parsing and top-level declaration-tag parsing. (Source: `docs/BtfResolvedFunctions.md:197-207`)
- [KNOWN] Session-local BTF ID mapping and reverse mapping. (Source: `docs/BtfResolvedFunctions.md:208-212`, `docs/BtfResolvedFunctions.md:226-227`)
- [KNOWN] `resolve_kfunc_call` callback usage and extern-call rewriting. (Source: `docs/BtfResolvedFunctions.md:215-243`)
- [KNOWN] Existing Windows verifier entry points, platform callback wiring, and TLS program-info caching relevant to verifier integration. (Source: `libs/api/Verifier.cpp:802-988`, `libs/api/windows_platform.cpp:100-113`, `libs/api_common/windows_platform_common.cpp:798-847`)

### 2.2 Out of Scope

- [KNOWN] Registry schema definition, because it belongs to `03-registry-publication.md`. (Source: `docs/BtfResolvedFunctions.md:140-190`)
- [KNOWN] Generated native import-table layout and hash materialization, because they belong to `05-bpf2c-integration.md`. (Source: `docs/BtfResolvedFunctions.md:245-310`)
- [KNOWN] Runtime address updates after load, because they belong to `08-runtime-execution.md`. (Source: `docs/BtfResolvedFunctions.md:396-428`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Top-level `BTF_KIND_DECL_TAG` | [KNOWN] A declaration-tag entry with no parent, used in the source design to map module identifiers to `.ksyms` functions. (Source: `docs/BtfResolvedFunctions.md:203-207`) |
| Ephemeral `call_btf` form | [KNOWN] The verifier-rewritten call form used inside the verifier/bpf2c pipeline and not exposed as a long-term public interface. (Source: `docs/BtfResolvedFunctions.md:239-243`) |
| TLS program-info cache | [KNOWN] The thread-local cache used by the current Windows verifier path to retain program information and expose it through `ebpf_get_program_info_from_verifier(...)`. (Source: `libs/api_common/windows_platform_common.cpp:798-847`, `libs/api/ebpf_api.cpp:4865-4873`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-VER-001: The caller-side preprocessing step MUST enumerate BTF-resolved function symbols from the `.ksyms` section, so that all external BTF-resolved calls are available for resolution before verification. (Source: `docs/BtfResolvedFunctions.md:199-205`)

Acceptance Criteria:
- [INFERRED] AC-1: The verifier requirements explicitly list `.ksyms` enumeration as an input-discovery step before any BTF ID assignment occurs. (Source: `docs/BtfResolvedFunctions.md:199-205`)

[KNOWN] REQ-VER-002: The caller-side preprocessing step MUST enumerate top-level `BTF_KIND_DECL_TAG` entries and MUST use each tag's function reference plus tag string to build the module-to-function mapping for `.ksyms` functions, so that each symbol is associated with a provider module GUID. (Source: `docs/BtfResolvedFunctions.md:203-207`)

Acceptance Criteria:
- [INFERRED] AC-1: The preprocessing requirements identify both the decl-tag string and the function reference as required mapping inputs. (Source: `docs/BtfResolvedFunctions.md:205-207`)

[KNOWN] REQ-VER-003: The caller-side preprocessing step MUST resolve each `(module_guid, function_name)` pair to a deterministic session-local BTF ID and MUST build both forward and reverse mappings, so that later verification can recover provider identity from `btf_id`. (Source: `docs/BtfResolvedFunctions.md:208-212`, `docs/BtfResolvedFunctions.md:226-227`)

Acceptance Criteria:
- [INFERRED] AC-1: The verifier requirements describe both `(module_guid, function_name) -> btf_id` and `btf_id -> (module_guid, function_name)` mappings. (Source: `docs/BtfResolvedFunctions.md:210-212`, `docs/BtfResolvedFunctions.md:226-227`)
- [INFERRED] AC-2: The requirements state that allocation is deterministic within the session. (Source: `docs/BtfResolvedFunctions.md:210`)

[KNOWN] REQ-VER-004: When PREVAIL encounters a `call_btf` instruction, the platform implementation of `resolve_kfunc_call` MUST map `btf_id` back to `(module_guid, function_name)`, load the function prototype from the registry, and return the corresponding PREVAIL `Call` contract, so that verification uses the provider's declared callable signature. (Source: `docs/BtfResolvedFunctions.md:215-227`)

Acceptance Criteria:
- [INFERRED] AC-1: The callback requirements treat reverse lookup, registry-prototype load, and `Call` creation as three distinct mandatory steps. (Source: `docs/BtfResolvedFunctions.md:226-227`)

[KNOWN] REQ-VER-005: The verifier MUST rewrite an external BTF-resolved function call from the extern-call form into `call_btf` with `src=2`, `imm=btf_id`, and `offset=0`, so that PREVAIL consumes the call in the documented BTF-call form. (Source: `docs/BtfResolvedFunctions.md:231-237`)

Acceptance Criteria:
- [INFERRED] AC-1: The rewritten call form preserves `btf_id` in `imm` and sets `offset` to `0`. (Source: `docs/BtfResolvedFunctions.md:233-237`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-VER-006: The system MUST treat verifier-assigned `call_btf` IDs as ephemeral and MUST NOT expose them as a long-term public kernel-code API, so that build-to-build BTF-ID instability does not become an external compatibility contract. (Source: `docs/BtfResolvedFunctions.md:239-243`)

Acceptance Criteria:
- [INFERRED] AC-1: The verifier requirements explicitly distinguish the internal rewritten form from a persisted public interface. (Source: `docs/BtfResolvedFunctions.md:241-243`)

[INFERRED] REQ-VER-007: If Windows BTF-resolved verifier support is added, it SHOULD integrate into the existing file-based and memory-based verifier entry points and the existing Windows platform callback table, so that callers continue to use the current verifier API surface rather than a separate BTF-specific verification API. (Source: `libs/api/Verifier.cpp:802-988`, `libs/api/windows_platform.cpp:100-113`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify the current verifier entry points and platform table as the preferred integration surface for future BTF-resolved support. (Source: `libs/api/Verifier.cpp:802-988`, `libs/api/windows_platform.cpp:100-113`)

### 4.3 Constraints

- [KNOWN] CON-001: Current PREVAIL `CallBtf` carries only `btf_id`, and `offset` must be `0`. (Source: `docs/BtfResolvedFunctions.md:237-238`)
- [UNKNOWN: the deterministic BTF-ID allocation algorithm is not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:208-212`)
- [KNOWN] CON-002: The current Windows verifier platform wires `resolve_ksym_btf_id` and `resolve_kfunc_call` as `nullptr`, so the current in-scope implementation does not yet provide Windows-side BTF callback behavior. (Source: `libs/api/windows_platform.cpp:100-113`)
- [KNOWN] CON-003: The current verifier API surface in `libs/api` is file-based and memory-based (`ebpf_api_elf_verify_program_from_file(...)` and `ebpf_api_elf_verify_program_from_memory(...)`) plus TLS-backed program-info retrieval; it does not expose any public BTF-ID parameter or result. (Source: `libs/api/Verifier.cpp:949-988`, `libs/api/ebpf_api.cpp:4865-4873`)

## 5. Dependencies

- DEP-VER-001: This requirement set depends on `03-registry-publication.md` for provider and prototype metadata. Impact if unavailable: `resolve_kfunc_call` cannot reconstruct a verified callable contract. (Source: `docs/BtfResolvedFunctions.md:208-227`)
- DEP-VER-002: This requirement set depends on the current Windows verifier integration points in `libs/api/Verifier.cpp`, `libs/api/windows_platform.cpp`, and `libs/api_common/windows_platform_common.cpp` because future BTF-resolved support must either extend or intentionally replace those existing verifier and TLS-caching paths. Impact if unavailable: the delta between the current verifier surface and the source requirements cannot be made explicit. (Source: `libs/api/Verifier.cpp:802-988`, `libs/api/windows_platform.cpp:100-113`, `libs/api_common/windows_platform_common.cpp:798-847`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] The decl-tag string format remains parseable as `module_id:{guid}` during preprocessing. If this assumption is wrong, module-to-function mapping needs an alternate encoding requirement. Justification: the source only documents the GUID-tag string format. (Source: `docs/BtfResolvedFunctions.md:103-104`, `docs/BtfResolvedFunctions.md:206-207`)
- ASM-002: [ASSUMPTION] Any future Windows-side BTF ID mapping state will be carried through the existing verifier request path and/or its current TLS support rather than through a new public verifier API. If this assumption is wrong, the verifier integration requirements need an explicit public-surface change. Justification: the current Windows verifier path already centralizes verification entry points and verifier-side TLS program info. (Source: `libs/api/Verifier.cpp:802-988`, `libs/api_common/windows_platform_common.cpp:798-847`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-VER-001 | [KNOWN] Non-deterministic BTF-ID allocation would break agreement between preprocessing, verification, and downstream generation. (Source: `docs/BtfResolvedFunctions.md:210-212`, `docs/BtfResolvedFunctions.md:226-227`) | Medium | High | [INFERRED] Keep deterministic mapping explicit as a requirement. |
| RISK-VER-002 | [KNOWN] Treating rewritten BTF IDs as stable public identifiers would create a compatibility contract the source explicitly rejects. (Source: `docs/BtfResolvedFunctions.md:239-243`) | Low | High | [INFERRED] Preserve the ephemerality constraint in this file and dependent files. |
| RISK-VER-003 | [KNOWN] Leaving the Windows platform BTF callback slots unset means a future BTF-resolved object cannot rely on the current in-scope verifier platform to perform Windows-specific kfunc resolution. (Source: `libs/api/windows_platform.cpp:100-113`) | High | High | [INFERRED] Make the callback gap explicit in the design and validation deltas. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial verifier-integration requirements extracted from `docs/BtfResolvedFunctions.md`. |
| 0.2 | 2026-06-02 | Copilot | Added code-backed verifier deltas for current API entry points, TLS program-info caching, and missing Windows BTF callback wiring. |

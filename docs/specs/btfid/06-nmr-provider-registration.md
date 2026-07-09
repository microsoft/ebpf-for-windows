# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source marks the NPI GUID name as proposed and not yet present in `include/ebpf_extension_uuids.h`, so the final public identifier remains unknown. (Source: `docs/BtfResolvedFunctions.md:316-324`)
- [KNOWN] The current public UUID header defines `EBPF_PROGRAM_INFO_EXTENSION_IID`, `EBPF_HOOK_EXTENSION_IID`, and `EBPF_MAP_INFO_EXTENSION_IID`, but no BTF-resolved-function NPI identifier, so the exact insertion point for the new NPI is implied rather than already implemented. (Source: `include/ebpf_extension_uuids.h:11-27`)
- [KNOWN] The current in-scope provider-validation path is built around `ebpf_program_data_t` carried through `EBPF_PROGRAM_INFO_EXTENSION_IID`; the source does not define whether BTF-resolved provider validation should reuse that code path, add a sibling path, or introduce a generic provider-data abstraction. (Source: `docs/BtfResolvedFunctions.md:326-346`, `libs/execution_context/ebpf_program.c:247-310`)

## Implicit requirements in this area

- [INFERRED] Provider registration data must preserve a 1:1 correspondence between published prototypes and published addresses, because the consumer uses provider data to bind callable addresses to declared functions. (Source: `docs/BtfResolvedFunctions.md:333-346`, `docs/BtfResolvedFunctions.md:359-365`)
- [INFERRED] Any future BTF-resolved provider should follow the existing NMR pattern of GUID-typed `ModuleId`, typed `NpiSpecificCharacteristics`, and `provider_dispatch = NULL`, because current execution-context providers and test helpers already use that shape for data-driven NPIs. (Source: `libs/execution_context/ebpf_core.c:195-208`, `libs/execution_context/ebpf_core.c:213-242`, `tests/end_to_end/helpers.h:1543-1596`)

## Actual or possible conflicts

- [KNOWN] The source requires a dedicated BTF-resolved-function NPI and `ebpf_btf_resolved_function_provider_data_t`, but the current execution-context code and tests only expose the existing `EBPF_PROGRAM_INFO_EXTENSION_IID` + `ebpf_program_data_t` provider contract. (Source: `docs/BtfResolvedFunctions.md:318-340`, `include/ebpf_extension_uuids.h:11-27`, `libs/execution_context/ebpf_core.c:195-208`, `tests/end_to_end/helpers.h:1583-1596`)
- [KNOWN] The source requires provider data fields for BTF-resolved function count, prototypes, and addresses, but the current in-scope provider-data validator only understands `ebpf_program_data_t` and helper-function-address counts. (Source: `docs/BtfResolvedFunctions.md:333-340`, `libs/execution_context/ebpf_program.c:247-310`)

## Coverage statement

- **Examined:** Section 7 NMR Provider Registration; `include/ebpf_extension_uuids.h`; `include/ebpf_extension.h`; `include/ebpf_program_types.h`; `libs/execution_context/ebpf_core.c`; `libs/execution_context/ebpf_program.c`; `libs/execution_context/unit/execution_context_unit_test.cpp`; selected provider/client test helpers under `tests\`.
- **Method:** extracted NPI, provider-registration, and provider-data requirements, then compared them with current NMR provider registration, provider-data validation, and repo test helper/provider patterns.
- **Excluded:** detailed client attach/detach behavior for native modules and runtime invocation semantics.
- **Limitations:** no in-scope code currently defines a BTF-resolved-function provider type, so future public type names beyond the proposed GUID and struct name remain source-driven only.

# NMR Provider Registration — Requirements Document

## 1. Overview

[KNOWN] This area defines how provider drivers expose BTF-resolved functions to native modules at load time through NMR. The source requires provider registration against a BTF-resolved function NPI and requires provider data to include prototypes and resolved implementation addresses. (Source: `docs/BtfResolvedFunctions.md:312-346`)

[KNOWN] The source also states that no provider dispatch table is required because function addresses are provided directly. (Source: `docs/BtfResolvedFunctions.md:343-346`)

[KNOWN] The current execution-context implementation already contains NMR provider infrastructure, but the in-scope provider registration is for the existing program-information NPI. Production code registers a global-helper provider using `EBPF_PROGRAM_INFO_EXTENSION_IID`, a GUID-typed `ModuleId`, and `ebpf_program_data_t` in `NpiSpecificCharacteristics`, with `provider_dispatch = NULL`. [KNOWN] No in-scope code currently defines or registers a BTF-resolved-function provider. (Source: `include/ebpf_extension_uuids.h:11-27`, `libs/execution_context/ebpf_core.c:27-37`, `libs/execution_context/ebpf_core.c:195-208`, `libs/execution_context/ebpf_core.c:213-242`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] BTF-resolved function NPI identification. (Source: `docs/BtfResolvedFunctions.md:316-324`)
- [KNOWN] Required NMR registration fields and provider data. (Source: `docs/BtfResolvedFunctions.md:326-340`)
- [KNOWN] Absence of a dispatch-table requirement. (Source: `docs/BtfResolvedFunctions.md:343-346`)
- [KNOWN] Existing execution-context NMR provider and provider-data validation behavior relevant to a future BTF-resolved provider contract. (Source: `libs/execution_context/ebpf_core.c:195-208`, `libs/execution_context/ebpf_program.c:247-310`)

### 2.2 Out of Scope

- [KNOWN] Header declaration metadata, because it belongs to `02-header-authoring.md`. (Source: `docs/BtfResolvedFunctions.md:85-133`)
- [KNOWN] Load-time client attach handling, because it belongs to `07-native-module-loading.md`. (Source: `docs/BtfResolvedFunctions.md:348-394`)
- [KNOWN] Runtime invocation and detach-failure semantics, because they belong to `08-runtime-execution.md`. (Source: `docs/BtfResolvedFunctions.md:396-428`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Provider data | [KNOWN] The `ebpf_btf_resolved_function_provider_data_t` payload supplied through `NpiSpecificCharacteristics`, including prototype and address arrays. (Source: `docs/BtfResolvedFunctions.md:331-340`) |
| Dispatch table omission | [KNOWN] The source statement that providers do not require a dispatch table because addresses are supplied directly. (Source: `docs/BtfResolvedFunctions.md:343-346`) |
| Program-info provider baseline | [KNOWN] The current NMR provider contract in the codebase that uses `EBPF_PROGRAM_INFO_EXTENSION_IID` and `ebpf_program_data_t` in `NpiSpecificCharacteristics`. (Source: `libs/execution_context/ebpf_core.c:195-208`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-NMR-001: A driver that exposes BTF-resolved functions MUST register as an NMR provider for the BTF-resolved function NPI, so that native modules can bind to the provider at load time. (Source: `docs/BtfResolvedFunctions.md:314-324`)

Acceptance Criteria:
- [INFERRED] AC-1: The registration requirements identify NMR provider registration as mandatory for provider participation. (Source: `docs/BtfResolvedFunctions.md:314-324`)

[KNOWN] REQ-NMR-002: The provider registration MUST use the driver's module GUID as `ModuleId`, so that NMR attachment uses the same provider identity as header metadata and registry publication. (Source: `docs/BtfResolvedFunctions.md:328-330`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify `ModuleId` as the same GUID used by the header and registry requirements. (Source: `docs/BtfResolvedFunctions.md:328-330`, `docs/BtfResolvedFunctions.md:120-125`)

[KNOWN] REQ-NMR-003: The provider registration MUST supply `ebpf_btf_resolved_function_provider_data_t` through `NpiSpecificCharacteristics`, so that consumers receive the provider's callable prototypes and addresses during binding. (Source: `docs/BtfResolvedFunctions.md:331-340`)

Acceptance Criteria:
- [INFERRED] AC-1: The registration requirements identify `NpiSpecificCharacteristics` as carrying provider data rather than a dispatch table. (Source: `docs/BtfResolvedFunctions.md:331-346`)

[KNOWN] REQ-NMR-004: Provider data MUST include the BTF-resolved function count, the prototype array, and the function-address array, so that a client can bind provider metadata to callable entry points. (Source: `docs/BtfResolvedFunctions.md:333-340`)

Acceptance Criteria:
- [INFERRED] AC-1: The provider-data requirements enumerate count, prototypes, and addresses as required fields. (Source: `docs/BtfResolvedFunctions.md:333-340`)

[KNOWN] REQ-NMR-005: The provider registration contract MUST NOT require a provider dispatch table, so that function addresses are supplied directly in provider data. (Source: `docs/BtfResolvedFunctions.md:343-346`)

Acceptance Criteria:
- [INFERRED] AC-1: The NMR requirements identify direct function-address publication as the replacement for dispatch-table indirection. (Source: `docs/BtfResolvedFunctions.md:343-346`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-NMR-006: The provider registration contract MUST preserve cross-phase identity by reusing the same module GUID across header metadata, registry publication, and NMR registration, so that provider lookup stays coherent across the full pipeline. (Source: `docs/BtfResolvedFunctions.md:120-125`, `docs/BtfResolvedFunctions.md:328-330`)

Acceptance Criteria:
- [INFERRED] AC-1: No NMR requirement introduces an alternate provider identity separate from the documented module GUID. (Source: `docs/BtfResolvedFunctions.md:120-125`, `docs/BtfResolvedFunctions.md:328-330`)

[INFERRED] REQ-NMR-007: If BTF-resolved-function provider registration is added, it SHOULD extend the existing execution-context NMR provider pattern of GUID-typed `ModuleId`, typed `NpiSpecificCharacteristics`, and `provider_dispatch = NULL`, so that provider registration remains structurally consistent with current data-driven NPI contracts. (Source: `libs/execution_context/ebpf_core.c:195-208`, `libs/execution_context/ebpf_core.c:213-242`, `tests/end_to_end/helpers.h:1543-1596`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify the current execution-context/data-provider NMR pattern as the preferred extension point for BTF-resolved provider registration rather than introducing an unrelated provider shape. (Source: `libs/execution_context/ebpf_core.c:195-208`, `tests/end_to_end/helpers.h:1583-1596`)

### 4.3 Constraints

- [KNOWN] CON-001: The GUID name `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID` is proposed and is not currently present in `include/ebpf_extension_uuids.h`. (Source: `docs/BtfResolvedFunctions.md:318-324`)
- [UNKNOWN: the final public-header identifier and versioning rules for the NPI are not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:318-324`)
- [KNOWN] CON-002: The current public UUID header contains no BTF-resolved-function NPI identifier; only program-info, hook, and map extension IIDs are defined in the examined header. (Source: `include/ebpf_extension_uuids.h:11-27`)
- [KNOWN] CON-003: The current in-scope provider-data validator is specialized for `ebpf_program_data_t` and helper-function-address count validation, not BTF-resolved function provider data. (Source: `libs/execution_context/ebpf_program.c:247-310`)
- [KNOWN] CON-004: The current execution-context provider/client matching path expects `ModuleId->Type == MIT_GUID` before comparing GUID values. (Source: `libs/execution_context/ebpf_program.c:217-239`)

## 5. Dependencies

- DEP-NMR-001: This requirement set depends on `02-header-authoring.md` and `03-registry-publication.md` because registration reuses the same provider identity and callable metadata lineage. Impact if unavailable: NMR identity cannot be tied back to compile-time and verification-time contracts. (Source: `docs/BtfResolvedFunctions.md:120-125`, `docs/BtfResolvedFunctions.md:328-340`)
- DEP-NMR-002: This requirement set depends on the existing execution-context NMR provider and provider-data validation patterns because future BTF-resolved registration must either extend or intentionally diverge from those current contracts. Impact if unavailable: the delta between the source design and the current implementation cannot be stated concretely. (Source: `libs/execution_context/ebpf_core.c:195-208`, `libs/execution_context/ebpf_program.c:247-310`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] The provider's address array order matches the prototype array order used by consumers. If this assumption is wrong, an explicit address-to-prototype correlation rule is required. Justification: the source lists both arrays but does not define an alternate matching key. (Source: `docs/BtfResolvedFunctions.md:333-340`)
- ASM-002: [ASSUMPTION] Future BTF-resolved-function provider data would be declared alongside other extension provider-data types in `include\ebpf_extension.h` rather than alongside `ebpf_program_data_t` in `include\ebpf_program_types.h`. If this assumption is wrong, the public-header touch points in the design delta must be updated. Justification: existing extension provider-data types such as `ebpf_attach_provider_data_t` and `ebpf_map_provider_data_t` live in `include\ebpf_extension.h`. (Source: `include/ebpf_extension.h:112-118`, `include/ebpf_extension.h:494-501`, `include/ebpf_program_types.h:88-103`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-NMR-001 | [KNOWN] Mismatched module GUIDs break provider/client binding even if function names match. (Source: `docs/BtfResolvedFunctions.md:328-330`) | Medium | High | [INFERRED] Keep GUID reuse mandatory across area files. |
| RISK-NMR-002 | [KNOWN] Changing the proposed NPI identifier before public-header ratification can invalidate early consumers. (Source: `docs/BtfResolvedFunctions.md:318-324`) | High | Medium | [INFERRED] Keep the identifier documented as proposed rather than final. |
| RISK-NMR-003 | [KNOWN] Reusing the current program-info provider contract without a distinct BTF-resolved provider type can prevent consumers from distinguishing helper/program-info metadata from BTF-resolved callable metadata. (Source: `libs/execution_context/ebpf_core.c:195-208`, `docs/BtfResolvedFunctions.md:326-340`) | High | High | [INFERRED] Make the dedicated BTF NPI and provider-data contract explicit in the design and validation deltas. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial NMR-provider-registration requirements extracted from `docs/BtfResolvedFunctions.md`. |
| 0.2 | 2026-06-02 | Copilot | Added code-backed deltas for the current program-info provider baseline, missing BTF NPI/provider-data types, and existing no-dispatch provider pattern. |

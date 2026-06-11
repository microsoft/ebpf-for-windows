# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The architecture diagram describes four phases and their handoffs, but it does not assign ownership for failures that occur between verification-time resolution and load-time provider attachment. (Source: `docs/BtfResolvedFunctions.md:35-82`)

## Implicit requirements in this area

- [INFERRED] The feature requires a stable end-to-end handoff from compile-time metadata to runtime address resolution, because each phase consumes artifacts produced by the previous phase. (Source: `docs/BtfResolvedFunctions.md:35-82`)

## Actual or possible conflicts

- [INFERRED] No additional conflicts were identified within the examined architecture source lines beyond the global cross-area items in `README.md`. (Source: `docs/BtfResolvedFunctions.md:35-82`)

## Coverage statement

- **Examined:** Section 2 Architecture, with Section 1 overview context.
- **Method:** extracted phase-level and boundary-level requirements only.
- **Excluded:** detailed verifier, bpf2c, NMR, runtime, and security rules captured in their dedicated area specs.
- **Limitations:** this area is architectural and therefore depends on other files for low-level contract details.

# Architecture — Requirements Document

## 1. Overview

[KNOWN] This area defines the end-to-end lifecycle for BTF-resolved functions across compile time, verification time, load time, and runtime. The source describes BTF-resolved functions as driver-exposed callable functions resolved by name via BTF and disambiguated by module GUID rather than by static helper ID. (Source: `docs/BtfResolvedFunctions.md:5-9`, `docs/BtfResolvedFunctions.md:35-82`)

[KNOWN] The architectural goal is modular extension: any driver can act as a provider without becoming a program-type specific information provider, while the eBPF pipeline resolves names into session-local BTF IDs and ultimately into callable addresses. (Source: `docs/BtfResolvedFunctions.md:23-33`, `docs/BtfResolvedFunctions.md:49-80`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] Phase boundaries from compile time through runtime. (Source: `docs/BtfResolvedFunctions.md:35-82`)
- [KNOWN] Namespace and resolution model differences from static-ID helpers. (Source: `docs/BtfResolvedFunctions.md:18-27`)
- [KNOWN] Provider independence from program-type specific information providers. (Source: `docs/BtfResolvedFunctions.md:23`, `docs/BtfResolvedFunctions.md:30-33`)

### 2.2 Out of Scope

- [KNOWN] Header syntax details, because those are specified in `02-header-authoring.md`. (Source: `docs/BtfResolvedFunctions.md:85-133`)
- [KNOWN] Registry key/value schema, because that is specified in `03-registry-publication.md`. (Source: `docs/BtfResolvedFunctions.md:134-190`)
- [KNOWN] Runtime detach sequencing internals, because those are specified in `07-native-module-loading.md`, `08-runtime-execution.md`, and `09-ebpf-program-internal-changes.md`. (Source: `docs/BtfResolvedFunctions.md:348-466`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Provider independence | [KNOWN] The property that any driver registered as a BTF-resolved function provider can expose functions without being a program-type specific provider. (Source: `docs/BtfResolvedFunctions.md:23`, `docs/BtfResolvedFunctions.md:30-33`) |
| Phase handoff | [INFERRED] The transfer of required artifacts from one lifecycle phase to the next, such as `.ksyms` metadata into verification-time lookup and provider addresses into runtime execution. (Source: `docs/BtfResolvedFunctions.md:35-82`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-ARCH-001: The system MUST treat BTF-resolved functions as a per-module callable namespace that is disambiguated by module GUID when resolving external function calls, so that functions with the same name can be distinguished by provider. (Source: `docs/BtfResolvedFunctions.md:22-25`)

Acceptance Criteria:
- [INFERRED] AC-1: A requirements reviewer can trace the namespace key for resolution to `(module GUID, function name)` rather than to a global helper ID. (Source: `docs/BtfResolvedFunctions.md:8-9`, `docs/BtfResolvedFunctions.md:22-25`)

[KNOWN] REQ-ARCH-002: The system MUST support compile-time discovery of BTF-resolved functions through header-provided BTF metadata that produces `.ksyms` entries for later resolution, so that verification-time tooling has named symbols to resolve. (Source: `docs/BtfResolvedFunctions.md:42-43`, `docs/BtfResolvedFunctions.md:87-91`)

Acceptance Criteria:
- [INFERRED] AC-1: The compile-time phase description includes `.ksyms` output as an artifact consumed by later phases. (Source: `docs/BtfResolvedFunctions.md:41-43`, `docs/BtfResolvedFunctions.md:52-56`)

[KNOWN] REQ-ARCH-003: The system MUST resolve each BTF-resolved function into a session-local BTF ID during verification-time preprocessing, so that the verifier and downstream pipeline consume call sites in `call_btf` form rather than unresolved extern calls. (Source: `docs/BtfResolvedFunctions.md:52-57`, `docs/BtfResolvedFunctions.md:199-243`)

Acceptance Criteria:
- [INFERRED] AC-1: The verification-time requirements show a transition from unresolved extern-call metadata to `call_btf(btf_id)` semantics. (Source: `docs/BtfResolvedFunctions.md:57`, `docs/BtfResolvedFunctions.md:231-237`)

[KNOWN] REQ-ARCH-004: The system MUST resolve load-time callable addresses through NMR provider attachment keyed by module GUID, so that native modules obtain provider function addresses before execution. (Source: `docs/BtfResolvedFunctions.md:65-70`, `docs/BtfResolvedFunctions.md:350-365`)

Acceptance Criteria:
- [INFERRED] AC-1: The load-time requirements show that provider attachment supplies function addresses, not only metadata. (Source: `docs/BtfResolvedFunctions.md:67-69`, `docs/BtfResolvedFunctions.md:339-346`)

[KNOWN] REQ-ARCH-005: The system MUST fail program invocation while a required provider is detached and MUST resume normal invocation only after reattachment, so that runtime behavior remains explicit when address resolution is unavailable. (Source: `docs/BtfResolvedFunctions.md:78-80`, `docs/BtfResolvedFunctions.md:426-428`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements include a failure outcome for detached providers and a distinct successful outcome when providers are attached. (Source: `docs/BtfResolvedFunctions.md:78-80`, `docs/BtfResolvedFunctions.md:402-406`, `docs/BtfResolvedFunctions.md:426-428`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-ARCH-006: The system MUST preserve modular provider extensibility by allowing drivers that are not program-type specific information providers to expose BTF-resolved functions, so that specialized driver functionality can be added without extending eBPF core helper IDs. (Source: `docs/BtfResolvedFunctions.md:23`, `docs/BtfResolvedFunctions.md:30-33`)

Acceptance Criteria:
- [INFERRED] AC-1: The architecture requirements do not require a provider to be a program-type specific information provider as a precondition for participation. (Source: `docs/BtfResolvedFunctions.md:23`, `docs/BtfResolvedFunctions.md:30-33`)

### 4.3 Constraints

- [KNOWN] CON-001: The requirements baseline MUST treat the documented architecture as a proposed design because the source explicitly states that the relevant NPI IDs, store APIs, and C types are planned interfaces not yet present in public headers. (Source: `docs/BtfResolvedFunctions.md:14-16`)
- [KNOWN] CON-002: The architecture MUST use `call_btf` for BTF-resolved function calls rather than the static helper `call imm` form. (Source: `docs/BtfResolvedFunctions.md:24`, `docs/BtfResolvedFunctions.md:231-237`)

## 5. Dependencies

- DEP-ARCH-001: This requirement set depends on `02-header-authoring.md`, `03-registry-publication.md`, `06-nmr-provider-registration.md`, and `08-runtime-execution.md` for the compile-time, verification-time, load-time, and runtime contracts that implement the architecture. Impact if unavailable: the phase handoffs are underspecified. (Source: `docs/BtfResolvedFunctions.md:35-82`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] Downstream design artifacts will keep the same phase boundaries used in the source architecture diagram. If this assumption is wrong, cross-file requirement ownership will need to be remapped. Justification: the prompt requests area grouping that follows the source layout. (Source: `docs/BtfResolvedFunctions.md:35-82`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-ARCH-001 | [KNOWN] A missing provider at runtime prevents invocation until reattachment. (Source: `docs/BtfResolvedFunctions.md:78-80`, `docs/BtfResolvedFunctions.md:426-428`) | Medium | High | [INFERRED] Keep runtime readiness checks explicit in `08-runtime-execution.md`. |
| RISK-ARCH-002 | [KNOWN] Proposed interfaces may change before public-header ratification. (Source: `docs/BtfResolvedFunctions.md:14-16`) | High | Medium | [INFERRED] Keep constraints and assumptions explicit instead of baking in final names. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial architecture requirements extracted from `docs/BtfResolvedFunctions.md`. |

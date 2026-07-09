# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source states that the eBPF store can be rooted at either HKCU or HKLM, but it does not define the policy that chooses one root over the other for a given publication flow. [INFERRED] Existing `store_helper` update APIs currently attempt HKCU first and then HKLM, suppressing `EBPF_ACCESS_DENIED` only for the HKLM write, so a BTF-resolved-function store API will need an explicit decision on whether to inherit that convention. (Source: `docs/BtfResolvedFunctions.md:136-139`, `libs/store_helper/ebpf_store_helper.c:159-171`, `libs/store_helper/ebpf_store_helper.c:274-285`, `libs/store_helper/ebpf_store_helper.c:485-496`)
- [KNOWN] The source describes a proposed store API, but it does not define version negotiation or compatibility behavior for that API. (Source: `docs/BtfResolvedFunctions.md:161-190`)
- [KNOWN] The source's illustrative registry layout uses per-function `Prototype`, `ReturnType`, `Arguments`, and `Flags` values, but the existing `store_helper` implementation for helper metadata uses extension-header values plus serialized binary prototype data, so the persistence shape for BTF-resolved-function metadata is not aligned with an existing store-helper pattern yet. (Source: `docs/BtfResolvedFunctions.md:149-152`, `libs/store_helper/ebpf_store_helper.c:68-100`)

## Implicit requirements in this area

- [INFERRED] Published registry metadata must be complete enough for verifier lookup to derive the callable prototype without loading the provider driver. (Source: `docs/BtfResolvedFunctions.md:136-190`, `docs/BtfResolvedFunctions.md:208-227`)

## Actual or possible conflicts

- [KNOWN] The source's root-agnostic publication description conflicts with the more concrete dual-root write behavior already used by `store_helper` update APIs for other registry-published eBPF metadata. (Source: `docs/BtfResolvedFunctions.md:136-139`, `libs/store_helper/ebpf_store_helper.c:159-171`, `libs/store_helper/ebpf_store_helper.c:274-285`, `libs/store_helper/ebpf_store_helper.c:485-496`)
- [KNOWN] The source's illustrative per-field function schema does not match the existing `store_helper` convention of using extension-header values plus binary serialization for helper prototype payloads. (Source: `docs/BtfResolvedFunctions.md:149-152`, `libs/store_helper/ebpf_store_helper.c:68-100`)

## Coverage statement

- **Examined:** Section 4 Registry Publication.
- **Method:** extracted store layout and publication-data requirements, then compared them against `libs/store_helper/ebpf_store_helper.c` and `include/ebpf_store_helper.h` for existing store-helper API and persistence conventions.
- **Excluded:** verifier-side lookup logic, runtime binding, and tests because no test scope was provided in this run.
- **Limitations:** no BTF-resolved-function store API exists yet in the examined public header or implementation, so code-backed deltas are inferred from adjacent store-helper patterns rather than from a BTF-specific implementation.

# Registry Publication — Requirements Document

## 1. Overview

[KNOWN] This area defines the verification-time metadata publication contract for providers. The source requires BTF-resolved function metadata to be published to the Windows registry so the verifier can discover and validate calls before runtime provider attachment occurs. (Source: `docs/BtfResolvedFunctions.md:136-190`)

[KNOWN] The published metadata is organized under a provider GUID and then by function name, with function prototype data stored as typed values. (Source: `docs/BtfResolvedFunctions.md:140-157`)

[KNOWN] The current public `store_helper` surface already exposes registry-publication APIs for global helpers, sections, and program information, but it does not yet expose a BTF-resolved-function publication API. [INFERRED] That missing API is the main implementation gap between this requirements area and the examined code scope. (Source: `include/ebpf_store_helper.h:23-77`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] Registry hierarchy for provider and function metadata. (Source: `docs/BtfResolvedFunctions.md:140-157`)
- [KNOWN] Per-function metadata elements required for verification. (Source: `docs/BtfResolvedFunctions.md:149-152`)
- [KNOWN] Proposed store-API publication shape. (Source: `docs/BtfResolvedFunctions.md:161-190`)
- [INFERRED] Existing `store_helper` publication conventions that a new BTF-resolved-function API would need either to reuse or to override explicitly, including dual-root writes and the existing public-header API pattern. (Source: `libs/store_helper/ebpf_store_helper.c:159-171`, `libs/store_helper/ebpf_store_helper.c:274-285`, `libs/store_helper/ebpf_store_helper.c:485-496`, `include/ebpf_store_helper.h:23-77`)

### 2.2 Out of Scope

- [KNOWN] Header declaration rules, because they are specified in `02-header-authoring.md`. (Source: `docs/BtfResolvedFunctions.md:85-133`)
- [KNOWN] Verifier-side reverse mapping and instruction rewriting, because they are specified in `04-verifier-integration.md`. (Source: `docs/BtfResolvedFunctions.md:197-243`)
- [KNOWN] Provider-address publication for runtime binding, because that is specified through NMR in `06-nmr-provider-registration.md`. (Source: `docs/BtfResolvedFunctions.md:333-346`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Store root | [KNOWN] The root of the eBPF store, which may be either HKCU or HKLM in the source description. (Source: `docs/BtfResolvedFunctions.md:137-139`) |
| Provider data size | [KNOWN] The `Size` value stored with provider metadata to describe the provider data size. (Source: `docs/BtfResolvedFunctions.md:145-146`) |
| Dual-root publication convention | [KNOWN] The existing `store_helper` behavior in which update APIs write HKCU first, then attempt HKLM, and suppress `EBPF_ACCESS_DENIED` only for the HKLM write. (Source: `libs/store_helper/ebpf_store_helper.c:159-171`, `libs/store_helper/ebpf_store_helper.c:274-285`, `libs/store_helper/ebpf_store_helper.c:485-496`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-REG-001: The system MUST publish BTF-resolved function metadata under `Software\eBPF\Providers\BtfResolvedFunctions\{module_guid}` relative to the selected store root, so that verification-time lookup can locate provider metadata by module GUID. (Source: `docs/BtfResolvedFunctions.md:136-145`)

Acceptance Criteria:
- [INFERRED] AC-1: The registry publication requirements identify the provider GUID node as the immediate grouping key beneath `BtfResolvedFunctions`. (Source: `docs/BtfResolvedFunctions.md:142-145`)

[KNOWN] REQ-REG-002: The system MUST publish `Version` and `Size` values for each provider metadata node, so that stored provider information carries explicit version and sizing metadata. (Source: `docs/BtfResolvedFunctions.md:145-146`)

Acceptance Criteria:
- [INFERRED] AC-1: A published provider node is incomplete if either `Version` or `Size` is absent from the documented schema. (Source: `docs/BtfResolvedFunctions.md:145-146`)

[KNOWN] REQ-REG-003: The system MUST publish a `Functions` child collection under each provider node and MUST group function metadata by function name within that collection, so that verifier lookup can address a function by `{module_guid}` plus `{name}`. (Source: `docs/BtfResolvedFunctions.md:147-157`, `docs/BtfResolvedFunctions.md:209-210`)

Acceptance Criteria:
- [INFERRED] AC-1: The publication requirements show `{module_guid}` and `{name}` as separate lookup segments rather than a flattened key. (Source: `docs/BtfResolvedFunctions.md:147-157`, `docs/BtfResolvedFunctions.md:209-210`)

[KNOWN] REQ-REG-004: For each published BTF-resolved function, the system MUST publish `Prototype`, `ReturnType`, `Arguments`, and `Flags` metadata, so that the verifier can reconstruct the callable contract from registry data. (Source: `docs/BtfResolvedFunctions.md:149-152`, `docs/BtfResolvedFunctions.md:226-227`)

Acceptance Criteria:
- [INFERRED] AC-1: A function metadata entry is incomplete if any of the four documented values is missing. (Source: `docs/BtfResolvedFunctions.md:149-152`)

[KNOWN] REQ-REG-005: The system SHOULD support publication through a store API that accepts provider-level metadata containing the module GUID, function count, and prototype array, so that providers can publish metadata without directly authoring registry keys. (Source: `docs/BtfResolvedFunctions.md:161-188`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements preserve provider-level API inputs for GUID, count, and prototype array as the minimum documented publication contract. (Source: `docs/BtfResolvedFunctions.md:175-188`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-REG-006: Provider metadata MUST be available at verification time before program execution, so that verification does not depend on runtime provider attachment to discover prototypes. (Source: `docs/BtfResolvedFunctions.md:136-139`, `docs/BtfResolvedFunctions.md:194-227`)

Acceptance Criteria:
- [INFERRED] AC-1: The registry-publication requirements make verification-time availability explicit rather than treating publication as a runtime concern. (Source: `docs/BtfResolvedFunctions.md:136-139`, `docs/BtfResolvedFunctions.md:209-227`)

[INFERRED] REQ-REG-007: If BTF-resolved-function metadata is added to `store_helper`, the publication path SHOULD follow the existing dual-root publication convention used by other `ebpf_store_update_*` APIs, so that BTF publication behavior stays consistent with the current store-helper contract for registry-backed metadata. (Source: `libs/store_helper/ebpf_store_helper.c:155-173`, `libs/store_helper/ebpf_store_helper.c:268-287`, `libs/store_helper/ebpf_store_helper.c:479-498`, `include/ebpf_store_helper.h:23-57`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify HKCU-first publication and HKLM `EBPF_ACCESS_DENIED` suppression as the existing convention to preserve or explicitly override. (Source: `libs/store_helper/ebpf_store_helper.c:159-171`, `libs/store_helper/ebpf_store_helper.c:274-285`, `libs/store_helper/ebpf_store_helper.c:485-496`)

### 4.3 Constraints

- [KNOWN] CON-001: The source allows either HKCU or HKLM as the eBPF store root, but does not define selection policy between them. (Source: `docs/BtfResolvedFunctions.md:137-139`)
- [KNOWN] CON-002: The documented store API is proposed and is not currently present in `include/ebpf_store_helper.h`. (Source: `docs/BtfResolvedFunctions.md:184-190`)
- [KNOWN] CON-003: The examined public `store_helper` header currently declares update APIs only for global helpers, sections, and program information; no BTF-resolved-function publication API is currently declared there. (Source: `include/ebpf_store_helper.h:23-77`)
- [KNOWN] CON-004: Existing `store_helper` metadata writers persist extension-header version/size information through `_ebpf_store_update_extension_header_information`, so any BTF-resolved-function store integration must either reuse that convention or document why it diverges. (Source: `libs/store_helper/ebpf_store_helper.c:13-21`, `libs/store_helper/ebpf_store_helper.c:68-69`, `libs/store_helper/ebpf_store_helper.c:217-218`, `libs/store_helper/ebpf_store_helper.c:296-299`, `libs/store_helper/ebpf_store_helper.c:348-349`)

## 5. Dependencies

- DEP-REG-001: This requirement set depends on `04-verifier-integration.md` because the verifier consumes the published metadata to resolve prototypes. Impact if unavailable: publication completeness cannot be justified against a consumer contract. (Source: `docs/BtfResolvedFunctions.md:208-227`)
- DEP-REG-002: This requirement set depends on the existing `store_helper` public API surface in `include/ebpf_store_helper.h` and implementation conventions in `libs/store_helper/ebpf_store_helper.c` because a BTF-resolved-function publication API does not yet exist and would need to integrate into that surface. Impact if unavailable: the requirements cannot identify whether BTF publication should reuse or intentionally diverge from existing store-helper behavior. (Source: `include/ebpf_store_helper.h:23-77`, `libs/store_helper/ebpf_store_helper.c:155-173`, `libs/store_helper/ebpf_store_helper.c:268-287`, `libs/store_helper/ebpf_store_helper.c:479-498`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] A future BTF-resolved-function publication API added to `store_helper` will follow the existing HKCU-first, HKLM-second publication convention unless an explicit design decision says otherwise. If this assumption is wrong, this area needs an explicit root-selection and error-handling requirement for BTF publication. Justification: the source is root-agnostic, but all examined `store_helper` update APIs share the same dual-root behavior. (Source: `docs/BtfResolvedFunctions.md:137-139`, `libs/store_helper/ebpf_store_helper.c:159-171`, `libs/store_helper/ebpf_store_helper.c:274-285`, `libs/store_helper/ebpf_store_helper.c:485-496`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-REG-001 | [KNOWN] Missing or incomplete registry metadata prevents the verifier from discovering valid prototypes. (Source: `docs/BtfResolvedFunctions.md:136-137`, `docs/BtfResolvedFunctions.md:226-227`) | Medium | High | [INFERRED] Require all documented metadata fields explicitly. |
| RISK-REG-002 | [KNOWN] Proposed store APIs may change before they are added to public headers. (Source: `docs/BtfResolvedFunctions.md:184-190`) | High | Medium | [INFERRED] Keep the registry schema authoritative, and keep the API requirement as SHOULD rather than MUST. |
| RISK-REG-003 | [KNOWN] Reusing existing `store_helper` conventions without an explicit BTF schema decision could create a mismatch between the source's illustrative per-field registry layout and the binary-serialization pattern used by current helper publication code. (Source: `docs/BtfResolvedFunctions.md:149-152`, `libs/store_helper/ebpf_store_helper.c:74-100`) | Medium | Medium | [INFERRED] Keep the schema conflict explicit until a BTF-specific store design chooses whether to reuse or diverge from current serialization conventions. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial registry-publication requirements extracted from `docs/BtfResolvedFunctions.md`. |
| 0.2 | 2026-06-02 | Copilot | Added code-backed deltas from `libs/store_helper` and `include/ebpf_store_helper.h` for root-write behavior, public API gaps, and serialization-pattern conflicts. |

# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source requires argument and return types to be representable in `ebpf_argument_type_t` and `ebpf_return_type_t`, but it does not enumerate the allowed values in this document. (Source: `docs/BtfResolvedFunctions.md:128-131`)

## Implicit requirements in this area

- [INFERRED] Header declarations must preserve enough metadata for verifier-time symbol discovery, because the source ties `.ksyms` entries and declaration tags to later resolution. (Source: `docs/BtfResolvedFunctions.md:87-91`, `docs/BtfResolvedFunctions.md:199-212`)

## Actual or possible conflicts

- [INFERRED] No additional conflicts were identified within the examined header-authoring source lines beyond the global cross-area items in `README.md`. (Source: `docs/BtfResolvedFunctions.md:85-133`)

## Coverage statement

- **Examined:** Section 3 Authoring BTF-resolved Function Headers.
- **Method:** extracted declaration-format, GUID, and signature constraints.
- **Excluded:** registry publication and NMR registration details.
- **Limitations:** type-system specifics outside this source remain unknown.

# Authoring BTF-resolved Function Headers — Requirements Document

## 1. Overview

[KNOWN] This area defines the compile-time contract that a provider driver exposes to eBPF program authors through a header file. The source requires declaration metadata that places symbols in `.ksyms` and tags them with the provider module identifier. (Source: `docs/BtfResolvedFunctions.md:85-118`)

[KNOWN] This area also constrains the module GUID and callable signature shape so the same declarations can be resolved, verified, and bound across later lifecycle phases. (Source: `docs/BtfResolvedFunctions.md:120-133`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] Header-file contents needed for BTF-resolved function declarations. (Source: `docs/BtfResolvedFunctions.md:87-118`)
- [KNOWN] Module GUID consistency requirements. (Source: `docs/BtfResolvedFunctions.md:120-125`)
- [KNOWN] Function signature constraints inherited from helper-function rules. (Source: `docs/BtfResolvedFunctions.md:126-133`)

### 2.2 Out of Scope

- [KNOWN] Registry storage layout, because it belongs to `03-registry-publication.md`. (Source: `docs/BtfResolvedFunctions.md:134-190`)
- [KNOWN] Verifier lookup and call rewriting, because they belong to `04-verifier-integration.md`. (Source: `docs/BtfResolvedFunctions.md:192-243`)
- [KNOWN] Provider authentication and argument-validation duties, because they are captured as security requirements in `10-security-considerations.md`. (Source: `docs/BtfResolvedFunctions.md:470-490`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Declaration tag | [KNOWN] The `btf_decl_tag` metadata string that associates a function declaration with a provider module identifier such as `module_id:{GUID}`. (Source: `docs/BtfResolvedFunctions.md:103-112`) |
| Header format | [KNOWN] The combination of extern declaration, `.ksyms` placement, and module-tag metadata shown in the source header example. (Source: `docs/BtfResolvedFunctions.md:93-118`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-HDR-001: The provider header MUST declare each BTF-resolved function with metadata that places the symbol in the `.ksyms` section, so that verification-time tooling can discover the callable symbol from BTF. (Source: `docs/BtfResolvedFunctions.md:89-90`, `docs/BtfResolvedFunctions.md:106-112`)

Acceptance Criteria:
- [INFERRED] AC-1: Each documented declaration pattern includes `.ksyms` placement as part of the function declaration contract. (Source: `docs/BtfResolvedFunctions.md:106-112`)

[KNOWN] REQ-HDR-002: The provider header MUST associate each BTF-resolved function declaration with a module identifier expressed as a declaration tag, so that later stages can map the function name to the correct provider module. (Source: `docs/BtfResolvedFunctions.md:91-92`, `docs/BtfResolvedFunctions.md:103-112`)

Acceptance Criteria:
- [INFERRED] AC-1: The header requirements identify the declaration tag string as carrying the module identifier. (Source: `docs/BtfResolvedFunctions.md:103-112`)

[KNOWN] REQ-HDR-003: The provider header MUST use a module GUID that is unique to the driver, so that the provider namespace is not ambiguous. (Source: `docs/BtfResolvedFunctions.md:120-123`)

Acceptance Criteria:
- [INFERRED] AC-1: The header requirements prohibit reuse of another provider's module GUID. (Source: `docs/BtfResolvedFunctions.md:120-123`)

[KNOWN] REQ-HDR-004: The provider header MUST use the same module GUID that is later used for registry publication and NMR registration, so that compile-time metadata, verification-time lookup, and load-time binding refer to the same provider. (Source: `docs/BtfResolvedFunctions.md:123-125`)

Acceptance Criteria:
- [INFERRED] AC-1: The same GUID value is identified as the cross-phase provider key in header, registry, and NMR requirements. (Source: `docs/BtfResolvedFunctions.md:120-125`, `docs/BtfResolvedFunctions.md:142-157`, `docs/BtfResolvedFunctions.md:328-340`)

[KNOWN] REQ-HDR-005: A BTF-resolved function signature MUST have no more than five arguments, so that it stays within the helper-function constraint adopted by the source design. (Source: `docs/BtfResolvedFunctions.md:128-130`)

Acceptance Criteria:
- [INFERRED] AC-1: No header requirement permits a BTF-resolved function declaration with six or more parameters. (Source: `docs/BtfResolvedFunctions.md:128-130`)

[KNOWN] REQ-HDR-006: Each BTF-resolved function argument type MUST be representable in `ebpf_argument_type_t`, and each return type MUST be representable in `ebpf_return_type_t`, so that verification can interpret the callable contract. (Source: `docs/BtfResolvedFunctions.md:130-131`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements explicitly reject argument or return types that fall outside the documented eBPF type representations. (Source: `docs/BtfResolvedFunctions.md:130-131`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-HDR-007: Each BTF-resolved function MUST be safe to call at the IRQL where eBPF programs execute, so that provider-side callable contracts remain valid at runtime. (Source: `docs/BtfResolvedFunctions.md:132-133`)

Acceptance Criteria:
- [INFERRED] AC-1: The header-area requirements include IRQL safety as a mandatory callable-property constraint, not as an optional note. (Source: `docs/BtfResolvedFunctions.md:132-133`)

### 4.3 Constraints

- [KNOWN] CON-001: The source provides an example macro and example declarations, but these artifacts are illustrative rather than ratified public-header APIs because the overall feature remains proposed. (Source: `docs/BtfResolvedFunctions.md:14-16`, `docs/BtfResolvedFunctions.md:95-118`)
- [UNKNOWN: the enumerated sets of valid `ebpf_argument_type_t` and `ebpf_return_type_t` values are not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:128-131`)

## 5. Dependencies

- DEP-HDR-001: This requirement set depends on `03-registry-publication.md` and `06-nmr-provider-registration.md` for the same module GUID to be reused after compilation. Impact if unavailable: the header GUID cannot be validated as the provider's cross-phase identifier. (Source: `docs/BtfResolvedFunctions.md:120-125`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] The header authoring contract will continue to use `.ksyms` and declaration tags rather than an alternate BTF encoding. If this assumption is wrong, the compile-time discovery requirements will need to be rewritten. Justification: those are the only mechanisms described in the source. (Source: `docs/BtfResolvedFunctions.md:89-112`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-HDR-001 | [KNOWN] Reusing or mismatching the module GUID breaks later registry lookup and NMR binding. (Source: `docs/BtfResolvedFunctions.md:122-125`) | Medium | High | [INFERRED] Keep GUID consistency explicit across dependent specs. |
| RISK-HDR-002 | [KNOWN] Unsupported signature shapes cannot be represented or verified under the documented helper-function constraints. (Source: `docs/BtfResolvedFunctions.md:128-133`) | Medium | High | [INFERRED] Keep argument-count and type-representation requirements atomic. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial header-authoring requirements extracted from `docs/BtfResolvedFunctions.md`. |

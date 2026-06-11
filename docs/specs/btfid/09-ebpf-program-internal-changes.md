# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source names the new `ebpf_program_t` fields and lifecycle steps, but it does not define the locking protocol beyond `_Guarded_by_(lock)` annotations. (Source: `docs/BtfResolvedFunctions.md:444-466`)
- [KNOWN] The source does not define whether `btf_resolved_function_count` counts imported functions, attached functions, or address slots after partial attach. (Source: `docs/BtfResolvedFunctions.md:449-455`)
- [KNOWN] The current `ebpf_program_t` already contains comparable lifecycle state for program-information providers and helper metadata, but the examined code does not define how any future BTF-resolved binding arrays would relate to the existing single `program_information_rundown_reference`, current NMR client handles, or helper-state fields. (Source: `libs/execution_context/ebpf_program.c:38-101`, `libs/execution_context/ebpf_program.c:738-895`, `libs/execution_context/ebpf_program.c:1813-1873`, `libs/execution_context/ebpf_program.c:2690-2701`)

## Implicit requirements in this area

- [INFERRED] Internal state must preserve both binding metadata and address arrays for the full program lifetime, because creation allocates them, attach populates them, and free releases them. (Source: `docs/BtfResolvedFunctions.md:449-466`)
- [INFERRED] Any future BTF-resolved internal state should extend the existing `ebpf_program_t` lifecycle pattern for NMR client registration, provider attach/detach handling, helper/callback storage, and final teardown rather than introducing a second unrelated object lifecycle, because the current program object already centralizes those responsibilities. (Source: `libs/execution_context/ebpf_program.c:38-101`, `libs/execution_context/ebpf_program.c:314-619`, `libs/execution_context/ebpf_program.c:667-733`, `libs/execution_context/ebpf_program.c:738-895`)

## Actual or possible conflicts

- [KNOWN] The source distinguishes the provider-binding record in Section 8 from the per-function binding record in Section 10; implementations must not merge them without redefining responsibilities. (Source: `docs/BtfResolvedFunctions.md:390-392`, `docs/BtfResolvedFunctions.md:435-455`)
- [KNOWN] The source requires `ebpf_program_t` fields for BTF-resolved bindings, addresses, and callback/context, but the current structure contains only program-information NMR client handles, one rundown reference, helper-function ID storage, and a helper-address callback/context pair. (Source: `docs/BtfResolvedFunctions.md:444-456`, `libs/execution_context/ebpf_program.c:38-101`)
- [KNOWN] The source requires creation-time allocation of BTF-resolved arrays and registration for a BTF-resolved-function NPI, but the current creation path registers only the two existing program-information clients and does not allocate any BTF-resolved arrays. (Source: `docs/BtfResolvedFunctions.md:459-466`, `libs/execution_context/ebpf_program.c:738-895`)

## Coverage statement

- **Examined:** Section 10 Internal Changes to `ebpf_program_t`; `libs/execution_context/ebpf_program.c`; `libs/execution_context/ebpf_program.h`; internal-state tests in `libs\execution_context\unit` and selected tests under `tests`.
- **Method:** extracted required fields, binding-record shape, and lifecycle transitions from the source doc, then compared them against the current `ebpf_program_t` structure, current create/attach/detach/free paths, current helper-state APIs, and representative provider/helper tests.
- **Excluded:** detailed BTF provider registration payload design and native runtime execution semantics, because they are covered in other area documents.
- **Limitations:** no BTF-resolved internal-state implementation exists in the examined code, so future storage and API touch points beyond the current helper/provider baseline remain inferred.

# Internal Changes to ebpf_program_t — Requirements Document

## 1. Overview

[KNOWN] This area defines the internal program-state additions needed to support BTF-resolved functions. The source introduces a binding structure, new `ebpf_program_t` fields for bindings, addresses, and callbacks, and a six-step lifecycle from creation through free. (Source: `docs/BtfResolvedFunctions.md:430-466`)

[KNOWN] The purpose of these changes is to make provider attachment state, resolved addresses, and notification hooks persistent across program load, execution, and teardown. (Source: `docs/BtfResolvedFunctions.md:449-466`)

[KNOWN] The current implementation already centralizes comparable state on `ebpf_program_t`, but only for the existing program-information/helper model. `ebpf_program_t` currently stores two program-information NMR client handles, one `program_information_rundown_reference`, pointers to general/type-specific program data, helper-function ID storage, and a helper-address callback/context pair. The current lifecycle registers the two program-information clients during `ebpf_program_create(...)`, populates provider data during attach callbacks, waits for rundown and clears extension program data during detach, and deregisters the current clients plus frees helper-function ID state during final teardown. [KNOWN] No in-scope code defines `btf_resolved_function_bindings`, `btf_resolved_function_addresses`, `btf_resolved_function_count`, or a BTF-resolved-function callback/context on `ebpf_program_t`. (Source: `libs/execution_context/ebpf_program.c:38-101`, `libs/execution_context/ebpf_program.c:314-619`, `libs/execution_context/ebpf_program.c:667-733`, `libs/execution_context/ebpf_program.c:738-895`, `libs/execution_context/ebpf_program.c:1813-1873`, `libs/execution_context/ebpf_program.c:2690-2701`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] Binding-record fields. (Source: `docs/BtfResolvedFunctions.md:435-442`)
- [KNOWN] Additions to `ebpf_program_t`. (Source: `docs/BtfResolvedFunctions.md:444-456`)
- [KNOWN] Program lifecycle requirements for the new state. (Source: `docs/BtfResolvedFunctions.md:459-466`)
- [KNOWN] Existing `ebpf_program_t` internal-state and lifecycle behavior that provides the current baseline for any future BTF-resolved additions. (Source: `libs/execution_context/ebpf_program.c:38-101`, `libs/execution_context/ebpf_program.c:314-619`, `libs/execution_context/ebpf_program.c:667-733`, `libs/execution_context/ebpf_program.c:738-895`)

### 2.2 Out of Scope

- [KNOWN] Provider-registration data structure, because it belongs to `06-nmr-provider-registration.md`. (Source: `docs/BtfResolvedFunctions.md:333-340`)
- [KNOWN] Native-module attach/detach callback behavior, because it belongs to `07-native-module-loading.md`. (Source: `docs/BtfResolvedFunctions.md:359-375`)
- [KNOWN] Security-policy requirements, because they belong to `10-security-considerations.md`. (Source: `docs/BtfResolvedFunctions.md:468-490`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Function binding record | [KNOWN] The `ebpf_btf_resolved_function_binding_t` structure that tracks module GUID, NMR binding handle, provider data, and attached state. (Source: `docs/BtfResolvedFunctions.md:435-442`) |
| Address-change context | [KNOWN] The callback/context pair stored on `ebpf_program_t` for BTF-resolved function address updates. (Source: `docs/BtfResolvedFunctions.md:454-455`) |
| Helper/provider baseline | [KNOWN] The current `ebpf_program_t` model in which provider state is represented by program-information NMR handles and program-data pointers, helper metadata is represented by `helper_function_ids` plus `helper_function_count`, and callback state is represented by `helper_function_addresses_changed_callback` plus context. (Source: `libs/execution_context/ebpf_program.c:65-100`, `libs/execution_context/ebpf_program.c:1813-1873`, `libs/execution_context/ebpf_program.c:2690-2701`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-PROG-001: The system MUST represent each tracked BTF-resolved function binding with a record that stores the provider's module GUID, NMR binding handle, provider data pointer, and attached state, so that program state can correlate provider identity, attachment, and callable metadata. (Source: `docs/BtfResolvedFunctions.md:435-442`)

Acceptance Criteria:
- [INFERRED] AC-1: The internal-state requirements enumerate all four documented binding-record fields. (Source: `docs/BtfResolvedFunctions.md:437-442`)

[KNOWN] REQ-PROG-002: `ebpf_program_t` MUST store a binding-array pointer and binding-count field for BTF-resolved function support, so that the program can retain attachment state across its lifetime. (Source: `docs/BtfResolvedFunctions.md:449-451`)

Acceptance Criteria:
- [INFERRED] AC-1: The internal-state requirements identify both storage location and cardinality for the binding set. (Source: `docs/BtfResolvedFunctions.md:449-451`)

[KNOWN] REQ-PROG-003: `ebpf_program_t` MUST store a BTF-resolved function address array and an address-count field, so that runtime execution can access resolved provider call targets. (Source: `docs/BtfResolvedFunctions.md:452-453`)

Acceptance Criteria:
- [INFERRED] AC-1: The internal-state requirements keep address storage distinct from binding metadata storage. (Source: `docs/BtfResolvedFunctions.md:450-453`)

[KNOWN] REQ-PROG-004: `ebpf_program_t` MUST store an address-change callback and callback context for BTF-resolved function support, so that runtime components can be notified when provider addresses change. (Source: `docs/BtfResolvedFunctions.md:454-455`)

Acceptance Criteria:
- [INFERRED] AC-1: The callback and callback context are both present in the documented field set. (Source: `docs/BtfResolvedFunctions.md:454-455`)

[KNOWN] REQ-PROG-005: During program creation, the system MUST allocate arrays based on the BTF-resolved function import-table size, so that storage capacity matches the imported-function set. (Source: `docs/BtfResolvedFunctions.md:459-462`)

Acceptance Criteria:
- [INFERRED] AC-1: The lifecycle requirements define array allocation during creation rather than after first provider attach. (Source: `docs/BtfResolvedFunctions.md:461-462`)

[KNOWN] REQ-PROG-006: During initialization, the system MUST register an NMR client for the BTF-resolved function NPI so that provider attach callbacks can populate program state. (Source: `docs/BtfResolvedFunctions.md:462-463`)

Acceptance Criteria:
- [INFERRED] AC-1: The lifecycle requirements identify NMR client registration as a distinct step before provider attach. (Source: `docs/BtfResolvedFunctions.md:462-463`)

[KNOWN] REQ-PROG-007: On provider attach, the system MUST populate `btf_resolved_function_bindings` and `btf_resolved_function_addresses`, so that both binding metadata and callable addresses become available to the program. (Source: `docs/BtfResolvedFunctions.md:463-464`)

Acceptance Criteria:
- [INFERRED] AC-1: The lifecycle requirements identify both binding and address population as attach-time work. (Source: `docs/BtfResolvedFunctions.md:463-464`)

[KNOWN] REQ-PROG-008: During program load, the system MUST verify that all required providers are attached, so that programs do not complete load with unresolved provider dependencies. (Source: `docs/BtfResolvedFunctions.md:464`)

Acceptance Criteria:
- [INFERRED] AC-1: The lifecycle requirements include an explicit provider-readiness check at load time. (Source: `docs/BtfResolvedFunctions.md:464`)

[KNOWN] REQ-PROG-009: On provider detach, the system MUST clear addresses, invoke the address-change callback, and wait for rundown, so that program state transitions to a safe unavailable state without interrupting in-flight execution. (Source: `docs/BtfResolvedFunctions.md:465`)

Acceptance Criteria:
- [INFERRED] AC-1: The detach lifecycle requirements include all three documented actions: clear, notify, and wait. (Source: `docs/BtfResolvedFunctions.md:465`)

[KNOWN] REQ-PROG-010: During program free, the system MUST deregister the NMR client and free the BTF-resolved function arrays, so that BTF-resolved function state does not outlive the program. (Source: `docs/BtfResolvedFunctions.md:466`)

Acceptance Criteria:
- [INFERRED] AC-1: The free lifecycle requirements include both deregistration and storage release. (Source: `docs/BtfResolvedFunctions.md:466`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-PROG-011: Access to BTF-resolved function state on `ebpf_program_t` SHOULD honor the documented lock-guarding annotations, so that concurrent lifecycle and runtime transitions do not operate on unguarded state. (Source: `docs/BtfResolvedFunctions.md:449-455`)

Acceptance Criteria:
- [INFERRED] AC-1: The internal-state requirements preserve `_Guarded_by_(lock)` as a concurrency constraint on the documented fields. (Source: `docs/BtfResolvedFunctions.md:450-455`)

[INFERRED] REQ-PROG-012: If BTF-resolved internal state is added, it SHOULD reuse the existing `ebpf_program_t` lifecycle pattern for client registration, provider attach/detach handling, callback/context storage, and teardown rather than creating a separate state owner, so that the feature remains aligned with the current execution-context object model. (Source: `libs/execution_context/ebpf_program.c:38-101`, `libs/execution_context/ebpf_program.c:314-619`, `libs/execution_context/ebpf_program.c:667-733`, `libs/execution_context/ebpf_program.c:738-895`, `libs/execution_context/ebpf_program.c:2690-2701`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify the current `ebpf_program_t` create/attach/detach/free and callback-storage paths as the preferred extension points for BTF-resolved internal state. (Source: `libs/execution_context/ebpf_program.c:314-619`, `libs/execution_context/ebpf_program.c:667-733`, `libs/execution_context/ebpf_program.c:738-895`, `libs/execution_context/ebpf_program.c:2690-2701`)

### 4.3 Constraints

- [KNOWN] CON-001: The source defines lock-guarded fields but does not describe the full lock-ordering protocol. (Source: `docs/BtfResolvedFunctions.md:449-455`)
- [UNKNOWN: the exact semantics of `btf_resolved_function_count` are not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:452-453`)
- [KNOWN] CON-003: The current `ebpf_program_t` structure has no BTF-resolved binding array, BTF-resolved address array, or BTF-resolved callback/context fields. (Source: `libs/execution_context/ebpf_program.c:38-101`)
- [KNOWN] CON-004: The current program lifecycle registers only the two existing `EBPF_PROGRAM_INFO_EXTENSION_IID` clients during creation and deregisters only those clients during final free. (Source: `libs/execution_context/ebpf_program.c:667-688`, `libs/execution_context/ebpf_program.c:853-895`)
- [KNOWN] CON-005: The current comparable dynamic array lifecycle is helper-centric: helper IDs are allocated later via `ebpf_program_set_helper_function_ids(...)` and freed via `ebpf_program_clear_helper_function_ids(...)` or final program teardown. (Source: `libs/execution_context/ebpf_program.c:1813-1873`, `libs/execution_context/ebpf_program.c:731-733`)

## 5. Dependencies

- DEP-PROG-001: This requirement set depends on `05-bpf2c-integration.md`, `07-native-module-loading.md`, and `08-runtime-execution.md` because import-table size drives allocation, attach/detach drives state transitions, and runtime callbacks consume the stored state. Impact if unavailable: internal fields and lifecycle steps lose their behavioral purpose. (Source: `docs/BtfResolvedFunctions.md:279-280`, `docs/BtfResolvedFunctions.md:359-375`, `docs/BtfResolvedFunctions.md:400-419`, `docs/BtfResolvedFunctions.md:459-466`)
- DEP-PROG-002: This requirement set depends on the current `ebpf_program_t` provider/helper lifecycle because any BTF-resolved internal-state design must either extend or intentionally diverge from the existing create/attach/detach/free and callback-storage patterns. Impact if unavailable: the delta between the source requirements and the present implementation cannot be stated concretely. (Source: `libs/execution_context/ebpf_program.c:38-101`, `libs/execution_context/ebpf_program.c:314-619`, `libs/execution_context/ebpf_program.c:667-733`, `libs/execution_context/ebpf_program.c:738-895`, `libs/execution_context/ebpf_program.c:2690-2701`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] The import-table size is known before program creation allocates BTF-resolved function arrays. If this assumption is wrong, creation needs a deferred-allocation requirement. Justification: the source bases creation-time allocation on import-table size. (Source: `docs/BtfResolvedFunctions.md:461`)
- ASM-002: [ASSUMPTION] Future BTF-resolved binding/address state would most naturally be added directly to `ebpf_program_t` and managed through the same create/attach/detach/free flow already used for provider/helper state. If this assumption is wrong, the design delta's expected touch points must change. Justification: the source explicitly shows the new fields as `ebpf_program_t` additions, and the current implementation already centralizes comparable state there. (Source: `docs/BtfResolvedFunctions.md:444-456`, `libs/execution_context/ebpf_program.c:38-101`, `libs/execution_context/ebpf_program.c:738-895`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-PROG-001 | [KNOWN] Missing lifecycle cleanup would leave NMR registration or BTF-resolved function arrays alive after program free. (Source: `docs/BtfResolvedFunctions.md:466`) | Medium | High | [INFERRED] Keep teardown actions explicit and atomic. |
| RISK-PROG-002 | [KNOWN] Blurring provider-binding and function-binding responsibilities can make attachment and address-tracking semantics ambiguous. (Source: `docs/BtfResolvedFunctions.md:390-392`, `docs/BtfResolvedFunctions.md:435-455`) | Medium | Medium | [INFERRED] Preserve the source's separation of responsibilities across the two structures. |
| RISK-PROG-003 | [KNOWN] Reusing the current program-information/helper state without adding distinct BTF-resolved binding/address storage can conflate generic provider readiness with per-function BTF binding state. (Source: `docs/BtfResolvedFunctions.md:435-466`, `libs/execution_context/ebpf_program.c:38-101`) | High | High | [INFERRED] Keep the missing BTF-resolved fields and lifecycle steps explicit in the design and validation deltas. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial `ebpf_program_t` internal-change requirements extracted from `docs/BtfResolvedFunctions.md`. |
| 0.2 | 2026-06-02 | Copilot | Added code-backed deltas for the current provider/helper internal-state baseline and the missing BTF-resolved fields and lifecycle. |

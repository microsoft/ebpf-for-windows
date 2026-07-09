# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source requires wildcard-module-ID client registration, but it does not define the exact wildcard representation or filtering mechanism. (Source: `docs/BtfResolvedFunctions.md:352-355`)
- [KNOWN] The source states that the detach path waits for current execution to complete, but it does not define whether callback invocation occurs before or after that wait in every implementation path. (Source: `docs/BtfResolvedFunctions.md:368-375`)
- [KNOWN] The current in-scope code implements native-module loading from the execution-context provider side of a private native NPI, not from a native module's client side for BTF-resolved-function providers, so the precise landing point for future BTF client registration logic is not present in the examined code. (Source: `docs/BtfResolvedFunctions.md:352-375`, `libs/execution_context/ebpf_native.c:107-144`, `libs/execution_context/ebpf_native.c:800-977`)
- [KNOWN] The current public native-module contract in `include\bpf2c.h` already defines `btf_resolved_function_data` in `program_runtime_context_t` and BTF import metadata in `program_entry_t`, but it still does not define a BTF-resolved address-change callback field in `metadata_table_t`. (Source: `include/bpf2c.h:98-110`, `include/bpf2c.h:163-170`, `include/bpf2c.h:190-193`, `include/bpf2c.h:220-238`)

## Implicit requirements in this area

- [INFERRED] Native loading must correlate provider attachments to generated import-table entries by module GUID, because the import table carries module GUIDs and the attach callback checks provider GUID matches against that table. (Source: `docs/BtfResolvedFunctions.md:255-258`, `docs/BtfResolvedFunctions.md:359-365`)
- [INFERRED] Any future BTF-resolved native-loading path should extend the existing native-module load pipeline that validates metadata, allocates runtime-context arrays, and registers for helper-address change notifications, because that is the current mechanism by which execution-context wires resolved callable addresses into native programs. (Source: `libs/execution_context/ebpf_native.c:1849-2005`, `libs/execution_context/ebpf_program.h:389-407`)

## Actual or possible conflicts

- [KNOWN] Provider-binding state in Section 8 must remain distinct from per-function binding state in Section 10 even though both track NMR-related information. (Source: `docs/BtfResolvedFunctions.md:377-392`, `docs/BtfResolvedFunctions.md:435-455`)
- [KNOWN] The source requires the native module to register as an NMR client for a BTF-resolved-function NPI with wildcard module ID, but the current in-scope execution-context code registers only as a provider for a private native-module NPI and does not contain any BTF-resolved client-registration path. (Source: `docs/BtfResolvedFunctions.md:352-355`, `libs/execution_context/ebpf_native.c:107-144`, `libs/execution_context/ebpf_native.c:1068-1073`)
- [KNOWN] The source requires copying provider addresses into `btf_resolved_function_data` and invoking `btf_resolved_function_addresses_changed_callback`, but the current execution-context implementation still allocates only helper/map/global-variable runtime state, registers only `ebpf_helper_function_addresses_changed_callback_t` / `_ebpf_native_helper_address_changed`, and now fails native loads closed when BTF imports are present. (Source: `docs/BtfResolvedFunctions.md:364-375`, `include/bpf2c.h:163-170`, `libs/execution_context/ebpf_program.h:389-407`, `libs/execution_context/ebpf_native.c:1963-1970`, `libs/execution_context/ebpf_native.c:2407-2452`)

## Coverage statement

- **Examined:** Section 8 Native Module Loading; `include/bpf2c.h`; `libs/execution_context/ebpf_native.c`; `libs/execution_context/ebpf_program.h`; `libs/execution_context/ebpf_program.c`; generated native scaffolding in `tests\bpf2c_tests\expected\btf_resolved_sys.c`; native-module load tests in `libs/execution_context\unit`, `tests\api_test`, `tests\end_to_end`, and runtime harnesses in `tests\bpf2c_plugin` and `tests\bpf2c_tests`.
- **Method:** extracted NMR client registration and attach/detach handling requirements, then compared them with the current native-module provider attach path, public runtime-context layout, generated native metadata scaffolding, helper-address change callback path, fail-closed native-load behavior, and native-module/runtime tests.
- **Excluded:** runtime invocation semantics after successful address resolution and internal `ebpf_program_t` field design beyond the callback contract used by native loading.
- **Limitations:** the examined execution-context code does not contain a BTF-resolved-function native-module client implementation, so several future change points remain inferred from current helper-centric loading paths.

# Native Module Loading — Requirements Document

## 1. Overview

[KNOWN] This area defines how a native module binds to BTF-resolved function providers after load. The source requires the module skeleton to register as an NMR client, accept relevant provider attachments, copy addresses into runtime context, and handle provider detach events. (Source: `docs/BtfResolvedFunctions.md:348-394`)

[KNOWN] The source also requires support for multiple providers and makes successful execution contingent on all required providers being attached. (Source: `docs/BtfResolvedFunctions.md:377-394`)

[KNOWN] The current in-scope execution-context implementation already has a native-module loading pipeline, but it is still oriented around a private native-module NPI and helper/map/global-variable runtime-context wiring. Production code registers a provider for `_ebpf_native_npi_id`, validates the module metadata table on attach, allocates `runtime_context.helper_data` / `map_data` / `global_variable_section_data`, resolves helper addresses, and registers a helper-address change callback. [KNOWN] Adjacent groundwork for BTF-resolved native loading now exists: `include\bpf2c.h` defines BTF import/runtime structures, generated native code emits BTF import tables and dereferences `runtime_context->btf_resolved_function_data`, and user-mode harnesses populate that field. [KNOWN] But no in-scope code currently defines BTF-resolved-function provider bindings, wildcard BTF client registration, or a BTF-resolved address-change callback, and the native loader currently rejects native loads that declare BTF imports. (Source: `libs/execution_context/ebpf_native.c:107-144`, `libs/execution_context/ebpf_native.c:800-977`, `libs/execution_context/ebpf_native.c:1963-1970`, `include/bpf2c.h:98-110`, `include/bpf2c.h:163-170`, `include/bpf2c.h:190-193`, `tests/bpf2c_tests/expected/btf_resolved_sys.c:106-107`, `tests/bpf2c_tests/expected/btf_resolved_sys.c:187-247`, `tests/bpf2c_plugin/bpf2c_test.cpp:191-222`, `tests/bpf2c_tests/bpf_test.cpp:85-116`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] NMR client registration for native modules. (Source: `docs/BtfResolvedFunctions.md:352-355`)
- [KNOWN] Attach and detach callback behavior. (Source: `docs/BtfResolvedFunctions.md:357-375`)
- [KNOWN] Tracking multiple provider attachments. (Source: `docs/BtfResolvedFunctions.md:377-394`)
- [KNOWN] Existing native-module loading, runtime-context allocation, generated native metadata, and helper-address change behavior relevant to a future BTF-resolved loading path. (Source: `libs/execution_context/ebpf_native.c:800-977`, `libs/execution_context/ebpf_native.c:1658-1744`, `libs/execution_context/ebpf_native.c:1849-2005`, `libs/execution_context/ebpf_native.c:2407-2452`, `include/bpf2c.h:98-110`, `include/bpf2c.h:163-170`, `include/bpf2c.h:190-193`, `tests/bpf2c_tests/expected/btf_resolved_sys.c:187-247`)

### 2.2 Out of Scope

- [KNOWN] Provider registration payload definition, because it belongs to `06-nmr-provider-registration.md`. (Source: `docs/BtfResolvedFunctions.md:326-346`)
- [KNOWN] Runtime invocation and rundown semantics, because they belong to `08-runtime-execution.md`. (Source: `docs/BtfResolvedFunctions.md:398-428`)
- [KNOWN] `ebpf_program_t` field layout, because it belongs to `09-ebpf-program-internal-changes.md`. (Source: `docs/BtfResolvedFunctions.md:430-466`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Provider binding list | [KNOWN] The native-module-maintained list of provider attachment state records keyed by module GUID. (Source: `docs/BtfResolvedFunctions.md:363-365`, `docs/BtfResolvedFunctions.md:381-388`) |
| `STATUS_NOINTERFACE` decline | [KNOWN] The documented attach-callback result returned when the provider's module GUID does not match any imported BTF-resolved function entry. (Source: `docs/BtfResolvedFunctions.md:361-367`) |
| Helper-centric native-loader baseline | [KNOWN] The current native-loading path that allocates `runtime_context.helper_data`, resolves helpers, and updates helper addresses through the helper-address change callback infrastructure. (Source: `libs/execution_context/ebpf_native.c:1658-1744`, `libs/execution_context/ebpf_native.c:1849-2005`, `libs/execution_context/ebpf_native.c:2407-2452`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-LOAD-001: The native module skeleton MUST register as an NMR client for the BTF-resolved function NPI with a wildcard module ID, so that it can receive attach callbacks for all registered BTF-resolved function providers. (Source: `docs/BtfResolvedFunctions.md:352-355`)

Acceptance Criteria:
- [INFERRED] AC-1: The loading requirements identify receipt of attach callbacks for all registered providers as the purpose of wildcard registration. (Source: `docs/BtfResolvedFunctions.md:354-355`)

[KNOWN] REQ-LOAD-002: During the client attach callback, the native module MUST check whether the provider's module GUID matches any entry in the BTF-resolved function import table, so that unrelated providers can be declined. (Source: `docs/BtfResolvedFunctions.md:359-366`)

Acceptance Criteria:
- [INFERRED] AC-1: The attach-callback requirements perform GUID matching before storing any binding state or addresses. (Source: `docs/BtfResolvedFunctions.md:361-365`)

[KNOWN] REQ-LOAD-003: If the provider's module GUID matches the import table, the native module MUST store the binding handle, copy function addresses to the runtime context's `btf_resolved_function_data` array, and record the binding in the provider-binding list, so that the program can later execute through resolved provider addresses. (Source: `docs/BtfResolvedFunctions.md:362-365`)

Acceptance Criteria:
- [INFERRED] AC-1: The attach-callback requirements list binding-handle storage, address-copying, and binding-record creation as separate mandatory actions. (Source: `docs/BtfResolvedFunctions.md:362-365`)

[KNOWN] REQ-LOAD-004: If the provider's module GUID does not match any import-table entry, the native module MUST return `STATUS_NOINTERFACE`, so that it declines bindings for unrelated providers. (Source: `docs/BtfResolvedFunctions.md:366-367`)

Acceptance Criteria:
- [INFERRED] AC-1: The loading requirements specify a negative path with `STATUS_NOINTERFACE` rather than silent acceptance or silent ignore. (Source: `docs/BtfResolvedFunctions.md:366-367`)

[KNOWN] REQ-LOAD-005: When a BTF-resolved function provider detaches, the native module MUST set the corresponding runtime-context addresses to `NULL` and MUST mark the binding as detached, so that later execution can detect unavailable providers. (Source: `docs/BtfResolvedFunctions.md:368-375`)

Acceptance Criteria:
- [INFERRED] AC-1: The detach requirements separate address clearing from binding-state updates and make both mandatory. (Source: `docs/BtfResolvedFunctions.md:370-373`)

[KNOWN] REQ-LOAD-006: When a BTF-resolved function provider detaches, the native module MUST wait for current execution to complete and MUST invoke `btf_resolved_function_addresses_changed_callback` if one is registered, so that detach preserves in-flight execution while notifying consumers of address change. (Source: `docs/BtfResolvedFunctions.md:373-375`)

Acceptance Criteria:
- [INFERRED] AC-1: The detach requirements include both in-flight execution completion and callback notification as required behaviors. (Source: `docs/BtfResolvedFunctions.md:373-375`)

[KNOWN] REQ-LOAD-007: The native module MUST support multiple BTF-resolved function providers per program and MUST require all required providers to be attached before the program can execute, so that multi-provider programs do not run with partial provider availability. (Source: `docs/BtfResolvedFunctions.md:377-394`)

Acceptance Criteria:
- [INFERRED] AC-1: The loading requirements allow more than one provider-binding record per program. (Source: `docs/BtfResolvedFunctions.md:377-388`)
- [INFERRED] AC-2: The loading requirements explicitly prohibit execution when a required provider remains unattached. (Source: `docs/BtfResolvedFunctions.md:394`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-LOAD-008: Provider-binding state tracking for native loading SHOULD remain distinct from per-function binding state tracked on `ebpf_program_t`, so that per-provider attachment state and per-function address resolution do not collapse into one ambiguous structure. (Source: `docs/BtfResolvedFunctions.md:390-392`, `docs/BtfResolvedFunctions.md:435-455`)

Acceptance Criteria:
- [INFERRED] AC-1: The loading and internal-state requirements use separate binding structures for provider-level and function-level responsibilities. (Source: `docs/BtfResolvedFunctions.md:381-392`, `docs/BtfResolvedFunctions.md:435-455`)

[INFERRED] REQ-LOAD-009: If BTF-resolved native-module loading is added, it SHOULD extend the existing native-module load pipeline and public native contract rather than introduce a second unrelated runtime-context/update path, so that native loading remains consistent with current metadata-table validation, runtime-context allocation, and address-change notification mechanisms. (Source: `include/bpf2c.h:149-155`, `include/bpf2c.h:202-220`, `libs/execution_context/ebpf_native.c:1849-2005`, `libs/execution_context/ebpf_program.h:389-407`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify current `program_runtime_context_t`, `metadata_table_t`, and helper-address change registration as the preferred extension points for future BTF-resolved loading support. (Source: `include/bpf2c.h:149-155`, `include/bpf2c.h:202-220`, `libs/execution_context/ebpf_native.c:1971-2005`)

### 4.3 Constraints

- [UNKNOWN: the exact wildcard module-ID value or encoding is not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:352-355`)
- [KNOWN] CON-002: The provider-binding record in this area tracks per-provider NMR attachment state only; it is not the same structure as the per-function binding record described in Section 10. (Source: `docs/BtfResolvedFunctions.md:390-392`)
- [KNOWN] CON-003: The current public native-module contract in `include\bpf2c.h` includes `btf_resolved_function_data` and BTF import metadata, but `metadata_table_t` still has no BTF-resolved address-change callback field. (Source: `include/bpf2c.h:98-110`, `include/bpf2c.h:163-170`, `include/bpf2c.h:190-193`, `include/bpf2c.h:220-238`)
- [KNOWN] CON-004: The current address-change callback contract is `ebpf_helper_function_addresses_changed_callback_t`, not a BTF-resolved-function address-change callback contract. (Source: `libs/execution_context/ebpf_program.h:389-407`)
- [KNOWN] CON-005: The current in-scope native-loading code is the provider side of `_ebpf_native_npi_id`, not a native module's client registration path for provider-specific NPIs. (Source: `libs/execution_context/ebpf_native.c:107-144`, `libs/execution_context/ebpf_native.c:800-977`)

## 5. Dependencies

- DEP-LOAD-001: This requirement set depends on `05-bpf2c-integration.md` for the import-table contract and on `06-nmr-provider-registration.md` for provider data delivered at attach time. Impact if unavailable: the attach callback cannot correlate provider GUIDs to emitted imports and address arrays. (Source: `docs/BtfResolvedFunctions.md:255-258`, `docs/BtfResolvedFunctions.md:333-340`, `docs/BtfResolvedFunctions.md:359-365`)
- DEP-LOAD-002: This requirement set depends on the current native-module load pipeline in `libs\execution_context` and the public native-module contract in `include\bpf2c.h`, because future BTF-resolved loading must either extend or intentionally diverge from those current helper-centric behaviors. Impact if unavailable: the delta between the source design and current loading behavior cannot be stated concretely. (Source: `include/bpf2c.h:149-155`, `include/bpf2c.h:202-220`, `libs/execution_context/ebpf_native.c:1849-2005`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] A provider's address array order aligns with the import-table expectation for that provider when addresses are copied into runtime context. If this assumption is wrong, a per-function matching requirement must replace simple copying. Justification: the source prescribes copying addresses but does not define a separate reconciliation algorithm. (Source: `docs/BtfResolvedFunctions.md:339-340`, `docs/BtfResolvedFunctions.md:364`)
- ASM-002: [ASSUMPTION] Future BTF-resolved-function runtime-context storage and metadata-table callback declarations would most naturally extend `include\bpf2c.h`, because that is where the current native runtime-context and metadata-table contracts are declared. If this assumption is wrong, the design delta's public-header touch points must be updated. (Source: `include/bpf2c.h:149-155`, `include/bpf2c.h:202-220`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-LOAD-001 | [KNOWN] Accepting unrelated providers would populate incorrect addresses into runtime state. (Source: `docs/BtfResolvedFunctions.md:361-367`) | Low | High | [INFERRED] Keep GUID matching and `STATUS_NOINTERFACE` decline explicit. |
| RISK-LOAD-002 | [KNOWN] Failing to clear addresses on detach would allow later execution to observe stale provider addresses. (Source: `docs/BtfResolvedFunctions.md:370-372`) | Medium | High | [INFERRED] Keep address clearing and detached-state updates as separate MUST requirements. |
| RISK-LOAD-003 | [KNOWN] Reusing the current helper-centric callback surface without completing the distinct BTF-resolved extension can leave native modules with public BTF runtime scaffolding but no provider-level attachment state or callback contract. (Source: `include/bpf2c.h:163-170`, `libs/execution_context/ebpf_program.h:389-407`, `docs/BtfResolvedFunctions.md:377-392`) | High | High | [INFERRED] Make the remaining missing BTF callback and provider-binding contracts explicit in the design and validation deltas. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial native-module-loading requirements extracted from `docs/BtfResolvedFunctions.md`. |
| 0.2 | 2026-06-02 | Copilot | Added code-backed deltas for the current private-native-NPI/provider baseline, helper-centric runtime-context path, and missing BTF-resolved loading contracts. |
| 0.3 | 2026-06-05 | Copilot | Updated the document to reflect current BTF native-contract scaffolding, generated runtime use of `btf_resolved_function_data`, user-mode harness coverage, and fail-closed kernel native-load behavior. |

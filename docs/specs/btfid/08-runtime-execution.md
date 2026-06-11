# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source requires rundown protection on all BTF-resolved function bindings before execution, but it does not define the exact binding-set computation when multiple providers contribute functions. The current code now has a native-only per-program binding-index list, but no general JIT/interpreter BTF binding model is visible in scope. (Source: `docs/BtfResolvedFunctions.md:400-406`, `libs\execution_context\ebpf_native.c:1051-1095`)
- [KNOWN] The source states that the address-change callback updates the jump table for JIT programs and runtime context directly for native programs, but it does not define the callback sequencing relative to concurrent invocations. The current implementation directly updates native runtime context during attach/detach and does not expose the explicit BTF callback type described by the source. (Source: `docs/BtfResolvedFunctions.md:408-419`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_program.h:389-407`)
- [KNOWN] The current runtime path in `libs\execution_context` still exposes a generic single-provider readiness helper through `ebpf_program_reference_providers(...)`, but native invocation now adds a separate BTF-specific rundown gate in `ebpf_program_invoke(...)`. The exact long-term division of responsibility between those two gates is not defined in the examined code. (Source: `libs\execution_context\ebpf_program.c:1538-1547`, `libs\execution_context\ebpf_program.c:1557-1615`)

## Implicit requirements in this area

- [INFERRED] Runtime readiness checks must be provider-complete rather than function-complete because the documented pre-invocation check is phrased in terms of required providers being attached, and the current native implementation models BTF readiness per provider binding rather than per imported function. (Source: `docs/BtfResolvedFunctions.md:400-404`, `libs\execution_context\ebpf_native.c:1051-1095`)
- [INFERRED] Any BTF-resolved runtime path should extend the existing invoke/rundown/address-update pipeline rather than create a second unrelated execution gate, because current execution already centralizes generic provider readiness in `ebpf_program.c` and now centralizes native BTF readiness plus runtime-context address updates in `ebpf_native.c`. (Source: `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_native.c:2375-2469`)

## Actual or possible conflicts

- [KNOWN] The source requires provider-complete BTF-resolved readiness checks and rundown protection on all BTF bindings. The current code now implements that behavior for native execution through `ebpf_native_acquire_btf_references(...)`, but the generic `ebpf_program_reference_providers(...)` helper remains a single-provider program-information gate. (Source: `docs/BtfResolvedFunctions.md:400-406`, `libs\execution_context\ebpf_program.c:1538-1547`, `libs\execution_context\ebpf_program.c:1557-1615`, `libs\execution_context\ebpf_native.c:1051-1095`)
- [KNOWN] The source requires `ebpf_btf_resolved_function_addresses_changed_callback_t` and BTF-resolved address propagation for JIT and native programs. The current native implementation already updates `runtime_context.btf_resolved_function_data` on provider attach/detach, but the explicit BTF callback type and any JIT-specific propagation path are still absent in the examined code. (Source: `docs/BtfResolvedFunctions.md:408-419`, `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_program.h:389-407`)

## Coverage statement

- **Examined:** Section 9 Runtime Execution; `libs\execution_context\ebpf_program.h`; `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c`; `include\bpf2c.h`; `tests\bpf2c_plugin\bpf2c_test.cpp`; `tests\bpf2c_tests\bpf_test.cpp`; `tests\bpf2c_tests\expected\btf_resolved_sys.c`; runtime-oriented tests in `libs\execution_context\unit` and `tests\end_to_end`.
- **Method:** extracted invocation preconditions, address-change propagation, and error-handling outcomes, then compared them with the current generic provider-readiness gate, native BTF rundown path, native BTF address-update path, generated native-call indirection, and representative runtime tests/harnesses.
- **Excluded:** detailed load-time BTF attach mechanics beyond the runtime effects they create; internal `ebpf_program_t` storage changes beyond what is visible through invocation and callback contracts.
- **Limitations:** the examined code still has no explicit `ebpf_btf_resolved_function_addresses_changed_callback_t` or JIT-side BTF callback path, so some future touch points remain inferred.

# Runtime Execution — Requirements Document

## 1. Overview

[KNOWN] This area defines the execution-time contract after providers have been loaded and bound. The source requires provider-attachment checks before invocation, rundown protection during execution, and explicit failure behaviors when providers are missing or detach. (Source: `docs/BtfResolvedFunctions.md:396-428`)

[KNOWN] The source also describes how address changes are propagated differently for JIT and native programs. (Source: `docs/BtfResolvedFunctions.md:408-419`)

[KNOWN] The current runtime implementation already has an invocation gate and address-change propagation path. It still uses the existing extension/helper model for generic provider readiness and helper callbacks, but native BTF-resolved execution support now exists: `program_runtime_context_t` includes `btf_resolved_function_data`, native load allocates that storage, provider attach/detach updates those addresses, generated native code dereferences `runtime_context->btf_resolved_function_data[...]`, and native invocation acquires/releases BTF provider rundown protection around execution. [KNOWN] The explicit `ebpf_btf_resolved_function_addresses_changed_callback_t` contract and any JIT-specific BTF propagation path are still absent in the examined code. (Source: `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170`, `libs\execution_context\ebpf_program.h:200-214`, `libs\execution_context\ebpf_program.h:389-407`, `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_native.c:1051-1095`, `libs\execution_context\ebpf_native.c:2375-2469`, `tests\bpf2c_tests\expected\btf_resolved_sys.c:245-247`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] Program invocation preconditions and runtime execution flow. (Source: `docs/BtfResolvedFunctions.md:398-406`)
- [KNOWN] Address-change callback contract. (Source: `docs/BtfResolvedFunctions.md:408-419`)
- [KNOWN] Runtime error-handling scenarios. (Source: `docs/BtfResolvedFunctions.md:422-428`)
- [KNOWN] Existing execution-context invoke, rundown, helper-address update, native BTF address propagation, and generated native BTF call-indirection behavior relevant to the runtime path. (Source: `libs\execution_context\ebpf_program.c:1154-1238`, `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_native.c:1051-1095`, `libs\execution_context\ebpf_native.c:2375-2469`, `tests\bpf2c_tests\expected\btf_resolved_sys.c:245-247`)

### 2.2 Out of Scope

- [KNOWN] Provider attach/detach callback mechanics, because they belong to `07-native-module-loading.md`. (Source: `docs/BtfResolvedFunctions.md:357-375`)
- [KNOWN] Internal storage layout on `ebpf_program_t`, because it belongs to `09-ebpf-program-internal-changes.md`. (Source: `docs/BtfResolvedFunctions.md:430-466`)
- [KNOWN] Proof-of-verification hash inputs, because they belong to `05-bpf2c-integration.md`. (Source: `docs/BtfResolvedFunctions.md:300-310`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Address-change callback | [KNOWN] The `ebpf_btf_resolved_function_addresses_changed_callback_t` callback used to propagate BTF-resolved function address changes. (Source: `docs/BtfResolvedFunctions.md:410-417`) |
| Provider-complete execution | [INFERRED] An invocation state in which all required providers are attached before execution starts. (Source: `docs/BtfResolvedFunctions.md:400-404`) |
| Native-BTF runtime baseline | [KNOWN] The current runtime model in which generic provider readiness is still represented by `extension_program_data`, native invocation additionally acquires BTF provider rundown protection, and native runtime updates write to `runtime_context.btf_resolved_function_data`. (Source: `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_native.c:1051-1095`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-RUN-001: Before invoking an eBPF program that uses BTF-resolved functions, the system MUST check that all required BTF-resolved function providers are attached, so that execution does not begin with missing provider dependencies. (Source: `docs/BtfResolvedFunctions.md:400-403`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements define provider-attachment validation as a mandatory pre-invocation step. (Source: `docs/BtfResolvedFunctions.md:400-403`)

[KNOWN] REQ-RUN-002: If any required provider is detached at invocation time, the system MUST return `EBPF_EXTENSION_FAILED_TO_LOAD`, so that missing providers produce an explicit failure result. (Source: `docs/BtfResolvedFunctions.md:402-404`, `docs/BtfResolvedFunctions.md:426-427`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements state the failure code for a detached or unregistered required provider. (Source: `docs/BtfResolvedFunctions.md:403`, `docs/BtfResolvedFunctions.md:426-427`)

[KNOWN] REQ-RUN-003: Before program execution begins, the system MUST take rundown protection on all BTF-resolved function bindings and MUST release that rundown protection after execution completes, so that provider detach can wait for in-flight execution safely. (Source: `docs/BtfResolvedFunctions.md:404-406`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements identify both acquisition and release of rundown protection as mandatory execution steps. (Source: `docs/BtfResolvedFunctions.md:404-406`)

[KNOWN] REQ-RUN-004: Program execution MUST call BTF-resolved functions through runtime-context indirection rather than through fixed direct provider calls, so that address changes can be propagated without recompiling the eBPF program. (Source: `docs/BtfResolvedFunctions.md:405`, `docs/BtfResolvedFunctions.md:419`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements tie BTF-resolved function execution to address storage that can be updated. (Source: `docs/BtfResolvedFunctions.md:405`, `docs/BtfResolvedFunctions.md:419`)

[KNOWN] REQ-RUN-005: The system MUST propagate BTF-resolved function address changes through `ebpf_btf_resolved_function_addresses_changed_callback_t`, so that JIT-compiled programs can update jump tables and native programs can update runtime-context address storage. (Source: `docs/BtfResolvedFunctions.md:408-419`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements preserve both documented callback consumers: JIT jump-table updates and native runtime-context updates. (Source: `docs/BtfResolvedFunctions.md:410-419`)

[KNOWN] REQ-RUN-006: If a provider detaches during program execution, the current execution MUST complete and subsequent invocations MUST fail until the provider reattaches, so that in-flight execution and post-detach availability are handled distinctly. (Source: `docs/BtfResolvedFunctions.md:427-428`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements distinguish in-flight completion from later invocation failure for the same detach event. (Source: `docs/BtfResolvedFunctions.md:427-428`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-RUN-007: Runtime failure behavior for unavailable providers MUST be explicit and deterministic across the three documented scenarios, so that provider absence, detach-while-loaded, and detach-during-execution are not conflated. (Source: `docs/BtfResolvedFunctions.md:422-428`)

Acceptance Criteria:
- [INFERRED] AC-1: The runtime requirements preserve all three documented scenarios with distinct outcomes. (Source: `docs/BtfResolvedFunctions.md:424-428`)

[INFERRED] REQ-RUN-008: If BTF-resolved runtime support is added, it SHOULD extend the existing invoke/rundown/address-update pipeline in `ebpf_program.c` and native runtime-context update path in `ebpf_native.c` rather than introduce a second unrelated execution gate, so that runtime behavior stays consistent with current execution-context structure. (Source: `libs/execution_context/ebpf_program.c:1154-1238`, `libs/execution_context/ebpf_program.c:1538-1608`, `libs/execution_context/ebpf_native.c:2407-2452`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify current invoke readiness checks, rundown protection, and helper/native address-update paths as the preferred extension points for BTF-resolved runtime behavior. (Source: `libs/execution_context/ebpf_program.c:1154-1238`, `libs/execution_context/ebpf_program.c:1538-1608`, `libs/execution_context/ebpf_native.c:2407-2452`)

### 4.3 Constraints

- [KNOWN] CON-001: The source defines the address-change callback signature but does not define additional ordering or locking guarantees around callback execution. (Source: `docs/BtfResolvedFunctions.md:410-417`)
- [UNKNOWN: the exact algorithm for selecting the full set of bindings covered by rundown protection is not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:404-406`)
- [KNOWN] CON-003: The current explicit callback contract in `libs\execution_context` is still `ebpf_helper_function_addresses_changed_callback_t`, not `ebpf_btf_resolved_function_addresses_changed_callback_t`. (Source: `libs\execution_context\ebpf_program.h:389-407`)
- [KNOWN] CON-004: The current public native runtime context in `include\bpf2c.h` already contains `btf_resolved_function_data`, and generated native code already calls through it. (Source: `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170`, `tests\bpf2c_tests\expected\btf_resolved_sys.c:245-247`)
- [KNOWN] CON-005: The current invoke gate in `ebpf_program_invoke(...)` is still split: generic provider readiness uses `extension_program_data`, while native BTF readiness/rundown is enforced by `ebpf_native_acquire_btf_references(...)`. (Source: `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_native.c:1051-1095`)

## 5. Dependencies

- DEP-RUN-001: This requirement set depends on `07-native-module-loading.md` for provider attachment state and on `09-ebpf-program-internal-changes.md` for callback and binding storage. Impact if unavailable: the runtime cannot know which providers are attached or where to store address-change state. (Source: `docs/BtfResolvedFunctions.md:400-419`, `docs/BtfResolvedFunctions.md:449-455`)
- DEP-RUN-002: This requirement set depends on the current execution-context invoke path, helper callback pipeline, and native BTF runtime path because future BTF-resolved runtime behavior must either extend or intentionally diverge from those existing mechanisms. Impact if unavailable: the delta between source requirements and current runtime behavior cannot be stated concretely. (Source: `libs\execution_context\ebpf_program.c:1154-1238`, `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_native.c:1051-1095`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] The runtime can enumerate all required bindings before taking rundown protection. If this assumption is wrong, an additional discovery requirement is needed before invocation. Justification: the source requires rundown on all bindings but does not define the enumeration mechanism in this section. (Source: `docs/BtfResolvedFunctions.md:404-406`)
- ASM-002: [ASSUMPTION] A future explicit BTF-resolved callback surface would most naturally extend the existing callback and runtime-context surfaces in `ebpf_program.h` and `include\bpf2c.h`. If this assumption is wrong, the design delta's public touch points must be updated. Justification: those files define the current helper callback and native runtime-context contracts, and `include\bpf2c.h` already carries `btf_resolved_function_data`. (Source: `libs\execution_context\ebpf_program.h:389-407`, `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-RUN-001 | [KNOWN] Invoking a program while a required provider is detached must fail, which directly affects program availability. (Source: `docs/BtfResolvedFunctions.md:402-404`, `docs/BtfResolvedFunctions.md:426-427`) | Medium | High | [INFERRED] Preserve explicit pre-invocation readiness checks and failure codes. |
| RISK-RUN-002 | [KNOWN] Inconsistent address-change propagation could leave JIT and native execution paths observing different provider addresses. (Source: `docs/BtfResolvedFunctions.md:408-419`) | Medium | High | [INFERRED] Keep callback propagation mandatory for both execution modes. |
| RISK-RUN-003 | [KNOWN] Leaving runtime behavior split between generic helper-oriented callback infrastructure and native-only direct BTF runtime-context updates can make JIT/native behavior drift if the explicit BTF callback contract is never added. (Source: `libs\execution_context\ebpf_program.h:389-407`, `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `docs/BtfResolvedFunctions.md:408-419`) | High | High | [INFERRED] Make the remaining callback/JIT gap explicit in the design and validation deltas. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial runtime-execution requirements extracted from `docs/BtfResolvedFunctions.md`. |
| 0.2 | 2026-06-02 | Copilot | Added code-backed deltas for the current single-provider invoke gate, helper-specific callback path, and missing BTF-resolved runtime contracts. |
| 0.3 | 2026-06-05 | Copilot | Updated the document to reflect current native BTF runtime support in `include\bpf2c.h`, native attach/detach address propagation, invoke-time BTF rundown protection, and the remaining callback/JIT gaps. |

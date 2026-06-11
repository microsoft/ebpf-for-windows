<!-- Delta artifact: Runtime Execution alignment set -->

# Runtime Execution — Design Delta

## 1. Change Context

- **Area**: Runtime Execution
- **Requirements source**: `docs\specs\btfid\08-runtime-execution.md`
- **Existing design doc**: N/A — no existing design document was provided for this run
- **Code scope**: `libs\execution_context`
- **Test scope**: `libs\execution_context\unit`; selected runtime tests under `tests\`
- **Goal**: identify the minimal design deltas needed to align the runtime-execution requirements with the current execution-context implementation and test baseline

[KNOWN] The current execution-context runtime already implements explicit invocation gating, rundown protection, and address-change propagation. Generic provider readiness and helper callbacks still use the existing extension/helper model, but native BTF runtime support now exists: native load allocates `runtime_context.btf_resolved_function_data`, provider attach/detach updates those addresses, generated native code dereferences them, and native invocation acquires/releases BTF provider rundown protection around execution. [KNOWN] The remaining runtime gap is the lack of an explicit BTF callback surface and any JIT-side BTF propagation path. (Evidence: CE-001, CE-002, CE-003, CE-004, CE-005, CE-006)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-RUN-001 | Modify | Required | Keep the native per-provider BTF readiness gate, but decide whether generic provider-reference helpers or any non-native execution path must also understand BTF provider-complete readiness. | CE-001, CE-003, CE-006 |
| DD-002 | REQ-RUN-002 | Modify | Required | Preserve `EBPF_EXTENSION_FAILED_TO_LOAD` for missing BTF providers while keeping the current split between generic extension-provider failure and native BTF-provider failure paths understandable. | CE-001, CE-003 |
| DD-003 | REQ-RUN-003 | Modify | Required | Retain the native all-bindings rundown path and decide whether any shared runtime abstraction or non-native path must participate in the same contract. | CE-001, CE-003 |
| DD-004 | REQ-RUN-004 | No-Impact/Constrain | Not required | Use the existing native `runtime_context.btf_resolved_function_data` indirection already present in the public contract and generated code. | CE-004, CE-005 |
| DD-005 | REQ-RUN-005 | Modify | Required | Add the explicit `ebpf_btf_resolved_function_addresses_changed_callback_t` contract and any JIT-side BTF propagation path; native direct runtime-context updates already exist. | CE-002, CE-003, CE-004, CE-006 |
| DD-006 | REQ-RUN-006 | No-Impact/Constrain | Not required | Preserve the current native detach sequence that marks bindings detached, waits for rundown, and clears addresses. | CE-003 |
| DD-007 | REQ-RUN-007 | Modify | Required | Document and test the three runtime failure scenarios explicitly; current native behavior is partly present but not yet covered or generalized. | CE-001, CE-003, CE-006 |
| DD-008 | REQ-RUN-008 | No-Impact/Constrain | Required | Extend the existing invoke/rundown/address-update pipeline rather than invent a second runtime path. | CE-001, CE-002, CE-003, CE-004 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-RUN-001
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-003
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`; `[UNKNOWN: any BTF binding-state declarations outside the examined scope]`
- **Before**: The current invoke gate still checks whether `extension_program_data` is non-null as its generic readiness check, but the native branch now additionally calls `ebpf_native_acquire_btf_references(...)`, which validates that every required BTF provider binding is attached before invoking native code. (Evidence: CE-001, CE-003)
- **After**: Keep that native provider-complete readiness behavior and decide whether any shared or non-native runtime path also needs to surface BTF provider-complete readiness explicitly.
- **Rationale**: The core BTF-native readiness contract now exists, but it is not yet reflected in a shared runtime abstraction.

### DD-002

- **Upstream REQ-ID**: REQ-RUN-002
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-003
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`
- **Before**: The current invoke path returns `EBPF_EXTENSION_FAILED_TO_LOAD` when the program information provider is unavailable, and the native branch now also returns the same error if `ebpf_native_acquire_btf_references(...)` cannot acquire all required BTF provider bindings. (Evidence: CE-001, CE-003)
- **After**: Preserve the BTF-native failure code while documenting and, if needed, clarifying the split between generic extension failure and native BTF-provider failure.
- **Rationale**: The source keeps the same error code, but the implementation now has two distinct paths that can produce it.

### DD-003

- **Upstream REQ-ID**: REQ-RUN-003
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-003
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`; `[UNKNOWN: BTF binding-state declarations]`
- **Before**: Current runtime still acquires and releases one `program_information_rundown_reference` for generic program-information availability, but native execution now acquires and releases rundown protection on every required BTF provider binding via `program->btf_provider_binding_indices`. (Evidence: CE-001, CE-003)
- **After**: Keep the native all-bindings rundown behavior and decide whether any shared or non-native execution path needs the same abstraction.
- **Rationale**: The source requires binding-complete rundown protection, and the native implementation now supplies it.

### DD-004

- **Upstream REQ-ID**: REQ-RUN-004
- **Existing design location**: `include\bpf2c.h`; generated native fixtures
- **Related code evidence IDs**: CE-004, CE-005
- **Expected code change locations**: None
- **Before**: The public native runtime contract already includes `btf_resolved_function_data`, and generated native code already calls through `runtime_context->btf_resolved_function_data[...]`. (Evidence: CE-004, CE-005)
- **After**: No additional design delta is required for native runtime-context indirection itself.
- **Rationale**: This part of the runtime contract is already implemented for native execution.

### DD-005

- **Upstream REQ-ID**: REQ-RUN-005
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-003, CE-004
- **Expected code change locations**: `libs\execution_context\ebpf_program.h`; `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c`; `[ASSUMPTION] include\bpf2c.h`
- **Before**: The current explicit address-change callback surface is still `ebpf_helper_function_addresses_changed_callback_t`; however, native BTF provider attach/detach already updates `runtime_context.btf_resolved_function_data` directly. (Evidence: CE-002, CE-003, CE-004)
- **After**: Add `ebpf_btf_resolved_function_addresses_changed_callback_t` and any JIT-side BTF propagation path; keep the existing native direct-update behavior aligned with that contract.
- **Rationale**: The native half of the update behavior exists, but the explicit callback/JIT half does not.

### DD-006

- **Upstream REQ-ID**: REQ-RUN-006
- **Existing design location**: `libs\execution_context\ebpf_native.c`; `libs\execution_context\ebpf_program.c`
- **Related code evidence IDs**: CE-001, CE-003
- **Expected code change locations**: None
- **Before**: Native detach now marks the binding detached, waits for rundown protection release, clears addresses, and later native invocations fail because `ebpf_native_acquire_btf_references(...)` no longer succeeds. (Evidence: CE-001, CE-003)
- **After**: No additional native design delta is required for the detach-during-execution contract itself.
- **Rationale**: The native implementation already preserves in-flight execution and causes later invocations to fail until reattach.

### DD-007

- **Upstream REQ-ID**: REQ-RUN-007
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-003, CE-006
- **Expected code change locations**: `libs\execution_context\ebpf_program.c`; `[UNKNOWN: BTF binding-state declarations]`
- **Before**: Current failure behavior is explicit for generic provider absence and for native BTF provider-acquire failure, but the implementation and tests do not yet document or distinguish all three source scenarios as first-class runtime outcomes. (Evidence: CE-001, CE-003, CE-006)
- **After**: Document and validate the three BTF runtime scenarios explicitly, even if they continue to converge on `EBPF_EXTENSION_FAILED_TO_LOAD`.
- **Rationale**: The source requires deterministic distinction among these scenarios.

### DD-008

- **Upstream REQ-ID**: REQ-RUN-008
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-002, CE-003, CE-004
- **Expected code change locations**: Existing invoke/callback/native runtime files only
- **Before**: The current runtime behavior is already centralized in `ebpf_program.c` plus native helper update code. (Evidence: CE-001, CE-002, CE-003, CE-004)
- **After**: Keep BTF runtime support inside those existing runtime paths rather than inventing a separate execution/update architecture.
- **Rationale**: This preserves the current runtime structure and minimizes divergence.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-RUN-001 | PARTIAL | DD-001 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | Native provider-complete BTF readiness exists, but it is not surfaced as a shared runtime abstraction. |
| REQ-RUN-002 | PARTIAL | DD-002 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | Failure code exists for both generic provider absence and native BTF-provider failure, but the split remains implicit. |
| REQ-RUN-003 | PARTIAL | DD-003 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | Native all-bindings rundown exists, but only for the native path. |
| REQ-RUN-004 | SATISFIED | No-Impact | None | Native runtime-context indirection already exists in the public contract and generated code. |
| REQ-RUN-005 | PARTIAL | DD-005 | `libs\execution_context\ebpf_program.h`; `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | Native update behavior exists, but the explicit BTF callback/JIT path does not. |
| REQ-RUN-006 | SATISFIED | No-Impact | None | Native detach already preserves in-flight execution and causes later invocations to fail. |
| REQ-RUN-007 | PARTIAL | DD-007 | `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c` | Native failure behavior is partly present, but the three scenarios are not yet explicitly documented and tested. |
| REQ-RUN-008 | SATISFIED | No-Impact/Constrain | None | Existing invoke/rundown/address-update pipeline is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] The current invoke path still centralizes generic readiness checks in `ebpf_program.c`, while native BTF-specific readiness/rundown now lives in the native branch of that same invoke path. The remaining deltas preserve that structure. (Evidence: CE-001, CE-003)
- [KNOWN] The current callback/update mechanism remains split between `ebpf_program.c` for helper/JIT-interpreter behavior and `ebpf_native.c` for native address updates; the remaining deltas preserve that split while making the missing explicit BTF callback/JIT gap visible. (Evidence: CE-002, CE-003)
- [KNOWN] The current public native runtime contract remains a single surface in `include\bpf2c.h`, and it already includes `btf_resolved_function_data`. (Evidence: CE-004, CE-005)

## 6. Application Notes

1. [KNOWN] No existing design document was provided, so these deltas are synthesized additions rather than edits against a prior design artifact.
2. [KNOWN] The main gap is no longer total absence of BTF runtime support; native BTF invoke/rundown/address-update behavior now exists, while the explicit callback/JIT side remains incomplete.
3. [KNOWN] The remaining `[UNKNOWN]` areas are concentrated around any future shared callback/JIT design rather than around native runtime-context indirection itself.

## Coverage
- **Examined**: `docs\specs\btfid\08-runtime-execution.md`; `libs\execution_context\ebpf_program.h`; `libs\execution_context\ebpf_program.c`; `libs\execution_context\ebpf_native.c`; `include\bpf2c.h`; `tests\bpf2c_tests\expected\btf_resolved_sys.c`
- **Method**: targeted `view` on invoke readiness, native BTF rundown protection, native BTF address updates, helper-address callbacks, public runtime-context declarations, and generated native BTF call sites; targeted `rg` for BTF-resolved runtime symbols and failure terms
- **Excluded**: load-time BTF attach mechanics; internal `ebpf_program_t` binding storage beyond runtime-accessible behavior
- **Limitations**: the examined code still lacks an explicit BTF callback/JIT propagation implementation, so those future change points remain `[UNKNOWN]`

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\execution_context\ebpf_program.c:1538-1615`, `libs\execution_context\ebpf_program.h:200-214` | Current invoke path still checks `extension_program_data`, returns `EBPF_EXTENSION_FAILED_TO_LOAD`, and in the native branch additionally calls `ebpf_native_acquire_btf_references(...)` / `ebpf_native_release_btf_references(...)`. | Establishes the current invoke/rundown baseline plus the native BTF invoke gate. |
| CE-002 | `libs\execution_context\ebpf_program.h:389-407`, `libs\execution_context\ebpf_program.c:1154-1238` | Current explicit callback/update surface is still `ebpf_helper_function_addresses_changed_callback_t` and helper-specific JIT/interpreter propagation. | Establishes the remaining helper-specific callback baseline. |
| CE-003 | `libs\execution_context\ebpf_native.c:282-327`, `libs\execution_context\ebpf_native.c:460-565`, `libs\execution_context\ebpf_native.c:1051-1095` | Native BTF provider attach/detach updates `runtime_context.btf_resolved_function_data`, detach waits for rundown release, and native invoke acquires/releases rundown protection on all required BTF provider bindings. | Establishes the implemented native BTF runtime path. |
| CE-004 | `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170` | `include\bpf2c.h` defines `btf_resolved_function_data_t` and includes `btf_resolved_function_data` in `program_runtime_context_t`. | Establishes the current public native runtime contract. |
| CE-005 | `tests\bpf2c_tests\expected\btf_resolved_sys.c:245-247` | Generated native code already calls through `runtime_context->btf_resolved_function_data[0].address`. | Establishes the current native BTF call-indirection behavior. |
| CE-006 | Exact searches over `libs\execution_context`, `include`, and `tests` for `ebpf_btf_resolved_function_addresses_changed_callback_t` returned no implementation matches. | No explicit BTF-resolved runtime callback/JIT propagation contract exists in the examined scope. | Establishes the remaining callback/JIT gap. |

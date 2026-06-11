<!-- Delta artifact: Native Module Loading alignment set -->

# Native Module Loading — Design Delta

## 1. Change Context

- **Area**: Native Module Loading
- **Requirements source**: `docs\specs\btfid\07-native-module-loading.md`
- **Existing design doc**: N/A — no existing design document was provided for this run
- **Code scope**: `libs\execution_context`
- **Test scope**: `libs\execution_context\unit`; selected native-module tests under `tests\`
- **Goal**: identify the minimal design deltas needed to align the native-module-loading requirements with the current execution-context implementation and test baseline

[KNOWN] The current execution-context code already implements native-module loading, but it is still based on the private native-module NPI plus helper-resolution machinery. [KNOWN] Adjacent groundwork for BTF-resolved native loading now exists: `include\bpf2c.h` defines BTF import/runtime structures, generated native code emits BTF import tables and dereferences `runtime_context->btf_resolved_function_data`, and user-mode harnesses populate that field. [KNOWN] The in-scope execution-context implementation validates native BTF import metadata and then fails native loads closed when BTF imports are present. [KNOWN] No in-scope code currently defines a BTF-resolved-function provider-binding list, wildcard BTF client registration, or a BTF-resolved address-changed callback. (Evidence: CE-001, CE-002, CE-003, CE-004, CE-005, CE-006, CE-007, CE-008)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-LOAD-001 | Add | Required | Add a BTF-resolved-function client registration path for native modules, distinct from the current private native NPI provider path. | CE-001, CE-002, CE-006 |
| DD-002 | REQ-LOAD-002 | Add | Required | Add client attach logic that matches provider module GUIDs against the BTF import table before accepting attachment. | CE-004, CE-006 |
| DD-003 | REQ-LOAD-003 | Add | Required | Complete provider-binding state plus kernel-side address-copy logic for the existing `btf_resolved_function_data` runtime context. | CE-003, CE-004, CE-007, CE-008 |
| DD-004 | REQ-LOAD-004 | Add | Required | Return `STATUS_NOINTERFACE` for unrelated BTF providers rather than accepting them. | CE-006 |
| DD-005 | REQ-LOAD-005 | Add | Required | Add a BTF-provider detach path that nulls BTF-resolved addresses and marks provider bindings detached. | CE-005, CE-006 |
| DD-006 | REQ-LOAD-006 | Add | Required | Add BTF-resolved address-change notification semantics, including wait-for-execution-completion and callback invocation. | CE-005, CE-006 |
| DD-007 | REQ-LOAD-007 | Add | Required | Add support for multiple BTF provider bindings and gate program execution on all required providers being attached instead of the current fail-closed load rejection. | CE-003, CE-006, CE-008 |
| DD-008 | REQ-LOAD-008 | Add | Required | Keep provider-binding state distinct from per-function state and from existing helper-resolution state. | CE-003, CE-004, CE-006 |
| DD-009 | REQ-LOAD-009 | No-Impact/Constrain | Required | Extend the existing native-module load pipeline and public native contract instead of creating an unrelated runtime path. | CE-001, CE-003, CE-004, CE-005 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-LOAD-001
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-002, CE-006
- **Expected code change locations**: `[UNKNOWN: native module skeleton/client registration site outside the examined execution-context code]`; `06-nmr-provider-registration` contract touch points
- **Before**: The in-scope execution-context code registers as a provider for the private native NPI `_ebpf_native_npi_id`; no in-scope code registers a native module as a client for a BTF-resolved-function NPI. (Evidence: CE-001, CE-002, CE-006)
- **After**: Add native-module client registration for the BTF-resolved-function NPI using the wildcard module-id semantics required by the source.
- **Rationale**: The source requirement is about a new client-side binding path, not about the existing private native-module provider path.

### DD-002

- **Upstream REQ-ID**: REQ-LOAD-002
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-004, CE-006
- **Expected code change locations**: `[UNKNOWN: native module client attach callback site]`; `include\bpf2c.h` if import-table/runtime structures need extension
- **Before**: The current native-loading path resolves helpers by helper ID and name, not by matching provider module GUIDs against BTF import-table entries. No BTF provider attach callback exists in scope. (Evidence: CE-004, CE-006)
- **After**: Add attach logic that checks provider module GUIDs against BTF import-table entries before accepting the provider.
- **Rationale**: The BTF path is provider-identity driven rather than helper-ID driven.

### DD-003

- **Upstream REQ-ID**: REQ-LOAD-003
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-004, CE-007, CE-008
- **Expected code change locations**: `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: native module client attach/load code outside the examined execution-context scope]`
- **Before**: The current public runtime context already includes `btf_resolved_function_data`, generated native code already dereferences it, and user-mode harnesses already populate it. The current execution-context loader still allocates and fills only helper/map/global-variable runtime fields and rejects native loads that declare BTF imports. (Evidence: CE-003, CE-007, CE-008)
- **After**: Keep the existing public runtime context and complete the missing kernel-side attach-time address-copy logic plus provider-binding-record creation.
- **Rationale**: The source explicitly requires binding tracking and native attach-time population, and the existing public scaffolding should be completed rather than replaced.

### DD-004

- **Upstream REQ-ID**: REQ-LOAD-004
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-006
- **Expected code change locations**: `[UNKNOWN: native module client attach callback site]`
- **Before**: The current in-scope native-loading code has no BTF provider attach callback and therefore no BTF-specific `STATUS_NOINTERFACE` decline path. (Evidence: CE-006)
- **After**: Add a negative attach path that returns `STATUS_NOINTERFACE` when the provider module GUID is not imported by the native module.
- **Rationale**: The source makes this a concrete, externally visible contract.

### DD-005

- **Upstream REQ-ID**: REQ-LOAD-005
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-005, CE-006
- **Expected code change locations**: `[UNKNOWN: native module client detach callback site]`; `[ASSUMPTION] include\bpf2c.h`
- **Before**: The current loader updates helper addresses through the helper-address callback path, but it has no BTF-provider detach path that nulls BTF-resolved addresses or marks BTF provider bindings detached. (Evidence: CE-005, CE-006)
- **After**: Add BTF-provider detach behavior that clears BTF-resolved addresses and updates provider-binding state.
- **Rationale**: The detach semantics are specific to provider-backed BTF addresses and are not satisfied by the current helper-only callback path.

### DD-006

- **Upstream REQ-ID**: REQ-LOAD-006
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-005, CE-006
- **Expected code change locations**: `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: native module client detach/runtime coordination code]`
- **Before**: The current address-change contract is `ebpf_helper_function_addresses_changed_callback_t`, and the current native loader registers `_ebpf_native_helper_address_changed`. No BTF-resolved callback contract exists in scope. (Evidence: CE-005)
- **After**: Add a BTF-resolved address-changed callback surface plus any required execution-rundown coordination so detach can wait for current execution and then notify consumers.
- **Rationale**: The source requires a distinct BTF address-change notification contract, not just helper-address updates.

### DD-007

- **Upstream REQ-ID**: REQ-LOAD-007
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-006, CE-008
- **Expected code change locations**: `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: native module client-side provider-binding state owner]`
- **Before**: Current runtime-context structures expose BTF import/runtime metadata, but the native-loader structures in scope still have no BTF provider-binding list or multi-provider readiness gate and instead reject BTF-importing native loads outright. (Evidence: CE-003, CE-006, CE-008)
- **After**: Add provider-binding-list state and require all needed BTF providers to be attached before execution proceeds instead of failing every BTF-importing native load up front.
- **Rationale**: Multi-provider readiness is the source-mandated replacement for the current temporary fail-closed behavior.

### DD-008

- **Upstream REQ-ID**: REQ-LOAD-008
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-004, CE-006
- **Expected code change locations**: `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: native module/provider-binding state owner]`
- **Before**: Current native runtime state is organized around helper/map/global-variable data and a helper-address-changed context. No separate BTF provider-binding structure exists in scope. (Evidence: CE-003, CE-004, CE-006)
- **After**: Introduce BTF provider-binding state as its own structure, separate from both helper-resolution state and any per-function BTF binding state added elsewhere.
- **Rationale**: The source explicitly separates provider-level and per-function responsibilities.

### DD-009

- **Upstream REQ-ID**: REQ-LOAD-009
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-003, CE-004, CE-005
- **Expected code change locations**: `include\bpf2c.h`; any native-module client loading code added for BTF
- **Before**: The current native loading pipeline already validates metadata, allocates runtime-context storage, resolves helper addresses, and registers for helper-address changes. (Evidence: CE-001, CE-004, CE-005)
- **After**: Extend that same pipeline for BTF-resolved loading rather than creating a second unrelated runtime-context/update architecture.
- **Rationale**: This preserves the existing loader structure and minimizes behavioral divergence.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-LOAD-001 | MISSING | DD-001 | `[UNKNOWN: native module client registration site]`; `06-nmr-provider-registration` touch points | In-scope code contains no BTF client-registration path. |
| REQ-LOAD-002 | MISSING | DD-002 | `[UNKNOWN: native module client attach callback site]`; possibly `include\bpf2c.h` | No BTF GUID-to-import matching exists in scope. |
| REQ-LOAD-003 | PARTIAL | DD-003 | `[UNKNOWN: native module attach/load code]` | Public/runtime scaffolding for `btf_resolved_function_data` exists, but kernel-side binding and copy logic do not. |
| REQ-LOAD-004 | MISSING | DD-004 | `[UNKNOWN: native module client attach callback site]` | No BTF-specific `STATUS_NOINTERFACE` path exists in scope. |
| REQ-LOAD-005 | MISSING | DD-005 | `[UNKNOWN: native module client detach callback site]`; `[ASSUMPTION] include\bpf2c.h` | No BTF detach behavior exists in scope. |
| REQ-LOAD-006 | MISSING | DD-006 | `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: native module detach/runtime coordination code]` | Current callback surface is helper-only. |
| REQ-LOAD-007 | MISSING | DD-007 | `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: provider-binding state owner]` | No multi-provider BTF readiness state exists in scope. |
| REQ-LOAD-008 | MISSING | DD-008 | `[ASSUMPTION] include\bpf2c.h`; `[UNKNOWN: provider-binding state owner]` | No distinct BTF provider-binding structure exists in scope. |
| REQ-LOAD-009 | SATISFIED | No-Impact/Constrain | None | Existing native loader/runtime pipeline is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] The current native-module loader is organized around a single metadata-table-based load pipeline; the deltas preserve that structure. (Evidence: CE-001, CE-004)
- [KNOWN] The current public runtime context is centralized in `include\bpf2c.h` and already includes BTF import/runtime fields; the deltas preserve that single public contract surface while completing the missing native-loading behavior around it. (Evidence: CE-003, CE-007)
- [KNOWN] The current callback/update mechanism is helper-address based; the deltas add a BTF-specific sibling path rather than replacing helper change handling. (Evidence: CE-005)

## 6. Application Notes

1. [KNOWN] No existing design document was provided, so these deltas are synthesized additions rather than edits against a prior design artifact.
2. [KNOWN] The main gap is not native-module loading in general; it is that current loading is helper-centric and scoped to the private native NPI even though the public/runtime BTF import scaffolding already exists.
3. [KNOWN] Several concrete change locations remain `[UNKNOWN]` because the native module skeleton/client side for BTF providers is not present in the examined code scope.

## Coverage
- **Examined**: `docs\specs\btfid\07-native-module-loading.md`; `include\bpf2c.h`; `libs\execution_context\ebpf_native.c`; `libs\execution_context\ebpf_program.h`; `libs\execution_context\ebpf_program.c`; `tests\bpf2c_tests\expected\btf_resolved_sys.c`; `tests\bpf2c_plugin\bpf2c_test.cpp`; `tests\bpf2c_tests\bpf_test.cpp`
- **Method**: targeted `view` on native NPI/provider registration, native attach validation, runtime-context allocation, helper resolution, helper-address update flow, generated BTF native scaffolding, and BTF-aware user-mode runtime harnesses; targeted `rg` for BTF-resolved symbols, native load entry points, and callback contracts
- **Excluded**: runtime invocation after successful load; native module skeleton code outside the examined execution-context scope
- **Limitations**: the native module client-side implementation required by the source is not present in the examined code, so some future touch points remain `[UNKNOWN]`

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\execution_context\ebpf_native.c:107-144`, `libs\execution_context\ebpf_native.c:1068-1073` | Execution-context registers a provider for the private native NPI `_ebpf_native_npi_id`. | Establishes the current provider-side native loading baseline. |
| CE-002 | `libs\execution_context\ebpf_native.c:800-977` | Native attach handling in scope validates and authorizes a native module through the provider-side attach callback. | Establishes that current scope is provider-side, not BTF client-side. |
| CE-003 | `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170`, `include\bpf2c.h:190-193`, `include\bpf2c.h:220-238` | `include\bpf2c.h` defines BTF import metadata and `program_runtime_context_t::btf_resolved_function_data`, but `metadata_table_t` has no BTF-specific address-change callback field. | Establishes the current public native contract baseline. |
| CE-004 | `libs\execution_context\ebpf_native.c:1658-1744`, `libs\execution_context\ebpf_native.c:1917-1970` | Native loading allocates `runtime_context.helper_data`, resolves helpers, and writes helper addresses into runtime context; when `btf_resolved_function_count > 0`, the loader returns `EBPF_EXTENSION_FAILED_TO_LOAD`. | Establishes the helper-centric runtime wiring baseline and current fail-closed BTF behavior. |
| CE-005 | `libs\execution_context\ebpf_program.h:389-407`, `libs\execution_context\ebpf_native.c:1971-2005`, `libs\execution_context\ebpf_native.c:2407-2452` | The current callback/update path is helper-address based via `ebpf_program_register_for_helper_changes` and `_ebpf_native_helper_address_changed`. | Establishes the current callback surface and update mechanism. |
| CE-006 | `libs\execution_context` search using `rg "btf_resolved_function_data|btf_resolved_function_addresses_changed_callback|STATUS_NOINTERFACE|wildcard module ID|provider binding list"` returned no native-loading implementation matches for the BTF-specific client-side contract. | No BTF-resolved native-loading path is visible in the examined code scope. | Establishes the feature gap. |
| CE-007 | `tests\bpf2c_tests\expected\btf_resolved_sys.c:106-107`, `tests\bpf2c_tests\expected\btf_resolved_sys.c:187-247` | Generated native code already emits a BTF import table and dereferences `runtime_context->btf_resolved_function_data[0].address` in the program body. | Establishes that generated/native scaffolding is ahead of the kernel consumer implementation. |
| CE-008 | `libs\execution_context\ebpf_native.c:1963-1970` | The native loader explicitly rejects native programs that declare BTF imports with `EBPF_EXTENSION_FAILED_TO_LOAD`. | Establishes the current temporary compatibility behavior in kernel native loading. |

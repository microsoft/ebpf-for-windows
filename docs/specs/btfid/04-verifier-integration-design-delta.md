<!-- Delta artifact: Verifier Integration alignment set -->

# Verifier Integration — Design Delta

## 1. Change Context

- **Area**: Verifier Integration
- **Requirements source**: `docs\specs\btfid\04-verifier-integration.md`
- **Existing design doc**: N/A — no existing design document was provided for this run
- **Code scope**: `libs\api_common`; `libs\api`
- **Test scope**: `tests`
- **Goal**: identify the minimal design deltas needed to align the verifier-integration requirements with the current Windows verifier implementation and its test baseline

[KNOWN] The current Windows verifier path already centralizes verification through `ebpf_api_elf_verify_program_from_file(...)` / `ebpf_api_elf_verify_program_from_memory(...)`, `read_elf(...)`, `unmarshal(...)`, and `ebpf_verify_program(...)`, while thread-local caches preserve program-type information for helper resolution and `ebpf_get_program_info_from_verifier(...)`. [KNOWN] The current Windows platform table, however, still leaves the two BTF-resolved callback slots unset. (Evidence: CE-001, CE-002, CE-003, CE-004, CE-005, CE-006, CE-007)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-VER-001 | Modify | Required | Extend the current Windows verifier pipeline with explicit `.ksyms` discovery for BTF-resolved symbols. | CE-002, CE-003 |
| DD-002 | REQ-VER-002 | Modify | Required | Add top-level declaration-tag parsing and module-to-function association in the Windows verifier integration layer. | CE-002, CE-003 |
| DD-003 | REQ-VER-003 | Add | Required | Add deterministic session-local BTF ID mapping plus reverse lookup state. | CE-001, CE-002, CE-004, CE-005 |
| DD-004 | REQ-VER-004 | Modify | Required | Implement and wire `resolve_kfunc_call_windows` into the Windows platform callback table. | CE-001, CE-004, CE-005, CE-006 |
| DD-005 | REQ-VER-005 | Modify | Required | Extend the existing ELF-to-verifier pipeline so Windows BTF extern-call inputs are rewritten to `call_btf` before verification. | CE-002, CE-003 |
| DD-006 | REQ-VER-007 | No-Impact/Constrain | Required | Keep BTF verifier support inside the existing verifier entry points and platform table rather than adding a new public verification API. | CE-001, CE-002, CE-006, CE-007 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-VER-001
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-003
- **Expected code change locations**: `libs\api\Verifier.cpp`; `[UNKNOWN: any supporting reader/parsing changes outside the provided code scope]`
- **Before**: The current Windows verifier entry points route ELF input into `read_elf(...)`, but the examined `libs\api` and `libs\api_common` code does not contain explicit Windows-side `.ksyms` discovery for BTF-resolved functions. (Evidence: CE-002, CE-003)
- **After**: Extend the current verifier load path with an explicit BTF-resolved-symbol discovery phase that feeds the Windows-specific preprocessing state needed before verification.
- **Rationale**: The generic ELF verification pipeline already exists; the minimal aligned change is to add the missing BTF-specific preprocessing within or immediately adjacent to that path rather than inventing a parallel verifier flow.

### DD-002

- **Upstream REQ-ID**: REQ-VER-002
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-003
- **Expected code change locations**: `libs\api\Verifier.cpp`; `[UNKNOWN: any declaration-tag parsing changes outside the provided code scope]`
- **Before**: No examined Windows-side verifier code parses top-level declaration tags or constructs module-to-function mappings for `.ksyms` functions. (Evidence: CE-002, CE-003)
- **After**: Add Windows-side declaration-tag parsing and mapping logic so `.ksyms` functions can be associated with provider module identifiers before verification.
- **Rationale**: The requirements call for caller-side preprocessing of declaration tags, and the current in-scope code does not implement it.

### DD-003

- **Upstream REQ-ID**: REQ-VER-003
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-002, CE-004, CE-005
- **Expected code change locations**: `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp`; `libs\api_common\windows_platform_common.hpp`; `[UNKNOWN: any supporting parser-state changes outside the provided code scope]`
- **Before**: The current Windows verifier path maintains TLS program-type information for helper resolution, but it has no visible BTF-specific forward or reverse mapping state for `(module_guid, function_name)` and `btf_id`. (Evidence: CE-001, CE-004, CE-005)
- **After**: Add deterministic session-local BTF ID allocation and reversible lookup state to the current Windows verifier integration, reusing existing request-scoped/TLS patterns where appropriate.
- **Rationale**: The current verifier path already relies on request-local state and TLS caches; a BTF mapping store is the minimal missing structure needed to support callback-based resolution.

### DD-004

- **Upstream REQ-ID**: REQ-VER-004
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-004, CE-005, CE-006
- **Expected code change locations**: `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp`; `libs\api_common\windows_platform_common.hpp`
- **Before**: `g_ebpf_platform_windows` wires both `resolve_ksym_btf_id` and `resolve_kfunc_call` as `nullptr`, so the Windows verifier platform does not currently provide BTF callback behavior. (Evidence: CE-001)
- **After**: Implement `resolve_kfunc_call_windows` and any required companion lookup helpers, then wire the callback into the Windows platform table so PREVAIL can resolve `call_btf` contracts using Windows provider metadata.
- **Rationale**: This is the clearest direct conflict between the source requirements and the current code.

### DD-005

- **Upstream REQ-ID**: REQ-VER-005
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-003
- **Expected code change locations**: `libs\api\Verifier.cpp`; `libs\api\windows_platform.cpp`; `[UNKNOWN: any reader/unmarshal changes outside the provided code scope]`
- **Before**: The current verifier code can classify an instruction as `call_btf` after parsing, but no examined Windows-side code rewrites BTF extern-call inputs into the `call_btf` form described by the requirements. (Evidence: CE-002, CE-003)
- **After**: Extend the current preprocessing path so Windows BTF extern-call inputs are rewritten into `call_btf` with the session-local BTF ID before PREVAIL verification consumes the program.
- **Rationale**: The instruction form is already understood by the verifier pipeline; the missing work is to make the Windows-side preprocessing produce it.

### DD-006

- **Upstream REQ-ID**: REQ-VER-007
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-002, CE-006, CE-007
- **Expected code change locations**: `libs\api\Verifier.cpp`; `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp`
- **Before**: The current verifier surface is already centralized around file/memory verification entry points and TLS-backed verifier-side program-info access. (Evidence: CE-002, CE-006, CE-007)
- **After**: Keep all BTF-resolved verifier integration work within that existing surface instead of designing a new BTF-only public verifier API.
- **Rationale**: This preserves the existing verifier surface and minimizes API churn; no additional public verification entry point is justified by the current code baseline.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-VER-001 | PARTIAL | DD-001 | `libs\api\Verifier.cpp`; `[UNKNOWN: out-of-scope reader internals]` | Generic ELF verification path exists, but explicit Windows-side `.ksyms` handling is not visible. |
| REQ-VER-002 | MISSING | DD-002 | `libs\api\Verifier.cpp`; `[UNKNOWN: out-of-scope reader internals]` | No in-scope declaration-tag parsing appears. |
| REQ-VER-003 | MISSING | DD-003 | `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp`; `libs\api_common\windows_platform_common.hpp` | No visible BTF ID mapping state exists in scope. |
| REQ-VER-004 | CONFLICT | DD-004 | `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp`; `libs\api_common\windows_platform_common.hpp` | The required callback is explicitly `nullptr` today. |
| REQ-VER-005 | PARTIAL | DD-005 | `libs\api\Verifier.cpp`; `libs\api\windows_platform.cpp`; `[UNKNOWN: out-of-scope reader/unmarshal internals]` | `CallBtf` is recognized after parsing, but no Windows-side rewrite path is visible. |
| REQ-VER-006 | SATISFIED | No-Impact | None | Current public verifier APIs do not expose BTF IDs as public inputs or outputs. |
| REQ-VER-007 | PARTIAL | DD-006 | `libs\api\Verifier.cpp`; `libs\api\windows_platform.cpp`; `libs\api_common\windows_platform_common.cpp` | Existing verifier entry points already exist, but BTF support is not integrated into them yet. |

## 5. Invariant Impact

- [KNOWN] The current verifier surface is centralized through `ebpf_api_elf_verify_program_from_file(...)` and `ebpf_api_elf_verify_program_from_memory(...)`; the deltas preserve that API-level invariant. (Evidence: CE-002, CE-007)
- [KNOWN] The current Windows platform table is the existing extension point for verifier behavior; the deltas preserve that invariant while filling the BTF-specific callback gaps. (Evidence: CE-001)
- [KNOWN] The current verifier path uses TLS/request-local state for program info; DD-003 extends that style of state management rather than introducing a new public API contract. (Evidence: CE-004, CE-005, CE-006)

## 6. Application Notes

1. [KNOWN] No existing design document was provided, so these deltas are synthesized additions rather than edits against a prior design artifact.
2. [KNOWN] The primary code conflict is the null BTF callback wiring in `g_ebpf_platform_windows`; that gap drives DD-003 through DD-005.
3. [KNOWN] Several requirements depend on `read_elf(...)` / PREVAIL behavior outside the user-provided code scope, so expected code change locations include `[UNKNOWN]` placeholders where out-of-scope internals may also need modification.

## Coverage
- **Examined**: `docs\specs\btfid\04-verifier-integration.md`; `libs\api\Verifier.cpp`; `libs\api\windows_platform.cpp`; `libs\api\ebpf_api.cpp`; `libs\api_common\api_common.cpp`; `libs\api_common\windows_platform_common.cpp`; `libs\api_common\windows_helpers.cpp`
- **Method**: targeted `view` on verifier entry points, platform table, TLS cache helpers, helper resolution, and verifier API tests; targeted `rg` for `call_btf`, `resolve_kfunc_call`, `resolve_ksym_btf_id`, `ksyms`, `decl_tag`, and verifier API symbols
- **Excluded**: external verifier-library implementation details outside `libs\api` / `libs\api_common`; runtime/native-code generation paths outside this area
- **Limitations**: some BTF parsing and unmarshal behavior may live outside the provided code scope, so not every preprocessing detail can be confirmed directly from the examined files

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\api\windows_platform.cpp:100-113` | `g_ebpf_platform_windows` wires helper/program-type callbacks but passes `nullptr` for `resolve_ksym_btf_id` and `resolve_kfunc_call`. | Direct evidence of the current BTF callback gap. |
| CE-002 | `libs\api\Verifier.cpp:802-988` | File/memory verification entry points route ELF input through `read_elf(...)`, `unmarshal(...)`, and `ebpf_verify_program(...)`. | Establishes the existing verifier integration surface. |
| CE-003 | `libs\api\Verifier.cpp:57-106` | `_instype(...)` classifies `prevail::CallBtf` as `call_btf`. | Shows the current verifier path can recognize `call_btf` after parsing. |
| CE-004 | `libs\api_common\api_common.cpp:195-279` | Verification clears TLS state, sets verification program type, and runs PREVAIL analysis over the instruction sequence. | Establishes current verifier-side request/TLS behavior. |
| CE-005 | `libs\api_common\windows_platform_common.cpp:236-286` | `get_program_type_windows(...)` populates TLS caches from execution-context or store-backed program info. | Shows existing request-local caching patterns reusable for BTF support. |
| CE-006 | `libs\api_common\windows_platform_common.cpp:792-847` | `get_program_type_info(...)`, `get_program_type_info_from_tls(...)`, `set_verification_program_type(...)`, and `clear_program_info_cache()` expose TLS-backed verifier program info. | Shows current verifier-side TLS program-info support. |
| CE-007 | `libs\api\ebpf_api.cpp:4847-4873` | `ebpf_get_program_type_by_name(...)` and `ebpf_get_program_info_from_verifier(...)` expose the current public verifier-related API surface. | Shows the current public surface is not BTF-ID oriented. |
| CE-008 | `libs\api_common\windows_helpers.cpp:27-75` | Helper usability/prototype resolution uses cached program info, not BTF callback resolution. | Shows the current verifier integration covers helper IDs but not BTF-resolved functions. |

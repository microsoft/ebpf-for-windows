<!-- Delta artifact: NMR Provider Registration alignment set -->

# NMR Provider Registration — Design Delta

## 1. Change Context

- **Area**: NMR Provider Registration
- **Requirements source**: `docs\specs\btfid\06-nmr-provider-registration.md`
- **Existing design doc**: N/A — no existing design document was provided for this run
- **Code scope**: `include`; `libs\execution_context`; `libs\store_helper`; `tools\bpf2c`
- **Test scope**: `libs\execution_context\unit`; selected BTF registry/verifier/native-codegen tests under `tests\`
- **Goal**: identify the minimal design deltas needed to align the NMR-provider-registration requirements with the current repository state after the registry-publication and native-codegen groundwork landed

[KNOWN] The current repository now carries BTF-resolved-function identity and metadata through earlier phases: store-helper
publication uses `ebpf_btf_resolved_function_provider_info_t` keyed by `module_guid`, `bpf2c` emits
`btf_resolved_function_entry_t` records containing `module_guid`, and generated/native test harnesses allocate
`runtime_context->btf_resolved_function_data`. [KNOWN] The remaining gap for this area is still the dedicated NMR
provider contract: there is no public BTF NPI IID, no `ebpf_btf_resolved_function_provider_data_t`, and no
execution-context BTF provider registration or provider-data validation path. (Evidence: CE-001, CE-002, CE-004,
CE-005, CE-006, CE-007, CE-008)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-NMR-001 | Add | Required | Add a dedicated BTF-resolved-function NPI identifier and register BTF providers against it rather than against the existing program-info NPI. | CE-001, CE-002, CE-008 |
| DD-002 | REQ-NMR-002 | Modify | Required | Add a BTF provider registration path that reuses the already-published module-GUID lineage as NMR `ModuleId`. | CE-002, CE-004, CE-005, CE-006, CE-007 |
| DD-003 | REQ-NMR-003 | Add | Required | Define a distinct NMR payload type, `ebpf_btf_resolved_function_provider_data_t`, and publish it through `NpiSpecificCharacteristics`. | CE-003, CE-004, CE-005, CE-008 |
| DD-004 | REQ-NMR-004 | Add | Required | Add validation and consumption rules for BTF-resolved function count, prototype array, and address array. | CE-004, CE-006, CE-008 |
| DD-005 | REQ-NMR-005 | No-Impact/Constrain | Partially satisfied | Keep the provider dispatch table omitted (`provider_dispatch = NULL`) for the BTF-resolved provider path. | CE-002 |
| DD-006 | REQ-NMR-006 | Modify | Required | Thread the same module GUID and function-ordering contract already used by store publication and native metadata into the new NMR provider path. | CE-004, CE-005, CE-006, CE-007 |
| DD-007 | REQ-NMR-007 | No-Impact/Constrain | Required | Extend the existing execution-context NMR provider pattern instead of creating an unrelated provider shape. | CE-002, CE-004 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-NMR-001
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-002, CE-008
- **Expected code change locations**: `include\ebpf_extension_uuids.h`; `[UNKNOWN: the concrete BTF-resolved provider registration site inside or adjacent to libs\execution_context]`
- **Before**: The public UUID header still contains no BTF-resolved-function NPI, and the only in-scope provider
  registration uses `EBPF_PROGRAM_INFO_EXTENSION_IID`. (Evidence: CE-001, CE-002)
- **After**: Add the BTF-resolved-function NPI identifier and register BTF-capable providers against that dedicated NPI.
- **Rationale**: Earlier BTF phases are present, but the runtime binding identity is still missing; a dedicated NPI is the
  smallest design change that closes that gap.

### DD-002

- **Upstream REQ-ID**: REQ-NMR-002
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-004, CE-005, CE-006, CE-007
- **Expected code change locations**: `[UNKNOWN: the concrete BTF-resolved provider registration site inside or adjacent to libs\execution_context]`; any consumer-side match helper reused for BTF provider validation
- **Before**: GUID-based identity already exists in adjacent BTF contracts: registry publication carries `module_guid`,
  generated native metadata carries `module_guid`, and execution-context provider matching already compares GUID-typed
  `ModuleId` values. However, there is no BTF-specific provider path that reuses that identity at NMR registration time.
  (Evidence: CE-004, CE-005, CE-006, CE-007)
- **After**: Reuse the same provider module GUID as `ModuleId` for BTF provider registration and BTF provider matching.
- **Rationale**: The design gap is continuity, not invention: the repo already established the module GUID as the BTF
  provider identity outside NMR.

### DD-003

- **Upstream REQ-ID**: REQ-NMR-003
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-004, CE-005, CE-008
- **Expected code change locations**: `[ASSUMPTION] include\ebpf_extension.h`; `[UNKNOWN: any execution-context source file that publishes the new provider data]`
- **Before**: The current public BTF publication type is `ebpf_btf_resolved_function_provider_info_t`, which is a
  registry-publication contract, not an NMR contract. Existing execution-context provider-data consumption still expects
  `ebpf_program_data_t`, and no BTF-specific NMR payload type exists in scope. (Evidence: CE-003, CE-004, CE-005, CE-008)
- **After**: Define `ebpf_btf_resolved_function_provider_data_t` and publish it through `NpiSpecificCharacteristics`.
- **Rationale**: The store-helper publication contract and the NMR binding contract have different responsibilities, so
  the design needs a distinct typed NMR payload rather than reusing the store-helper type implicitly.

### DD-004

- **Upstream REQ-ID**: REQ-NMR-004
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-004, CE-006, CE-008
- **Expected code change locations**: `libs\execution_context\ebpf_program.c` or a sibling validation path; `[UNKNOWN: any consumer that will attach to the future BTF-resolved NPI]`
- **Before**: The current execution-context validator verifies `ebpf_program_data_t` and helper-address counts only. At
  the same time, native metadata already expects separate `btf_resolved_function_data` address slots, so there is no
  current validator that can bridge published BTF prototypes to runtime addresses through NMR. (Evidence: CE-004, CE-006)
- **After**: Add a BTF-resolved provider-data validation path that checks the function count, prototype array, and
  address array, and preserves their required correspondence.
- **Rationale**: The existing validator and runtime address slot design are adjacent but disconnected; this delta connects
  them at the NMR contract boundary.

### DD-005

- **Upstream REQ-ID**: REQ-NMR-005
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002
- **Expected code change locations**: None required as a new architectural pattern
- **Before**: Existing data-driven provider attach callbacks already set `provider_dispatch = NULL` for program-info
  providers. (Evidence: CE-002)
- **After**: Keep that no-dispatch pattern for the BTF-resolved provider path.
- **Rationale**: The source requirement matches the current data-provider pattern, so no architectural divergence is
  needed here.

### DD-006

- **Upstream REQ-ID**: REQ-NMR-006
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-004, CE-005, CE-006, CE-007
- **Expected code change locations**: `[UNKNOWN: the concrete BTF-resolved provider registration site]`; any reused module-id match helper; possibly `tools\bpf2c` only if the NMR payload requires stronger ordering guarantees
- **Before**: Current BTF phases already preserve identity outside NMR: store publication keys metadata by `module_guid`,
  generated native metadata carries per-function `module_guid`, and `bpf2c` emits deterministic per-program BTF import
  arrays and counts. NMR is the missing phase in that lineage. (Evidence: CE-005, CE-006, CE-007)
- **After**: Thread the same module GUID and compatible function-ordering expectations into the BTF provider contract so
  NMR identity aligns with header metadata, registry publication, verifier lookup, and generated native metadata.
- **Rationale**: This requirement is now about preserving an already-established lineage across the one missing stage,
  rather than defining cross-phase identity from scratch.

### DD-007

- **Upstream REQ-ID**: REQ-NMR-007
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002, CE-004
- **Expected code change locations**: Any new BTF-resolved provider registration path in or adjacent to `libs\execution_context`
- **Before**: Current execution-context NMR provider patterns already use GUID-typed module IDs, typed
  `NpiSpecificCharacteristics`, and `provider_dispatch = NULL`, and the consumer side already has GUID-based module-id
  matching helpers. (Evidence: CE-002, CE-004)
- **After**: Extend that pattern for BTF-resolved registration instead of introducing an unrelated provider architecture.
- **Rationale**: The gap is missing feature-specific wiring, not missing NMR infrastructure.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-NMR-001 | PARTIAL | DD-001 | `include\ebpf_extension_uuids.h`; `[UNKNOWN: BTF provider registration site]` | Adjacent BTF metadata exists, but no BTF NPI/provider registration path exists. |
| REQ-NMR-002 | PARTIAL | DD-002 | `[UNKNOWN: BTF provider registration site]`; consumer-side match helper | Module-GUID lineage exists in store-helper and native metadata, but not yet in NMR `ModuleId`. |
| REQ-NMR-003 | MISSING | DD-003 | `[ASSUMPTION] include\ebpf_extension.h`; `[UNKNOWN: BTF provider publisher]` | No BTF-resolved NMR provider-data type exists in scope. |
| REQ-NMR-004 | MISSING | DD-004 | `libs\execution_context\ebpf_program.c` or sibling validator; `[UNKNOWN: BTF consumer attach path]` | Current validation is specialized for `ebpf_program_data_t`, while runtime BTF address slots already exist separately. |
| REQ-NMR-005 | PARTIAL | DD-005 | None | Existing data-provider attach callbacks already omit provider dispatch tables. |
| REQ-NMR-006 | PARTIAL | DD-006 | `[UNKNOWN: BTF provider registration site]`; possibly `tools\bpf2c` for ordering guarantees | Cross-phase identity already exists across header/registry/native metadata, but not through NMR. |
| REQ-NMR-007 | SATISFIED | No-Impact/Constrain | None | Existing execution-context NMR provider pattern is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] The current NMR data-provider pattern uses `NpiSpecificCharacteristics` as the primary data channel and does
  not expose a provider dispatch table. The deltas preserve that architecture. (Evidence: CE-002)
- [KNOWN] The current repository already treats the module GUID as the BTF provider identity outside NMR, via store
  publication and generated native metadata. The deltas preserve that lineage rather than redefining identity.
  (Evidence: CE-005, CE-006, CE-007)
- [KNOWN] The current native runtime context already contains `btf_resolved_function_data`; the deltas imply NMR should
  populate that existing address channel rather than inventing a second BTF runtime-address surface. (Evidence: CE-006)

## 6. Application Notes

1. [KNOWN] No existing design document was provided, so these deltas are synthesized additions rather than edits against a
   prior design artifact.
2. [KNOWN] The central gap has narrowed: the repo now has BTF publication and native metadata groundwork, but it still
   lacks the dedicated NMR provider contract that ties those phases together.
3. [KNOWN] The presence of `ebpf_btf_resolved_function_provider_info_t` in `store_helper` does not eliminate the need for
   a distinct NMR payload type; the existing type is publication-specific, not binding-specific.
4. [KNOWN] Some concrete change locations remain `[UNKNOWN]` because the in-scope code still contains no BTF-resolved
   provider implementation to anchor them.

## Coverage
- **Examined**: `docs\specs\btfid\06-nmr-provider-registration.md`; `include\ebpf_extension_uuids.h`; `include\ebpf_extension.h`; `include\ebpf_store_helper.h`; `include\bpf2c.h`; `libs\execution_context\ebpf_core.c`; `libs\execution_context\ebpf_program.c`; `tools\bpf2c\bpf_code_generator.cpp`
- **Method**: targeted `view` on current NMR provider registration, provider-data validation, BTF public contracts, and native metadata generation; targeted `rg` for BTF-resolved provider symbols and NMR provider registration symbols
- **Excluded**: detailed client attach logic for future BTF consumers; runtime execution behavior after attachment
- **Limitations**: no BTF-resolved provider implementation exists in the examined execution-context scope, so some future touch points remain `[UNKNOWN]`

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `include\ebpf_extension_uuids.h:11-27` | The public UUID header defines program-info, hook, and map extension IIDs only. | Establishes the absence of a BTF-resolved-function NPI identifier. |
| CE-002 | `libs\execution_context\ebpf_core.c:195-208`, `libs\execution_context\ebpf_core.c:213-242`, `libs\execution_context\ebpf_core.c:323-349` | Execution-context registers a provider for `EBPF_PROGRAM_INFO_EXTENSION_IID` with GUID-typed `ModuleId`, typed `NpiSpecificCharacteristics`, and `provider_dispatch = NULL`. | Establishes the current provider-registration baseline and the no-dispatch pattern. |
| CE-003 | `include\ebpf_extension.h:494-501` | Existing extension provider-data types live in `include\ebpf_extension.h`, but no BTF-resolved NMR provider payload is declared there. | Establishes the likely public contract extension point and the missing type. |
| CE-004 | `libs\execution_context\ebpf_program.c:217-310` | Consumer-side code requires GUID-typed `ModuleId` and validates `ebpf_program_data_t` from `NpiSpecificCharacteristics`. | Establishes the current module-id and provider-data validation baseline. |
| CE-005 | `include\ebpf_store_helper.h:23-39`, `include\ebpf_store_helper.h:103-111` | The current public BTF registry-publication contract uses `ebpf_btf_resolved_function_provider_info_t` with a `module_guid`, function count, and prototype array. | Establishes that BTF provider identity and prototype metadata already exist outside NMR. |
| CE-006 | `include\bpf2c.h:98-110`, `include\bpf2c.h:163-170`, `include\bpf2c.h:176-200` | Native metadata already includes `btf_resolved_function_entry_t::module_guid`, `program_runtime_context_t::btf_resolved_function_data`, and `program_entry_t::btf_resolved_function_count`. | Establishes that the native side already carries BTF dependency identity, counts, and address slots. |
| CE-007 | `tools\bpf2c\bpf_code_generator.cpp:2557-2625` | `bpf2c` emits per-program BTF dependency arrays and counts from module-guid keyed dependency state. | Establishes deterministic native metadata emission that the future NMR contract must line up with. |
| CE-008 | Searches over `include\` and `libs\execution_context` for `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID`, `ebpf_btf_resolved_function_provider_data_t`, and BTF-specific `NmrRegisterProvider` usage returned no implementation matches. | No dedicated BTF-resolved NMR provider identifier, payload type, or registration path exists in the examined implementation. | Establishes the remaining feature gap. |

<!-- Delta artifact: Registry Publication alignment set -->

# Registry Publication — Design Delta

## 1. Change Context

- **Area**: Registry Publication
- **Requirements source**: `docs\specs\btfid\03-registry-publication.md`
- **Existing design doc**: N/A — no existing design document was provided for this run
- **Code scope**: `libs\store_helper`
- **Test scope**: `tests`
- **Goal**: identify the minimal design deltas needed to align the registry-publication requirements with the examined `store_helper` implementation and the current test baseline

[KNOWN] The examined `store_helper` implementation already contains reusable publication patterns for global helpers, sections, and program information, including provider-root creation, extension-header persistence, keyed child-record creation, and HKCU/HKLM dual-root wrappers. [INFERRED] The missing design work is to add a BTF-resolved-function publication flow that reuses only the compatible parts of those patterns while explicitly diverging from helper binary-serialization where the requirements require per-field registry values. (Evidence: CE-001, CE-002, CE-003, CE-004, CE-005, CE-006)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-REG-001 | Add | Required | Add a BTF-resolved-function provider subtree rooted under `Providers\BtfResolvedFunctions\{module_guid}`. | CE-001, CE-004, CE-005, CE-006 |
| DD-002 | REQ-REG-002 | Add | Required | Add provider-node `Version` and `Size` persistence for BTF provider metadata. | CE-002 |
| DD-003 | REQ-REG-003 | Add | Required | Add a `Functions` child collection and function-name keyed records beneath each provider GUID node. | CE-003, CE-005, CE-006 |
| DD-004 | REQ-REG-004 | Add/Modify | Required | Define a BTF-specific per-function value schema instead of reusing helper binary prototype serialization. | CE-003 |
| DD-005 | REQ-REG-005 | Add | Required | Add a BTF-resolved-function store update entry point plus internal writer flow in `store_helper`. | CE-004, CE-005, CE-006 |
| DD-006 | REQ-REG-006 | Add | Required | Make publication complete and durable before a caller can depend on it for verification-time lookup. | CE-001, CE-002, CE-004, CE-005, CE-006 |
| DD-007 | REQ-REG-007 | Add | Required | Reuse the existing HKCU-first / HKLM-second wrapper convention for the BTF publication path. | CE-004, CE-005, CE-006, CE-007 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-REG-001
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-004, CE-005, CE-006
- **Expected code change locations**: `libs\store_helper\ebpf_store_helper.c`
- **Before**: The examined implementation creates the common eBPF store root and `Providers` path, then branches into `GlobalHelpers`, `Sections`, and `ProgramData`. No examined flow creates a `BtfResolvedFunctions` subtree keyed by provider GUID. (Evidence: CE-001, CE-004, CE-005, CE-006)
- **After**: Add a BTF-specific publication branch that creates `Providers\BtfResolvedFunctions\{module_guid}` beneath the existing provider root helper, with the provider GUID used as the stable grouping key for all BTF-resolved-function metadata.
- **Rationale**: The existing root-path helper is reusable, but the requirement-specific subtree is absent; adding the missing branch is the minimal design change that satisfies REQ-REG-001 without disturbing existing helper, section, or program-data layouts.

### DD-002

- **Upstream REQ-ID**: REQ-REG-002
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-002
- **Expected code change locations**: `libs\store_helper\ebpf_store_helper.c`
- **Before**: `_ebpf_store_update_extension_header_information` already writes `version` and `size` for existing registry-published records, but no examined BTF provider-node writer invokes that pattern. (Evidence: CE-002)
- **After**: Define the BTF provider-node write path so it persists `Version` and `Size` on the `{module_guid}` node before writing child function records.
- **Rationale**: This keeps BTF publication aligned with the existing extension-header convention while satisfying the explicit provider-node metadata requirement.

### DD-003

- **Upstream REQ-ID**: REQ-REG-003
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003, CE-005, CE-006
- **Expected code change locations**: `libs\store_helper\ebpf_store_helper.c`
- **Before**: Existing store-helper writers already create keyed child collections for other metadata domains (`GlobalHelpers` by helper name, `Sections` by section name, `ProgramData` by program-type GUID), but none of the examined flows create a BTF `Functions` child collection keyed by function name under a provider GUID. (Evidence: CE-003, CE-005, CE-006)
- **After**: Add a `Functions` subkey beneath each BTF provider GUID node and create one child key per BTF-resolved function using the function name as the stable record key.
- **Rationale**: The keyed-child pattern already exists and can be reused, but a dedicated BTF function collection is required to meet the verifier lookup contract.

### DD-004

- **Upstream REQ-ID**: REQ-REG-004
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-003
- **Expected code change locations**: `libs\store_helper\ebpf_store_helper.c`
- **Before**: The closest existing pattern, `_ebpf_store_update_helper_prototype`, writes extension-header metadata and then serializes helper prototype fields into a binary blob plus a separate flag value. That shape does not match the BTF requirement for discrete `Prototype`, `ReturnType`, `Arguments`, and `Flags` values. (Evidence: CE-003)
- **After**: Define a BTF-specific function-record writer that stores the four required BTF metadata elements as explicit registry values instead of reusing the helper binary-serialization format.
- **Rationale**: Reusing the helper serialization shape would preserve implementation familiarity but would conflict with the published BTF requirements and make later verifier lookup less direct.

### DD-005

- **Upstream REQ-ID**: REQ-REG-005
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-004, CE-005, CE-006
- **Expected code change locations**: `libs\store_helper\ebpf_store_helper.c`; `[UNKNOWN: any public declaration location was outside the user-provided code scope for this run]`
- **Before**: The examined implementation exposes update flows only for global helpers, sections, and program information. No BTF-resolved-function store update flow exists in the provided code scope. (Evidence: CE-004, CE-005, CE-006)
- **After**: Add an internal/public store-helper flow for BTF-resolved-function provider publication that accepts provider-level metadata, validates it, creates the provider subtree, and writes provider and function records.
- **Rationale**: The requirement calls for a store API shape; the minimal aligned design is a new BTF-specific sibling to the existing `ebpf_store_update_*` flows rather than overloading unrelated helpers.

### DD-006

- **Upstream REQ-ID**: REQ-REG-006
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-001, CE-002, CE-004, CE-005, CE-006
- **Expected code change locations**: `libs\store_helper\ebpf_store_helper.c`
- **Before**: The examined publication flows synchronously create keys and write values before returning success, but there is no BTF-specific publication flow that guarantees complete provider metadata is written before callers attempt verification-time lookup. (Evidence: CE-001, CE-002, CE-004, CE-005, CE-006)
- **After**: Define the BTF publication flow so that it writes the full provider node plus all required function records before returning success to the caller, with explicit failure propagation on incomplete writes.
- **Rationale**: This preserves the current synchronous store-helper model and aligns it with the requirement that metadata be available before verification depends on it.

### DD-007

- **Upstream REQ-ID**: REQ-REG-007
- **Existing design location**: N/A — no existing design doc
- **Related code evidence IDs**: CE-004, CE-005, CE-006, CE-007
- **Expected code change locations**: `libs\store_helper\ebpf_store_helper.c`
- **Before**: Existing update/delete flows consistently write or delete HKCU first, then HKLM, and suppress `EBPF_ACCESS_DENIED` only for the HKLM pass. No BTF publication flow currently reuses that wrapper. (Evidence: CE-004, CE-005, CE-006, CE-007)
- **After**: Wrap the BTF-specific internal write flow in the same dual-root wrapper pattern and mirror that pattern in any matching delete flow if one is added later.
- **Rationale**: This preserves a demonstrated store-helper invariant instead of introducing a one-off root-selection policy for BTF metadata.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-REG-001 | PARTIAL | DD-001 | `libs\store_helper\ebpf_store_helper.c` | Provider root exists; BTF subtree does not. |
| REQ-REG-002 | PARTIAL | DD-002 | `libs\store_helper\ebpf_store_helper.c` | Version/size writer exists; BTF provider-node use does not. |
| REQ-REG-003 | MISSING | DD-003 | `libs\store_helper\ebpf_store_helper.c` | No examined BTF `Functions` collection exists. |
| REQ-REG-004 | CONFLICT | DD-004 | `libs\store_helper\ebpf_store_helper.c` | Closest existing schema uses binary serialization, not the required discrete values. |
| REQ-REG-005 | MISSING | DD-005 | `libs\store_helper\ebpf_store_helper.c`; `[UNKNOWN: declaration site outside scope]` | Existing update APIs cover other metadata only. |
| REQ-REG-006 | PARTIAL | DD-006 | `libs\store_helper\ebpf_store_helper.c` | Existing writers are synchronous, but no BTF publication flow exists. |
| REQ-REG-007 | PARTIAL | DD-007 | `libs\store_helper\ebpf_store_helper.c` | Convention exists globally; BTF flow is absent. |

## 5. Invariant Impact

- [KNOWN] Existing `store_helper` flows centralize provider-root creation through `_ebpf_store_open_or_create_provider_registry_key`; the deltas preserve that invariant. (Evidence: CE-001, CE-004, CE-005, CE-006, CE-007)
- [KNOWN] Existing update and delete wrappers use a shared HKCU/HKLM convention with HKLM `EBPF_ACCESS_DENIED` suppression; the deltas preserve that invariant for BTF publication rather than changing it. (Evidence: CE-004, CE-005, CE-006, CE-007)
- [KNOWN] Existing helper publication uses binary prototype serialization; DD-004 intentionally changes that behavior for BTF metadata because the upstream requirement conflicts with that convention. (Evidence: CE-003)

## 6. Application Notes

1. [KNOWN] No existing design document was provided, so all deltas are synthesized additions rather than before/after edits against a prior design artifact.
2. [KNOWN] The largest design decision is whether BTF publication reuses the helper binary-serialization pattern or diverges to discrete per-field registry values; the upstream requirements and current registry-publication spec require divergence. (Evidence: CE-003)
3. [KNOWN] The code scope for this run was limited to `libs\store_helper`; any public declaration work outside that scope remains `[UNKNOWN]` in this artifact.

## Coverage
- **Examined**: `libs\store_helper\ebpf_store_helper.c`; `docs\specs\btfid\03-registry-publication.md`
- **Method**: `view` on targeted line ranges; `rg "ebpf_store_update_global_helper_information|ebpf_store_update_section_information|ebpf_store_update_program_information_array|ebpf_store_delete_program_information|ebpf_store_delete_section_information" Q:\ebpf-for-windows\tests`; `rg "BtfResolvedFunctions|btf_resolved_function|btf_resolved" Q:\ebpf-for-windows\tests`
- **Excluded**: code outside `libs\store_helper`, including public header and verifier implementation, because the user-scoped this run to `libs\store_helper`; tests were analyzed only as validation evidence, not as implementation evidence
- **Limitations**: the examined code scope contains no BTF-specific store implementation, so several deltas are derived from adjacent store-helper patterns rather than direct BTF code

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `libs\store_helper\ebpf_store_helper.c:25-46` | `_ebpf_store_open_or_create_provider_registry_key` creates the store root and `Providers` key. | Establishes reusable root-path behavior for REQ-REG-001 and REQ-REG-006. |
| CE-002 | `libs\store_helper\ebpf_store_helper.c:13-21` | `_ebpf_store_update_extension_header_information` writes `version` and `size`. | Establishes existing provider/header metadata persistence for REQ-REG-002. |
| CE-003 | `libs\store_helper\ebpf_store_helper.c:50-100` | `_ebpf_store_update_helper_prototype` creates a name-keyed child record and serializes helper prototype data into a binary value plus an optional flag value. | Establishes the closest existing schema pattern and the mismatch for REQ-REG-003/004. |
| CE-004 | `libs\store_helper\ebpf_store_helper.c:109-173` | Global-helper update flow validates input, opens `GlobalHelpers`, writes named records, and wraps HKCU/HKLM publication. | Establishes current publication and root-wrapper conventions for REQ-REG-001/005/006/007. |
| CE-005 | `libs\store_helper\ebpf_store_helper.c:177-288` | Section update flow creates `Sections`, writes named child records, and uses the same dual-root wrapper. | Shows existing keyed-child and root-wrapper patterns adjacent to the missing BTF flow. |
| CE-006 | `libs\store_helper\ebpf_store_helper.c:402-499` | Program-info update flow creates `ProgramData`, keys records by GUID, and uses the same dual-root wrapper. | Shows existing GUID-keyed publication and sibling API pattern relevant to REQ-REG-001/005/006/007. |
| CE-007 | `libs\store_helper\ebpf_store_helper.c:502-611` | Delete flows mirror the HKCU/HKLM dual-root convention used by update flows. | Shows the broader store-helper invariant preserved by DD-007. |

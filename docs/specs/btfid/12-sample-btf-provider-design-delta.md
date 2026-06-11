<!-- Derived artifact: Stable sample BTF provider alignment set -->

# Sample BTF Provider — Design Delta

## 1. Change Context

- **Area**: Sample BTF Provider
- **Requirements source**: `docs\specs\btfid\12-sample-btf-provider.md`
- **Existing design doc**: N/A — no existing design document was provided for this derived area
- **Code scope**: `undocked\tests\sample\ext`; `tests\sample`
- **Test scope**: `tests\sample`; `tests\end_to_end`; selected native-load/BTF harnesses under `tests\`
- **Goal**: identify the minimal design deltas needed to turn the current placeholder sample fixture into a stable in-tree BTF provider target backed by `sample_ebpf_ext`

[KNOWN] The current repository already has most of the surrounding sample-extension structure: shared sample headers exist, `sample_ebpf_ext` already registers map/program-info/hook providers through a common driver lifecycle, and sample programs already consume the shared include tree. [KNOWN] But the current `btf_resolved` fixture still hardcodes a placeholder `.ksyms` contract, the sample driver publishes no BTF-resolved-function provider, and the sample build still special-cases that fixture through checked-in generated code. (Evidence: CE-001, CE-002, CE-003, CE-004, CE-005, CE-006, CE-007)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Code Evidence |
| --- | --- | --- | --- | --- | --- |
| DD-001 | REQ-SAMP-001 | Add | Required | Add a canonical sample BTF declaration surface with a sample-owned module GUID and prototype. | CE-001, CE-005 |
| DD-002 | REQ-SAMP-002 | Add | Required | Add a `sample_ebpf_ext`-owned implementation for at least one deterministic BTF-resolved function. | CE-002, CE-003 |
| DD-003 | REQ-SAMP-003 | Add | Required | Add sample-provider registry publication that mirrors the canonical declaration. | CE-005, CE-007 |
| DD-004 | REQ-SAMP-004 | Add | Required | Add BTF NMR provider registration in `sample_ebpf_ext` using the sample module GUID and provider data. | CE-002, CE-003, CE-004 |
| DD-005 | REQ-SAMP-005 | Add | Required | Wire BTF provider registration and unregistration into the existing sample-driver startup/shutdown flow. | CE-004 |
| DD-006 | REQ-SAMP-006 | Change | Required | Retarget at least one sample program/fixture from the placeholder `.ksyms` contract to the canonical sample declaration. | CE-005, CE-006 |
| DD-007 | REQ-SAMP-007 | Add | Required | Keep the first sample provider contract deterministic and test-oriented. | CE-003, CE-005 |
| DD-008 | REQ-SAMP-008 | No-Impact/Constrain | Required | Extend the existing sample-extension include and provider-registration patterns instead of inventing a test-only contract. | CE-001, CE-002, CE-003, CE-004 |

## 3. Detailed Changes

### DD-001

- **Upstream REQ-ID**: REQ-SAMP-001
- **Existing design location**: `undocked\tests\sample\ext\inc\sample_ext_helpers.h`
- **Related code evidence IDs**: CE-001, CE-005
- **Expected code change locations**: `undocked\tests\sample\ext\inc\sample_ext_helpers.h`; `[ASSUMPTION] sibling header under undocked\tests\sample\ext\inc`
- **Before**: The sample include surface exposes helper contracts, but no canonical BTF-resolved-function declaration exists there; the only current BTF sample declaration is a placeholder `.ksyms` entry in `tests\sample\unsafe\btf_resolved.c`. (Evidence: CE-001, CE-005)
- **After**: Add a canonical sample BTF declaration surface with a sample-owned module GUID and function prototype that sample BPF sources can include directly.
- **Rationale**: A stable in-tree provider target must start with a stable compile-time declaration surface.

### DD-002

- **Upstream REQ-ID**: REQ-SAMP-002
- **Existing design location**: `undocked\tests\sample\ext\drv\sample_ext.c`
- **Related code evidence IDs**: CE-002, CE-003
- **Expected code change locations**: `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h`
- **Before**: `sample_ebpf_ext` already implements deterministic sample helper/map logic, but it does not implement or declare any BTF-resolved-function provider surface. (Evidence: CE-002, CE-003)
- **After**: Add at least one `sample_ebpf_ext`-owned BTF-resolved function with simple, testable semantics.
- **Rationale**: The repository needs a real in-tree provider implementation, not just metadata.

### DD-003

- **Upstream REQ-ID**: REQ-SAMP-003
- **Existing design location**: N/A — no existing sample BTF publication design
- **Related code evidence IDs**: CE-005, CE-007
- **Expected code change locations**: `[UNKNOWN: sample publication helper or driver-owned publication code]`; any sample-side registry publication helper/header
- **Before**: The placeholder `btf_resolved` fixture has no sample-driver-owned registry publication path, and current sample-tree searches show no BTF-resolved publication surface in `sample_ebpf_ext`. (Evidence: CE-005, CE-007)
- **After**: Add registry publication for the sample BTF provider under the same GUID/function/prototype contract used by the canonical declaration.
- **Rationale**: The sample target is only useful if verifier/bpf2c can resolve the same provider metadata the runtime will use.

### DD-004

- **Upstream REQ-ID**: REQ-SAMP-004
- **Existing design location**: `undocked\tests\sample\ext\drv\sample_ext.c`
- **Related code evidence IDs**: CE-002, CE-003, CE-004
- **Expected code change locations**: `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h`
- **Before**: The sample driver already contains NMR provider-registration patterns for map, program-info, and hook providers, but no BTF-resolved-function provider characteristics or registration function exists. (Evidence: CE-002, CE-003, CE-004)
- **After**: Add a BTF-resolved-function provider registration path that reuses the sample driver's existing NMR style with the sample module GUID and typed provider data.
- **Rationale**: The design should extend a proven in-tree provider-registration pattern instead of inventing a new one for tests.

### DD-005

- **Upstream REQ-ID**: REQ-SAMP-005
- **Existing design location**: `undocked\tests\sample\ext\drv\sample_ext_drv.c`
- **Related code evidence IDs**: CE-004
- **Expected code change locations**: `undocked\tests\sample\ext\drv\sample_ext_drv.c`
- **Before**: Driver startup/unload only registers and unregisters map, program-info, and hook providers. (Evidence: CE-004)
- **After**: Add BTF-provider registration at startup and BTF-provider unregistration during unload, adjacent to the existing sample-provider lifecycle.
- **Rationale**: The stable sample provider should follow the same lifecycle as the rest of the driver.

### DD-006

- **Upstream REQ-ID**: REQ-SAMP-006
- **Existing design location**: `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj`
- **Related code evidence IDs**: CE-005, CE-006
- **Expected code change locations**: `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj`; `[ASSUMPTION] generated expected fixtures if still needed`
- **Before**: The only current BTF-resolved sample source hardcodes a placeholder module GUID and is built through a special fixture path. (Evidence: CE-005, CE-006)
- **After**: Retarget at least one sample source or fixture to the canonical sample-provider declaration and associated sample driver contract.
- **Rationale**: The repository should validate the real in-tree provider, not a disconnected placeholder.

### DD-007

- **Upstream REQ-ID**: REQ-SAMP-007
- **Existing design location**: `undocked\tests\sample\ext\drv\sample_ext.c`
- **Related code evidence IDs**: CE-003, CE-005
- **Expected code change locations**: `undocked\tests\sample\ext\drv\sample_ext.c`; canonical sample BTF declaration header
- **Before**: The placeholder fixture implies a simple lookup-style contract, and the sample driver's existing helper set is similarly test-oriented. (Evidence: CE-003, CE-005)
- **After**: Keep the first sample BTF contract simple and directly assertable.
- **Rationale**: Simplicity makes failures easier to attribute across verifier, build, load, and runtime layers.

### DD-008

- **Upstream REQ-ID**: REQ-SAMP-008
- **Existing design location**: `undocked\tests\sample\ext\inc\sample_ext_helpers.h`; `undocked\tests\sample\ext\drv\sample_ext.c`
- **Related code evidence IDs**: CE-001, CE-002, CE-003, CE-004
- **Expected code change locations**: existing sample include and driver files
- **Before**: The sample extension already has a recognizable pattern for exposing shared contracts and registering providers. (Evidence: CE-001, CE-002, CE-003, CE-004)
- **After**: Extend that pattern for BTF-resolved functions rather than adding a disconnected test-only provider.
- **Rationale**: Reusing the existing sample-extension structure minimizes conceptual drift.

## 4. Traceability Matrix

| REQ-ID | Code Status | Design Delta IDs | Expected Code Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-SAMP-001 | MISSING | DD-001 | `undocked\tests\sample\ext\inc\sample_ext_helpers.h`; `[ASSUMPTION] sibling header` | No canonical sample BTF declaration exists. |
| REQ-SAMP-002 | MISSING | DD-002 | `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h` | No BTF provider implementation exists in `sample_ebpf_ext`. |
| REQ-SAMP-003 | MISSING | DD-003 | `[UNKNOWN: sample publication helper or driver-owned publication code]` | No sample-owned registry publication path is visible in scope. |
| REQ-SAMP-004 | MISSING | DD-004 | `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h` | Existing provider-registration pattern exists, but no BTF provider uses it. |
| REQ-SAMP-005 | MISSING | DD-005 | `undocked\tests\sample\ext\drv\sample_ext_drv.c` | Driver lifecycle currently omits BTF registration. |
| REQ-SAMP-006 | MISSING | DD-006 | `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj` | Current fixture still uses placeholder metadata. |
| REQ-SAMP-007 | PARTIAL | DD-007 | `undocked\tests\sample\ext\drv\sample_ext.c` | The current placeholder contract is simple, but no real sample BTF provider exists yet. |
| REQ-SAMP-008 | SATISFIED | DD-008 | None | The existing sample-extension structure is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] The current sample-extension model uses shared headers plus driver-owned provider registration; these deltas preserve that model. (Evidence: CE-001, CE-002, CE-003, CE-004)
- [KNOWN] The current sample BTF fixture is isolated from that model; these deltas replace the placeholder contract with an in-tree provider contract instead of adding yet another parallel sample path. (Evidence: CE-005, CE-006)
- [KNOWN] The current BTFID requirements already assume registry, NMR, load, and runtime phases use the same provider identity; the sample-provider deltas preserve that invariant. (Evidence: CE-005, CE-007)

## 6. Application Notes

1. [KNOWN] This is a derived design-delta artifact for repository implementation planning, not a direct update to a source-design section in `docs/BtfResolvedFunctions.md`.
2. [KNOWN] The key gap is not absence of a sample extension driver; it is absence of a stable BTF provider surface inside that existing driver.
3. [KNOWN] The only clearly stable in-tree home for such a provider today is `sample_ebpf_ext`, because that driver already owns the sample header and provider-registration model consumed by sample programs.

## Coverage

- **Examined**: `docs\specs\btfid\12-sample-btf-provider.md`; `undocked\tests\sample\ext\inc\sample_ext_helpers.h`; `undocked\tests\sample\ext\inc\sample_ext_program_info.h`; `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h`; `undocked\tests\sample\ext\drv\sample_ext_drv.c`; `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj`
- **Method**: targeted `view` on shared sample headers, provider characteristics/registration functions, driver lifecycle wiring, and the current placeholder sample fixture; targeted `rg` for BTF-resolved provider symbols in the sample tree
- **Excluded**: execution-context implementation details outside the sample-extension/test scope
- **Limitations**: current sample-tree code contains no BTF provider implementation, so some future publication touch points remain `[UNKNOWN]`

## Code Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| CE-001 | `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136` | The sample-extension include tree already exposes shared contracts consumed by sample programs. | Establishes the canonical declaration surface baseline. |
| CE-002 | `undocked\tests\sample\ext\drv\sample_ext.c:212-225`, `undocked\tests\sample\ext\drv\sample_ext.c:301-313`, `undocked\tests\sample\ext\drv\sample_ext.c:386-398` | `sample_ebpf_ext` already has NMR provider-characteristics patterns for map, program-info, and hook providers. | Establishes the provider-registration design baseline. |
| CE-003 | `undocked\tests\sample\ext\drv\sample_ext.c:43-99`, `undocked\tests\sample\ext\drv\sample_ext.c:918-1128` | The sample driver already implements deterministic helper/map behavior that is explicitly test-oriented. | Establishes the style baseline for a simple sample BTF function. |
| CE-004 | `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170` | The sample driver registers and unregisters only map, program-info, and hook providers during startup/shutdown. | Establishes the lifecycle gap for BTF provider wiring. |
| CE-005 | `tests\sample\unsafe\btf_resolved.c:6-17` | The current BTF sample uses a placeholder module GUID and placeholder `.ksyms` symbol. | Establishes the current placeholder-contract gap. |
| CE-006 | `tests\sample\sample.vcxproj:271-276` | The `btf_resolved` sample is built through a checked-in generated fixture path. | Establishes the current temporary sample-build path. |
| CE-007 | Search over `undocked\tests\sample\ext`, `tests\sample`, and `tests\end_to_end` for `btf_resolved`, `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID`, and `ebpf_btf_resolved_function_provider_data_t` returned only the existing sample fixture/build special-case, with no sample-extension BTF provider implementation matches. | No stable in-tree sample BTF provider exists in the examined sample/test scope. | Establishes the remaining feature gap. |

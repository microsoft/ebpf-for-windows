<!-- Derived artifact: Stable sample BTF provider alignment set -->

# Sample BTF Provider — Validation Delta

## 1. Change Context

- **Area**: Sample BTF Provider
- **Requirements source**: `docs\specs\btfid\12-sample-btf-provider.md`
- **Existing validation doc**: N/A — no existing validation plan was provided for this derived area
- **Code scope**: `undocked\tests\sample\ext`; `tests\sample`
- **Test scope**: `tests\sample`; `tests\end_to_end`; selected BTF/native-load harnesses under `tests\`
- **Goal**: identify the minimal validation-spec deltas needed to replace the current placeholder BTF sample fixture with a stable `sample_ebpf_ext`-backed provider target

[KNOWN] Current validation already has a place to host a stable sample target: the sample build contains a dedicated `btf_resolved` fixture path, and the sample driver already has a concrete provider lifecycle that can be exercised by higher-level tests. [KNOWN] But no current validation proves a real sample-provider-backed BTF contract, because the current fixture is placeholder metadata and the sample driver has no BTF provider implementation or lifecycle wiring. (Evidence: TE-001, TE-002, TE-003, TE-004)

## 2. Change Manifest

| Delta ID | Upstream REQ-ID | Type | Status | Summary | Related Test Evidence |
| --- | --- | --- | --- | --- | --- |
| VD-001 | REQ-SAMP-001, REQ-SAMP-006 | Change | Required | Retarget the current sample BTF fixture to consume the canonical sample declaration instead of placeholder metadata. | TE-001, TE-002 |
| VD-002 | REQ-SAMP-002, REQ-SAMP-007 | Add | Required | Add validation that the sample driver-backed BTF function returns deterministic, directly assertable results. | TE-001, TE-004 |
| VD-003 | REQ-SAMP-003 | Add | Required | Add validation for sample-provider registry publication before verification. | TE-003 |
| VD-004 | REQ-SAMP-004 | Add | Required | Add validation that native-load/client attach can bind to the sample provider through the BTF NMR contract. | TE-003, TE-004 |
| VD-005 | REQ-SAMP-005 | Add | Required | Add validation that sample-driver startup/shutdown registers and unregisters the BTF provider with the rest of the sample extension lifecycle. | TE-004 |
| VD-006 | REQ-SAMP-008 | No-Impact | Not required | Extend the existing sample/build/end-to-end validation architecture instead of creating a new test-only harness hierarchy. | TE-002, TE-004 |

## 3. Detailed Changes

### VD-001

- **Upstream REQ-ID**: REQ-SAMP-001, REQ-SAMP-006
- **Existing validation location**: `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj`
- **Related test evidence IDs**: TE-001, TE-002
- **Expected test change locations**: `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj`
- **Before**: The only current BTF sample fixture declares a placeholder module GUID/symbol pair and is built through a special-case sample target. (Evidence: TE-001, TE-002)
- **After**: Retarget that fixture or an equivalent sample source to the canonical sample-driver-owned BTF declaration.
- **Rationale**: The repository should keep using the existing sample validation slot, but with a real provider contract.

### VD-002

- **Upstream REQ-ID**: REQ-SAMP-002, REQ-SAMP-007
- **Existing validation location**: N/A — no current sample-driver-backed BTF validation
- **Related test evidence IDs**: TE-001, TE-004
- **Expected test change locations**: `[UNKNOWN: sample-provider-specific end-to-end test]`; possibly `tests\end_to_end\end_to_end.cpp`
- **Before**: The current placeholder fixture implies a simple lookup-style behavior, but there is no real sample-driver-backed function to validate. (Evidence: TE-001)
- **After**: Add tests that invoke the sample-driver-backed BTF function and assert deterministic results.
- **Rationale**: Deterministic behavior is the core property that makes the sample target useful.

### VD-003

- **Upstream REQ-ID**: REQ-SAMP-003
- **Existing validation location**: N/A — no sample-provider publication validation
- **Related test evidence IDs**: TE-003
- **Expected test change locations**: `[UNKNOWN: registry publication validation]`; possibly existing store/helper-oriented tests if the sample publication path reuses them
- **Before**: No current test validates sample-driver-owned BTF metadata publication. (Evidence: TE-003)
- **After**: Add validation that the sample provider's registry metadata exists and matches the canonical declaration before verification.
- **Rationale**: A stable sample provider must cover verifier-time metadata, not just runtime binding.

### VD-004

- **Upstream REQ-ID**: REQ-SAMP-004
- **Existing validation location**: N/A — no sample-provider BTF NMR validation
- **Related test evidence IDs**: TE-003, TE-004
- **Expected test change locations**: `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: helper fixture for sample-provider attach]`
- **Before**: The current sample driver lifecycle exposes where provider registration belongs, but no validation proves BTF client/provider attachment against the sample provider. (Evidence: TE-003, TE-004)
- **After**: Add native-load or end-to-end tests that bind to the sample provider through the actual BTF provider contract.
- **Rationale**: The sample provider is intended to make the real attach path testable.

### VD-005

- **Upstream REQ-ID**: REQ-SAMP-005
- **Existing validation location**: N/A — no BTF provider lifecycle validation in the sample driver
- **Related test evidence IDs**: TE-004
- **Expected test change locations**: `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: sample-driver lifecycle validation helper]`
- **Before**: Driver lifecycle wiring validates only the conceptual startup/shutdown slots for existing providers. (Evidence: TE-004)
- **After**: Add validation that the sample BTF provider registers on startup and unregisters on unload/reload transitions.
- **Rationale**: Lifecycle behavior is part of what makes the sample target realistic.

### VD-006

- **Upstream REQ-ID**: REQ-SAMP-008
- **Existing validation location**: current sample build and sample-driver lifecycle
- **Related test evidence IDs**: TE-002, TE-004
- **Expected test change locations**: None
- **Before**: Existing sample/build/end-to-end validation architecture already provides the right extension points. (Evidence: TE-002, TE-004)
- **After**: No new validation hierarchy is required; extend current sample and end-to-end assets.
- **Rationale**: The sample provider should fit the repo's current test topology.

## 4. Traceability Matrix

| REQ-ID | Test Status | Validation Delta IDs | Expected Test Change Locations | Notes |
| --- | --- | --- | --- | --- |
| REQ-SAMP-001 | MISSING | VD-001 | `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj` | No canonical sample declaration is consumed today. |
| REQ-SAMP-002 | MISSING | VD-002 | `[UNKNOWN: sample-provider-specific end-to-end test]`; possibly `tests\end_to_end\end_to_end.cpp` | No sample-driver-backed BTF function exists yet. |
| REQ-SAMP-003 | MISSING | VD-003 | `[UNKNOWN: registry publication validation]` | No sample-provider publication test exists. |
| REQ-SAMP-004 | MISSING | VD-004 | `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: helper fixture]` | No sample-provider BTF attach test exists. |
| REQ-SAMP-005 | MISSING | VD-005 | `tests\end_to_end\end_to_end.cpp`; `[UNKNOWN: lifecycle helper]` | No sample-driver BTF lifecycle test exists. |
| REQ-SAMP-006 | MISSING | VD-001 | `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj` | Current sample still uses placeholder metadata. |
| REQ-SAMP-007 | MISSING | VD-002 | `[UNKNOWN: sample-provider-specific end-to-end test]` | No deterministic result is validated from a real provider yet. |
| REQ-SAMP-008 | SATISFIED | No-Impact | None | Existing sample/build topology is already the right extension point. |

## 5. Invariant Impact

- [KNOWN] The repository already has a dedicated sample BTF fixture slot and an existing sample-driver provider lifecycle; the proposed deltas preserve those extension points. (Evidence: TE-001, TE-002, TE-004)
- [KNOWN] No current test validates a real sample-provider-backed BTF contract, so these deltas add missing feature-specific coverage rather than replacing established non-BTF sample tests. (Evidence: TE-003)
- [KNOWN] The sample-provider validation work should remain rooted in existing sample and end-to-end assets instead of creating a separate bespoke harness. (Evidence: TE-002, TE-004)

## 6. Application Notes

1. [KNOWN] This is a derived validation-delta artifact for repository planning, not a direct update to an upstream validation plan section from `docs/BtfResolvedFunctions.md`.
2. [KNOWN] The biggest current gap is not “no place to put tests”; it is that the existing place still targets placeholder metadata instead of a real in-tree provider.
3. [KNOWN] Once a real sample provider exists, the current special-case `btf_resolved` sample path becomes the most natural first place to retarget validation.

## Coverage

- **Examined**: `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj`; `undocked\tests\sample\ext\drv\sample_ext_drv.c`
- **Method**: targeted `view` on the current BTF sample fixture, sample build rule, and sample-driver lifecycle wiring; targeted `rg` for BTF provider symbols in the sample/test trees
- **Excluded**: detailed runtime validation outside the sample-provider use case
- **Limitations**: no sample-provider-backed BTF tests currently exist, so several expected test locations remain `[UNKNOWN]`

## Test Evidence Inventory

| Evidence ID | Location | Summary | Reason Relevant |
| --- | --- | --- | --- |
| TE-001 | `tests\sample\unsafe\btf_resolved.c:6-17` | The current BTF sample fixture uses placeholder metadata. | Establishes the current validation starting point. |
| TE-002 | `tests\sample\sample.vcxproj:271-276` | The sample build already has a dedicated path for `btf_resolved`. | Establishes the immediate build/test extension point. |
| TE-003 | Searches over `undocked\tests\sample\ext`, `tests\sample`, and `tests\end_to_end` for `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID`, `ebpf_btf_resolved_function_provider_data_t`, and `btf_resolved` returned no sample-extension BTF provider or end-to-end validation matches beyond the existing placeholder fixture/build path. | No real sample-provider-backed BTF validation exists today. | Establishes the remaining validation gap. |
| TE-004 | `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170` | The sample driver already provides concrete startup/shutdown lifecycle slots for provider registration. | Establishes the lifecycle validation extension point. |

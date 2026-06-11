<!-- Derived artifact: Stable sample BTF provider alignment set -->

# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The repository already has a shared sample-extension include surface, but it does not yet define whether the canonical BTF-resolved sample declaration should live in `sample_ext_helpers.h` or in a sibling sample-extension header under the same include tree. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `tests\sample\undocked\test_sample_ebpf.c:18`, `tests\sample\unsafe\btf_resolved.c:4-10`)
- [KNOWN] The existing BTFID specs require registry publication before verification, but they do not define whether the sample provider should publish through store-helper APIs, direct driver-owned registry writes, or a companion sample publication tool. (Source: `docs\specs\btfid\03-registry-publication.md:62-94`)
- [KNOWN] The current native-loading and runtime specs support multiple providers, but this follow-on area does not yet define whether the first stable sample target needs only one provider/function or should also model multi-provider coverage. (Source: `docs\specs\btfid\07-native-module-loading.md:95-108`, `docs\specs\btfid\08-runtime-execution.md:64-101`)

## Implicit requirements in this area

- [INFERRED] The stable sample BTF contract should reuse the existing sample-extension shared include surface, because that is already how sample programs consume sample-driver contracts and it avoids hardcoded one-off module GUIDs in test sources. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `tests\sample\undocked\test_sample_ebpf.c:18`, `tests\sample\undocked\custom_map_basic.c:20`, `tests\sample\unsafe\btf_resolved.c:6-10`)
- [INFERRED] The same module GUID and function prototype must flow through the sample header, registry metadata, NMR provider registration, and native/runtime consumers, because the existing BTFID specs already require cross-phase identity and prototype consistency for real providers. (Source: `docs\specs\btfid\03-registry-publication.md:62-89`, `docs\specs\btfid\06-nmr-provider-registration.md:68-90`, `docs\specs\btfid\07-native-module-loading.md:70-75`, `docs\specs\btfid\08-runtime-execution.md:79-84`)
- [INFERRED] The sample function should be deterministic and side-effect-light, because its primary role is to provide a stable validation target for verifier, bpf2c, native-load, and runtime tests rather than to model a production-only extension behavior. (Source: `tests\sample\unsafe\btf_resolved.c:12-17`, `undocked\tests\sample\ext\drv\sample_ext.c:918-1128`)

## Actual or possible conflicts

- [KNOWN] The current `btf_resolved` sample uses a placeholder module GUID string and a placeholder symbol name, so it is not tied to any in-tree provider contract. (Source: `tests\sample\unsafe\btf_resolved.c:6-17`)
- [KNOWN] The current `sample_ebpf_ext` driver already registers map, program-info, and hook providers, but it does not register or unregister any BTF-resolved-function provider. (Source: `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`)
- [KNOWN] The sample build currently special-cases `unsafe\btf_resolved.c` to compile from a checked-in generated fixture rather than from a real sample-provider-backed pipeline, which makes the existing artifact path a temporary compatibility mechanism instead of a stable end-to-end sample-provider contract. (Source: `tests\sample\sample.vcxproj:271-276`)

## Coverage statement

- **Examined:** `docs\specs\btfid\03-registry-publication.md`; `docs\specs\btfid\06-nmr-provider-registration.md`; `docs\specs\btfid\07-native-module-loading.md`; `docs\specs\btfid\08-runtime-execution.md`; `undocked\tests\sample\ext\inc\sample_ext_helpers.h`; `undocked\tests\sample\ext\inc\sample_ext_program_info.h`; `undocked\tests\sample\ext\drv\sample_ext.c`; `undocked\tests\sample\ext\drv\sample_ext.h`; `undocked\tests\sample\ext\drv\sample_ext_drv.c`; `tests\sample\unsafe\btf_resolved.c`; `tests\sample\sample.vcxproj`.
- **Method:** compared the current BTFID requirements for real providers with the sample-extension driver's existing publication/registration patterns and with the current placeholder `btf_resolved` sample fixture.
- **Excluded:** detailed implementation choices inside `libs\execution_context`; production-provider guidance outside the sample-extension tree.
- **Limitations:** this document is a downstream implementation-enabling spec, not a direct extraction of a new source section from `docs/BtfResolvedFunctions.md`.

# Sample BTF Provider — Requirements Document

## 1. Overview

[INFERRED] This area defines the requirements for adding a stable in-tree BTF-resolved-function provider to `sample_ebpf_ext`, so the repository has a real provider contract that can be used by verifier, bpf2c, native-load, and runtime tests. (Source: `docs\specs\btfid\03-registry-publication.md:62-94`, `docs\specs\btfid\06-nmr-provider-registration.md:63-95`, `docs\specs\btfid\07-native-module-loading.md:65-108`, `docs\specs\btfid\08-runtime-execution.md:64-101`)

[KNOWN] The current repository does not yet have that stable target: `sample_ebpf_ext` already exposes adjacent sample providers and shared sample headers, while `tests\sample\unsafe\btf_resolved.c` still uses placeholder `.ksyms` metadata disconnected from any in-tree provider. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `tests\sample\unsafe\btf_resolved.c:6-17`)

## 2. Scope

### 2.1 In Scope

- [INFERRED] A canonical sample BTF-resolved-function declaration surface for BPF sample programs. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `tests\sample\unsafe\btf_resolved.c:6-10`)
- [INFERRED] A `sample_ebpf_ext`-owned provider implementation, registry publication contract, NMR registration contract, and driver lifecycle wiring for at least one stable BTF-resolved function. (Source: `docs\specs\btfid\03-registry-publication.md:62-94`, `docs\specs\btfid\06-nmr-provider-registration.md:63-95`, `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`)
- [INFERRED] Retargeting at least one sample/fixture program to consume the canonical sample declaration instead of a hardcoded placeholder contract. (Source: `tests\sample\unsafe\btf_resolved.c:6-17`)

### 2.2 Out of Scope

- [KNOWN] Core runtime support for BTF-resolved functions in `libs\execution_context`, because that belongs to `07-native-module-loading.md` and `08-runtime-execution.md`. (Source: `docs\specs\btfid\07-native-module-loading.md:65-108`, `docs\specs\btfid\08-runtime-execution.md:64-101`)
- [KNOWN] Generic production guidance for all future providers, because this area is specifically about a stable sample-provider target. (Source: `docs\specs\btfid\03-registry-publication.md:62-94`, `docs\specs\btfid\06-nmr-provider-registration.md:63-95`)
- [KNOWN] Multi-provider scenario design beyond the minimum needed to supply one stable in-tree provider target. (Source: `docs\specs\btfid\07-native-module-loading.md:95-108`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Stable sample BTF provider | [INFERRED] A repository-owned BTF-resolved-function provider contract implemented by `sample_ebpf_ext` and consumed by sample/test programs. (Source: `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`) |
| Placeholder fixture | [KNOWN] The current `tests\sample\unsafe\btf_resolved.c` program that hardcodes `module_id:{12345678-1234-1234-1234-123456789abc}` and `my_driver_lookup` in `.ksyms`. (Source: `tests\sample\unsafe\btf_resolved.c:6-17`) |
| Shared sample declaration surface | [KNOWN] The common sample-extension include tree used by sample programs today, centered on `sample_ext_helpers.h`. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `tests\sample\undocked\test_sample_ebpf.c:18`, `tests\sample\undocked\custom_map_basic.c:20`) |
| Sample-extension provider baseline | [KNOWN] The current `sample_ebpf_ext` pattern of publishing shared include contracts and registering map, program-info, and hook providers during driver startup/shutdown. (Source: `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`) |

## 4. Requirements

### 4.1 Functional Requirements

[INFERRED] REQ-SAMP-001: The repository MUST expose at least one canonical sample BTF-resolved-function declaration through the sample-extension shared include surface, including a sample-owned module GUID and a concrete function prototype, so that sample BPF sources can reference a real in-tree provider contract instead of hardcoded placeholder metadata. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `tests\sample\unsafe\btf_resolved.c:6-10`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify one sample-owned module GUID and one sample-owned function prototype as the canonical declaration surface for tests. (Source: `tests\sample\unsafe\btf_resolved.c:6-10`)

[INFERRED] REQ-SAMP-002: The canonical sample BTF contract MUST be backed by `sample_ebpf_ext`, so that the provider participates in the same driver lifecycle and sample-extension packaging model as the repository's other sample extension contracts. (Source: `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify `sample_ebpf_ext` rather than a one-off in-test provider as the owner of the sample BTF contract. (Source: `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`)

[INFERRED] REQ-SAMP-003: The sample provider MUST publish registry metadata that matches the canonical sample module GUID, function name, and prototype before verification, so that verifier and bpf2c can resolve the same contract that the runtime will bind later. (Source: `docs\specs\btfid\03-registry-publication.md:62-89`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify registry publication as part of the sample provider, not as an optional out-of-band step. (Source: `docs\specs\btfid\03-registry-publication.md:62-89`)

[INFERRED] REQ-SAMP-004: The sample provider MUST register as an NMR provider for BTF-resolved functions using the same module GUID and matching provider data, so that native modules can bind to the same contract that was published for verification. (Source: `docs\specs\btfid\06-nmr-provider-registration.md:63-90`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify the module GUID, prototype array, and address array as the sample provider's NMR identity and payload. (Source: `docs\specs\btfid\06-nmr-provider-registration.md:68-90`)

[INFERRED] REQ-SAMP-005: Driver initialization and unload for `sample_ebpf_ext` MUST register and unregister the sample BTF provider alongside the existing sample providers, so that the sample BTF contract follows the same startup/shutdown behavior as the rest of the sample extension driver. (Source: `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify both startup registration and unload-time unregistration as mandatory lifecycle steps. (Source: `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`)

[INFERRED] REQ-SAMP-006: At least one sample program or checked-in sample fixture MUST consume the canonical sample BTF declaration instead of a hardcoded placeholder GUID/symbol pair, so that the repository exercises the real in-tree provider contract. (Source: `tests\sample\unsafe\btf_resolved.c:6-17`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify replacement of the placeholder `MY_DRIVER_MODULE` contract as a required outcome. (Source: `tests\sample\unsafe\btf_resolved.c:6-10`)

### 4.2 Non-Functional Requirements

[INFERRED] REQ-SAMP-007: The first sample BTF-resolved function SHOULD have deterministic, side-effect-light behavior, so that it is suitable for repeatable automated tests across verifier, native-load, and runtime paths. (Source: `tests\sample\unsafe\btf_resolved.c:12-17`, `undocked\tests\sample\ext\drv\sample_ext.c:918-1128`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements prefer a simple function contract whose result can be asserted directly by tests. (Source: `tests\sample\unsafe\btf_resolved.c:12-17`)

[INFERRED] REQ-SAMP-008: The sample BTF provider SHOULD extend the existing sample-extension header and provider-registration patterns rather than introduce a disconnected test-only contract, so that the new sample target stays coherent with how the repository already exposes sample extension surfaces. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `undocked\tests\sample\ext\drv\sample_ext.c:212-225`, `undocked\tests\sample\ext\drv\sample_ext.c:301-313`, `undocked\tests\sample\ext\drv\sample_ext.c:386-398`)

Acceptance Criteria:
- [INFERRED] AC-1: The requirements identify the current sample-extension include/provider-registration style as the preferred extension point. (Source: `undocked\tests\sample\ext\drv\sample_ext.c:212-225`, `undocked\tests\sample\ext\drv\sample_ext.c:301-313`, `undocked\tests\sample\ext\drv\sample_ext.c:386-398`)

### 4.3 Constraints

- [KNOWN] CON-001: The current sample BTF fixture uses a placeholder module GUID and symbol name instead of a sample-extension-owned contract. (Source: `tests\sample\unsafe\btf_resolved.c:6-17`)
- [KNOWN] CON-002: The current `sample_ebpf_ext` driver only wires map, program-info, and hook providers into startup/shutdown. (Source: `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`)
- [KNOWN] CON-003: The current sample build still special-cases `unsafe\btf_resolved.c` through checked-in generated fixture C. (Source: `tests\sample\sample.vcxproj:271-276`)
- [KNOWN] CON-004: The existing BTFID contracts already require registry publication before verification and NMR/runtime alignment after load, so the sample provider cannot be specified as an NMR-only or runtime-only artifact. (Source: `docs\specs\btfid\03-registry-publication.md:62-89`, `docs\specs\btfid\06-nmr-provider-registration.md:63-90`, `docs\specs\btfid\07-native-module-loading.md:65-108`, `docs\specs\btfid\08-runtime-execution.md:64-101`)

## 5. Dependencies

- DEP-SAMP-001: This requirement set depends on `03-registry-publication.md`, because the sample provider must publish verification-time metadata under the same module GUID and function name it exposes to sample programs. Impact if unavailable: the sample target would not exercise the real verifier/bpf2c lookup path. (Source: `docs\specs\btfid\03-registry-publication.md:62-89`)
- DEP-SAMP-002: This requirement set depends on `06-nmr-provider-registration.md`, because the sample provider must publish callable addresses and prototypes through the BTF NMR contract. Impact if unavailable: the sample target would not exercise the real native-load attach path. (Source: `docs\specs\btfid\06-nmr-provider-registration.md:63-90`)
- DEP-SAMP-003: This requirement set depends on `07-native-module-loading.md` and `08-runtime-execution.md`, because the value of a stable sample provider is that native modules can bind to it and execute through it. Impact if unavailable: the sample target would stop at metadata publication without validating load/runtime behavior. (Source: `docs\specs\btfid\07-native-module-loading.md:65-108`, `docs\specs\btfid\08-runtime-execution.md:64-101`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] One stable sample BTF-resolved function is sufficient for the initial repository test target. If this assumption is wrong, the follow-on design delta must expand to cover multi-provider or multi-function scenarios. Justification: the immediate gap is absence of any stable in-tree provider target at all. (Source: `tests\sample\unsafe\btf_resolved.c:6-17`, `docs\specs\btfid\07-native-module-loading.md:95-108`)
- ASM-002: [ASSUMPTION] The canonical declaration should live in the existing sample-extension include tree, most likely `sample_ext_helpers.h` or a sibling header in the same directory. If this assumption is wrong, the sample-program include strategy must be updated accordingly. Justification: current sample programs already depend on that include tree for sample-extension contracts. (Source: `undocked\tests\sample\ext\inc\sample_ext_helpers.h:21-136`, `tests\sample\undocked\test_sample_ebpf.c:18`, `tests\sample\undocked\custom_map_basic.c:20`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-SAMP-001 | [KNOWN] If the sample header, registry metadata, and NMR provider use different GUIDs or prototypes, tests may validate a contract that the runtime cannot actually bind. (Source: `docs\specs\btfid\03-registry-publication.md:62-89`, `docs\specs\btfid\06-nmr-provider-registration.md:68-90`) | Medium | High | [INFERRED] Keep cross-phase identity explicit and mandatory in the sample spec. |
| RISK-SAMP-002 | [KNOWN] If the sample function is too complex or side-effect-heavy, failures will be harder to localize across verifier, bpf2c, native-load, and runtime layers. (Source: `tests\sample\unsafe\btf_resolved.c:12-17`) | Medium | Medium | [INFERRED] Keep the first contract deterministic and easy to assert. |
| RISK-SAMP-003 | [KNOWN] Leaving the placeholder `btf_resolved` fixture in place as the canonical sample would continue to bypass the intended in-tree provider lifecycle. (Source: `tests\sample\unsafe\btf_resolved.c:6-17`, `tests\sample\sample.vcxproj:271-276`) | High | High | [INFERRED] Require at least one fixture/program to consume the real sample-provider declaration. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-05 | Copilot | Initial derived requirements for adding a stable sample BTF provider to `sample_ebpf_ext`. |

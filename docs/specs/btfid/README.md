# BTF-resolved function requirements specs

## Source boundary

- [KNOWN] Artifacts `01` through `11` are derived only from `docs/BtfResolvedFunctions.md`. (Source: `docs/BtfResolvedFunctions.md:1-507`)
- [KNOWN] The `12-sample-btf-provider*` artifacts are downstream implementation-enabling specs derived from the existing BTFID requirement set plus the current sample-extension and sample-test code, because the repository currently lacks a stable in-tree BTF provider target for end-to-end validation. (Source: `docs\specs\btfid\03-registry-publication.md:62-94`, `docs\specs\btfid\06-nmr-provider-registration.md:63-95`, `docs\specs\btfid\07-native-module-loading.md:65-108`, `docs\specs\btfid\08-runtime-execution.md:64-101`, `undocked\tests\sample\ext\drv\sample_ext.c:504-770`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:56-60`, `undocked\tests\sample\ext\drv\sample_ext_drv.c:160-170`, `tests\sample\unsafe\btf_resolved.c:6-17`)
- [KNOWN] The source document describes a proposed design, and the BTF-resolved-function NPI IDs, store APIs, and C types are planned interfaces not yet present in current public headers. Treat these specs as requirements extracted from a proposal, not from shipped APIs. (Source: `docs/BtfResolvedFunctions.md:14-16`)

## Artifact map

| File | Source area | Primary category tag |
| --- | --- | --- |
| `01-architecture.md` | Section 2 Architecture | `ARCH` |
| `02-header-authoring.md` | Section 3 Authoring BTF-resolved Function Headers | `HDR` |
| `03-registry-publication.md` | Section 4 Registry Publication | `REG` |
| `04-verifier-integration.md` | Section 5 Verifier Integration | `VER` |
| `05-bpf2c-integration.md` | Section 6 bpf2c Integration | `B2C` |
| `06-nmr-provider-registration.md` | Section 7 NMR Provider Registration | `NMR` |
| `07-native-module-loading.md` | Section 8 Native Module Loading | `LOAD` |
| `08-runtime-execution.md` | Section 9 Runtime Execution | `RUN` |
| `09-ebpf-program-internal-changes.md` | Section 10 Internal Changes to `ebpf_program_t` | `PROG` |
| `10-security-considerations.md` | Section 11 Security Considerations | `SEC` |
| `11-future-considerations.md` | Section 12 Future Considerations | `FUT` |
| `12-sample-btf-provider.md` | Derived follow-on artifact for a stable in-tree sample BTF provider target | `SAMP` |

## Global Pre-Authoring Analysis

### Ambiguities needing clarification

- [KNOWN] The source says the native module skeleton registers as an NMR client with a wildcard module ID, but it does not define the concrete wildcard value or the exact registration contract needed to express that wildcard. (Source: `docs/BtfResolvedFunctions.md:352-355`)
- [KNOWN] The source introduces proposed NPI IDs, store APIs, and C types, but it does not define the ratified public-header names or versioning policy for those interfaces. (Source: `docs/BtfResolvedFunctions.md:14-16`, `docs/BtfResolvedFunctions.md:184-190`, `docs/BtfResolvedFunctions.md:318-324`)
- [KNOWN] The source states that provider detach waits for current execution to complete and that runtime invocation takes rundown protection, but it does not define the exact lock ordering or callback sequencing needed to avoid deadlock. (Source: `docs/BtfResolvedFunctions.md:370-375`, `docs/BtfResolvedFunctions.md:400-406`, `docs/BtfResolvedFunctions.md:459-466`)

### Implicit requirements likely intended

- [INFERRED] A single module GUID must remain consistent across header metadata, registry publication, NMR registration, native loading, and runtime lookup, because each phase uses the GUID to refer to the same provider namespace. (Reasoning: sections 3, 4, 7, and 8 all bind behavior to the same module GUID.) (Source: `docs/BtfResolvedFunctions.md:120-125`, `docs/BtfResolvedFunctions.md:142-157`, `docs/BtfResolvedFunctions.md:328-340`, `docs/BtfResolvedFunctions.md:359-365`)
- [INFERRED] Session-local BTF ID allocation must be deterministic within a verification session so that verifier rewriting, reverse lookup, and downstream native-code generation agree on the same `(module_guid, function_name)` mapping. (Reasoning: the caller allocates IDs, builds both forward and reverse mappings, and the verifier consumes only the `btf_id`.) (Source: `docs/BtfResolvedFunctions.md:202-227`)
- [INFERRED] Provider detach handling must preserve in-flight execution safety while making later invocations fail predictably, because the source requires both rundown protection and post-detach invocation failure. (Source: `docs/BtfResolvedFunctions.md:372-375`, `docs/BtfResolvedFunctions.md:402-406`, `docs/BtfResolvedFunctions.md:426-428`)

### Actual or possible conflicts

- [KNOWN] There is a potential interpretation conflict between per-provider attachment state in Section 8 and per-function binding state in Section 10; the source resolves this partially by stating that the two structures have different responsibilities, but downstream design still needs to keep those responsibilities distinct. (Source: `docs/BtfResolvedFunctions.md:377-392`, `docs/BtfResolvedFunctions.md:432-466`)
- [KNOWN] Future considerations describe optional enhancements such as function sets and dynamic discovery, while the current design requires registry metadata at verification time; downstream consumers must not treat future items as baseline scope. (Source: `docs/BtfResolvedFunctions.md:136-190`, `docs/BtfResolvedFunctions.md:492-507`)

### Coverage statement

- **Examined:** `docs/BtfResolvedFunctions.md` in full.
- **Method:** section-by-section extraction into area-specific requirement specs, with cross-area dependencies tracked in this manifest.
- **Excluded:** implementation details not present in the source, final public-header names not yet defined, and requirements derivable only from other repository documents.
- **Limitations:** these artifacts inherit the source document's proposed-design status and its unspecified details for not-yet-public interfaces.

## Shared glossary

| Term | Definition |
| --- | --- |
| BTF-resolved function | [KNOWN] A function exposed by a Windows kernel driver and resolved by name via BTF rather than by a fixed helper ID. (Source: `docs/BtfResolvedFunctions.md:5-9`) |
| `.ksyms` section | [KNOWN] The BTF section used in the source design to carry external function symbols for BTF-resolved functions. (Source: `docs/BtfResolvedFunctions.md:42-43`, `docs/BtfResolvedFunctions.md:89-90`, `docs/BtfResolvedFunctions.md:199-206`) |
| Module GUID | [KNOWN] The provider-specific GUID used to disambiguate a BTF-resolved function namespace across header metadata, registry publication, and NMR binding. (Source: `docs/BtfResolvedFunctions.md:8-9`, `docs/BtfResolvedFunctions.md:120-125`, `docs/BtfResolvedFunctions.md:328-340`) |
| Session-local BTF ID | [KNOWN] A BTF ID allocated during caller-side resolution for a specific `(module GUID, function name)` pair within a session. (Source: `docs/BtfResolvedFunctions.md:22-25`, `docs/BtfResolvedFunctions.md:208-212`) |
| `call_btf` | [KNOWN] The instruction form used for BTF-resolved function calls, with `src=2`, `imm=btf_id`, and `offset=0` in the current PREVAIL description. (Source: `docs/BtfResolvedFunctions.md:24`, `docs/BtfResolvedFunctions.md:231-243`) |
| NPI | [KNOWN] The NMR programming interface used for provider registration and client attachment in the source design. (Source: `docs/BtfResolvedFunctions.md:314-346`, `docs/BtfResolvedFunctions.md:348-375`) |
| Rundown protection | [KNOWN] The runtime safety mechanism taken on all BTF-resolved function bindings before execution and released afterward so detach can wait for in-flight execution to complete. (Source: `docs/BtfResolvedFunctions.md:402-406`) |

## Cross-area dependency index

| Dependency | Source file | Depends on | Why |
| --- | --- | --- | --- |
| `DEP-ARCH-001` | `01-architecture.md` | `02-header-authoring.md`, `03-registry-publication.md`, `06-nmr-provider-registration.md`, `08-runtime-execution.md` | [KNOWN] The architecture spans compile-time metadata, verification-time lookup, load-time provider binding, and runtime execution. (Source: `docs/BtfResolvedFunctions.md:35-82`) |
| `DEP-VER-001` | `04-verifier-integration.md` | `03-registry-publication.md` | [KNOWN] Verification lookup uses registry-published prototypes and provider metadata. (Source: `docs/BtfResolvedFunctions.md:208-227`) |
| `DEP-B2C-001` | `05-bpf2c-integration.md` | `04-verifier-integration.md`, `03-registry-publication.md` | [KNOWN] Generated native artifacts depend on resolved BTF IDs and verified prototypes. (Source: `docs/BtfResolvedFunctions.md:231-310`) |
| `DEP-LOAD-001` | `07-native-module-loading.md` | `05-bpf2c-integration.md`, `06-nmr-provider-registration.md` | [KNOWN] Load-time binding uses the generated import table and NMR provider registration. (Source: `docs/BtfResolvedFunctions.md:247-258`, `docs/BtfResolvedFunctions.md:328-346`, `docs/BtfResolvedFunctions.md:359-365`) |
| `DEP-RUN-001` | `08-runtime-execution.md` | `07-native-module-loading.md`, `09-ebpf-program-internal-changes.md` | [KNOWN] Runtime invocation depends on attached providers, binding state, and callback/rundown fields stored on `ebpf_program_t`. (Source: `docs/BtfResolvedFunctions.md:394-428`, `docs/BtfResolvedFunctions.md:432-466`) |
| `DEP-SEC-001` | `10-security-considerations.md` | `04-verifier-integration.md`, `05-bpf2c-integration.md`, `08-runtime-execution.md` | [KNOWN] Security guarantees depend on verifier checks, proof-of-verification hashing, and runtime/provider behavior. (Source: `docs/BtfResolvedFunctions.md:477-490`) |
| `DEP-SAMP-001` | `12-sample-btf-provider.md` | `03-registry-publication.md`, `06-nmr-provider-registration.md`, `07-native-module-loading.md`, `08-runtime-execution.md` | [INFERRED] A stable sample provider must satisfy the existing registry, provider-registration, native-loading, and runtime contracts so tests exercise the real end-to-end path instead of placeholder metadata. (Source: `docs\specs\btfid\03-registry-publication.md:62-94`, `docs\specs\btfid\06-nmr-provider-registration.md:63-95`, `docs\specs\btfid\07-native-module-loading.md:65-108`, `docs\specs\btfid\08-runtime-execution.md:64-101`, `tests\sample\unsafe\btf_resolved.c:6-17`) |

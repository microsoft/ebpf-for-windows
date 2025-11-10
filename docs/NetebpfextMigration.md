# Migration Doc for netebpfext

## Rationale for Moving netebpfext to Ntosebpext repo

### Introduction
The eBPF for Windows project comprises two main components:
- **Core Engine**: Delivers foundational capabilities for eBPF on Windows.
- **Extensions**: Build on top of the core engine to enable hook points for specific functionalities.

Currently, extensions are distributed across four different repositories with only `netebpfext` being in the ebpf-for-windows repo.

### Vision
The long-term goal is to consolidate all extensions into the `ntosebpfext` repository. The migration begins with `netebpfext`.

---

## Advantages of a Dedicated Extensions Repository
- **Improved Code Reusability**: All extensions share a common interaction model with the core engine. A unified repo allows for better reuse of shared logic.
- **Lower Barrier for Community Contributions**: Developers can reference existing extensions to implement new ones, streamlining onboarding and collaboration.

---

## Benefits of Migrating netebpfext to ntosebpfext
- **Clear Separation of Concerns**: Enables independent evolution of the core engine and extensions, with well-defined boundaries.
- **Test Infrastructure Readiness**: Migrating `netebpfext` includes moving its test collateral and setting up self-hosted runners, preparing `ntosebpfext` for future extension migrations.

## Migration Process

### Phase 1: Initial Copy and Build netebpfext.sys
- Copy `ebpf-for-windows/netebpfext` to `ntosebpfext/ebpf_extensions`.
- Update project files to compile `netebpfext.sys`.
- Preserve commit history using `git filter-repo` or `git subtree split`.
- **Checkpoint 1**: Validate built .sys using execute-cicd script.

### Phase 2: Compile netebpfext_unit
- Address linking issues with usersim observed during previous extension additions.
- Build user-mode lib (`netebpfext_user.lib`) and test binary (`netebpfext_unit`).
- **Checkpoint 2**: Ensure successful compilation and execution of `netebpfext_unit`.

### Phase 3: Bring over test collateral
- Setup CI/CD scripts and self hosted runners in `ntosebpfext` repo
- Bring over all tests related to `netebpfext` this includes multiple directories under `ebpf-for-windows/tests` folder (`connect_redirect`, `socket`, `tcp_udp_listener`) and also possibly parts of `end_to_end`.
- Update generic tests in ebpf repo that use `netebpfext` to start using sample extensions.
- **Checkpoint 3**: Working CI/CD in `ntosebpfext` that builds and tests `netebpfext`.

### Phase 4: Code Refactoring
- Reuse shared logic from `ntosebpfext/libs/ebpf_ext` for hook provider and NMR registration.
- **Checkpoint 4**: Both user mode and kernel mode test should pass with the refactored code.

### Phase 5: Packaging and Pipeline Updates
- Remove `netebpfext` from ebpf-for-windows installation scripts.
- Add it to the extensions installation script in `ntosebpfext`.
- Update internal pipelines to ingest from the new repo. Update pipelines for IMDS, WCN/CNC and ES teams.
- Finalize next releases for both ebpf-for-windows and `ntosebpfext`.

## Packaging Strategy

### RC Release
The RC release of ebpf-for-windows will produce a production-signed package in the internal Microsoft NuGet feed, including `netebpfext`.

### v1 Release
ebpf-for-windows and `netebpfext` will be ingested together.
`ntosebpfext` v1 will follow after consuming ebpf-for-windows v1.

### v1.x Release
After migration is complete both `ntosebpfext` will be updated to the next minor bump v1.x.
Ingestion pipelines and internal packaging repos will be updated to source `netebpfext` from its new location. Once that is done, `netebpfext` can be removed from ebpf-for-windows whenever ebpf-for-windows v1.x is released.

---
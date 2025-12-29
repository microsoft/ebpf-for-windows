# eBPF Extension Code Deduplication Plan


### Introduction
The eBPF for Windows project comprises two main components:
- **Core Engine**: Delivers foundational capabilities for eBPF on Windows.
- **Extensions**: Build on top of the core engine to enable hook points for specific functionalities.

Currently, extensions are distributed across multiple repositories with significant code duplication between `netebpfext`, `ntosebpfext` and `xdp-for-windows`.

### Vision
The new approach focuses on creating a shared **eBPF Extension Common Repository** that contains common code for developing eBPF extensions. This repo would be included as a submodule into other extension repositories as needed. This eliminates code duplication and provides a standardized foundation for all extensions.

**Initial Scope**: The initial effort will focus on extracting common code shared between `netebpfext`, `ntosebpfext` and `xdp-for-windows` extensions to establish the foundation and prove the architecture.

---

## Advantages of a Shared Extension Common Repository
- **Eliminates Code Duplication**: Common extension development patterns, helper functions, and boilerplate code are centralized.
- **Standardized Extension Development**: Provides a consistent framework for building eBPF extensions across all repositories.
- **Clear Separation of Concerns**: Core engine, shared extension helpers, and specific extension implementations are cleanly separated.
- **Reduced Maintenance Overhead**: Common code updates propagate automatically through submodule updates.

## High Level Plan

### Phase 1: Create Extension Common Repository
- Create new repository `ebpf-extension-common` .
- Extract all common code for developing eBPF extensions from netebpf and ntos extensions.
- Setup simple CI that builds the code into static libraries.
- **Checkpoint 1**: Validate that common repository builds successfully and produces expected artifacts.

### Phase 2: Integrate Submodules
- Update `netebpfext` in ebpf-for-windows to use the common repository as a submodule.
- Update `ntosebpfext` repository to use the common repository as a submodule.
- **Checkpoint 2**: Both repositories build successfully with the new submodule dependency.

### Phase 3: Move Sample Extension
- Move sample extension implementations to the common repository.
- Use sample extension as the primary CI/CD test for the common repository.
- **Checkpoint 3**: Sample extensions build and run successfully, serving as both test cases and developer documentation.

### Phase 4: Future work
- Publish the extension common repository as an official sample Extension SDK.
- Consume the common submodule in xdp and other internal extension repos.
- Re-evaluate the need for migrating `netebpfext` to its own repository or merging with `ntosebpfext` based on the new architecture.

## Packaging Strategy

### Current Phase
Both ebpf-for-windows and extension repositories continue with their existing packaging while integrating the new repository as a submodule.

### Future Releases
- Common repository will maintain clear release branches and tagged releases to support stable integration points for extensions.
- Extension repositories can independently version and release while depending on stable common repository versions.

---
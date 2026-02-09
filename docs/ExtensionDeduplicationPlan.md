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
- Extract all common code for developing eBPF extensions from netebpf and ntos extensions. See [detailed analysis](#phase-1-detailed-analysis) below.
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

## Phase 1: Detailed Analysis

### Common Functions Identified

The following sections detail functions that are nearly identical between `netebpfext` and `ntosebpfext`, making them prime candidates for extraction into the common repository.

#### Program Info Provider
| netebpfext Function | ntosebpfext Function |
|---------------------|----------------------|
| `_net_ebpf_extension_program_info_provider_attach_client` | `_ebpf_extension_program_info_provider_attach_client` |
| `_net_ebpf_extension_program_info_provider_detach_client` | `_ebpf_extension_program_info_provider_detach_client` |
| `_net_ebpf_extension_program_info_provider_cleanup_binding_context` | `_ebpf_extension_program_info_provider_cleanup_binding_context` |
| `net_ebpf_extension_program_info_provider_register` | `ebpf_extension_program_info_provider_register` |
| `net_ebpf_extension_program_info_provider_unregister` | `ebpf_extension_program_info_provider_unregister` |

#### Rundown Protection
| netebpfext Function | ntosebpfext Function |
|---------------------|----------------------|
| `_ebpf_ext_init_hook_rundown` | (inline) |
| `_ebpf_ext_attach_init_rundown` | `_ebpf_ext_attach_init_rundown` |
| `_ebpf_ext_wait_for_rundown` | `_ebpf_ext_attach_wait_for_rundown` |
| `_net_ebpf_extension_detach_client_completion` | `_ebpf_extension_detach_client_completion` |
| `_net_ebpf_ext_enter_rundown` | (inline) |
| `_net_ebpf_ext_leave_rundown` | (inline) |
| `net_ebpf_extension_hook_client_enter_rundown` | `ebpf_extension_hook_client_enter_rundown` |
| `net_ebpf_extension_hook_client_leave_rundown` | `ebpf_extension_hook_client_leave_rundown` |
| `net_ebpf_extension_hook_provider_enter_rundown` | N/A |
| `net_ebpf_extension_hook_provider_leave_rundown` | N/A |
| `_net_ebpf_extension_release_rundown_for_clients` | N/A |

#### Trace Logging
| netebpfext Function | ntosebpfext Function |
|---------------------|----------------------|
| `net_ebpf_ext_trace_initiate` | `ebpf_ext_trace_initiate` |
| `net_ebpf_ext_trace_terminate` | `ebpf_ext_trace_terminate` |
| `net_ebpf_ext_log_ntstatus_api_failure` | `ebpf_ext_log_ntstatus_api_failure` |
| `net_ebpf_ext_log_ntstatus_api_failure_message_string` | `ebpf_ext_log_ntstatus_api_failure_message_string` |
| `net_ebpf_ext_log_message` | `ebpf_ext_log_message` |

#### Hook Provider (Direct Migration)
| netebpfext Function | ntosebpfext Function |
|---------------------|----------------------|
| `_net_ebpf_extension_hook_invoke_single_program` | `ebpf_extension_hook_invoke_program` |
| `_net_ebpf_extension_hook_client_cleanup` | `_ebpf_extension_hook_client_cleanup` |
| `_net_ebpf_extension_hook_provider_cleanup_binding_context` | `_ebpf_extension_hook_provider_cleanup_binding_context` |

#### Hook Provider (Requires Refactoring)
| netebpfext Function | ntosebpfext Function |
|---------------------|----------------------|
| `net_ebpf_extension_hook_provider_register` | `ebpf_extension_hook_provider_register` |
| `net_ebpf_extension_hook_provider_unregister` | `ebpf_extension_hook_provider_unregister` |
| `_net_ebpf_extension_hook_provider_attach_client` | `_ebpf_extension_hook_provider_attach_client` |
| `_net_ebpf_extension_hook_provider_detach_client` | `_ebpf_extension_hook_provider_detach_client` |
| `net_ebpf_extension_hook_invoke_programs` | N/A |
| `net_ebpf_extension_hook_expand_stack_and_invoke_programs` | N/A |
| `_net_ebpf_extension_invoke_programs_callout` | N/A |

---


---
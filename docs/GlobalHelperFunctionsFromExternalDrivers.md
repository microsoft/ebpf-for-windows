# Global Helper Functions from External Drivers

## Overview

This document outlines the requirements for enabling drivers outside of `ebpfcore.sys` to expose global helper functions to eBPF programs without requiring centralized management of helper function IDs.

## Problem Statement

The current eBPF for Windows global helper function system has the following limitations:
- **Global helper IDs and prototypes are centrally defined in `ebpfcore.sys`** — while extensions can override existing helper implementations via `ebpf_program_data_t.global_helper_function_addresses`, they cannot independently define new global helper IDs or prototypes without central coordination
- **Pre-coordination is required for new global helpers** — introducing a new global helper requires updating central definitions, preventing independent driver development
- **Static ID allocation** — new helper IDs must be allocated centrally, creating a coordination bottleneck

This creates barriers for independent driver development and limits the extensibility of the eBPF ecosystem by preventing external drivers from contributing new global helper functions without prior coordination with the core platform.

## Requirements

The requirements in this section describe properties the system must have, not a single mandated implementation approach. Any design that satisfies these requirements (for example, a BTF-based identification and signature mechanism) is acceptable.

### R1: External Driver Global Helper Registration
- Drivers outside of `ebpfcore.sys` **MUST** be able to register global helper functions
- The system **MUST** support global helper function registration without requiring pre-coordination
- Existing interfaces **MUST** remain unchanged to maintain application compatibility
- New interfaces **MAY** be added if needed to support this capability

### R2: Elimination of Central Coordination
- Driver developers **MUST NOT** be required to coordinate helper function registration with other drivers
- The system **MUST** support global helper registration even when multiple drivers register helper functions with the same name
- Global helper function identity **MUST NOT** rely solely on the helper function name (for example, it can be based on a stable ID such as a BTF ID and/or provider identity)
- The eBPF runtime **MUST** manage helper registration automatically (for example, maintaining a registry of providers and helper metadata/signatures) without requiring manual ID allocation or coordination
- The system **MUST** provide a deterministic resolution mechanism for global helper calls, based on a stable, provider-qualified identity (for example, combining provider identity with a BTF-based helper identifier), so that programs can unambiguously reference the intended helper implementation
- If, at program load or helper resolution time, a global helper reference cannot be uniquely resolved to a single implementation (for example, due to ambiguous identity or a missing provider), the system **MUST** reject program load and return a clear, specific error indicating the resolution failure

### R3: Per-Program Global Helper Resolution
- Each eBPF program **MUST** have access to a consistent set of global helper functions for its lifetime (from successful load/attach until detach/unload)
- The system **MUST** resolve global helper function references during program loading
- Programs **MUST** be able to access global helpers from both `ebpfcore.sys` and external drivers

### R4: Backward Compatibility
- Existing global helper functions **MUST** continue to work unchanged
- Existing driver code **MUST NOT** require modification to continue functioning
- Existing compiled programs **MUST** remain compatible
- Consequently, programs can use existing and new global helper functions together within the same program

### R5: C Program Support
- eBPF programs written in C **MUST** be able to call global helper functions using standard function call syntax
- The compilation process **MUST** handle global helper function resolution transparently
- Generated code **MUST** support global helper function calls from external drivers

### R6: Multiple Provider Support
- eBPF programs **MUST** be able to utilize global helper functions from multiple providers simultaneously
- The system **MUST** support discovery and resolution of global helper functions across all registered providers
- Provider lifecycle events (attach/detach) **MUST** be handled independently for each provider

### R7: Program Integrity
- Programs **MUST** execute with global helper function signature information that matches what was used during program verification and native image generation
- The system **MUST** reject program load if the resolved runtime signature/ABI of any global helper does not match the signature/ABI assumed during verification and native image generation
- Program verification **MUST** account for global helper functions from external drivers

### R8: Standards Consistency
- The global helper function identification and signature mechanism **SHOULD** be consistent with the BPF ISA standard (for example, using BTF-based identification as described in RFC 9669)
- For new global helpers, helper identity **SHOULD** be based on stable type/signature identifiers (for example, BTF-based IDs) rather than centrally allocated numeric helper IDs
- Helper function names **MAY** be used as source-level identifiers in C, but **MUST NOT** be the sole mechanism used to identify a helper at verification/load time

## Success Criteria

### SC1: Driver Independence
- Third-party drivers can register custom global helper functions without coordination with Microsoft or other driver developers
- Conflicts that prevent unambiguous helper resolution (for example, duplicate stable helper identifiers within the same provider identity) are detected and rejected at registration time with clear error messages

### SC2: Developer Experience
- eBPF program developers can call global helper functions using familiar C function names in their C code
- Compilation and loading processes handle global helper function resolution transparently
- Error messages provide clear diagnostics for unavailable global helper functions

### SC3: System Stability

For the purposes of this section:
- An **invocation** of an eBPF program is a single execution of that program's entry point triggered by a hook (e.g., packet arrival, syscall, timer event), from the first instruction until the program returns.
- An eBPF program is **affected** by a provider lifecycle event if it was successfully bound to at least one global helper function supplied by that provider at verification/load time.

Requirements:
- Global helper function availability remains stable throughout each program's lifetime
- Provider lifecycle events (registration, re-registration, and unregistration) **MUST NOT** cause running programs to crash, hang, or exhibit undefined behavior
- During provider unregistration:
  - The system **MUST** wait for all in-flight invocations of affected programs to complete before the provider is unloaded
  - New invocations of affected programs **MUST** be blocked, including new program loads that would bind to the unregistering provider's helpers, new attaches of already-loaded affected programs, and new executions of already-attached affected programs
  - Blocked operations **MUST** fail immediately (fail fast) with a documented, retryable error indicating that the provider is temporarily unavailable; blocked operations **MUST NOT** wait for provider unregistration or re-registration to complete
- After a provider is registered again, new invocations initiated after successful re-registration **MAY** resume if the provider's helper signatures/ABIs remain compatible with what was verified during native image generation; operations that failed while the provider was unavailable are not automatically retried

### SC4: Ecosystem Growth
- Independent software vendors can develop eBPF extensions with custom global helper functions without platform dependencies
- Global helper function libraries can be developed and distributed independently by external drivers
- Future extensibility is enabled for advanced scenarios (versioning, namespacing, etc.)

## Non-Requirements

- **Dynamic helper function loading** after program compilation is not required
- **Global helper function versioning** is not required in the initial implementation
- **Namespace management** for global helper function names is not required
- **Runtime global helper function replacement** is not required

## Implementation Constraints

- **Zero breaking changes** to existing APIs or driver interfaces
- **Minimal modifications** to core eBPF subsystems
- **Preserve existing performance** characteristics for current global helpers
- **Maintain security model** for global helper function access and verification

## Implementation Notes

While this document focuses on requirements rather than implementation details, it should be noted that BTF (BPF Type Format) provides a standard mechanism to describe helper function signatures and identify them in a way that is consistent with the BPF ISA standard.

In particular, this design is intended to be compatible with a BTF-based approach:
- Providers can publish helper function prototypes via BTF so the verifier can validate helper calls against the expected signature.
- Helper identity can be expressed using stable identifiers derived from BTF (noting that raw BTF IDs are scoped to a given BTF object, so the overall identity may need to incorporate provider identity and/or a stable BTF identity).
- R7 then ensures that if a provider changes a helper's signature/ABI, programs verified and native-image-generated against the old signature are rejected at load time.

### Source-Level Disambiguation

When multiple providers register helpers with the same C function name, disambiguation at the source level can be achieved through:
- **Provider-specific header files**: Each provider supplies a header file that declares its helpers with provider-qualified metadata (for example, via attributes or macros that embed provider identity into the compiled program's BTF or relocation data).
- **Toolchain-level mapping**: The compilation toolchain can emit provider-qualified identifiers in the program's BTF or relocation records, allowing the loader to resolve the correct implementation.
- **Explicit provider binding at load time**: The program loader API can accept an optional provider binding that specifies which provider(s) should be used for helper resolution when names collide.

The specific mechanism is an implementation choice; the requirement (R2) is that the system must support deterministic resolution and reject ambiguous references with a clear error.

## Conclusion

This requirements document establishes the foundation for enabling external drivers to expose global helper functions to eBPF programs, creating a more flexible and developer-friendly eBPF helper function ecosystem while maintaining complete backward compatibility and system integrity. The solution must eliminate coordination barriers for independent driver development while preserving the reliability and security of the existing eBPF platform.
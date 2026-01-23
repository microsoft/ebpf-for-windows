# Global Helper Functions from External Drivers

## Overview

This document outlines the requirements for enabling drivers outside of `ebpfcore.sys` to expose global helper functions to eBPF programs without requiring centralized management of helper function IDs.

## Problem Statement

The current eBPF for Windows global helper function system requires:
- **Global helpers hosted only in `ebpfcore.sys`** limiting extensibility by third-party drivers
- **Pre-coordination of helper function registration** to prevent conflicts
- **Static management** making it difficult for external drivers to expose custom global helper functions

This creates barriers for independent driver development and limits the extensibility of the eBPF ecosystem by preventing external drivers from contributing global helper functions.

## Requirements

### R1: External Driver Global Helper Registration
- Drivers outside of `ebpfcore.sys` **MUST** be able to register global helper functions
- The system **MUST** support global helper function registration without requiring pre-coordination
- Existing interfaces **MUST** remain unchanged to maintain application compatibility
- New interfaces **MAY** be added if needed to support this capability

### R2: Elimination of Central Coordination
- Driver developers **MUST NOT** be required to coordinate helper function registration with other drivers
- The system **MUST** support global helper registration even when multiple drivers register helper functions with the same name
- Global helper function identity **MUST NOT** rely solely on the helper function name (for example, it can be based on a stable ID such as a BTF ID and/or provider identity)
- Helper function registration **MUST** be managed automatically by the system

### R3: Per-Program Global Helper Resolution
- Each eBPF program **MUST** have access to a consistent set of global helper functions for its lifetime
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

## Success Criteria

### SC1: Driver Independence
- Third-party drivers can register custom global helper functions without coordination with Microsoft or other driver developers
- Global helper function name conflicts are detected and rejected at registration time with clear error messages

### SC2: Developer Experience
- eBPF program developers can use descriptive global helper function names in their C code
- Compilation and loading processes handle global helper function resolution transparently
- Error messages provide clear diagnostics for unavailable global helper functions

### SC3: System Stability
- Global helper function availability remains stable throughout each program's lifetime
- Provider lifecycle events (registration, re-registration, and unregistration) **MUST NOT** cause running programs to crash, hang, or exhibit undefined behavior
- Provider unregistration **MUST** block new invocations of affected eBPF programs and **MUST** wait for in-flight invocations to complete before the provider is unloaded
- After a provider is registered again, new invocations of affected eBPF programs **MAY** resume if the provider's helper function signatures/ABIs remain compatible with what was verified and assumed during native image generation
- System performance is not significantly impacted by global helper function resolution

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

While this document focuses on requirements rather than implementation details, it should be noted that BTF (BPF Type Format) IDs represent one possible mechanism that could be leveraged to implement helper function identification and resolution without requiring pre-coordination between drivers.

## Conclusion

This requirements document establishes the foundation for enabling external drivers to expose global helper functions to eBPF programs, creating a more flexible and developer-friendly eBPF helper function ecosystem while maintaining complete backward compatibility and system integrity. The solution must eliminate coordination barriers for independent driver development while preserving the reliability and security of the existing eBPF platform.
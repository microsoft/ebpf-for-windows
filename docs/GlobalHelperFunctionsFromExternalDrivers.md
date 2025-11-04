# Global Helper Functions from External Drivers

## Overview

This document outlines the requirements for enabling drivers outside of `ebpfcore.sys` to expose global helper functions to eBPF programs without requiring centralized management of helper function IDs.

## Problem Statement

The current eBPF for Windows global helper function system requires:
- **Global helpers hosted only in `ebpfcore.sys`** limiting extensibility by third-party drivers
- **Pre-assigned numeric IDs** for all helper functions
- **Centralized coordination** of helper ID assignments to prevent conflicts
- **Static ID management** making it difficult for external drivers to expose custom global helper functions

This creates barriers for independent driver development and limits the extensibility of the eBPF ecosystem by preventing external drivers from contributing global helper functions.

## Requirements

### R1: External Driver Global Helper Registration
- Drivers outside of `ebpfcore.sys` **MUST** be able to register global helper functions as general program information providers
- The system **MUST** support global helper function registration using descriptive names instead of pre-assigned numeric IDs
- Registration **MUST** use existing NMR (Network Module Registrar) interfaces without modification
- External drivers **MUST** be able to register global helpers with `helper_id = -1` to indicate name-based registration

### R2: Elimination of Central ID Coordination
- Driver developers **MUST NOT** be required to coordinate helper function ID assignments with other drivers
- The system **MUST** reject registration attempts when multiple drivers try to register helper functions with the same name
- Helper function names **MUST** be globally unique across all registered providers
- Helper function ID assignment **MUST** be managed automatically by the runtime

### R3: Per-Program Global Helper Resolution
- Each eBPF program **MUST** maintain its own stable mapping of global helper function names to IDs
- Global helper function IDs **MUST** remain consistent for the lifetime of each program
- The system **MUST** resolve global helper function names to program-specific IDs during program loading
- Programs **MUST** be able to access global helpers from both `ebpfcore.sys` and external drivers

### R4: Backward Compatibility
- Existing global helper functions using numeric IDs **MUST** continue to work unchanged
- Existing driver code **MUST NOT** require modification to continue functioning
- The bpf2c contract **MUST** remain compatible with existing compiled programs
- Mixed usage of named and numeric global helper functions **MUST** be supported within the same program

### R5: External Function Call Support
- eBPF programs compiled from C **MUST** be able to use external function calls that resolve to global helper functions by name
- The bpf2c compiler **MUST** detect external function calls and mark them for name-based resolution
- Generated native code **MUST** support both traditional helper IDs and name-based resolution for global helpers

### R6: Multiple General Program Information Provider Support
- eBPF programs **MUST** be able to utilize global helper functions from multiple general program information providers simultaneously
- The system **MUST** search across all registered providers (including external drivers) when resolving global helper function names
- Provider lifecycle events (attach/detach) **MUST** be handled independently for each provider
- Global helper function name conflicts between providers **MUST** be detected and rejected during registration

### R7: Metadata Integrity
- Program metadata hashing **MUST** remain consistent between compile-time and runtime for name-based global helpers
- Hash computation **MUST** exclude helper IDs for name-based global helpers while including all other prototype information
- Verification **MUST** ensure programs execute with the same global helper function information used during compilation

## Success Criteria

### SC1: Driver Independence
- Third-party drivers can register custom global helper functions without coordination with Microsoft or other driver developers
- Global helper function name conflicts are detected and rejected at registration time with clear error messages

### SC2: Developer Experience
- eBPF program developers can use descriptive global helper function names in their C code
- Compilation and loading processes handle name resolution transparently
- Error messages provide clear diagnostics for unresolvable global helper function names

### SC3: System Stability
- Global helper function ID assignments remain stable throughout each program's lifetime
- Provider lifecycle events do not disrupt running programs
- System performance is not significantly impacted by name resolution overhead

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
- **Minimal code modifications** to core eBPF subsystems
- **Preserve existing performance** characteristics for traditional numeric global helpers
- **Maintain security model** for global helper function access and verification

## Conclusion

This requirements document establishes the foundation for enabling external drivers to expose global helper functions to eBPF programs, creating a more flexible and developer-friendly eBPF helper function ecosystem while maintaining complete backward compatibility and system integrity. The solution must eliminate coordination barriers for independent driver development while preserving the reliability and security of the existing eBPF platform.
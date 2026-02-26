# BTF-resolved functions

## 1 Overview

BTF-resolved functions are a mechanism for Windows kernel drivers to expose functions that can be called directly
from eBPF programs, without requiring those drivers to be program-type specific information providers. Unlike helper
functions, which are identified by a fixed numeric ID, BTF-resolved functions are resolved by name via BTF (BPF Type Format) and
called using the `call_btf` instruction with a BTF ID and module identifier.

This document uses the term "BTF-resolved functions". Linux documentation commonly calls the same
concept "kfuncs".

> **Design status:** This document describes a proposed design.
> The BTF-resolved-function NPI IDs, store APIs, and C types shown here are planned interfaces and are not yet present
> in current public headers.

### 1.1 BTF-resolved functions vs Helper Functions by Static ID

| Aspect | Helper Functions by Static ID | BTF-resolved functions |
|--------|------------------|---------------------------|
| **Resolution** | Fixed numeric ID (0-65535 for global, >65535 for program-type specific) | BTF ID + module ID resolved from function name |
| **Provider** | eBPF runtime (global) or program-type extension (type-specific) | Any driver registered as a BTF-resolved function provider (independent of program-type providers) |
| **Instruction** | `call imm` (src=0) | `call_btf` (src=2, imm=btf_id, offset=module_id) |
| **Namespace** | Single global namespace with reserved ranges | Per-module namespace, disambiguated by module GUID |
| **Discovery** | Compile-time via header inclusion | Compile-time via header with BTF metadata |

### 1.2 Use Cases

BTF-resolved functions enable scenarios such as:
- Exposing driver-specific functionality to eBPF programs without modifying the eBPF core
- Providing specialized operations that are too complex or domain-specific to be general helpers
- Allowing drivers that are not program-type specific providers to extend eBPF capabilities in a modular fashion

## 2 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Compile Time                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────┐   │
│  │ my_prog.c    │    │ clang/LLVM   │    │ my_prog.o (ELF)              │   │
│  │ #include     ├───>│ -g (BTF)     ├───>│ - .ksyms section in BTF      │   │
│  │ <helpers.h>  │    │              │    │ - extern calls with decl_tag │   │
│  └──────────────┘    └──────────────┘    └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     v
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Verification Time                                 │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         bpf2c / netsh                                │   │
│  │  1. Parse .ksyms from BTF                                            │   │
│  │  2. Resolve each helper name:                                        │   │
│  │     - Query registry (BtfResolvedFunctions) for prototype + GUID     │   │
│  │     - Assign session-local module ID (uint16)                        │   │
│  │     - Provide prototype to verifier                                  │   │
│  │  3. Verifier rewrites extern calls to call_btf(btf_id, module_id)    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     v
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Load Time                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        Native Module (.sys)                          │   │
│  │  1. Register as NMR client for BTF-resolved function NPI             │   │
│  │  2. For each provider (by module GUID):                              │   │
│  │     - Attach to provider, receive function addresses                 │   │
│  │  3. Populate import table with resolved addresses                    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     v
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Runtime                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        Program Execution                             │   │
│  │  - call_btf resolves to indirect call through import table           │   │
│  │  - If provider detaches, addresses become NULL                       │   │
│  │  - Program invocation fails until provider reattaches                │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 3 Authoring BTF Helper Headers

Drivers that expose BTF-resolved functions must author a header file that eBPF program developers include. This
header contains:
1. Function declarations with appropriate attributes
2. BTF metadata to place the function in the `.ksyms` section
3. A declaration tag identifying the provider module

### 3.1 Header Format

```c
// Copyright (c) Example Corp
// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>

// Module GUID for this BTF-resolved function provider
// Format: "module_id:{GUID}"
#define MY_DRIVER_MODULE "module_id:{12345678-1234-1234-1234-123456789abc}"

// Declare a BTF-resolved function with BTF metadata
// __attribute__((section(".ksyms"))) places the symbol in the .ksyms BTF section
// __attribute__((btf_decl_tag(MY_DRIVER_MODULE))) associates it with the module
#define DECLARE_BTF_RESOLVED_FUNCTION(ret, name, ...) \
    extern ret name(__VA_ARGS__) \
        __attribute__((section(".ksyms"))) \
        __attribute__((btf_decl_tag(MY_DRIVER_MODULE)))

// Example BTF-resolved function declarations
DECLARE_BTF_RESOLVED_FUNCTION(int, my_driver_lookup, uint64_t key, void* value, uint32_t value_size);
DECLARE_BTF_RESOLVED_FUNCTION(int, my_driver_update, uint64_t key, const void* value, uint32_t value_size);
DECLARE_BTF_RESOLVED_FUNCTION(void, my_driver_log, const char* message, uint32_t length);
```

### 3.2 Module GUID Requirements

- The module GUID must be unique to your driver
- Use the same GUID for registry publication and NMR registration
- The GUID is embedded in the compiled eBPF program and used at load time to find your driver

### 3.3 Function Signature Constraints

BTF-resolved function signatures must follow the same constraints as helper functions:
- Maximum of 5 arguments
- Arguments must be types representable in `ebpf_argument_type_t`
- Return type must be representable in `ebpf_return_type_t`
- Function must be safe to call at the IRQL where eBPF programs execute

## 4 Registry Publication

Drivers that expose BTF-resolved functions must publish their function metadata to the Windows registry. This
allows the verifier to discover and validate helper calls at verification time. The eBPF store can be rooted at either
HKCU or HKLM, so the path below is shown relative to the store root.

### 4.1 Registry Structure

```
Software\eBPF\Providers\BtfResolvedFunctions
└── {12345678-1234-1234-1234-123456789abc}     <- Module GUID
    ├── Version: REG_DWORD = 1
    ├── Size: REG_DWORD = <size of provider data>
    └── Functions
        ├── my_driver_lookup
        │   ├── Prototype: REG_SZ = "int my_driver_lookup(uint64_t, void*, uint32_t)"
        │   ├── ReturnType: REG_DWORD = <ebpf_return_type_t value>
        │   ├── Arguments: REG_BINARY = <array of ebpf_argument_type_t>
        │   └── Flags: REG_DWORD = <flags>
        ├── my_driver_update
        │   └── ...
        └── my_driver_log
            └── ...
```

### 4.2 Publishing via eBPF Store APIs

Similar to program type registration, BTF-resolved function providers can publish metadata via a store API like the
following:

```c
// Structure describing a BTF-resolved function prototype
typedef struct _ebpf_btf_resolved_function_prototype
{
    ebpf_extension_header_t header;
    const char* name;
    ebpf_return_type_t return_type;
    ebpf_argument_type_t arguments[5];
    uint32_t flags;
} ebpf_btf_resolved_function_prototype_t;

// Structure describing a BTF-resolved function provider
typedef struct _ebpf_btf_resolved_function_provider_info
{
    ebpf_extension_header_t header;
    GUID module_guid;
    uint32_t btf_resolved_function_count;
    const ebpf_btf_resolved_function_prototype_t* btf_resolved_function_prototypes;
} ebpf_btf_resolved_function_provider_info_t;

// Proposed API to register BTF-resolved function provider information
ebpf_result_t
ebpf_store_update_btf_resolved_function_provider_information(
    _In_ const ebpf_btf_resolved_function_provider_info_t* provider_info);
```

This API is not currently present in `include/ebpf_store_helper.h`.

## 5 Verifier Integration

The PREVAIL verifier supports BTF-resolved functions through a two-phase resolution process, implemented via
platform callbacks.

### 5.1 Phase 1: ELF Parsing (Symbol Resolution)

When the verifier parses the ELF file, it identifies external function calls in the `.ksyms` BTF section. For each
symbol, it calls the platform callback to resolve the name to a BTF ID and module ID:

```c
// Platform callback signature
typedef bool (*resolve_ksym_btf_id_fn)(
    const char* symbol_name,
    uint32_t* btf_id,        // Output: BTF ID for this symbol
    uint16_t* module_id);    // Output: Session-local module identifier
```

The caller (bpf2c or netsh) implements this callback as a two-step process:
1. **Build helper and module mappings from BTF**
   - Enumerate helper symbols from the `.ksyms` section
   - Enumerate top-level `BTF_KIND_DECL_TAG` entries (entries with no parent)
   - Parse each decl tag string (for example, `module_id:{guid}`) and use the tag's function reference to build the
     module-to-function mapping for `.ksyms` functions
2. **Resolve each symbol**
   - Look up each function in the registry under `BtfResolvedFunctions\{module_guid}\Functions\{name}`
   - Assign a session-local module ID (uint16) and maintain a mapping to the GUID
   - Return the BTF ID from the compiled object's BTF metadata

### 5.2 Phase 2: Verification (Prototype Resolution)

During verification, when the verifier encounters a `call_btf` instruction, it calls back to get the prototype:

```c
// Platform callback signature
typedef const ebpf_helper_function_prototype_t* (*get_btf_resolved_function_prototype_fn)(
    uint32_t btf_id,
    uint16_t module_id);
```

The caller looks up the prototype from the registry using the (btf_id, module_id) → (name, GUID) mapping established
in phase 1.

### 5.3 Instruction Rewriting

The verifier rewrites external calls to BTF-resolved functions as follows:

| Before (extern call) | After (call_btf) |
|---------------------|------------------|
| `call imm=0 (src=1)` | `call imm=btf_id offset=module_id (src=2)` |

The `offset` field (16 bits) stores the module ID, and the `imm` field (32 bits) stores the BTF ID.

### 5.4 BTF ID Stability and Visibility

BTF IDs are assigned by Clang/LLVM when the eBPF object is compiled and are not stable across builds. In eBPF for
Windows, the verifier-rewritten `call_btf` form is ephemeral and consumed by the verifier/bpf2c pipeline; it is not a
long-term persisted interface. Unlike Linux, eBPF for Windows does not expose kernel-code BTF IDs as a public API.

## 6 bpf2c Integration

When generating native code, bpf2c emits a BTF-resolved function import table alongside the existing helper import table.

### 6.1 BTF-resolved Function Entry Structure

```c
typedef struct _btf_resolved_function_entry
{
    ebpf_native_module_header_t header;
    uint64_t zero_marker;      // Marker for section parsing
    const char* name;          // Function name
    GUID module_guid;          // Module GUID for NMR binding
} btf_resolved_function_entry_t;
```

### 6.2 Runtime Context Extension

The `program_runtime_context_t` structure is extended to include BTF-resolved function addresses:

```c
typedef struct _btf_resolved_function_data
{
    helper_function_t address;  // Resolved function address
} btf_resolved_function_data_t;

typedef struct _program_runtime_context
{
    helper_function_data_t* helper_data;
    map_data_t* map_data;
    global_variable_section_data_t* global_variable_section_data;
    btf_resolved_function_data_t* btf_resolved_function_data;  // NEW: BTF-resolved function addresses
} program_runtime_context_t;
```

### 6.3 Generated Code

For a BTF-resolved function call, bpf2c generates:

```c
// BTF-resolved function import table
static btf_resolved_function_entry_t _btf_resolved_functions[] = {
    {BTF_RESOLVED_FUNCTION_ENTRY_HEADER, 0, "my_driver_lookup",
     {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}}},
    {BTF_RESOLVED_FUNCTION_ENTRY_HEADER, 0, "my_driver_update",
     {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}}},
};

// In program code, BTF-resolved function calls go through the runtime context
result = ((int (*)(uint64_t, void*, uint32_t))runtime_context->btf_resolved_function_data[0].address)(key, value, size);
```

### 6.4 Hash Computation

The program info hash (used for proof of verification) must include BTF-resolved function dependencies:

1. For each BTF-resolved function used (in order of BTF ID):
   - `btf_resolved_function_entry_t::name`
   - `btf_resolved_function_entry_t::module_guid`
   - `ebpf_btf_resolved_function_prototype_t::return_type`
   - Each element of `ebpf_btf_resolved_function_prototype_t::arguments`
   - `ebpf_btf_resolved_function_prototype_t::flags` (only if non-default)

## 7 NMR Provider Registration

Drivers that expose BTF-resolved functions register as NMR providers for the BTF-resolved function NPI.

### 7.1 NPI Definition

The GUID name below is a proposed identifier and is not currently present in `include/ebpf_extension_uuids.h`.

```c
// BTF-resolved function NPI ID
static const GUID EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID = {
    0xaabbccdd, 0x1234, 0x5678, {0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78}};
```

### 7.2 Provider Registration

When registering as an NMR provider:
- `NpiId`: Set to the proposed `EBPF_BTF_RESOLVED_FUNCTION_EXTENSION_IID` once this identifier is added
- `ModuleId`: Set to the driver's module GUID (same as in the header and registry)
- `NpiSpecificCharacteristics`: Pointer to `ebpf_btf_resolved_function_provider_data_t`

```c
typedef struct _ebpf_btf_resolved_function_provider_data
{
    ebpf_extension_header_t header;
    uint32_t btf_resolved_function_count;
    const ebpf_btf_resolved_function_prototype_t* btf_resolved_function_prototypes;
    const uint64_t* btf_resolved_function_addresses;  // Addresses of the BTF-resolved function implementations
} ebpf_btf_resolved_function_provider_data_t;
```

### 7.3 Provider Dispatch Table

The BTF-resolved function provider does not require a dispatch table. Function addresses are provided directly in the
provider data.

## 8 Native Module Loading

When a native module (.sys) is loaded, it attaches to BTF-resolved function providers to resolve function addresses.

### 8.1 NMR Client Registration

The native module skeleton registers as an NMR client for the BTF-resolved function NPI with a wildcard module ID, meaning
it will receive attach callbacks for all registered BTF-resolved function providers.

### 8.2 Client Attach Callback

When NMR calls the client attach callback for a BTF-resolved function provider:

1. Check if the provider's module GUID matches any entry in the BTF-resolved function import table
2. If yes:
   - Store the binding handle
   - Copy function addresses to the `btf_resolved_function_data` array in the runtime context
   - Record the binding in the module's BTF-resolved function provider binding list
3. If no: Return `STATUS_NOINTERFACE` to decline the binding

### 8.3 Client Detach Callback

When a BTF-resolved function provider detaches:

1. Set the corresponding `btf_resolved_function_data` addresses to NULL
2. Mark the binding as detached
3. If the program is currently executing, wait for completion
4. Invoke `btf_resolved_function_addresses_changed_callback` if registered

### 8.4 Multiple BTF Helper Providers

A single eBPF program may use BTF-resolved functions from multiple providers. The native module maintains:

```c
typedef struct _ebpf_btf_resolved_function_provider_binding
{
    GUID module_guid;
    HANDLE nmr_binding_handle;
    bool attached;
} ebpf_btf_resolved_function_provider_binding_t;
```

All required providers must be attached before the program can execute.

## 9 Runtime Execution

### 9.1 Program Invocation

Before invoking an eBPF program that uses BTF-resolved functions:

1. Check that all required BTF-resolved function providers are attached
2. If any provider is detached, return `EBPF_EXTENSION_FAILED_TO_LOAD`
3. Take rundown protection on all BTF-resolved function bindings
4. Execute the program (BTF-resolved function calls go through runtime context indirection)
5. Release rundown protection

### 9.2 Address Change Notification

Similar to helper functions, BTF-resolved function address changes are propagated via callback:

```c
typedef ebpf_result_t (*ebpf_btf_resolved_function_addresses_changed_callback_t)(
    size_t address_count,
    _In_reads_(address_count) const uint64_t* addresses,
    _Inout_ void* context);
```

For JIT-compiled programs, this callback updates the jump table. For native programs, the runtime context is updated
directly.

### 9.3 Error Handling

| Scenario | Behavior |
|----------|----------|
| BTF-resolved function provider not registered | Program load fails with `EBPF_EXTENSION_FAILED_TO_LOAD` |
| BTF-resolved function provider detaches while program loaded | Program invocation fails until provider reattaches |
| BTF-resolved function provider detaches during program execution | Execution completes, subsequent invocations fail |

## 10 Internal Changes to ebpf_program_t

The `ebpf_program_t` structure requires the following additions to support BTF-resolved functions:

```c
// New structure for tracking BTF-resolved function provider bindings
typedef struct _ebpf_btf_resolved_function_binding
{
    GUID module_guid;
    HANDLE nmr_binding_handle;
    const ebpf_btf_resolved_function_provider_data_t* provider_data;
    bool attached;
} ebpf_btf_resolved_function_binding_t;

// Additions to ebpf_program_t
typedef struct _ebpf_program_t
{
    // ... existing fields ...

    // BTF-resolved function support
    _Guarded_by_(lock) ebpf_btf_resolved_function_binding_t* btf_resolved_function_bindings;
    _Guarded_by_(lock) size_t btf_resolved_function_binding_count;
    _Guarded_by_(lock) uint64_t* btf_resolved_function_addresses;  // Resolved addresses array
    _Guarded_by_(lock) size_t btf_resolved_function_count;
    _Guarded_by_(lock) ebpf_btf_resolved_function_addresses_changed_callback_t btf_resolved_function_addresses_changed_callback;
    _Guarded_by_(lock) void* btf_resolved_function_addresses_changed_context;
} ebpf_program_t;
```

### 10.1 Lifecycle

1. **Program Creation**: Allocate arrays based on BTF-resolved function import table size
2. **NMR Client Registration**: Register for BTF-resolved function NPI to receive provider attach callbacks
3. **Provider Attach**: Populate `btf_resolved_function_bindings` and `btf_resolved_function_addresses`
4. **Program Load**: Verify all required providers are attached
5. **Provider Detach**: Clear addresses, invoke callback, wait for rundown
6. **Program Free**: Deregister NMR client, free arrays

## 11 Security Considerations

### 11.1 Provider Authentication

BTF-resolved function providers are kernel drivers and must be signed according to Windows driver signing requirements. The
eBPF runtime does not perform additional authentication beyond what Windows enforces.

### 11.2 Verification Guarantees

The verifier validates that:
- All BTF-resolved function calls have valid prototypes registered
- Argument types match the declared prototype
- Return values are handled correctly

The program info hash includes BTF-resolved function dependencies, ensuring that a signed native module cannot call helpers
that were not present during verification.

### 11.3 Isolation

Each BTF-resolved function provider is responsible for:
- Validating arguments passed from eBPF programs
- Ensuring safe execution at the IRQL where programs run
- Not exposing security-sensitive operations without proper authorization

## 12 Future Considerations

### 12.1 BTF-resolved Function Sets

A future enhancement could support "BTF-resolved function sets" - groups of related functions that are versioned together.
This would simplify compatibility management when BTF-resolved function signatures evolve.

### 12.2 Per-Program BTF-resolved Function Authorization

A policy mechanism could allow administrators to control which programs can call which BTF-resolved functions,
providing finer-grained
security control.

### 12.3 Dynamic BTF-resolved Function Discovery

Currently, BTF-resolved function metadata must be in the registry at verification time. Dynamic discovery could allow
programs to query available BTF-resolved functions at runtime, enabling more flexible extension models.

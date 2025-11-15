# eBPF-for-Windows Extensible Maps Design Document

## Table of Contents
1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Architecture](#architecture)
4. [Detailed Design](#detailed-design)
5. [API Specifications](#api-specifications)
6. [Implementation Plan](#implementation-plan)
7. [Testing Strategy](#testing-strategy)
8. [Performance Considerations](#performance-considerations)
9. [Security Considerations](#security-considerations)
10. [Compatibility and Migration](#compatibility-and-migration)

## Overview

### Purpose
This document defines the design and implementation requirements for Extensible Maps in eBPF-for-Windows. Extensible Maps are program-type-specific maps implemented by extensions (program info providers) rather than the core eBPF runtime.

### Goals
- Enable program info providers to implement custom map types
- Maintain compatibility with existing eBPF map APIs
- Ensure proper lifecycle management and security isolation
- Provide performance comparable to built-in maps
- Support dynamic extension loading/unloading where possible

### Non-Goals
- Modifying existing global map implementations
- Breaking compatibility with existing eBPF programs
- Supporting map types that violate eBPF semantics

## Requirements

### Functional Requirements
- **FR1**: Extensions must be able to register custom map types with unique IDs
- **FR2**: Custom maps must support all standard eBPF map operations (create, lookup, update, delete)
- **FR3**: Custom maps must integrate with existing eBPF usermode and kernel APIs
- **FR4**: Map lifecycle must be managed by eBPFCore with extension callbacks
- **FR5**: Extensions must validate map-to-program-type associations
- **FR6**: Custom maps must support pinning and sharing between programs

### Non-Functional Requirements
- **NFR1**: Map operations must have minimal performance overhead
- **NFR2**: Extension failures must not crash eBPFCore
- **NFR3**: Memory usage must be tracked and bounded
- **NFR4**: Extensions with active maps cannot be unloaded
- **NFR5**: All operations must be thread-safe

## Architecture

### High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Mode     │    │   eBPFCore      │    │   Extension     │
│   Application   │    │                 │    │   (Provider)    │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ bpf_create_map()│────│ NMR Map Client  │────│ Custom Map Impl │
│ bpf_map_lookup()│    │ Provider Lookup │    │ NMR Provider    │
│ bpf_map_update()│    │ Lifecycle Mgmt  │    │ Validation      │
│ bpf_map_delete()│    │ Reference Count │    │ CRUD Operations │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### NMR Client-Provider Pattern
Following the same pattern used by programs and links:
- **Map Creation**: Each extensible map registers as NMR client to find its provider
- **Dynamic Discovery**: No central registry - providers discovered via NMR at runtime
- **Lifecycle Management**: Maps attach/detach from providers using NMR callbacks

### Map ID Namespace Partitioning

```
Map Type ID Range:
├── 1-4095:     Global/Built-in Maps (BPF_MAP_TYPE_*)
└── 4096+:      Extensible Maps (EBPF_MAP_TYPE_EXTENSIBLE_*)
```

## Detailed Design

### 1. Data Structures

#### Core Map Structure
```c
// New extensible map structure
typedef struct _ebpf_extensible_map {
    ebpf_core_map_t core_map;                    // Base map structure
    void* extension_map_context;                 // Extension-specific map data
    
    // NMR client components (similar to ebpf_program_t and ebpf_link_t)
    NPI_CLIENT_CHARACTERISTICS client_characteristics;
    HANDLE nmr_client_handle;
    NPI_MODULEID module_id;
    
    ebpf_lock_t lock;                            // Synchronization
    _Guarded_by_(lock) const ebpf_extensible_map_provider_t* provider; // Provider interface
    _Guarded_by_(lock) bool provider_attached;   // Provider attachment state
    _Guarded_by_(lock) uint32_t reference_count; // Lifecycle management
    
    EX_RUNDOWN_REF provider_rundown_reference;  // Synchronization for provider access
} ebpf_extensible_map_t;
```

#### Provider Interface Structure
```c
typedef struct _ebpf_extensible_map_provider {
    // Provider identification  
    GUID provider_guid;
    uint32_t supported_map_type;        // Single map type per provider (follows NMR pattern)
    
    // Map lifecycle operations
    ebpf_result_t (*map_create)(
        uint32_t map_type,
        uint32_t key_size,
        uint32_t value_size,
        uint32_t max_entries,
        const ebpf_map_definition_in_memory_t* map_definition,
        void** map_context);
    
    void (*map_delete)(void* map_context);
    
    // Map data operations
    ebpf_result_t (*map_lookup)(
        void* map_context,
        const uint8_t* key,
        uint8_t* value);
    
    ebpf_result_t (*map_update)(
        void* map_context,
        const uint8_t* key,
        const uint8_t* value,
        uint64_t flags);
    
    ebpf_result_t (*map_delete_element)(
        void* map_context,
        const uint8_t* key);
    
    // Validation and compatibility
    ebpf_result_t (*validate_map_program_association)(
        uint32_t map_type,
        const GUID* program_type);
    
    // Iterator support (optional)
    ebpf_result_t (*map_get_next_key)(
        void* map_context,
        const uint8_t* previous_key,
        uint8_t* next_key);
        
} ebpf_extensible_map_provider_t;
### 2. Core Workflows

#### Extension Registration Flow (Same as existing program providers)
```
1. Extension loads and registers as NMR provider with EBPF_MAP_EXTENSION_IID
2. Provider specifies supported_map_type in extension data
3. Provider is available for NMR client attachment
4. No central registry - discovery happens per map creation
```

#### Map Creation Flow (Similar to ebpf_link_create pattern)
```
1. User calls bpf_create_map() with extensible map type
2. eBPFAPI validates map type and parameters  
3. eBPFCore receives map creation request
4. eBPFCore checks if map_type >= 4096 (extensible range)
5. eBPFCore creates ebpf_extensible_map_t with NMR client characteristics
6. eBPFCore calls NmrRegisterClient() to find provider for this map_type
7. NMR calls _ebpf_extensible_map_client_attach_provider callback
8. If provider found and compatible, provider->map_create() is called
9. Map handle returned to user
```

#### Map Operation Flow (Using rundown protection like programs)
```
1. User calls map operation (lookup/update/delete)
2. eBPFCore identifies map as extensible
3. eBPFCore acquires rundown protection on provider_rundown_reference
4. If rundown acquired successfully:
   a. eBPFCore calls provider operation function
   b. eBPFCore releases rundown protection
5. Result returned to user
```

## API Specifications

### 1. Extension Provider APIs

#### Map Provider Registration (Using Standard NMR Pattern)
```c
// Extensions use standard NMR registration - no special APIs needed
// Example extension registration:
static const ebpf_map_extension_data_t sample_map_extension_data = {
    .version = 1,
    .size = sizeof(ebpf_map_extension_data_t),
    .supported_map_type = EBPF_MAP_TYPE_SAMPLE,  // Single map type per provider
    .provider_interface = &sample_map_provider,
};

static const NPI_PROVIDER_CHARACTERISTICS sample_provider_characteristics = {
    0,
    sizeof(sample_provider_characteristics),
    sample_provider_attach_client,
    sample_provider_detach_client,
    NULL,
    {
        0,
        sizeof(NPI_REGISTRATION_INSTANCE),
        &EBPF_MAP_EXTENSION_IID,
        &sample_map_extension_data,
        0,
        NULL,
    },
};

// Standard NMR provider registration
NTSTATUS status = NmrRegisterProvider(&sample_provider_characteristics, extension_context, &provider_handle);
```

### 2. Core Integration APIs

#### Map Creation Extension (Following ebpf_link pattern)
```c
// Internal API - extends existing map creation
ebpf_result_t ebpf_core_create_extensible_map(
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t* map_handle);
```

#### NMR Client Callbacks (Similar to ebpf_link callbacks)
```c
// Called by NMR when provider is found
static NTSTATUS _ebpf_extensible_map_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance);

// Called by NMR when provider detaches  
static NTSTATUS _ebpf_extensible_map_client_detach_provider(
    _In_ void* client_binding_context);
```

### 3. Helper Function Extensions

#### Map Helper Routing
```c
// Internal - routes map helpers to appropriate implementation
ebpf_result_t ebpf_core_map_lookup_helper(
    ebpf_map_t* map,
    const uint8_t* key,
    uint8_t* value);

ebpf_result_t ebpf_core_map_update_helper(
    ebpf_map_t* map,
    const uint8_t* key,
    const uint8_t* value,
    uint64_t flags);
```

## Sample Extension Update for Testing

### Overview
To test the extensible maps functionality, the existing sample extension (`undocked/tests/sample/ext/drv/`) needs to be updated to register as a map provider for `BPF_MAP_TYPE_SAMPLE_MAP` (value 0xF000, already defined in `ebpf_structs.h`).

### Current Sample Extension Architecture
The sample extension already demonstrates the NMR provider pattern with two providers:
1. **Program Info Provider**: Registers with `EBPF_PROGRAM_INFO_EXTENSION_IID`
2. **Hook Provider**: Registers with `EBPF_HOOK_EXTENSION_IID`

We'll add a third provider following the same pattern:
3. **Map Provider**: Registers with `EBPF_MAP_EXTENSION_IID`

### Required Changes

#### 1. Add Map Provider Data Structure (sample_ext.c)
```c
// Map provider extension data
static ebpf_map_extension_data_t _sample_ebpf_extension_map_provider_data = {
    .version = 1,
    .size = sizeof(ebpf_map_extension_data_t),
    .supported_map_type = BPF_MAP_TYPE_SAMPLE_MAP,
    .provider_interface = &_sample_ebpf_extension_map_provider,
};

// Module ID for map provider
NPI_MODULEID DECLSPEC_SELECTANY _sample_ebpf_extension_map_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {BPF_MAP_TYPE_SAMPLE_MAP, 0, 0, {0}}
};
```

#### 2. Add Map Provider Interface Implementation (sample_ext.c)
```c
// Sample map provider implementation
static ebpf_result_t _sample_map_create(
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size, 
    uint32_t max_entries,
    const ebpf_map_definition_in_memory_t* map_definition,
    void** map_context)
{
    // Simple hash table implementation for testing
    // Allocate context, initialize hash table, etc.
    return EBPF_SUCCESS;
}

static void _sample_map_delete(void* map_context)
{
    // Cleanup map context
    if (map_context) {
        CXPLAT_FREE(map_context);
    }
}

static ebpf_result_t _sample_map_lookup(
    void* map_context,
    const uint8_t* key,
    uint8_t* value)
{
    // Implement lookup logic
    return EBPF_SUCCESS;
}

static ebpf_result_t _sample_map_update(
    void* map_context,
    const uint8_t* key,
    const uint8_t* value,
    uint64_t flags)
{
    // Implement update logic
    return EBPF_SUCCESS;
}

static ebpf_result_t _sample_map_delete_element(
    void* map_context,
    const uint8_t* key)
{
    // Implement delete logic
    return EBPF_SUCCESS;
}

static ebpf_result_t _sample_map_get_next_key(
    void* map_context,
    const uint8_t* previous_key,
    uint8_t* next_key)
{
    // Implement iterator logic
    return EBPF_SUCCESS;
}

static const ebpf_extensible_map_provider_t _sample_ebpf_extension_map_provider = {
    .provider_guid = SAMPLE_MAP_PROVIDER_GUID,
    .supported_map_type = BPF_MAP_TYPE_SAMPLE_MAP,
    .map_create = _sample_map_create,
    .map_delete = _sample_map_delete,
    .map_lookup = _sample_map_lookup,
    .map_update = _sample_map_update,
    .map_delete_element = _sample_map_delete_element,
    .map_get_next_key = _sample_map_get_next_key,
};
```

#### 3. Add NMR Provider Characteristics (sample_ext.c)
```c
// Sample eBPF extension Map NPI provider characteristics
const NPI_PROVIDER_CHARACTERISTICS _sample_ebpf_extension_map_provider_characteristics = {
    0,
    sizeof(NPI_PROVIDER_CHARACTERISTICS),
    _sample_ebpf_extension_map_provider_attach_client,
    _sample_ebpf_extension_map_provider_detach_client,
    _sample_ebpf_extension_map_provider_cleanup_binding_context,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &EBPF_MAP_EXTENSION_IID,
     &_sample_ebpf_extension_map_provider_moduleid,
     0,
     &_sample_ebpf_extension_map_provider_data},
};
```

#### 4. Add NMR Callbacks (sample_ext.c)
```c
// Map provider client context
typedef struct _sample_ebpf_extension_map_client {
    HANDLE nmr_binding_handle;
    GUID client_module_id;
} sample_ebpf_extension_map_client_t;

typedef struct _sample_ebpf_extension_map_provider {
    HANDLE nmr_provider_handle;
} sample_ebpf_extension_map_provider_t;

static sample_ebpf_extension_map_provider_t _sample_ebpf_extension_map_provider_context = {0};

static NTSTATUS _sample_ebpf_extension_map_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
    _In_ const void* client_dispatch,
    _Outptr_ void** provider_binding_context,
    _Outptr_result_maybenull_ const void** provider_dispatch)
{
    // Implementation similar to existing attach callbacks
    // Validate client, allocate binding context, etc.
    return STATUS_SUCCESS;
}

static NTSTATUS _sample_ebpf_extension_map_provider_detach_client(
    _In_ const void* provider_binding_context)
{
    // Cleanup binding context
    return STATUS_SUCCESS;
}

static void _sample_ebpf_extension_map_provider_cleanup_binding_context(
    _Frees_ptr_ void* provider_binding_context)
{
    // Free binding context
    if (provider_binding_context) {
        CXPLAT_FREE(provider_binding_context);
    }
}
```

#### 5. Add Registration Functions (sample_ext.c)
```c
NTSTATUS sample_ebpf_extension_map_provider_register()
{
    sample_ebpf_extension_map_provider_t* local_provider_context;
    NTSTATUS status = STATUS_SUCCESS;

    local_provider_context = &_sample_ebpf_extension_map_provider_context;

    status = NmrRegisterProvider(
        &_sample_ebpf_extension_map_provider_characteristics,
        local_provider_context,
        &local_provider_context->nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        sample_ebpf_extension_map_provider_unregister();
    }
    return status;
}

void sample_ebpf_extension_map_provider_unregister()
{
    sample_ebpf_extension_map_provider_t* provider_context = &_sample_ebpf_extension_map_provider_context;
    if (provider_context->nmr_provider_handle != NULL) {
        NTSTATUS status = NmrDeregisterProvider(provider_context->nmr_provider_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForProviderDeregisterComplete(provider_context->nmr_provider_handle);
        }
        provider_context->nmr_provider_handle = NULL;
    }
}
```

#### 6. Update Driver Entry/Unload (sample_ext_drv.c)
```c
// In _sample_ebpf_ext_driver_initialize_objects():
status = sample_ebpf_extension_program_info_provider_register();
if (!NT_SUCCESS(status)) {
    goto Exit;
}

status = sample_ebpf_extension_hook_provider_register();
if (!NT_SUCCESS(status)) {
    goto Exit;
}

// ADD THIS:
status = sample_ebpf_extension_map_provider_register();
if (!NT_SUCCESS(status)) {
    goto Exit;
}

// In _sample_ebpf_ext_driver_unload():
sample_ebpf_extension_program_info_provider_unregister();
sample_ebpf_extension_hook_provider_unregister();
// ADD THIS:
sample_ebpf_extension_map_provider_unregister();
```

#### 7. Update Header File (sample_ext.h)
```c
// Add function declarations
NTSTATUS sample_ebpf_extension_map_provider_register();
void sample_ebpf_extension_map_provider_unregister();

// Add GUID definition
#define SAMPLE_MAP_PROVIDER_GUID \
    {0x11223344, 0x5566, 0x7788, {0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}}
```

### Testing the Implementation
Once updated, the sample extension will:
1. Register as a map provider for `BPF_MAP_TYPE_SAMPLE_MAP`
2. Accept map creation requests from eBPFCore
3. Provide a simple map implementation for testing
4. Allow end-to-end testing of the extensible maps feature

### Integration with Existing Tests
The existing sample tests can be extended to:
- Create maps of type `BPF_MAP_TYPE_SAMPLE_MAP`
- Perform map operations (lookup, update, delete)
- Verify map behavior with sample programs
- Test map lifecycle and cleanup scenarios



### Phase 1: Core Infrastructure (4-6 weeks)
1. **Week 1-2**: Implement NMR interface and client/provider callbacks
   - Define EBPF_MAP_EXTENSION_IID interface
   - Implement _ebpf_extensible_map_client_attach_provider callback  
   - Implement _ebpf_extensible_map_client_detach_provider callback
   - Create client characteristics structure

2. **Week 3-4**: Implement core map structures and NMR client registration
   - Define ebpf_extensible_map_t structure with NMR components
   - Implement map creation with NmrRegisterClient() call
   - Create provider attachment/detachment logic
   - Add rundown protection for provider access

3. **Week 5-6**: Integrate with existing map APIs
   - Extend map creation APIs to handle extensible maps
   - Route helper functions to providers using rundown protection
   - Implement lifecycle management and cleanup

### Phase 2: Advanced Features (3-4 weeks)
1. **Week 7-8**: Implement pinning and sharing support
   - Extend pinning APIs for extensible maps
   - Implement map sharing between programs
   - Add reference counting

2. **Week 9-10**: Add validation and error handling
   - Implement program-map association validation
   - Add comprehensive error handling
   - Create provider failure recovery

### Phase 3: Optimization and Testing (4-5 weeks)
1. **Week 11-12**: Performance optimization
   - Optimize provider lookup performance
   - Minimize lock contention
   - Add performance telemetry

2. **Week 13-15**: Comprehensive testing
   - Unit tests for all components
   - Integration tests with sample extensions
   - Stress testing and performance validation

### Phase 4: Documentation and Samples (2-3 weeks)
1. **Week 16-17**: Create extension developer guide
   - API documentation
   - Sample extension implementation
   - Best practices guide

2. **Week 18**: Final validation and release preparation
   - Code review and security audit
   - Performance benchmarking
   - Release documentation

## Testing Strategy

### Unit Tests
- **NMR Client/Provider Tests**
  - Valid/invalid provider attachment via NMR
  - Multiple providers for same map type (NMR should find first compatible)
  - Provider detachment during map operations
  - Rundown protection validation

- **Map Creation Tests**
  - Valid/invalid map creation parameters
  - Provider attachment failure handling 
  - NMR client registration/deregistration
  - Memory leak verification

- **Map Operation Tests**
  - Basic CRUD operations with rundown protection
  - Concurrent access scenarios
  - Provider unavailability handling
  - Provider detachment during operations

### Integration Tests
- **End-to-End Scenarios**
  - Complete map lifecycle with extensions
  - Multiple extensions with different map types
  - Extension loading/unloading scenarios

- **Compatibility Tests**
  - Existing eBPF programs with new map types
  - Mixed global and extensible maps
  - API compatibility verification

### Performance Tests
- **Throughput Testing**
  - Map operation throughput comparison
  - Scalability with multiple extensions
  - Memory usage under load

- **Latency Testing**
  - Operation latency measurements
  - Provider lookup overhead
  - Lock contention analysis

### Stress Tests
- **Resource Exhaustion**
  - Maximum number of maps
  - Provider failure scenarios
  - Memory pressure conditions

- **Concurrency Testing**
  - High concurrency map operations
  - Provider registration during operations
  - Race condition detection

## Performance Considerations

### Critical Performance Paths
1. **Map Operations**: Minimize overhead in rundown protection acquire/release
2. **Provider Access**: Use efficient rundown reference pattern (no hash table lookups)
3. **NMR Client Registration**: Optimize one-time cost during map creation
4. **Memory Allocation**: Pool allocation for frequent operations

### Performance Targets
- **Map Operation Overhead**: < 5% compared to global maps (better than registry approach)
- **Rundown Protection**: < 50ns acquire/release overhead
- **Memory Overhead**: < 512 bytes per extensible map (no registry overhead)
- **Concurrent Operations**: Support 1000+ operations/second

### Optimization Strategies
- Cache provider interface pointer in map structure (no lookups)
- Use optimized rundown protection for provider access
- Minimize memory allocations in hot paths
- NMR handles provider discovery - no custom lookup logic needed

## Security Considerations

### Attack Surface Analysis
1. **Provider Interface**: Validate all provider-supplied function pointers
2. **Map Data**: Ensure proper bounds checking in all operations
3. **Memory Management**: Prevent buffer overflows and use-after-free
4. **Resource Limits**: Enforce limits on map count and memory usage

### Mitigation Strategies
- **Input Validation**: Validate all parameters at API boundaries
- **Capability Checking**: Verify caller permissions for map operations
- **Memory Safety**: Use safe memory allocation and deallocation patterns
- **Provider Isolation**: Isolate provider failures from core system
- **Audit Logging**: Log all security-relevant operations

### Security Requirements
- All provider callbacks must be called at appropriate IRQL
- Provider failures must not compromise system stability
- Map data must be properly isolated between programs
- Extension unloading must cleanup all resources

## Compatibility and Migration

### Backward Compatibility
- All existing eBPF programs continue to work unchanged
- Global map types (1-4095) remain unchanged
- Existing APIs maintain same semantics
- No breaking changes to user-mode or kernel APIs

### Migration Path
1. **Phase 1**: Introduce extensible map support alongside existing maps
2. **Phase 2**: Provide migration utilities for custom map implementations
3. **Phase 3**: Deprecate any legacy custom map approaches (if any)

### Version Management
- Support multiple versions of provider interface
- Graceful fallback for older providers
- Clear deprecation timeline for interface changes

## Appendices

### Appendix A: Error Codes
```c
// New error codes for extensible maps
#define EBPF_ERROR_EXTENSION_NOT_FOUND          0x80000001
#define EBPF_ERROR_EXTENSION_PROVIDER_FAILED    0x80000002
#define EBPF_ERROR_INVALID_MAP_TYPE             0x80000003
#define EBPF_ERROR_PROVIDER_UNAVAILABLE         0x80000004
#define EBPF_ERROR_MAP_TYPE_NOT_SUPPORTED       0x80000005
```

### Appendix B: Configuration Options
```c
// Configuration for extensible maps (NMR-based)
#define EBPF_EXTENSIBLE_MAP_OPERATION_TIMEOUT_MS   5000
#define EBPF_EXTENSIBLE_MAP_MAX_CONCURRENT_MAPS    1024
#define EBPF_EXTENSIBLE_MAP_PROVIDER_ATTACH_TIMEOUT_MS 1000
```

### Appendix C: Sample Extension Implementation
```c
// Example of minimal extensible map provider (following NMR pattern)
static ebpf_result_t sample_map_create(/* parameters */) {
    // Implementation details
}

static const ebpf_extensible_map_provider_t sample_provider = {
    .provider_guid = SAMPLE_PROVIDER_GUID,
    .supported_map_type = EBPF_MAP_TYPE_SAMPLE,  // Single map type
    .map_create = sample_map_create,
    // ... other function pointers
};

// NMR provider registration (standard pattern)
static const ebpf_map_extension_data_t sample_extension_data = {
    .version = 1,
    .size = sizeof(ebpf_map_extension_data_t),
    .supported_map_type = EBPF_MAP_TYPE_SAMPLE,
    .provider_interface = &sample_provider,
};

static NTSTATUS sample_provider_attach_client(/* standard NMR parameters */) {
    // Validate client and attach
}

static const NPI_PROVIDER_CHARACTERISTICS sample_provider_characteristics = {
    // Standard NMR provider characteristics
    .ProviderAttachClient = sample_provider_attach_client,
    .ProviderDetachClient = sample_provider_detach_client,
    .ProviderRegistrationInstance = {
        .NpiId = &EBPF_MAP_EXTENSION_IID,
        .ModuleId = &sample_module_id,
        .NpiSpecificCharacteristics = &sample_extension_data,
    },
};
```

---

**Document Version**: 1.0  
**Last Updated**: November 14, 2025  
**Authors**: eBPF-for-Windows Development Team  
**Review Status**: Draft for Implementation
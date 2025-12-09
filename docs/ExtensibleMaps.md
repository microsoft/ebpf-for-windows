# Introduction

Extensible maps are custom map types that can be implemented by eBPF extensions (e.g. BPF_MAP_TYPE_XSKMAP) through a new
NMR (Network Module Registrar) provider interface. This document contains the design for adding support for extensible
maps in eBPF-for-Windows. Extensible maps enable extensions to register and manage their own map types beyond those
provided by the core eBPF runtime.

## NMR Interface for Extensions
A new NMR interface is added and extensions register as map info providers using NMR, similar to existing program and
hook providers.

**New NMR Provider Interface**: `EBPF_MAP_INFO_EXTENSION_IID`

**Provider Registration Data**:
```c
typedef struct _ebpf_map_provider_data {
    ebpf_extension_header_t header;
    uint32_t map_type;  // Single map type per provider
    ebpf_map_provider_dispatch_table_t* dispatch_table;
} ebpf_map_provider_data_t;
```

**Provider Dispatch Table**:
```c
typedef struct _ebpf_map_provider_dispatch_table {
    ebpf_extension_header_t header;
    _Notnull_ ebpf_map_create_t create_map_function;
    _Notnull_ ebpf_map_delete_t delete_map_function;
    _Notnull_ ebpf_map_associate_program_type_t associate_program_function;
    ebpf_map_find_element_t find_element_function;
    ebpf_map_update_element_t update_element_function;
    ebpf_map_delete_element_t delete_element_function;
    ebpf_map_get_next_key_and_value_t get_next_key_and_value_function;
} ebpf_map_provider_dispatch_table_t;
```

**Client Services** (provided by eBPF core):
```c
typedef struct _ebpf_map_client_dispatch_table {
    ebpf_extension_header_t header;
    epoch_allocate_with_tag_t epoch_allocate_with_tag;
    epoch_allocate_cache_aligned_with_tag_t epoch_allocate_cache_aligned_with_tag;
    epoch_free_t epoch_free;
    epoch_free_cache_aligned_t epoch_free_cache_aligned;
} ebpf_map_client_dispatch_table_t;
```

## Map Type Enum Partitioning
Currently map type IDs are allocated from a global namespace. With extensible maps, global map type ID space is
partitioned into 2 disjoint sets: for global maps (implemented in eBPFCore) and for the extensible maps.
Global maps will use IDs from 1 to 4095. Extensible maps will use IDs 4096 onwards.

- **Global Maps (1-4095)**: Reserved for core eBPF runtime map types (hash, array, etc.)
- **Extensible Maps (4096+)**: Available for extension-implemented custom map types

Extensions *can* reserve unique map type IDs by submitting PRs to update the enum in the eBPF repository.

## Map Discovery and Creation

**Dynamic Provider Discovery**: Uses NMR's built-in discovery mechanism
- No central registry required - providers are discovered on-demand during map creation
- When a map is created with an extensible type (>= 4096), eBPF core:
  1. Creates an `ebpf_extensible_map_t` structure with NMR client characteristics
  2. Calls `NmrRegisterClient()` to find a provider for the specific map type
  3. On successful provider attachment, delegates map creation to the provider
  4. Returns map handle to user application

**Map Creation Flow**:
```
User calls bpf_create_map(BPF_MAP_TYPE_CUSTOM, ...)
    ↓
ebpfapi validates parameters
    ↓
ebpfcore checks if map_type >= 4096
    ↓
ebpfcore creates extensible map with NMR client
    ↓
NMR finds and attaches to provider
    ↓
Provider creates actual map instance
    ↓
Map handle returned to user
```

## Verification
- No impact on verification (online or offline), as the verifier only cares about the actual map definitions.

## Map Lifecycle
**Provider Binding**: eBPF core maintains map lifecycle and coordinates with extensions for map creation, deletion,
and othr map operations.
- eBPF core creates a corresponding map entry for each extensible map.
- Map CRUD operations are delegated to the extension via dispatch table function pointers.
- Map lifetime managed by eBPF core, including proper cleanup coordination.
- Map pinning handled by eBPF core as it impacts map lifetime.

**Note**: Extensions with active maps cannot unload / restart until the map is deleted.

## Map CRUD APIs

### User-mode APIs
**Transparent Compatibility**: All existing libbpf APIs work unchanged with extensible maps
- `bpf_create_map()` / `bpf_map_create()` - Creates extensible maps when type >= 4096
- `bpf_map_lookup_elem()` - Lookup operations routed to provider
- `bpf_map_update_elem()` - Update operations routed to provider
- `bpf_map_delete_elem()` - Delete operations routed to provider
- `bpf_map_get_next_key()` - Iteration routed to provider

### eBPF Helper Functions
**Transparent Helper Routing**: Map helpers automatically work with extensible maps
- `bpf_map_lookup_elem()` helper detects extensible maps and routes to provider
- `bpf_map_update_elem()` helper routes update operations to provider
- `bpf_map_delete_elem()` helper routes delete operations to provider

### Batch Operations
**Advanced Features** (implemented in test scenarios):
- `update_batch()` - Batch update operations
- `delete_batch()` - Batch delete operations
- `lookup_and_delete_batch()` - Atomic lookup and delete operations

## Memory Management and RCU Semantics

Extensions require RCU support to implement a performant map. For this, eBPFCore exports epoch-based memory allocation
APIs to the extensions via NMR client dispatch table.
**Implemented Approach**: Epoch-based APIs exposed via NMR client dispatch table

**Available Epoch APIs**:
```c
// Memory allocation with epoch tracking
epoch_allocate_with_tag_t epoch_allocate_with_tag;
epoch_allocate_cache_aligned_with_tag_t epoch_allocate_cache_aligned_with_tag;

// Safe memory deallocation
epoch_free_t epoch_free;
epoch_free_cache_aligned_t epoch_free_cache_aligned;
```

**Benefits of this approach**:
- **Centralized RCU Management**: Single epoch system across core and extensions.
- **Automatic Updates**: Extensions benefit from eBPF core RCU improvements without recompilation.

**Usage Example**:
```c
// In extension map implementation
void* map_entry = client_dispatch->epoch_allocate_with_tag(
    sizeof(my_map_entry_t), EBPF_POOL_TAG_EXTENSION);

// Safe deallocation
client_dispatch->epoch_free(map_entry);
```

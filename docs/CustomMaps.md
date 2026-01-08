# Introduction

This document contains proposal for adding support for custom maps. Custom maps are program type specific or global
map types that can be implemented / coordinated by eBPF extensions (e.g. BPF_MAP_TYPE_XSKMAP) through a new NMR
(Network Module Registrar) provider interface. This document contains the design for adding support for custom maps
in eBPF-for-Windows. Custom maps enable extensions to register and manage their own map types beyond those provided
by the core eBPF runtime.

Custom maps will be based on one of the underlying / base map types already implemented in eBPFCore. When extensions
declare a new custom map type, they also declare the base map type on which the custom map should be based.
For example, BPF_MAP_TYPE_XSKMAP can be based on the existing BPF_MAP_TYPE_HASH_MAP.
With this approach, eBPFCore can implement the custom map, and extensions will provide hooks / callbacks for map
creation, and CRUD operations on the map.

This approach has a benefit that extensions do not need to re-implement a performant, RCU (Read-Copy-Update) aware data structure and can leverage the implementation that is present in eBPFCore.

Currently, eBPF-for-Windows will only allow base map type BPF_MAP_TYPE_HASH_MAP. This support can be extended to other
base map types in future based on the requirements.

Note: If there is a need for an extension to implement a map type that cannot be based on any existing map type, we can
extend this interface for extensions to optionally provide their whole implementation, instead of relying on a base map
type in eBPF-for-Windows.

## NMR Interface for Extensions
To implement custom maps, a new NMR interface will be added and extensions will register as map info providers using
NMR, similar to existing program and hook providers. An extension implementing more than one custom maps needs to
register as a map provider once for each map type it supports.

**New NMR Provider Interface**: `EBPF_MAP_INFO_EXTENSION_IID`

**Provider Registration Data**:
```c
typedef struct _ebpf_map_provider_data {
    ebpf_extension_header_t header;
    uint32_t custom_map_type;  // Single map type per provider.
    uint32_t base_map_type;
    ebpf_map_provider_dispatch_table_t* dispatch_table;
} ebpf_map_provider_data_t;
```

**Provider Dispatch Table**:
```c
typedef struct _ebpf_map_provider_dispatch_table {
    ebpf_extension_header_t header;
    _Notnull_ ebpf_process_map_create_t process_map_create;
    _Notnull_ ebpf_process_map_delete_t process_map_delete;
    _Notnull_ ebpf_process_map_associate_program_type_t process_map_associate_program;
    ebpf_process_map_find_element_t process_map_find_element;
    ebpf_process_map_update_element_t process_map_update_element;
    ebpf_process_map_delete_element_t process_map_delete_element;
    ebpf_process_map_get_next_key_and_value_t process_map_get_next_key_and_value;
} ebpf_map_provider_dispatch_table_t;
```

An extension (provider) needs to implement the above dispatch table. eBPF runtime will invoke the above functions in the
following scenarios:
1. **Map Creation** -- eBPF runtime will invoke `process_map_create` to validate the key and value sizes, and optionally
get actual value size.
2. **Map Deletion** -- eBPF runtime will invoke process_map_delete to notify the extension that the map is being deleted.
3. **CRUD operations** -- For each CRUD operation, eBPF runtime will invoke the corresponding dispatch function to notify extension. In case of update functions, extension can optionally provide a different value to be stored in the map.

In the above dispatch table, `process_map_create`, `process_map_delete` and `process_map_associate_program` are required
to be non-NULL. If the extension intends to update the actual value size during map creation, other fields in the table
also need to be non-NULL, otherwise eBPFCore will fail the map creation. If extension does not intend to update the
actual value size during map creation, these fields can be optionally NULL.

**Client Services** (provided by eBPF core):
```c
typedef struct _ebpf_map_client_dispatch_table {
    ebpf_extension_header_t header;
    ebpf_map_find_element_t find_element_function;
} ebpf_map_client_dispatch_table_t;
```
eBPF runtime will expose a *find_element_function* dispatch function that extension can use to query a map
value, given the key.

## Map Type Enum Partitioning
Currently map type IDs are allocated from a global namespace. With custom maps, global map type ID space is
partitioned into 2 disjoint sets: for global maps (implemented in eBPFCore) and for the custom maps.
Global maps will use IDs from 1 to 4095. Custom maps will use IDs 4096 onwards.

- **Global Maps (1-4095)**: Reserved for core eBPF runtime map types (hash, array, etc.)
- **Custom Maps (4096+)**: Available for extension-implemented custom map types

Note: Extensions **should** register the map types for the custom maps by creating a pull request to eBPF-for-Windows
repository and updating `ebpf_map_type_t` enum in ebpf_structs.h. This helps in any map type collision with another
extension.

## Map Discovery and Creation

**Dynamic Provider Discovery**: Uses NMR's built-in discovery mechanism
- No central registry required - providers are discovered on-demand during map creation
- When a map is created with a custom type (>= 4096), eBPF core:
  1. Creates an `ebpf_custom_map_t` structure with NMR client characteristics
  2. Calls `NmrRegisterClient()` to find a provider for the specific map type
  3. On successful provider attachment, creates the custom map with the provided base map type.
  4. Returns map handle to user application

**Map Creation Flow**:
```
User calls bpf_create_map(BPF_MAP_TYPE_CUSTOM, ...)
    ↓
ebpfapi validates parameters
    ↓
ebpfcore checks if map_type >= 4096
    ↓
ebpfcore registers new map NMR client for the map instance
    ↓
NMR finds and attaches to provider implementing the custom map type
    ↓
ebpfcore creates actual map instance
    ↓
Map handle returned to user
```

## Verification
- No impact on verification (online or offline), as the verifier only cares about the actual map definitions.

## Map Lifecycle
**Provider Binding**: eBPF core maintains map lifecycle and coordinates with extensions for map creation, deletion,
and othr map operations.
- eBPF core creates a corresponding map entry for each custom map.
- For Map CRUD operations, corresponding dispatch functions provided by the extension will be invoked.
- Map lifetime managed by eBPF core, including proper cleanup coordination.
- Map pinning handled by eBPF core as it impacts map lifetime.

**Note**: Extensions with active maps cannot unload / restart until the map is deleted.

## Map CRUD APIs

### User-mode APIs
All existing libbpf APIs work unchanged with custom maps
- `bpf_create_map()` / `bpf_map_create()` - Creates custom maps when type >= 4096
- Map operations - Operations are routed to custom maps, whicn in turn invokes provider callbacks.

### eBPF Helper Functions
As with user mode APIs, helper functions also automatically work with custom maps in a similar manner.

## Memory Management and RCU Semantics
Since the actual map is implemented in eBPFCore, it will automatically use Epoch-based APIs for memory allocation.

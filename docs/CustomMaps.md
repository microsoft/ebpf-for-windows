# Custom Maps Design

This document describes the design for custom maps in eBPF-for-Windows. Custom maps are program type specific or global
map types that can be implemented by eBPF extensions (e.g., BPF_MAP_TYPE_XSKMAP) through a new NMR
(Network Module Registrar) provider interface. Custom maps enable extensions to register and manage their own map types
beyond those provided by the core eBPF runtime.

Custom maps are based on one of the underlying / base map types already implemented in eBPFCore. When extensions
declare a new custom map type, they also declare the base map type on which the custom map should be based.
For example, BPF_MAP_TYPE_XSKMAP can be based on the existing BPF_MAP_TYPE_HASH.
With this approach, eBPFCore implements the base data structure for the custom map, while extensions provide
callbacks for map creation, deletion, and CRUD operations. The base map implementation in eBPFCore is used for
storing entries; extensions do not implement their own storage.

This approach has a benefit that extensions do not need to re-implement a performant, RCU (Read-Copy-Update) aware
data structure and can leverage the implementation that is present in eBPFCore.

Currently, eBPF-for-Windows only allows base map type BPF_MAP_TYPE_HASH. This support can be extended to other
base map types in the future based on requirements.

Note: If there is a need for an extension to implement a map type that cannot be based on any existing map type, we can
extend this interface for extensions to optionally provide their whole implementation, instead of relying on a base map
type in eBPF-for-Windows. To avoid breaking changes for fully custom maps, the base map type can be set to
unspecified, and additional callback functions can be added since the struct is versioned.

## NMR Interface for Extensions

To implement custom maps, a new NMR interface is used. Extensions register as map info providers using
NMR, similar to existing program and hook providers. An extension implementing more than one custom map type must
register a separate map provider for each map type it supports (i.e., one NMR provider registration per map type).

**New NMR Provider Interface**: `EBPF_MAP_INFO_EXTENSION_IID`

### Provider Registration Data

```c
typedef struct _ebpf_map_provider_data {
    ebpf_extension_header_t header;
    uint32_t map_type;                                      ///< Custom map type implemented by the provider.
    uint32_t base_map_type;                                 ///< Base map type used to implement the custom map.
    ebpf_base_map_provider_properties_t* base_properties;   ///< Base map provider properties.
    ebpf_base_map_provider_dispatch_table_t* base_provider_table; ///< Pointer to base map provider dispatch table.
} ebpf_map_provider_data_t;
```

### Provider Properties

```c
typedef struct _ebpf_base_map_provider_properties {
    ebpf_extension_header_t header;
    bool updates_original_value; // Whether the provider updates the original value during map operations,
                                 // which controls whether BPF programs can perform map CRUD operations.
} ebpf_base_map_provider_properties_t;
```

When `updates_original_value` is set to true, the extension transforms values during CRUD operations (e.g., converting
a user-mode handle to a kernel pointer). In this case, BPF programs are **not** allowed to perform map CRUD operations
directly, because a BPF program receives a pointer to the value for in-place reads/writes, whereas the stored value
is the transformed version (e.g., a kernel pointer) that should not be directly modified.

### Provider Dispatch Table

```c
typedef struct _ebpf_map_provider_dispatch_table {
    ebpf_extension_header_t header;
    _Notnull_ ebpf_preprocess_map_create_t preprocess_map_create;
    _Notnull_ ebpf_postprocess_map_delete_t postprocess_map_delete;
    _Notnull_ ebpf_preprocess_map_associate_program_type_t preprocess_associate_program_type;
    ebpf_postprocess_map_find_element_t postprocess_map_find_element;
    ebpf_preprocess_map_element_addition_t preprocess_map_element_addition;
    ebpf_preprocess_map_element_deletion_t preprocess_map_element_deletion;
} ebpf_base_map_provider_dispatch_table_t;
```

### Provider Dispatch Function Signatures

The function pointer types used in the dispatch table are defined in `ebpf_extension.h`. An extension (provider)
needs to implement the dispatch table. The eBPF runtime invokes these functions as described below.

`preprocess_map_create`, `postprocess_map_delete`, and `preprocess_associate_program_type` are required to be non-NULL. If the
extension sets `updates_original_value` to true, the CRUD callback fields (`postprocess_map_find_element`,
`preprocess_map_element_addition`, `preprocess_map_element_deletion`) must also be non-NULL, otherwise eBPFCore will fail the
map creation. If `updates_original_value` is false, these CRUD fields can be optionally NULL.

---

#### `ebpf_preprocess_map_create_t` — Map Creation (required)

eBPF runtime invokes `process_map_create` to validate the key and value sizes, allocate a provider-defined per-map
context, and optionally return a different `actual_value_size`. The extension allocates a map context and returns a
pointer to it (`map_context`) back to the eBPF runtime. Subsequent callbacks for this map receive this `map_context`
as an input parameter.

Note: When a map lookup happens from user mode, the value is copied into the buffer provided by the user, whereas
when a map lookup happens from a BPF program, a pointer to the value is provided to the program, and the program
can read or modify the value in place. Therefore, for maps where an extension intends to *modify* the actual value
being stored in the map, map CRUD operations from BPF programs are disallowed by the eBPF runtime.

```c
typedef ebpf_result_t (*ebpf_preprocess_map_create_t)(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Out_ uint32_t* actual_value_size,
    _Outptr_ void** map_context);
```

---

#### `ebpf_postprocess_map_delete_t` — Map Deletion (required)

eBPF runtime invokes `process_map_delete` to notify the extension that the map has been deleted. The extension
should free its per-map context.

```c
typedef void (*ebpf_postprocess_map_delete_t)(
    _In_ void* binding_context,
    _In_ _Post_invalid_ void* map_context);
```

---

#### `ebpf_preprocess_map_associate_program_type_t` — Associate Program (required)

eBPF runtime invokes `associate_program_function` before a custom map is associated with a program. The extension
can validate whether the map type is compatible with the given program type.

```c
typedef ebpf_result_t (*ebpf_preprocess_map_associate_program_type_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    _In_ const ebpf_program_type_t* program_type);
```

---

#### `ebpf_postprocess_map_find_element_t` — Find Element (optional)

Called *after* reading from the base map. If the provider sets `updates_original_value` to true, the extension can
transform the retrieved value (e.g., kernel pointer → user-visible value) via `out_value` before returning to the
caller. If `updates_original_value` is false, `out_value` will be NULL and `out_value_size` will be 0.

```c
typedef ebpf_result_t (*ebpf_postprocess_map_find_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value,
    uint32_t flags);
```

---

#### `ebpf_preprocess_map_element_addition_t` — Add/Update Element (optional)

Called *before* writing to the base map. If the provider sets `updates_original_value` to true, the extension can
transform the user-provided value (e.g., user fd → kernel pointer) via `out_value`, which eBPFCore then stores in
the base map. If `updates_original_value` is false, `out_value` will be NULL and `out_value_size` will be 0.

```c
typedef ebpf_result_t (*ebpf_preprocess_map_element_addition_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value,
    uint32_t flags);
```

---

#### `ebpf_preprocess_map_element_deletion_t` — Delete Element (optional)

Called *before* the entry is deleted from the base map. This allows the extension to perform cleanup (e.g., releasing
kernel resources). The `flags` parameter indicates the context: `EBPF_MAP_OPERATION_UPDATE` if the delete is part of
a replace operation, `EBPF_MAP_OPERATION_MAP_CLEANUP` if the map itself is being destroyed, and
`EBPF_MAP_OPERATION_HELPER` if invoked from a BPF program. When `EBPF_MAP_OPERATION_UPDATE` or
`EBPF_MAP_OPERATION_MAP_CLEANUP` is set, the provider must not fail the deletion.

```c
typedef ebpf_result_t (*ebpf_preprocess_map_element_deletion_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uint32_t flags);
```

---

#### Flags

The following flags are used with the CRUD dispatch functions:
```c
#define EBPF_MAP_OPERATION_HELPER      0x01 /* Called by a BPF program. When not set, the provider
                                              * function is called in the context of the original
                                              * user mode process. */
#define EBPF_MAP_OPERATION_UPDATE      0x02 /* Update operation. */
#define EBPF_MAP_OPERATION_MAP_CLEANUP 0x04 /* Map cleanup operation. */
```

#### Example: Object Map insert flow

For a custom map that stores kernel objects (similar to how XSKMAP might work), the insert operation works as follows:
1. User calls `bpf_map_update_elem()` with a user-mode handle (e.g., 4-byte fd) as the value.
2. eBPFCore invokes `preprocess_map_element_addition` with the handle in `in_value`.
3. The extension validates the handle and converts it to a kernel pointer, writing it into `out_value`.
4. eBPFCore stores the kernel pointer (from `out_value`) in the underlying hash map.
5. On lookup, eBPFCore retrieves the kernel pointer and invokes `process_map_find_element`, which converts it
   back to a user-visible value in `out_value`.

This transformation pattern allows extensions to store kernel objects while exposing user-mode handles to applications.

If the extension returns an `actual_value_size` different from the user-specified `value_size` during
`process_map_create`, CRUD callbacks are required to translate between the user-facing value format and the internal
storage format. For example:
- User declares a map with `value_size=4` (to store socket fds).
- Extension's `process_map_create` returns `actual_value_size=8` (to store kernel pointers).
- On insert: user passes 4-byte fd → `preprocess_map_element_addition` converts to 8-byte pointer → stored in base map.
- On lookup: 8-byte pointer retrieved → `process_map_find_element` converts to 4-byte fd → returned to user.

Without these callbacks, eBPFCore cannot perform the size/format translation.

### Client Data (provided by eBPF core)

When eBPFCore attaches to the NMR provider, it provides the following client data to the extension:

```c
typedef struct _ebpf_map_client_data {
    ebpf_extension_header_t header;
    uint64_t map_context_offset;                            ///< Offset within the map structure where the
                                                            ///< provider context data is stored.
    ebpf_base_map_client_dispatch_table_t* base_client_table; ///< Pointer to base map client dispatch table.
} ebpf_map_client_data_t;
```

`map_context_offset` is provided by eBPFCore to the extension so it can retrieve its extension-specific map context
when a custom map is used in a helper function. This value is constant for all bindings from eBPFCore to the extension
for all custom map types and instances. A `MAP_CONTEXT()` macro is provided in `ebpf_extension.h` for extensions to
conveniently retrieve their map context. Extensions should validate that the returned map context is not NULL.

### Client Dispatch Table

```c
typedef struct _ebpf_map_client_dispatch_table {
    ebpf_extension_header_t header;
    ebpf_map_find_element_t find_element_function;
    ebpf_epoch_enter_t epoch_enter;
    ebpf_epoch_exit_t epoch_exit;
    ebpf_epoch_allocate_with_tag_t epoch_allocate_with_tag;
    ebpf_epoch_allocate_cache_aligned_with_tag_t epoch_allocate_cache_aligned_with_tag;
    ebpf_epoch_free_t epoch_free;
    ebpf_epoch_free_cache_aligned_t epoch_free_cache_aligned;
} ebpf_base_map_client_dispatch_table_t;
```

The client dispatch table provides:
- `find_element_function` -- Used by the extension to query a map value given a key.
- **Epoch-based memory management APIs** -- `epoch_enter`, `epoch_exit`, `epoch_allocate_with_tag`,
  `epoch_allocate_cache_aligned_with_tag`, `epoch_free`, and `epoch_free_cache_aligned`.

Provider dispatch function invocations and BPF helper function callbacks are already epoch-protected, so the epoch
memory APIs can be called directly in those contexts. If the provider uses these APIs outside those contexts, it must
call `epoch_enter` / `epoch_exit` to bracket the calls. Similarly, `find_element_function` must only be invoked
within an epoch-protected region.

## Map Type Registration

Custom map types come from the same map type numbering space as the built-in maps. Extensions are **required** to
register the custom map types by creating a pull request to the eBPF-for-Windows repository and updating the
`ebpf_map_type_t` enum in `ebpf_structs.h`. This avoids any map type collision with another extension or eBPF core.

Map creation will fail if the map type is not registered in the `ebpf_map_type_t` enum.

**Runtime Behavior:**

- If no provider is registered for a custom map type, NMR client registration will fail to find a provider and
  map creation will return an error.

- If multiple extensions register as providers for the same custom map type ID, the behavior is undefined — NMR
  will offer all matching provider interfaces and eBPFCore will attach to the first one. This is why registering
  map types via PR is mandatory: it prevents collisions through code review rather than runtime enforcement.

## Map Discovery and Creation

**Dynamic Provider Discovery**: Uses NMR's built-in discovery mechanism.
- Providers are discovered on-demand during map creation.
- When a custom map is created, eBPF core:
  1. Identifies the map type as a custom map type (registered in the `ebpf_map_type_t` enum).
  2. Creates an NMR client registration for the map instance.
  3. Calls `NmrRegisterClient()` to find a provider for the specific map type.
  4. On successful provider attachment, invokes `process_map_create` and creates the custom map with the provided
     base map type.
  5. Returns map handle to user application.

This also applies when maps are implicitly created (i.e., defined within an eBPF program file). The map creation
flow is the same regardless of whether the map is created explicitly via API or implicitly during program load.

eBPFCore registers a new NMR client for each map instance. This per-instance registration serves two purposes:
1. **Discovery**: NMR locates the provider implementing the requested custom map type.
2. **Lifetime management**: The NMR binding prevents the extension from unloading while the map exists, ensuring
   callbacks remain valid for the map's lifetime.

This pattern matches the existing program-to-provider binding model used elsewhere in eBPF-for-Windows.

**Map Creation Flow**:
```
User calls bpf_create_map(BPF_MAP_TYPE_<custom>, ...)
    ↓
ebpfapi validates parameters
    ↓
ebpfcore identifies this as a custom map type
    ↓
ebpfcore registers new map NMR client for the map instance
    ↓
NMR finds and attaches to provider implementing the custom map type
    ↓
ebpfcore invokes process_map_create callback
    ↓
ebpfcore creates actual map instance using base map type
    ↓
Map handle returned to user
```

## Verification
- No impact on verification (online or offline), as the verifier only cares about the actual map definitions.

## Map Lifecycle

**Provider Binding**: eBPF core maintains map lifecycle and coordinates with extensions for map creation, deletion,
and other map operations.
- eBPF core creates a corresponding map entry for each custom map, using the base map type for storage.
- For map CRUD operations, corresponding dispatch functions provided by the extension will be invoked.
- Map lifetime managed by eBPF core, including proper cleanup coordination.
- Map pinning handled by eBPF core as it impacts map lifetime.

**Note**: Extensions with active maps cannot unload / restart until the map is deleted.

## Map CRUD APIs

### User-mode APIs
All existing libbpf APIs work unchanged with custom maps:
- `bpf_create_map()` / `bpf_map_create()` -- Creates custom maps when the type is a custom map type.
- Map operations -- Operations are routed to custom maps, which in turn invoke provider callbacks.

When `EBPF_MAP_OPERATION_HELPER` is not set in the flags (i.e., the operation is from user mode), the caller context
is the same as the original user-mode process. This allows providers to implicitly use the handle table of the
current process when resolving parameters like file descriptors.

### eBPF Helper Functions
As with user-mode APIs, eBPF helper functions also work with custom maps automatically.

If the extension is implementing a helper function that takes a custom map as input, when the helper function is
invoked, it will **not** get the map context that it originally passed to eBPFCore. Instead, it gets a pointer to
a separate map structure that eBPFCore maintains. Using this pointer and the `map_context_offset` provided in the
`ebpf_map_client_data_t`, the extension retrieves its map context via the `MAP_CONTEXT()` macro defined in
`ebpf_extension.h`. Extensions should validate that the map context is not NULL and handle it appropriately.

## Provider vs. Internal Dispatch Table Signatures

The eBPF runtime maintains an internal dispatch table (`ebpf_map_metadata_table_properties_t`, defined in
[ebpf_maps.c](https://github.com/microsoft/ebpf-for-windows/blob/main/libs/execution_context/ebpf_maps.c))
that implements the map CRUD operations for all built-in map types. This table has different function signatures
from the provider dispatch table (`ebpf_base_map_provider_dispatch_table_t`, defined in
[ebpf_extension.h](https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_extension.h))
that extensions implement. The key differences are explained below.

### Internal Dispatch Table (`ebpf_map_metadata_table_properties_t`)
```c
typedef struct _ebpf_map_metadata_table_properties {
    ebpf_result_t (*create_map)(
        _In_ const ebpf_map_definition_in_memory_t* map_definition,
        ebpf_handle_t inner_map_handle,
        _Outptr_ ebpf_core_map_t** map);
    void (*delete_map)(_In_ _Post_invalid_ ebpf_core_map_t* map);
    ebpf_result_t (*associate_program)(
        _Inout_ ebpf_map_t* map, _In_ const ebpf_program_t* program);
    ebpf_result_t (*find_entry)(
        _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key,
        uint64_t flags, _Outptr_ uint8_t** data);
    ebpf_result_t (*update_entry)(
        _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key,
        _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*update_entry_with_handle)(
        _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key,
        uintptr_t value_handle, ebpf_map_option_t option);
    ebpf_result_t (*update_entry_per_cpu)(
        _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key,
        _In_ const uint8_t* value, ebpf_map_option_t option);
    ebpf_result_t (*delete_entry)(_Inout_ ebpf_core_map_t* map, _In_ const uint8_t* key);
    ebpf_result_t (*next_key_and_value)(
        _Inout_ ebpf_core_map_t* map, _In_ const uint8_t* previous_key,
        _Out_ uint8_t* next_key, _Inout_opt_ uint8_t** next_value);
    // ... plus ring buffer / perf event array specific operations, and flags.
} ebpf_map_metadata_table_properties_t;
```

### Differences in Signatures

This section enumrates the differences in the custom map provider dispatch tables, and the intertnal dispatch table
used by eBPF core for implementing native maps.

1. **Notification vs. Implementation**: Internal dispatch functions **are** the map CRUD implementation --
   they directly manipulate the underlying data structure (hash table, array, etc.). Provider dispatch
   functions act like hooks in the actual map CRUD impelemtation -- eBPF core performs the actual CRUD using the base
   map type, and invokes the provider callbacks to allow the extension to validate, transform, or track the operation.
   For example, during an update, eBPF core first calls the provider's `preprocess_map_element_addition`, then
   inserts the (potentially transformed) value into the hash table.

2. **Value Transformation (in/out pattern)**: Provider functions use an explicit `in_value` / `out_value`
   pattern with separate size parameters, allowing the extension to receive the existing stored value and
   optionally provide a different value to be stored. Internal functions directly read and write values
   in-place since they own the memory.

3. **Flag Semantics**: Provider functions use `EBPF_MAP_OPERATION_*` flags (`EBPF_MAP_OPERATION_HELPER`,
   `EBPF_MAP_OPERATION_UPDATE`, `EBPF_MAP_OPERATION_MAP_CLEANUP`) to inform the extension about the
   calling context. Internal functions use different mechanisms such as `ebpf_map_option_t` for update
   semantics (ANY, NOEXIST, EXIST) and separate function pointers for per-CPU operations.

4. **Subset of Operations**: The provider dispatch table does not include `next_key_and_value`,
   `update_entry_with_handle`, `update_entry_per_cpu`, ring buffer operations, or perf event array
   operations. Key enumeration and per-CPU handling are transparently managed by the base map
   implementation in eBPF core, and handle-based updates are not applicable to custom map extensions.

## Memory Management and RCU Semantics
Since the base map is implemented in eBPFCore, it automatically uses epoch-based APIs for memory allocation.
Extensions can also use the epoch-based memory management APIs provided in the client dispatch table for their
own allocations (e.g., allocating per-entry kernel objects). See
[Epoch based memory management](EpochBasedMemoryManagement.md) for more details.

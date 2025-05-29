# Namespace isolation for BPF objects
This document describes how eBPF for Windows implements namespace isolation.

## Overview
BPF objects are by default system wide entities that can be opened via several libbpf APIs (meaning the caller receives
a fd to the object). While this is useful for the general case, there are some scenarios where BPF applications need to
be able to isolate themselves from other BPF applications to ensure that their state remains consistent.

To achieve this a BPF application can switch to a designated namespace. Namespaces are identified by a GUID, with the
default namespace having the zero GUID (all fields in the GUID are zero). All libbpf APIs that return fds are relative
to the namespace that the application has specified.

## Design details
Each BPF object will have a namespace identifier associated with it. Each new object created is marked with the current
namespace identifier. All calls to the execution context to open objects are relative to the current namespace.

### Namespace in ebpf_core_object_t
All user accessible BPF objects embed the ebpf_core_object_t structure:

```c
typedef struct _ebpf_core_object
{
    ebpf_base_object_t base;              ///< Base object for all reference counted eBPF objects.
    ebpf_object_type_t type;              ///< Type of this object.
    ebpf_free_object_t free_function;     ///< Function to free this object.
    ebpf_zero_ref_count_t zero_ref_count; ///< Function to notify the object that the reference count has reached
                                            ///< zero.
    ebpf_object_get_program_type_t get_program_type; ///< Function to get the program type of this object.
    ebpf_id_t id;                                    ///< ID of this object.
    ebpf_list_entry_t object_list_entry;             ///< Entry in the object list.
    volatile int32_t pinned_path_count;              ///< Number of pinned paths for this object.
    struct _ebpf_epoch_work_item* free_work_item;    ///< Work item to free this object when the epoch ends.
    GUID namespace;                                  ///< The namespace this object is part of. Zero guid by default.
} ebpf_core_object_t;
```

Each namespace will be identified by a GUID, with the zero GUID denoting the default namespace. When resolving an
object ID to an object, the current processes namespace will be compared against the namespace of the object and will
only resolve the object if the namespace matches.

### Object ID APIs
The following APIs can be used to locate objects and are namespace aware.
1) ebpf_object_reference_next_object - Find the next object in the caller's namespace.
2) ebpf_object_reference_by_id - Find the object by ID if it is in the caller's namespace.
3) ebpf_object_get_next_id - Find the next object by ID within the caller's namespace.


### Pinning APIs
The pinning namespace is global and not partitioned by namespace. If required, applications can prefix their pinning
path with the namespace GUID to ensure that they are unique.
The following APIs are namespace aware.
1) ebpf_pinning_table_find - Find the object by pin path and return if the namespace matches or return not found.
2) ebpf_pinning_table_enumerate_entries - Enumerate all pinning paths within the caller's namespace.
3) ebpf_pinning_table_get_next_path - Get the next pinning path within the caller's namespace.

### Namespace APIs
The following APIs can be used to associate the process with a namespace.
1) ebpf_set_namespace - Switch to the specified namespace.
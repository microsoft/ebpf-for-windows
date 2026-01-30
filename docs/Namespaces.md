# Namespaces for BPF objects
This document describes how eBPF for Windows implements namespaces.

## Overview
BPF objects are by default system-wide entities that can be opened via several libbpf APIs (meaning the caller receives
an fd to the object). While this is useful for the general case, there are some scenarios where BPF applications need to
be able to partition themselves from other BPF applications to prevent naming collisions.

To achieve this, a BPF application can switch to a designated namespace. Namespaces are identified by a GUID, with the
default namespace having the null GUID (GUID_NULL, all bytes zero). All libbpf APIs that return fds are relative
to the namespace that the application has specified.

## Backward Compatibility
Existing applications that do not use namespace APIs automatically operate in the default (null GUID) namespace. No
code changes are required for existing eBPF programs and maps—they continue to function as before, with all objects
created in and resolved from the default namespace. The namespace feature is entirely opt-in; applications must
explicitly call `ebpf_set_namespace` to switch to a non-default namespace.

## Security Considerations
Namespaces provide logical partitioning of BPF object identifiers and pin paths. They are not a replacement for existing
operating system security mechanisms (for example, access control lists or privilege checks), and all such mechanisms
continue to apply to namespace-aware operations.

From the perspective of BPF object lookup and enumeration, namespaces are isolated: a lookup by ID or pin path will only
succeed if the object's namespace matches the effective namespace of the caller. Cross-namespace object resolution is
not supported by these APIs.

The ability to create a new namespace or to change the effective namespace of a process is subject to the same security
policy as other privileged eBPF management operations. Implementations are expected to restrict namespace management to
callers that have sufficient rights (for example, administrative privileges or an approved service account).
Unprivileged processes cannot arbitrarily assume another process's namespace.

All permission checks that are performed today when accessing BPF objects (such as validating caller identity, access
rights, or capabilities) are performed in addition to the namespace comparison. Namespace matching never bypasses or
weakens those existing checks; it only narrows which objects are considered candidates for lookup.

## Namespace Lifecycle
Namespaces are implicit and identified solely by their GUID. There is no explicit creation or deletion of namespaces:

- A namespace comes into existence when the first object is created with that namespace GUID.
- A namespace ceases to be relevant when no objects exist with that namespace GUID.
- Objects persist until explicitly freed (handles closed, programs unloaded, maps deleted) regardless of whether any
  process currently has that namespace set as its effective namespace.
- Switching away from a namespace does not affect objects in that namespace; they remain accessible to any process
  that subsequently switches to that namespace GUID.

This design avoids the need for namespace management APIs beyond `ebpf_set_namespace` and ensures that namespace
cleanup is automatic and tied to normal object lifecycle management.

## Design Details
Each BPF object will have a namespace identifier associated with it. Each new object created is marked with the current
namespace identifier. All calls to the execution context to open objects are relative to the current namespace.

Namespace filtering is performed at the lookup level using a constant-time GUID comparison, adding minimal overhead to
object resolution. The default (null GUID) namespace is the common case and can be optimized with fast-path checks.

### Namespace in ebpf_core_object_t
All user-accessible BPF objects embed the ebpf_core_object_t structure:

```c
typedef struct _ebpf_core_object
{
    ebpf_base_object_t base;        ///< Base object for all reference counted eBPF objects.
    ebpf_object_type_t type;        ///< Type of this object.
    ebpf_free_object_t free_object; ///< Function to free this object.
    ebpf_notify_reference_count_zeroed_t notify_reference_count_zeroed; ///< Function to notify the object that the
                                                                        ///< reference count has reached zero.
    ebpf_notify_user_reference_count_zeroed_t notify_user_reference_count_zeroed; ///< Function to notify the object
                                                                                  ///< that the user reference count
                                                                                  ///< has reached zero.
    ebpf_object_get_program_type_t get_program_type;     ///< Function to get the program type of this object.
    ebpf_id_t id;                                        ///< ID of this object.
    ebpf_list_entry_t object_list_entry;                 ///< Entry in the object list.
    volatile int32_t pinned_path_count;                  ///< Number of pinned paths for this object.
    struct _ebpf_epoch_work_item* free_object_work_item; ///< Work item to free this object when the epoch ends.
    GUID namespace;                                      ///< The namespace this object is part of. Null GUID by default.
} ebpf_core_object_t;
```

Each namespace will be identified by a GUID, with the null GUID denoting the default namespace. When resolving an
object ID to an object, the current process's namespace will be compared against the namespace of the object and will
only resolve the object if the namespace matches.

### Object ID APIs
The following APIs can be used to locate objects and are namespace-aware. These APIs implicitly use the caller's
current namespace (as set by `ebpf_set_namespace`) rather than taking an explicit namespace parameter.

1) ebpf_object_reference_next_object - Find the next object in the caller's namespace.
2) ebpf_object_reference_by_id - Find the object by ID if it is in the caller's namespace.
3) ebpf_object_get_next_id - Find the next object by ID within the caller's namespace.


### Pinning APIs
The pinning table is partitioned by namespace. Pin paths are scoped to the caller's namespace, so the same path string
can exist in different namespaces without conflict. The following APIs are namespace aware.
1) ebpf_pinning_table_insert - Insert an entry into the pinning table.
2) ebpf_pinning_table_find - Find the object by pin path and return it if the namespace matches or return not found.
3) ebpf_pinning_table_delete - Remove an entry from the pinning table.
4) ebpf_pinning_table_enumerate_entries - Enumerate all pinning paths within the caller's namespace.
5) ebpf_pinning_table_get_next_path - Get the next pinning path within the caller's namespace.

### Namespace APIs
The following APIs can be used to associate the process with a namespace.

1) **ebpf_set_namespace** - Switch to the specified namespace.

   - **Scope**: Sets the namespace for the calling process. All threads in the process share the same current namespace.
   - **Persistence**: The namespace setting persists for the lifetime of the process, or until `ebpf_set_namespace` is
     called again to switch to a different namespace.
   - **Implementation**: Exposed as a user-mode API (in `ebpfapi.dll`) that communicates the requested namespace GUID
     to the eBPF kernel execution context (`ebpfcore.sys`) via IOCTL.
   - **Effect on existing objects**: Existing BPF objects are not modified when the process switches namespaces.
     Objects retain the namespace GUID that was current when they were created. Existing handles remain valid and
     continue to reference the same underlying objects. A namespace switch only affects subsequent lookups and the
     namespace assigned to newly created objects.

### eBPF netsh support
The eBPF netsh extension will be updated to support switching to a designated namespace. Users will be able to specify
the desired namespace using new netsh commands, such as `netsh ebpf set namespace {12345678-1234-1234-1234-123456789abc}`,
where the GUID is provided in standard Windows GUID text format (including braces and hyphens). This allows subsequent
eBPF operations within the session to be performed in the selected namespace. Additional commands and usage examples
will be provided in the netsh documentation as this feature is implemented.

#### Namespace discoverability
Namespace GUIDs are application-defined and not centrally registered. Administrators who need to manage BPF objects in
a specific namespace should consult the application's documentation to obtain its namespace GUID. Applications are
encouraged to document their namespace GUID in their installation or configuration materials.

For extension writers that use namespaces, a recommended pattern is to author a netsh subcontext under the `ebpf`
context. The subcontext can register the same commands as the parent ebpf context, with each command implementation
setting the appropriate namespace GUID, executing the parent command, and restoring the namespace. This allows
administrators to switch into the extension's context and use familiar ebpf commands without manually specifying the
namespace GUID.

### eBPF bpftool support
Support for eBPF namespaces is a Windows-specific feature. The bpftool command-line interface is kept aligned with the
Linux bpftool interface, which does not have GUID-based namespaces. To maintain command-line compatibility with Linux
bpftool and avoid platform-specific flags, namespace management on Windows is provided via the netsh eBPF extension
instead. bpftool will always interact with the default (null GUID) namespace.

#### netsh vs bpftool feature parity
Since bpftool will only operate in the default namespace, users who need namespace support must use netsh. The
following bpftool features are not currently available in the netsh eBPF extension and would need to be added to avoid
usability regressions for namespace users:

| Feature Category | bpftool | netsh | Notes |
|-----------------|---------|-------|-------|
| List programs | ✓ | ✓ | |
| List maps | ✓ | ✓ | |
| List links | ✓ | ✓ | |
| Pin/unpin objects | ✓ | ✓ | |
| Show disassembly | ✓ | ✓ | |
| Map create | ✓ | ✗ | Prerequisite for namespace support |
| Map update/lookup/delete | ✓ | ✗ | Prerequisite for namespace support |
| Program dump (xlated/jited) | ✓ | ✗ | |
| Program attach/detach | ✓ | ✗ | Prerequisite for namespace support |
| Batch operations | ✓ | ✗ | |

The minimum prerequisite features for namespace support are map CRUD operations and program attach/detach, as these
are essential for managing BPF objects in a non-default namespace.

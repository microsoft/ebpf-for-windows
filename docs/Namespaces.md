# BPF Object Namespaces

## Overview

Namespaces provide logical isolation of BPF objects (programs, maps, links) between applications. Each namespace is identified by a GUID, with the null GUID (`GUID_NULL`) representing the default namespace. Applications that do not explicitly set a namespace operate in the default namespace, ensuring full backward compatibility.

## Use Cases

1. **Multi-tenant isolation**: Multiple security products can deploy BPF programs on the same system without ID or pin path collisions.
2. **Testing isolation**: Test suites can run in a dedicated namespace without interfering with production BPF objects.
3. **Application partitioning**: An application can ensure its BPF objects are not visible to or affected by other applications.

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | Each BPF object SHALL be associated with exactly one namespace GUID at creation time. |
| R2 | The default namespace SHALL be the null GUID (`GUID_NULL`). |
| R3 | Object ID lookups SHALL only return objects whose namespace matches the caller's current namespace. |
| R4 | Pin path lookups SHALL only return objects whose namespace matches the caller's current namespace. |
| R5 | The same pin path string MAY exist in multiple namespaces without conflict. |
| R6 | Existing handles to BPF objects SHALL remain valid after a namespace switch. |
| R7 | A namespace switch SHALL NOT modify existing objects; it only affects subsequent operations. |
| R8 | Namespace management SHALL require the same privileges as other eBPF management operations. |
| R9 | Applications not using namespace APIs SHALL operate in the default namespace with no code changes. |

## API Specification

### ebpf_set_namespace

Sets the current namespace for the calling process.

```c
ebpf_result_t ebpf_set_namespace(_In_ const GUID* namespace_guid);
```

| Aspect | Behavior |
|--------|----------|
| Scope | Per-process (all threads share the namespace) |
| Persistence | Until changed or process exits |
| Default | Null GUID if never called |
| Effect on existing objects | None—existing handles remain valid |
| Effect on new objects | Created in the new namespace |
| Effect on lookups | Only objects in the new namespace are visible |

### Namespace-Aware APIs

The following APIs implicitly use the caller's current namespace:

| Category | APIs |
|----------|------|
| Object lookup | `ebpf_object_reference_by_id`, `ebpf_object_reference_next_object`, `ebpf_object_get_next_id` |
| Pinning | `ebpf_pinning_table_insert`, `ebpf_pinning_table_find`, `ebpf_pinning_table_delete`, `ebpf_pinning_table_enumerate_entries`, `ebpf_pinning_table_get_next_path` |

## Behavior Specification

1. **Namespace assignment**: When a BPF object is created, it inherits the caller's current namespace GUID.
2. **Lookup isolation**: ID and pin path lookups compare the caller's namespace against the object's namespace; mismatches return "not found."
3. **Handle semantics**: Once a handle is obtained, it references the object directly regardless of subsequent namespace switches.
4. **Implicit namespaces**: Namespaces are not explicitly created or deleted. A namespace exists as long as objects with that GUID exist.
5. **Cross-namespace access**: Not supported via lookup APIs. Direct handle passing between processes is unaffected.

## Acceptance Criteria

| ID | Criterion |
|----|-----------|
| AC1 | An application in namespace A cannot enumerate or open by ID any object created in namespace B. |
| AC2 | An application in namespace A cannot find by pin path any object pinned in namespace B. |
| AC3 | Two applications can pin objects at the same path in different namespaces without error. |
| AC4 | After calling `ebpf_set_namespace`, newly created objects have the new namespace GUID. |
| AC5 | After calling `ebpf_set_namespace`, existing handles continue to work. |
| AC6 | An application that never calls `ebpf_set_namespace` operates identically to pre-namespace behavior. |
| AC7 | Unprivileged callers receive an access denied error when calling `ebpf_set_namespace`. |

## Security Considerations

- Namespaces provide **logical isolation**, not security isolation. Existing ACLs and privilege checks still apply.
- `ebpf_set_namespace` requires administrative privileges.
- Namespace matching narrows lookup scope but does not bypass permission checks.

## Tooling

### netsh

```
netsh ebpf set namespace {GUID}
netsh ebpf show namespace
```

Namespace GUIDs are application-defined. Administrators should consult application documentation for the appropriate GUID.

### bpftool

bpftool always operates in the default namespace to maintain Linux CLI compatibility. Use netsh for namespace-aware operations.

# BPF Object Namespaces

## Overview

In this document, "thread" means an OS thread, not a logical task or fiber.

Namespaces provide logical isolation of BPF objects (programs, maps, links).
Each namespace is identified by a GUID, with `GUID_NULL` representing the
default namespace. An application selects a namespace **per thread** through
the shipped `ebpfapi.dll`. Selecting A on one thread does not change another
thread's selection.

Each newly initialized thread starts in `GUID_NULL`, independently of its
creator. Threads or applications intentionally using the same GUID share a
partition. Applications not using namespace APIs continue to use the default
namespace without changing existing `bpf_*` signatures.

The implementation scope is native loading/execution and its map, program,
link, ID, and pin-management operations. JIT/interpreter namespace integration
is not required; unrelated execution-mode functionality is not removed.
Native image signature/hash authorization remains required.

## Use Cases

1. **Multi-tenant isolation**: Multiple products can use separate discovery
   partitions and the same pin paths without naming conflicts. Object IDs
   remain globally unique.
2. **Testing isolation**: Test workers can select a dedicated namespace instead
   of discovering or modifying production objects through default discovery.
3. **Application partitioning**: Dedicated threads can manage separate
   partitions within one application.

These are cooperative management scenarios, not a hostile-administrator
security boundary.

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | Each BPF object SHALL be associated with exactly one immutable namespace GUID at creation, before its ID becomes discoverable. |
| R2 | The default namespace SHALL be the null GUID (`GUID_NULL`). |
| R3 | Object ID enumeration and open-by-ID SHALL only return objects matching the calling thread's selected namespace. IDs SHALL remain globally unique. |
| R4 | Pin lookup, insertion, deletion, and enumeration SHALL be relative to the calling thread's selected GUID. |
| R5 | The same pin path string MAY exist in multiple namespaces without conflict. |
| R6 | Existing handles to BPF objects SHALL remain valid after a namespace switch. |
| R7 | A namespace switch SHALL NOT modify existing objects; it only affects subsequent operations. |
| R8 | Namespace management SHALL require the same privileges as other eBPF management operations. |
| R9 | Applications not using namespace APIs SHALL operate in the default namespace with no code changes. |
| R10 | Namespace selection SHALL be per thread. New threads SHALL start in `GUID_NULL`, without inheritance. |
| R11 | A successful namespace change SHALL apply to subsequent namespace-dependent operations on the calling thread. A failed change SHALL preserve its previous selection. |
| R12 | New object relationships SHALL connect only objects in the same namespace. Existing ordinary handle-based access SHALL NOT depend on the caller's selected namespace. |
| R13 | Existing handle-based asynchronous operations SHALL remain independent of the caller's selected namespace. |

## API Specification

### ebpf_set_thread_namespace

Sets the namespace for the calling thread.

```c
ebpf_result_t ebpf_set_thread_namespace(_In_ const GUID* namespace_guid);
```

| Aspect | Behavior |
|--------|----------|
| Scope | Calling thread; other threads are unchanged. |
| Persistence | Selection remains effective until successfully changed or the thread/DLL lifetime ends. |
| Default | `GUID_NULL` on each newly initialized thread. |
| Reset | Pass the address of `GUID_NULL`; a NULL pointer is invalid, not a reset. |
| Effect on existing objects | None; their GUIDs and ordinary handle-based access remain unchanged. |
| Effect on new objects | Creation uses the calling thread's captured selection. |
| Effect on discovery | ID and pin discovery uses the selected GUID. |
| Failure | Return the error; retain the previous committed logical selection. |

### ebpf_get_thread_namespace

Returns the calling thread's selected namespace GUID. On failure, returns an
error and leaves the output unchanged.

```c
ebpf_result_t ebpf_get_thread_namespace(_Out_ GUID* namespace_guid);
```

### Namespace-Aware APIs

Existing API signatures do not gain GUID parameters. Classification depends
on the operation, not just whether an API accepts an fd or object pointer.

| Category | Examples and behavior |
|----------|------|
| Creation/loading | Map creation, native object loading, and program attachment use the selected GUID. Attachment creates a new link even if it takes an existing program fd. |
| ID discovery | `bpf_map_get_next_id`, `bpf_prog_get_next_id`, `bpf_link_get_next_id`, and corresponding open-by-ID APIs are namespace-filtered. |
| Pinning | `bpf_obj_get`, `bpf_obj_pin`, map/program/link pin/unpin, pinned-map information, and pin-path enumeration are namespace-relative. |
| Implicit link discovery | Program detach by attach parameters and XDP query/detach/replacement search links in the selected namespace. |
| Existing-object operations | Map data access, info-by-fd, direct link-fd detach, program test-run, fd close/duplicate, and ring/perf consumers do not select targets by the ambient GUID. Owner-compatibility checks still apply to graph updates. |
| Local/file metadata | Local wrapper queries, including `bpf_map__is_pinned()`, iteration/name lookup, object-file parsing, file program enumeration, verifier diagnostics, type/provider metadata, and path-text canonicalization do not depend on namespace selection. |

## Behavior Specification

1. **Namespace assignment**: Each new BPF object is assigned the calling
   thread's selected namespace GUID at creation. Its namespace does not change
   afterward.
2. **Discovery**: ID and pin-path discovery returns only objects in the calling
   thread's selected namespace. Enumeration skips objects in other namespaces
   rather than ending.
3. **Handle semantics**: Existing handles/fds remain valid after namespace
   changes and can be passed between threads or processes where permitted.
   Objects cannot be connected across namespaces or pinned outside their own
   namespace.
4. **Implicit namespaces**: Namespaces are not explicitly created or deleted.
   A namespace exists as long as objects with that GUID exist.

## Application Responsibilities

Call `ebpf_set_thread_namespace()` on the thread performing namespace-dependent
work. Check the result; if selection fails, do not proceed with that work.

Before returning a worker to a shared pool, reset its namespace by passing
the address of `GUID_NULL` to the setter. Perform this reset on success,
failure, early return, handled exceptions, and cooperative cancellation.

```text
Select namespace -> perform work -> reset to GUID_NULL -> return to pool
```

Without an explicit reset, subsequent work on that thread retains the previous
namespace. Check reset errors separately from work errors: a failed reset
preserves the previous selection and must not be treated as a successful return
to the default namespace.

Selection is not inherited by new threads and does not follow async
continuations. For callbacks or work spanning `await`, select on the executing
thread and reset before yielding or returning. Select again before resumed
work needs namespace-dependent APIs. Fibers sharing a thread also share its
namespace selection. Existing handle-based data access and namespace-neutral
async operations do not require reselection.

A dedicated worker may retain its selection, but must reset before returning
to a shared pool or default role. Remove pins by path while their namespace
is selected, before resetting the worker. Use a stable GUID to rediscover
surviving pins after an application restart.

## Acceptance Criteria

| ID | Criterion |
|----|-----------|
| AC1 | T1 selecting A cannot enumerate/open B objects by ID; T2 selecting B remains independent. Enumeration skips hidden entries and IDs remain globally unique. |
| AC2 | A thread selecting namespace A cannot open or enumerate pins in namespace B. |
| AC3 | Objects in different namespaces can be pinned at the same path. Unpinning in one namespace does not affect the other. |
| AC4 | After `ebpf_set_thread_namespace()` succeeds, new maps, programs, and links belong to the selected namespace. Existing objects and other threads' selections remain unchanged. |
| AC5 | Existing handles remain usable for permitted operations after SET/reset and across threads. Objects cannot be connected across namespaces or pinned outside their own namespace. |
| AC6 | An application that never calls `ebpf_set_thread_namespace()` behaves as it did before namespace isolation. |
| AC7 | Callers without eBPF management privileges receive an access-denied error from `ebpf_set_thread_namespace()` and `ebpf_get_thread_namespace()`. |
| AC8 | If `ebpf_set_thread_namespace()` fails, the calling thread's selected namespace remains unchanged. If `ebpf_get_thread_namespace()` fails, its output remains unchanged. |
| AC9 | Existing handle-based asynchronous operations and buffer APIs continue to work when threads change or reset their selected namespace. |
| AC10 | Local object metadata queries, including `bpf_map__is_pinned()`, and file-inspection APIs are unaffected by namespace selection. |
| AC11 | Native loading and automatic pinned-map reuse use the selected namespace. Failure cleanup is limited to resources created by that load and preserves pre-existing pins. |
| AC12 | After a complete unload and reload of `ebpfapi.dll`, with no outstanding SDK operations or callbacks, each thread starts in `GUID_NULL`. Surviving objects retain their namespace GUIDs. |

### Validation coverage

Validate the acceptance criteria with unit and real-driver tests, including
failure cases and regressions.

| Coverage | Focus |
|----------|-------|
| Unit tests | Per-thread selection, object ownership, ID/pin isolation, same-path pins in different namespaces, relationship restrictions, and failure handling. |
| Real-driver tests | Independent threads and applications using different GUIDs, intentional sharing through the same GUID, management permissions, and existing handle validity after selection changes. |
| Regression tests | Default-namespace behavior, native loading, local metadata queries, and existing handle-based asynchronous and buffer APIs. |

Unit tests do not replace real-driver validation. Detailed scenarios and
failure-injection cases remain in the separate implementation test plan.

## Security Considerations

- Namespaces provide **logical isolation**, not security isolation. Existing ACLs and privilege checks still apply.
- `ebpf_set_thread_namespace()` and `ebpf_get_thread_namespace()` require administrative privileges.
- A caller with administrative privileges can select any namespace by its GUID.
- Changing a thread's namespace does not revoke access through existing object handles.

## Tooling

### netsh

The proposed commands remain:

```text
netsh ebpf set namespace {GUID}
netsh ebpf show namespace
```

Their selection is on the executing netsh thread, not
machine-wide or persistent across separate command processes. Namespace-aware
follow-up commands must run on that same selected thread in the same netsh
session. If tooling dispatches work to another thread, it must explicitly
select/reset there under the application rules above.

Running SET in one netsh process does not configure another process, bpftool,
or an application's worker. Reset with the same SET syntax and the all-zero
GUID (`{00000000-0000-0000-0000-000000000000}`). Reset must be explicit.
These commands are proposed tooling behavior, not a claim that main already
implements them.

Namespace GUIDs are application-defined. Administrators should consult
application documentation for the appropriate stable GUID.

### bpftool

bpftool continues to operate in the default namespace to maintain Linux CLI
compatibility. A netsh selection does not change its namespace. Use a
namespace-aware SDK application or a correctly bound netsh session for
namespace-specific management.

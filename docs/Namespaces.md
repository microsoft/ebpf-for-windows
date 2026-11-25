# BPF Object Namespaces

## Overview

Namespaces provide logical isolation of BPF objects (programs, maps, links).
Each namespace is identified by a GUID, with `GUID_NULL` representing the
default namespace. An application selects a namespace **per OS thread** through
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

> **Note:** BPF object namespaces are orthogonal to network compartments: changing one
> does not change the other. They scope BPF objects rather than network resources,
> allowing products sharing a compartment to use separate BPF namespaces.
> Existing security checks still apply.

## Requirements

Namespace isolation lets applications partition their BPF objects for product
coexistence without pin-path naming conflicts, test isolation, and separation
between application components.

| ID | Requirement |
|----|-------------|
| R1 | Each BPF object SHALL be associated with exactly one immutable namespace GUID at creation, before its ID becomes discoverable. |
| R2 | The default namespace SHALL be the null GUID (`GUID_NULL`). |
| R3 | Object ID enumeration and open-by-ID SHALL only return objects matching the calling thread's selected namespace. IDs SHALL remain globally unique. |
| R4 | Pin lookup, insertion, deletion, and enumeration SHALL be relative to the calling thread's selected GUID. The same pin path string MAY exist in multiple namespaces without conflict. |
| R5 | Existing handles to BPF objects SHALL remain valid after a namespace switch. |
| R6 | A namespace switch SHALL affect only the scope of subsequent namespace-dependent operations. |
| R7 | Namespace management SHALL require the same privileges as other eBPF management operations. |
| R8 | Applications not using namespace APIs SHALL operate in the default namespace with no code changes. |
| R9 | Namespace selection SHALL be per thread. New threads SHALL start in `GUID_NULL`, without inheritance. |
| R10 | A successful namespace change SHALL apply to subsequent namespace-dependent operations on the calling thread. A failed change SHALL preserve its previous selection. |
| R11 | New object relationships SHALL connect only objects in the same namespace. Existing ordinary handle-based access SHALL NOT depend on the caller's selected namespace. |
| R12 | Existing handle-based asynchronous operations SHALL remain independent of the caller's selected namespace. |

## API Specification

### ebpf_set_thread_namespace

Sets the namespace for the calling thread.

```c
ebpf_result_t ebpf_set_thread_namespace(_In_ const GUID* namespace_guid);
```

**Parameter:** `namespace_guid` points to the namespace GUID to select. Pass
the address of `GUID_NULL` to reset. A NULL pointer is invalid.

**Returns:** An `ebpf_result_t` result code: `EBPF_SUCCESS` on success, or an
error code on failure. Failure leaves the previous selection unchanged.

| Aspect | Behavior |
|--------|----------|
| Scope | Calling thread; other threads are unchanged. |
| Persistence | Selection remains effective until successfully changed, the calling thread terminates (including process exit), or `ebpfapi.dll` is completely unloaded. |
| Default | `GUID_NULL` on each new thread and on surviving threads after a complete DLL unload/reload. |
| Reset | Pass the address of `GUID_NULL`; a NULL pointer is invalid, not a reset. |
| Effect on existing objects | None; their GUIDs and ordinary handle-based access remain unchanged. |
| Effect on new objects | Creation uses the calling thread's captured selection. |
| Effect on discovery | ID and pin discovery uses the selected GUID. |
| Failure | Return the error; retain the previous committed logical selection. |

### ebpf_get_thread_namespace

Gets the calling thread's selected namespace GUID.

```c
ebpf_result_t ebpf_get_thread_namespace(_Out_ GUID* namespace_guid);
```

**Parameter:** `namespace_guid` points to the GUID that receives the calling
thread's selected namespace on success. A NULL pointer is invalid.

**Returns:** An `ebpf_result_t` result code: `EBPF_SUCCESS` on success, or an
error code on failure. Failure leaves the output unchanged.

### Namespace-Aware APIs

Existing API signatures do not gain GUID parameters. Classification depends
on the operation, not just whether an API accepts an fd or object pointer.

| Category | Examples and behavior |
|----------|------|
| Creation/loading | Map creation, native object loading, and program attachment use the selected GUID. Attachment creates a new link even if it takes an existing program fd. |
| ID discovery | `bpf_map_get_next_id`, `bpf_prog_get_next_id`, `bpf_link_get_next_id`, and corresponding open-by-ID APIs are namespace-filtered. |
| Pinning | `bpf_obj_get`, `bpf_obj_pin`, map/program/link pin/unpin, pinned-map information, and pin-path enumeration are namespace-relative. |
| Implicit link discovery | Program detach by attach parameters and XDP query/detach/replacement search links in the selected namespace. |
| Existing-handle/fd operations | Map data access, info-by-fd, direct link-fd detach, program test-run, fd close/duplicate, and ring/perf consumers do not select targets by the ambient GUID. Owner-compatibility checks still apply to graph updates. |
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
   namespace. For maps-of-maps (`ARRAY_OF_MAPS` and `HASH_OF_MAPS`), the outer
   map, inner-map template, and inserted maps must share a namespace. A program
   array (`PROG_ARRAY`) and the programs inserted into it must also share a
   namespace, even when the caller already holds all the fds.
4. **Implicit namespaces**: Namespaces are not explicitly created or deleted.
   A namespace exists as long as objects with that GUID exist.

## Application Responsibilities

Call `ebpf_set_thread_namespace()` on the thread performing namespace-dependent
work. Check the result; if selection fails, do not proceed with that work.

Namespace selection remains on a worker until explicitly changed. If subsequent
work expects the default namespace, reset the worker to `GUID_NULL` before
returning it to the pool, whether the current work succeeds or fails. Check the
reset result; failure leaves the previous selection unchanged.

```text
Select namespace -> perform work -> reset to GUID_NULL -> return to pool
```

Handle reset errors separately from work errors. Alternatively, a pool can
explicitly select the intended namespace before each task's namespace-dependent
work, including selecting `GUID_NULL` for default-namespace work.

New threads start in `GUID_NULL`. Asynchronous work may resume on a different
thread with a different namespace. Callbacks may also run on another thread.
Before namespace-aware work, select the intended namespace on the thread
running it. Follow the pool's namespace policy before pausing the work or
returning the worker. Existing handle-based data access and namespace-neutral
async operations need no reselection.

A dedicated worker may retain its selection until it takes on work that needs
a different namespace. Remove pins by path while their namespace
is selected, before resetting the worker. Selection does not survive process
exit. Pinned BPF objects can survive and retain their GUIDs; after restarting,
select the same stable GUID to rediscover those pins.

## Acceptance Criteria

| ID | Criterion |
|----|-----------|
| AC1 | T1 selecting A cannot enumerate/open B objects by ID; T2 selecting B remains independent. Enumeration skips hidden entries and IDs remain globally unique. |
| AC2 | A thread selecting namespace A cannot open or enumerate pins in namespace B. |
| AC3 | Objects in different namespaces can be pinned at the same path. Unpinning in one namespace does not affect the other. |
| AC4 | After `ebpf_set_thread_namespace()` succeeds, new maps, programs, and links belong to the selected namespace. Existing objects and other threads' selections remain unchanged. |
| AC5 | Existing handles remain usable for permitted operations after SET/reset and across threads. Cross-namespace inner-map templates, map-of-maps entries, program-array entries, and program/map/link relationships are rejected, as is pinning outside an object's namespace. |
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
| Unit tests | Per-thread selection, object ownership, ID/pin isolation, same-path pins in different namespaces, same-namespace acceptance and cross-namespace rejection for map-of-maps/program-array relationships, and failure handling. |
| Real-driver tests | Independent threads and applications using different GUIDs, intentional sharing through the same GUID, management permissions, relationship restrictions, compartment/namespace independence, and existing handle validity after selection changes. |
| Regression tests | Default-namespace behavior, native loading, local metadata queries, and existing handle-based asynchronous and buffer APIs. |

Unit tests do not replace real-driver validation. Detailed scenarios and
failure-injection cases remain in the separate implementation test plan.

## Design Details

This section describes how the driver manages file contexts, tracks namespace
selection, propagates it to the kernel, and applies it to IOCTL calls.

### WDF file object configuration

The driver registers `EvtDeviceFileCreate` and `EvtFileClose` callbacks and
associates a per-file context type (`ebpf_file_context_t`) with every WDF file
object:

```c
WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, ebpf_file_context_t);
WDF_FILEOBJECT_CONFIG_INIT(&config, _ebpf_driver_file_create,
                           _ebpf_driver_file_close, WDF_NO_EVENT_CALLBACK);
config.FileObjectClass = WdfFileObjectWdfCannotUseFsContexts;
```

`WdfFileObjectWdfCannotUseFsContexts` tells WDF not to store its framework
pointer in the kernel `FILE_OBJECT`'s `FsContext` or `FsContext2` fields. This
is necessary because ebpfcore already uses `FsContext2` to store a direct
pointer to a BPF object when creating object handles (`ebpf_handle_create`
calls `ZwCreateFile` on the device and stores the object in
`file_object->FsContext2`). WDF uses an internal lookup table instead, which
adds a minor per-request lookup cost but avoids field conflicts.

### File context creation (CreateFile)

When user mode calls `CreateFile` on `\\.\EbpfIoDevice`:

```text
1. I/O Manager creates a kernel FILE_OBJECT and sends IRP_MJ_CREATE
2. WDF creates a WDFFILEOBJECT and allocates ebpf_file_context_t alongside it
     (automatic — configured by WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE above)
3. WDF calls EvtDeviceFileCreate (_ebpf_driver_file_create):
     → initializes the spinlock and sets namespace_id to GUID_NULL
     → sets initialized = true
     → completes the create request with STATUS_SUCCESS
4. CreateFile returns a HANDLE to user mode
```

Each thread's synchronous device handle in `ebpfapi.dll` is a separate
`CreateFile` call, so each gets its own `FILE_OBJECT` → `WDFFILEOBJECT` →
`ebpf_file_context_t` → independent namespace GUID.

The `initialized` flag guards `EvtFileClose`: WDF can call close even if
create was never delivered or failed, so close only destroys the namespace
state if `initialized` is true.

### Control files vs. object files

The same device has two kinds of file objects:

| Kind | Opened by | `FsContext2` | Has namespace state |
|------|-----------|-------------|---------------------|
| Control file | User-mode `CreateFile` for IOCTLs | NULL | Yes |
| Object file | Kernel `ebpf_handle_create` for BPF objects | BPF object pointer | No |

The IOCTL dispatch path checks `FsContext2 == NULL` to identify control files.
Only control files carry namespace state; object files are internal handles
to maps, programs, and links.

### Namespace state storage

Namespace state is tracked at two layers:

**User mode (`ebpfapi.dll`):** Each thread has a thread-local `_thread_namespace`
GUID variable and a corresponding per-thread synchronous device handle
(`_sync_device_handle`). The DLL records the logical namespace selection after
each successful kernel round-trip. New threads start with `GUID_NULL`.

**Kernel mode (`ebpfcore.sys`):** Each control file object has a WDF file
context containing an `ebpf_namespace_state_t`:

```text
ebpf_file_context_t
├── ebpf_namespace_state_t
│   ├── lock           (serializes reads and writes)
│   └── namespace_id   (the GUID currently selected on this file)
└── initialized
```

The spinlock protects against concurrent reads and writes on a shared file
object (e.g., if user mode calls `DuplicateHandle` and two threads use the
same underlying `FILE_OBJECT`). For the normal per-thread sync handle pattern,
the lock is uncontended. Benchmarking shows the spinlock adds approximately
70–100 ns (~3–5%) to each IOCTL, within measurement noise relative to the
~2200 ns per-IOCTL round-trip cost.

### Updating a thread's namespace

The sequence for `ebpf_set_thread_namespace(&A)`:

```text
1.  User calls ebpf_set_thread_namespace(&A)
2.  SDK obtains the calling thread's sync device handle
      (opens one if needed — triggers file context creation above)
3.  SDK sends SET_NAMESPACE IOCTL with GUID A through
      that handle
4.  Driver validates privileges (SeAccessCheck)
5.  Driver updates the file context's namespace_id to A
      under the spinlock
6.  IOCTL succeeds
7.  SDK records A in the thread-local _thread_namespace
8.  Returns EBPF_SUCCESS
```

SET_NAMESPACE is handled directly at the driver layer before the protocol
handler framework, because the protocol handlers receive only a captured GUID
snapshot (`ebpf_request_context_t`) with no write-back pointer to the file
state. Only the driver has access to the file context.

If the IOCTL fails at step 4–5, the thread-local selection is **not** updated
(step 7 is skipped), preserving the previous committed selection. The kernel
file context also remains unchanged on failure.

If a cached sync handle is closed and later recreated (e.g., after a verifier-
cache cleanup), the SDK checks the thread-local GUID. For non-default GUIDs,
it sends an internal SET on the new handle before using it, so the replacement
file context matches the thread's logical selection.

### Namespace propagation during IOCTL dispatch

When the driver receives a synchronous IOCTL, it captures the file's current
GUID into a stack-local `ebpf_request_context_t` before calling the protocol
handler:

```text
IOCTL arrives
  → driver retrieves WDF file object
  → checks FsContext2 == NULL (control file, not object file)
  → reads file_context->namespace_state.namespace_id
      under the spinlock (ebpf_namespace_state_capture)
  → copies the GUID into a local ebpf_request_context_t
  → passes that context to ebpf_core_invoke_protocol_handler
```

`ebpf_request_context_t` contains only the captured `namespace_id` GUID. Each
protocol handler receives this as a `const` pointer. Handlers that create
objects, enumerate IDs, or manage pins use the captured GUID to scope their
operations. Handlers that operate on existing handles (map data access,
program test-run, etc.) ignore the GUID.

The capture is a snapshot: if another thread changes the same file's namespace
concurrently, only that thread's subsequent IOCTLs see the new value. The
captured value for the current request is immutable.

Asynchronous operations are namespace-neutral — they operate on already-held
object handles and do not use the captured GUID.

## Security Considerations

- Namespaces provide **logical isolation**, not security isolation. Existing ACLs and privilege checks still apply.
- `ebpf_set_thread_namespace()` and `ebpf_get_thread_namespace()` require administrative privileges.
- A caller with administrative privileges can select any namespace by its GUID.
- Changing a thread's namespace does not revoke access through existing object handles.

## Tooling

### netsh

Within the `ebpf` context of a persistent netsh session, select a namespace,
run existing commands, then reset. These commands must execute on the same
thread:

```text
set namespace {GUID}
show namespace
show programs
set namespace {00000000-0000-0000-0000-000000000000}
```

Selection does not persist after netsh exits. Running SET in one netsh process
does not affect a later invocation or another application.

Existing commands also accept an optional `namespace={GUID}` argument, scoped
to that command:

```text
netsh ebpf add program filename=<file> namespace={GUID}
netsh ebpf show programs namespace={GUID}
```

The `namespace={GUID}` argument lets a standalone command target a namespace
without a prior `set namespace` call. If omitted, the command uses the thread's
selected namespace (`GUID_NULL` by default).

### bpftool

bpftool always operates in the default namespace to maintain Linux CLI compatibility. Use netsh for namespace-aware operations.

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
| Pinning | `bpf_obj_get`, `bpf_obj_pin`, map/program/link pin/unpin, pinned-map information, and pin-path enumeration are namespace-relative. Cached pin state such as `bpf_map__is_pinned` must be namespace-qualified. |
| Implicit link discovery | Program detach by attach parameters and XDP query/detach/replacement search links in the selected namespace. |
| Existing-object operations | Map data access, info-by-fd, direct link-fd detach, program test-run, fd close/duplicate, and ring/perf consumers do not select targets by the ambient GUID. Owner-compatibility checks still apply to graph updates. |
| Local/file metadata | Local wrapper iteration/name lookup, object-file parsing, file program enumeration, verifier diagnostics, type/provider metadata, and path-text canonicalization are not kernel namespace discovery. |

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

Select on the thread actually performing namespace-dependent work, check
success, and reset that same worker before returning it to a shared pool:

```text
Worker W: SET(A) succeeds -> work in A -> SET(GUID_NULL) succeeds -> return
```

Otherwise the namespace **leaks into subsequent work on that worker**:

```text
Worker W: SET(A) -> returns to pool without reset
Worker W: later work expecting GUID_NULL -> still uses A for creation/discovery
```

This is ambient selection carryover, not a memory leak or object ownership
transfer. Closing/recreating the sync handle is not reset: the remembered A
will be rebound.

Applications must attempt/check reset on supported success, error,
early-return, handled-exception, and cooperative-cancellation paths. A failed
reset preserves the previous committed selection and must not be reported
as a clean/default worker. Handle work and cleanup failures separately.
The SDK does not reset a worker's namespace automatically or require a new
scoped-helper API.

To remove a pin by path, select the namespace containing that pin before
unpinning it. For example, remove namespace A's pins while A is selected,
then reset the worker.

Namespace selection is not task-local, fiber-local, or `.NET AsyncLocal`.
Carry the GUID as work data; reset before yielding/returning the worker and
select/check again before a resumed segment needs namespace-dependent work:

```text
T1: select A -> synchronous work -> reset -> await/yield
T2: select A -> synchronous work -> reset -> return
```

A final reset on T2 cannot reset T1. Fibers sharing a thread share its TLS.
Application callback creation/discovery follows the same select/reset rule;
ordinary held-object operations and existing eBPF async operations do not
need automatic namespace propagation. The SDK remains responsible for correct
per-thread binding and checked sync-handle recreation.

A dedicated worker can retain A for its dedicated lifetime, but must reset
before returning to a shared pool or default role. Selecting A on the main
thread does not initialize workers into A. Reuse a stable application GUID
when later sessions must rediscover surviving pins.

## Acceptance Criteria

| ID | Criterion |
|----|-----------|
| AC1 | T1 selecting A cannot enumerate/open B objects by ID; T2 selecting B remains independent. Enumeration skips hidden entries and IDs remain globally unique. |
| AC2 | A cannot discover B pins by path or pin enumeration. |
| AC3 | The same canonical pin path can identify separate A/B objects without conflict; unpin affects only the selected partition. |
| AC4 | After successful `ebpf_set_thread_namespace`, newly created maps/programs/links use the new GUID. Other threads and existing objects do not change. |
| AC5 | Existing handles continue ordinary permitted operations after SET/reset and across threads; foreign-owner graph/pin/link creation remains rejected. |
| AC6 | Default-only applications retain existing behavior with the updated DLL/driver pair. New workers start null, without inheriting their creator's GUID. |
| AC7 | Management privilege checks apply to SET, GET, and internal rebinding, including explicit same/default SET; unauthorized calls fail. |
| AC8 | Failed SET preserves committed TLS; failed GET leaves output unchanged. Malformed/failed replies never produce false success or default fallback. |
| AC9 | Supported sync-handle recreation preserves logical selection and restores non-default A before creation/discovery. A failed rebind has no default-namespace side effects. |
| AC10 | Explicit SET uses IOCTL-before-TLS ordering; internal restore does not recursively enter the public getter/setter. |
| AC11 | Admitted synchronous native load/pin sequences and rollback keep their binding through supported cache reset and concurrent SET on another thread. |
| AC12 | An application-owned worker fixture selects/resets correctly on all supported exits and reports reset failure. A negative fixture omitting reset demonstrates A carrying into subsequent work on the same thread, even after handle recreation. |
| AC13 | Controlled task/fiber fixtures demonstrate explicit application select/reset without SDK task/fiber propagation. |
| AC14 | Existing async test-run, notifications, cancellation/rearm and buffer operations remain correct while threads select/reset A/B/default. The shared async handle is not retagged. |
| AC15 | Local wrapper/file metadata queries remain selection-neutral; cached pin-state queries remain namespace-qualified. |
| AC16 | Native loading, auto-pin reuse, failure rollback, immutable-owner restrictions and native image authorization remain correct. |
| AC17 | Quiescent DLL reload initializes new namespace TLS to null without requiring repairs to existing handle-cleanup behavior; surviving objects keep their GUIDs. |

### Validation coverage

These are tests required for implementation, not executed results from this
documentation change. Use NativeOnly unit fixtures and isolated real-driver
fixtures. Usersim tests do not establish actual Windows FILE_OBJECT, token,
or KMDF request-lifecycle behavior.

| Test layer | Required scenarios |
|------------|--------------------|
| Unit: TLS and IOCTL routing | Explicit SET/GET success/failure, invalid pointers/replies, default/idempotent SET authorization, IOCTL-before-TLS commit, ambiguous responses, direct candidate binding, no recursion/default fallback. |
| Unit: creation/discovery | Immutable owner before publication, GUID-filtered IDs including gaps/deletion, same-path A/B pins, namespace-qualified cached pin state, attach creation versus direct-link detach and implicit detach discovery. |
| Unit: transactions and graph rules | Native creation/reuse/rollback failures, retained binding during cache retirement, independent thread SET, held-object data/info/bind operations and immutable-owner relationship rejection. |
| Unit: application fixtures | New-thread default, worker reset on success/error and reset failure, negative carryover, task/fiber migration without automatic propagation. |
| Driver: independent files/threads | Two same-process threads selecting A/B, same-GUID sharing across applications, raw file defaults, duplicate-file semantics, ID/pin/link isolation, handle validity and file context lifetime. |
| Driver: permission/failure paths | Effective-subject authorization, denied SET/GET/rebind, handle recreation, no unintended default object creation, protocol/endpoint validation, correct queued cancellation and terminal completion. |
| Regression | Existing native loading/data/async/buffer behavior, ordinary default-only APIs, object lifetime and quiescent reload semantics; no new cleanup-hardening or older-driver interoperability matrix. |

## Security Considerations

- Namespaces provide **logical isolation**, not security isolation. Existing
  ACLs, device access policy, effective-subject checks and native image
  authorization still apply.
- SET/GET and internal non-default rebinding require the existing eBPF
  management privileges. TLS is not an authorization token.
- An authorized administrator knowing A's GUID can deliberately select A.
  Namespace matching is not a new secret-based access-control boundary.
- Shared-address-space code can pass held handles; selection does not revoke
  them. Cross-owner graph checks remain separate.
- ACL-based per-object delegation and break-glass/global enumeration are not
  introduced by this GUID namespace proposal.

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

# netebpfext Architecture

`netebpfext.sys` implements eBPF hooks for the sock_addr and sock_ops program types using
Windows Filtering Platform (WFP) callouts. It also supports the deprecated bind program
type. The driver translates network events into eBPF program contexts and applies program
verdicts to WFP classification.

## Scope

This overview describes the implemented architecture, lifecycle, and ownership invariants
reviewed at commit `2b64664adffc525d72917ab47df1fa834d25e374`, not a proposed design.
Before making changes, verify implementation details against the current source; symbols
and line references below describe the reviewed revision.
Only native program invocation is in scope. Other execution modes are intentionally
omitted.

For general extension contracts, see [eBPF extensions](eBpfExtensions.md).

## Architecture overview

`netebpfext.sys` bridges WFP and `ebpfcore` through two roles:

1. **WFP callout driver**
   - Registers kernel callouts at ALE layers.
   - Adds WFP filters when an eBPF link attaches.
   - Receives classify, notify, and flow-delete callbacks from WFP.
   - Converts WFP data into the context expected by an eBPF program.
   - Applies the program verdict back to WFP.
2. **eBPF extension**
   - Registers NMR program-information providers that describe supported program types,
     context layouts, helpers, and section names.
   - Registers NMR hook providers for supported attach types.
   - Converts an attached NMR client into a `net_ebpf_extension_hook_client_t`.
   - Uses the client dispatch function supplied by `ebpfcore` to invoke the linked program.

NMR (Network Module Registrar) connects these providers to `ebpfcore` clients, separating
program metadata from hook attachment.

```text
Control path:
  ebpfcore link -> NMR hook binding -> netebpfext hook provider -> WFP filters

Data path:
  WFP network event -> netebpfext classify callback -> ebpfcore link -> native eBPF program
                       <- WFP action              <- program verdict
```

Matching multi-attach clients share a filter context and WFP filters. Classification
snapshots clients under the filter-context lock, then invokes programs synchronously
outside the lock. Rundown protects client lifetime during invocation.

The runtime object relationship is:

```text
WFP filter.rawContext
  -> net_ebpf_extension_wfp_filter_context_t
     -> client_contexts[]
        -> net_ebpf_extension_hook_client_t
           -> client_binding_context (ebpf_link_t in ebpfcore)
           -> invoke_program (_ebpf_link_instance_invoke)
```

## Driver and WFP lifecycle

### Startup

Driver startup ([`DriverEntry`](../netebpfext/sys/net_ebpf_ext_drv.c#L146)) performs:

1. Trace initialization.
2. NX nonpaged-pool opt-in.
3. WDF driver and control-device creation.
4. NDIS handle initialization.
5. Initialize WFP infrastructure: register the provider, sublayers, and callouts, then
   create the L2 injection handle
   ([`net_ebpf_extension_initialize_wfp_components`](../netebpfext/net_ebpf_ext.c#L797)).
6. Register [eBPF program-information and hook providers](#program-information-and-hook-providers)
   with NMR ([`net_ebpf_ext_register_providers`](../netebpfext/net_ebpf_ext.c#L1177)).

#### WFP initialization

WFP infrastructure initialization consists of:

1. Opens the WFP engine.
2. Begins a transaction.
3. Adds the eBPF WFP provider.
4. Adds the default and connect-redirect sublayers.
5. Registers each kernel callout with `FwpsCalloutRegister`.
6. Adds the corresponding management-plane callout with `FwpmCalloutAdd`.
7. Commits the transaction.
8. Creates the L2 injection handle.

The static callout table in
[`_net_ebpf_ext_wfp_callout_states`](../netebpfext/net_ebpf_ext.c#L80) maps each callout
GUID and WFP layer to its classify, notify, and flow-delete callbacks.

### Shutdown

Driver unload deliberately orders teardown as follows:

1. Mark the driver as unloading.
2. Deregister NMR hook and program-information providers.
3. Unregister WFP kernel callouts.
4. Clean up filters and any zombie filter contexts.
5. Delete management-plane callouts, sublayers, and provider.
6. Close the WFP engine and destroy the injection handle.
7. Wait for provider rundown and free deferred provider contexts.
8. Uninitialize NDIS/tracing and delete the WDF device.

Callouts must be unregistered before forcibly reclaiming zombie filter contexts. If a
callout remains active, freeing its `filter->context` would create a use-after-free.

## Program-information and hook providers

Three program-information providers are registered:

| Program type | Context | Required IRQL | Notable properties |
|---|---|---:|---|
| Deprecated bind | `bind_md_t` | `PASSIVE_LEVEL` | No local helpers; plain link |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `bpf_sock_addr_t` | `DISPATCH_LEVEL` | Redirect/network-context helpers and socket identity helpers |
| `BPF_PROG_TYPE_SOCK_OPS` | `bpf_sock_ops_t` | `DISPATCH_LEVEL` | Flow-established and flow-delete events |

The program-information provider is mostly descriptive. It publishes `ebpf_program_data_t`
and helper metadata through the NMR registration's `NpiSpecificCharacteristics`, which
`ebpfcore` reads during attachment. The provider's attach callback creates a per-client
binding context; it does not return program metadata through a dispatch table.

Section descriptors use
[`EBPF_PROGRAM_SECTION_INFORMATION_HEADER`](../include/ebpf_windows.h#L153) from
`ebpf_windows.h`. Keep all three versioned header fields (`version`, `size`, and
`total_size`); the old two-field section initializer is no longer used.

Hook providers are per attach type:

- One deprecated bind hook provider.
- Ten sock-address hook providers: IPv4/IPv6 connect, recv/accept,
  connect authorization, bind, and listen.
- One sock-ops provider.

Attach capabilities determine how many clients can share a hook:

| Hook family | Capability |
|---|---|
| Deprecated bind | Single attach |
| sock_addr connect, connect authorization, bind, and listen | Multi-attach with wildcard |
| sock_addr recv/accept | Single attach per hook |
| sock_ops | Single attach per hook |

Multi-attach contexts hold at most 16 clients per matching attach parameter, not 16
clients across the entire provider. For sock_addr, the attach parameter is a compartment
ID; omitted parameters or `UNSPECIFIED_COMPARTMENT_ID` select a wildcard.

## Attach, filter creation, detach, and lifetime

### Attach

[`_net_ebpf_extension_hook_provider_attach_client`](../netebpfext/net_ebpf_ext_hook_provider.c#L409):

1. Validates NMR client characteristics and attach data.
2. Allocates a `net_ebpf_extension_hook_client_t`.
3. Saves:
   - NMR binding handle and module ID.
   - `client_binding_context` supplied by `ebpfcore` (an `ebpf_link_t`).
   - The program invocation function from the client dispatch table.
   - Attach data and attach type.
4. Initializes per-client rundown.
5. Takes the provider push lock to serialize attach/detach.
6. Enforces the provider's attach capability.
7. Reuses a matching filter context for eligible multi-attach hooks and appends the
   client, or calls the hook-specific `create_filter_context`, which installs the first
   client in the new context.
8. For a new context, adds one or more WFP filters whose raw context points at the
   filter context. Reusing a context does not create additional filters.
9. Publishes the new context on the provider's active filter-context list.

Filter contexts and client arrays are allocated from `NonPagedPoolNx`. Each filter context
holds a rundown reference on its hook provider.

### Detach

[`_net_ebpf_extension_hook_provider_detach_client`](../netebpfext/net_ebpf_ext_hook_provider.c#L638):

1. Runs at `PASSIVE_LEVEL`.
2. Removes the client under the provider lock.
3. Marks an empty filter context as deleting.
4. Deletes its WFP filters and releases hook-specific resources, such as redirect
   handles and sock-ops flow associations.
5. Releases the context's initial reference if all filters are deleted; otherwise
   transfers it to the provider's zombie list, retaining the initial reference.
6. Queues a work item and returns `STATUS_PENDING`.
7. The work item waits for client rundown, then calls
   `NmrProviderDetachClientComplete`.

Invocation takes client rundown before dropping the filter-context lock. Therefore the
client and its `ebpf_link_t` binding remain valid while an in-flight classify callback
invokes the program.

### Filter deletion state

Each WFP filter ID transitions through:

```text
ADDED -> DELETING -> DELETED
                   \-> DELETE_FAILED -> retry
```

The WFP delete notification owns the transition to `DELETED` and releases the per-filter
reference. `FwpmFilterDeleteById` is called without holding the filter lock because WFP
can synchronously invoke the delete notification, which takes the same lock.

Deletion makes up to three inline attempts per filter. Persistent failures leave the
context on the provider's zombie list until unload unregisters every kernel callout.
Only then may cleanup retry deletion and forcibly reclaim the context without waiting
for missing WFP notifications. Terminating filters use
`FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED`, so a filter that still cannot be
deleted permits traffic once its callout is unregistered.

## WFP-to-program invocation flow

### Shared invocation path

The generic extension path is:

```text
WFP classify callback
  -> build program context from FWPS inputs
  -> net_ebpf_extension_hook_invoke_filtered_programs
       acquire filter-context shared spin lock
       snapshot up to 16 client pointers into a local array
       acquire each client's rundown
       release filter-context lock
       for each selected client:
         client->invoke_program(client_binding_context, context, verdict)
           -> _ebpf_link_instance_invoke
                create 64-byte ebpf_execution_context_state_t
                enter epoch
                invoke linked program:
                  -> ebpf_program_invoke
                       set runtime state and context descriptor in EBPF_CONTEXT_HEADER
                       validate native BTF providers
                       call the bpf2c entry point with context and runtime_context
                       follow up to 33 tail calls
                exit epoch
         optional process_verdict(context, verdict)
       release client rundown
  -> classify callback translates verdict to WFP action
```

Program execution completes before epoch exit and client rundown release.

For a native program, [`ebpf_program_invoke`](../libs/execution_context/ebpf_program.c#L2176)
loads `code_or_vm.native.code_pointer` and
`code_or_vm.native.code_context.runtime_context`, verifies that BTF-resolved providers
are ready, and calls the bpf2c entry point. Tail-called native programs are invoked
sequentially by the outer loop after the previous entry point returns; their entry-point
frames are not simultaneously nested by the tail-call mechanism.

### Stack-expanded sock_addr path

All five sock-address callbacks currently expand only the invocation portion:

```text
sock_addr classify callback, context remains on original WFP stack
  -> net_ebpf_extension_hook_expand_stack_and_invoke_filtered_programs
       KeExpandKernelStackAndCalloutEx(..., 16 KiB, ...)

expanded stack:
  -> _net_ebpf_extension_invoke_programs_callout
       -> net_ebpf_extension_hook_invoke_filtered_programs
            -> _ebpf_link_instance_invoke
                 -> ebpf_program_invoke
                      -> native bpf2c program entry point
```

The deprecated bind and sock-ops classify callbacks invoke the generic dispatcher
directly and do not currently expand the stack.

Listen now keeps an original-context snapshot on the WFP stack, just like bind and the
two connect callbacks. Stack expansion does not move these contexts or snapshots off
the original stack.

## Hook-specific data paths

### Deprecated bind

Resource allocation and release callbacks:

1. Build a `bind_context_header_t` and IPv4-shaped `SOCKADDR_IN`.
2. Populate process ID, operation, protocol, local address/port, and app-ID bounds.
3. Validate the UTF-16 application-ID byte length and bounds, then scan bytewise to
   truncate it to the executable file name without requiring aligned `wchar_t` access.
4. Invoke the attached program directly.

Resource allocation maps `BIND_PERMIT_SOFT` and `BIND_REDIRECT` to soft permit,
`BIND_PERMIT_HARD` to hard permit, and other returned values to block. Despite the
`BIND_REDIRECT` name, this callback does not copy a modified socket address back into
WFP. Invalid app-ID input, a missing program, or invocation failure leaves the default
permit in place. Resource release always permits; it invokes the program only as an
unbind notification.

### sock_addr

`net_ebpf_sock_addr_t` contains:

- The 64-byte private `EBPF_CONTEXT_HEADER`.
- Public `bpf_sock_addr_t`.
- Access token information, process ID, flags, and hook ID.
- Redirect context and transport endpoint handle.
- A pointer to an original `bpf_sock_addr_t` snapshot.
- Accumulated verdict and redirect state.
- Additional interface, tunnel, next-hop LUID, and sub-interface properties.

Flows:

| WFP event | Callback behavior |
|---|---|
| Listen authorization | Copy local listen fields, skip reauthorization, preserve original context, invoke multiple programs, apply most restrictive verdict |
| Receive/accept authorization | Copy connection fields, skip reauthorization, invoke, apply allow/reject |
| Bind | Copy local bind fields, preserve original context for multi-attach restoration, invoke, choose most restrictive verdict |
| Connect authorization | Consume cached redirect-layer verdict, skip programs only for cached reject, preserve original context, invoke authorization attach types, apply accumulated verdict |
| Connect redirect | Check redirect state/family, acquire classify handle, preserve original context, invoke connect programs, apply redirect, cache hard permit or reject for authorization |

Connect, connect authorization, bind, and listen support multi-attach, but use different
`process_verdict` callbacks:

- Bind and listen use `_net_ebpf_extension_sock_addr_accumulate_verdict`. They do not
  support address rewriting, restore the entire public context after every program,
  accumulate the most restrictive verdict, and stop at reject.
- Connect and connect authorization use `_net_ebpf_extension_sock_addr_process_verdict`.
  They accumulate verdicts and stop at reject or a destination rewrite. At connect
  authorization, destination rewrites are instead discarded and the original context
  restored, allowing subsequent programs to run.
- Receive/accept has no multi-attach verdict callback.

The original 64-byte `bpf_sock_addr_t` snapshot is therefore required for restoration
or redirect detection; it cannot simply be removed.

#### Verdict and failure rules

The priority is `REJECT > PROCEED_HARD > PROCEED_SOFT`; unknown return values are
treated as reject. Bind and listen start their accumulated verdict at `PROCEED_SOFT`.
Connect authorization starts with the cached redirect-layer verdict, so authorization
can reject a hard-permitted connection but cannot downgrade hard permit to soft permit.

`_net_ebpf_extension_sock_addr_get_effective_verdict` preserves the current verdict for
`EBPF_OBJECT_NOT_FOUND` (no matching client), but rejects other dispatch failures,
including stack-expansion failure. Successful multi-attach dispatch uses the
accumulated `net_ebpf_sock_addr_t::verdict`, not the last program's output parameter.

Listen, receive/accept, bind, and connect authorization map soft permit to
`FWP_ACTION_PERMIT` without clearing `FWPS_RIGHT_ACTION_WRITE`; hard permit and block
clear that right. When the right is absent on entry, programs are skipped and the WFP
action is preserved. Connect authorization consumes its cached verdict before this
no-write check.

Connect redirect does not directly block a rejected connection: it caches the reject
for connect authorization and returns `FWP_ACTION_PERMIT`. Redirects and reauthorization
also return permit; non-redirected proceed verdicts return `FWP_ACTION_CONTINUE`.

### sock_ops

Flow-established classify:

1. Allocates the complete flow context from `NonPagedPoolNx` (184 bytes on x64).
2. Copies WFP connection fields into the embedded program context (144 bytes on x64).
3. Associates the context with the WFP flow.
4. Invokes the attached program directly.
5. Links the flow context into the filter-context flow list.

The large program context is already off-stack. Each flow context holds a filter-context
reference. Flow delete unlinks the flow first, invokes the program with the stored heap
context unless the filter context is deleting, and then releases the reference and
frees the flow context.

## Concurrency, IRQL, and ownership invariants

- WFP management and NMR attach/detach operations are `PASSIVE_LEVEL`.
- sock_addr and sock_ops program contexts are valid at `DISPATCH_LEVEL`; any hot-path
  allocation must be nonpaged and nonblocking.
- The filter-context spin lock protects the client list, not program execution.
- Client rundown protects copied client pointers after releasing the spin lock.
- Provider rundown keeps provider dispatch and custom data alive for filter contexts.
- `context_deleting` is an opportunistic, lock-free check for an empty detaching filter
  context, not a substitute for rundown protection or WFP callback lifetime guarantees.
- A sock_addr `original_context` pointer is valid only during synchronous invocation.
- Redirect-context ownership must survive every error and verdict path.
- Do not wait, touch pageable code, or allocate paged memory in sock_addr/sock_ops paths.

## Source map

| File | Responsibility |
|---|---|
| [`net_ebpf_ext_drv.c`](../netebpfext/sys/net_ebpf_ext_drv.c) | WDF driver entry, device creation, subsystem startup, unload ordering |
| [`net_ebpf_ext.c`](../netebpfext/net_ebpf_ext.c) | WFP provider/sublayer/callout registration, filter management, shared filter-context lifetime |
| [`net_ebpf_ext_prog_info_provider.c`](../netebpfext/net_ebpf_ext_prog_info_provider.c) | Generic NMR program-information provider |
| [`net_ebpf_ext_hook_provider.c`](../netebpfext/net_ebpf_ext_hook_provider.c) | Generic NMR hook provider, attach/detach, client snapshot, rundown, invocation, stack expansion |
| [`net_ebpf_ext_program_info.h`](../netebpfext/net_ebpf_ext_program_info.h) | Program type descriptors, context descriptors, helpers, and section definitions |
| [`net_ebpf_ext_bind.c`](../netebpfext/net_ebpf_ext_bind.c) | Deprecated bind program type, resource-allocation/release classify callbacks |
| [`net_ebpf_ext_sock_addr.c`](../netebpfext/net_ebpf_ext_sock_addr.c) | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`, connect/authorization/accept/bind/listen processing |
| [`net_ebpf_ext_sock_ops.c`](../netebpfext/net_ebpf_ext_sock_ops.c) | `BPF_PROG_TYPE_SOCK_OPS`, flow-established and flow-delete processing |
| [`net_ebpf_ext_structs.h`](../netebpfext/net_ebpf_ext_structs.h) | Shared provider, client, dispatch, filter, and invocation structures |
| [`ebpf_link.c`](../libs/execution_context/ebpf_link.c) | NMR hook-provider client and extension dispatch into a linked program |
| [`ebpf_program.c`](../libs/execution_context/ebpf_program.c) | Native program dispatch and tail-call loop |
| [`ebpf_nethooks.h`](../include/ebpf_nethooks.h) | Public network program contexts, operations, and verdict contracts |
| [`netebpfext_unit.cpp`](../tests/netebpfext_unit/netebpfext_unit.cpp) | Provider, invocation, context, and WFP filter-cleanup regression tests |

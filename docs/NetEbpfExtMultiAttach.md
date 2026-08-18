# Introduction

Multi-attach support allows multiple eBPF programs to be attached to the same attach point (aka "hook") with the
same attach parameters. For example, for `BPF_CGROUP_INET4_CONNECT` attach type, the attach parameter is the
compartment ID. With this feature, multiple eBPF programs can be attached to the same compartment ID.

This document describes the design changes required in `netebpfext` to support multiple attach of eBPF programs in
`netebpfext`. This is independent of the platform changes needed in BPF runtime to add support for new multi-attach
APIs and flags. These changes in netebpfext also help enable the "default" behavior of multi-attach feature where the
multiple legacy apps using older libbpf APIs to attach programs can still attach to the same hook, with the programs
being "appended" in the invoke list in the order they are attached.

# Current Design

`net_ebpf_extension_hook_provider_t` is the provider context for the hook NPI provider. It maintains a list of client
contexts. A client context represents the eBPF program that is attached to this specific "attach point". It also holds
the attach params with which the program was attached. For each client context, a filter context is created. The filter
context is container for all the WFP filters that are configured for this "attach point". Since only one client is
allowed to attach for each attach parameter (i.e. "attach point"), there is a one-to-one mapping between client context
and filter context.

Whenever a new eBPF program is attached, following is the existing flow:
1. Check the list of current client contexts in hook provider, to see if any other program with same attach params is
already attached. This check happens with hook provider lock held. (There is a bug today in this logic where this lock
is released after checking the list, causing 2 threads to both find that no matching client exists, and both threads
can then proceed with attach for clients with same attach params).
2. If a program is already attached, reject the new attach request.
3. If no program is already attached with same attach params, create a new client context.
4. Create a new filter context for this client context and add WFP filters.
4. Add the new client context in the list of clients in the hook provider.

## Synchronization

There are 2 flows that need synchronization -- program invocation by the hook, and client attach and detach callbacks.
In the current design, this synchronization is achieved by using rundown references.

**Program invocation flow**:
1. Acquire rundown reference for the client context. If this fails, bail.
2. Invoke program.
3. Release rundown reference for client context.

**Client attach callback flow**
1. Filter context that is created on program attach takes an initial rundown reference on the client context.
2. Each WFP filter that is added takes a normal reference on filter context.

**Client detach callback flow**
1. Delete all the WFP filters. These will eventually release references on the filter context.
2. Queue a work item that waits for rundown on client context. This blocks until all the current invocations of the
program are completed. This also fails any new invocations of the program.
3. When all the references to the filter context are released (as part of WFP filter delete notification), it releases
the initial rundown reference taken on the client context, and the work item is unblocked, which then completes the NMR
client detach callback.

# New Design

In the new design, multiple programs attaching to the same attach point (i.e. same attach params) is allowed. The
required data structures changes are described below.

Even though multiple programs will attach with same "attach params", there will be a single instance of the
corresponding WFP filters added. This means there will be one-to-many mapping from filter context to client context.
The hook provider will now contain a list of filter contexts, which in turn will have list (or an array) of the clients
corresponding to those attach params.

Whenever a new eBPF program is attached, following will be the new flow:
1. Check the list of current filter contexts in hook provider, to see if a filter context with same attach params
already exists. If an existing filter context is found, the new client is added to the list of client contexts in the
existing filter context.
2. If an existing filter context does not exist, create a new filter context and a new client context.
3. Configure corresponding WFP filters.
4. Add the new client context to the list of client contexts in the filter context.
5. Add the filter context in the list of filter contexts in hook provider context.

**Multiple program invocation flow**

Whenever WFP callout is invoked  based on a matching filter, the callout driver gets pointer to filter context. From
the filter context, the callout gets the list of all the attached clients. The callout loops over all the clients and
invokes them. The *out* context of one program invocation becomes the *in* context of the next program. In the chain of
invocation, if any program **drops** the packet, the chain breaks there, and the callout returns the verdict to WFP.


## Synchronization
In the new design, access to the list of clients in the filter context and the list of filter contexts in the provider
context needs to be synchronized. The 2 flows that need synchronization specifically are:
1. Program invocation
2. Client attach / detach callback.

To provide synchronization, the hook provider will maintain a *dispatch* level RW lock to synchronize access to these
lists. (A dispatch level lock is chosen here as the WFP callouts can be invoked at either PASSIVE_LEVEL or DISPATCH_LEVEL).
1. Attach and detach callbacks flow will acquire this lock in exclusive mode.
2. Program invocation flow acquires this lock in shared mode.

This approach allows multiple program invocations at the same time, as well as protecting the list when a client is
being attached / detached. Client / attach operations are expected to be much less frequent than program invocations.
This approach eliminates any need for rundown reference for the client context. Since the list of client contexts for a
filter context is synchronized via a lock, it is always guaranteed that in the client detach flow, if the dispatch level
lock is acquired, there is no program invocation in progress for that program. Also, once the client context is removed
from the list of clients in the filter context, no new classify callback will find this program in the list, hence no
new invocation can also happen.

Along with the above synchronization, there is also a need to **serialize multiple attach and detach operations callbacks**,
as the whole flow of creating filter context, adding filter context to the provider list, and configuring WFP filters
needs to happen atomically (as mentioned in the current design section, there is bug currently where a lock is not held
for the whole duration of attach / detach callback).

As the above mentioned dispatch level RW already serializes attach / detach callbacks for a hook provider, it could have
solved this serialization problem also. But there is a problem with using dispatch level locks: WFP APIs for adding
filters require PASSIVE_LEVEL, hence same DISPATCH_LEVEL lock cannot be used to serialize the attach and detach
operations. To address this, a separate PASSIVE lock will be maintained in the provider context to serialize attach and
detach operations. As a result of this, in attach and detach operations, the flow acquires both the DISPATCH_LEVEL lock
and the PASSIVE_LEVEL lock. In the program invocation flow, only the DISPATCH_LEVEL lock is acquired.

**Expected flow for client attach callback**:
1. Acquire passive lock --> Serializes multiple attach / detach calls to the same hook provider.
2. Acquire dispatch lock (exclusive). --> Synchronizes access to the client and filter context lists.
3. Check if a matching filter context already exists. If it exists, insert the new client context, and return.
4. If no matching filter context exists, release dispatch lock.
5. Create filter context and client context.
6. Configure WFP filters --> We are not holding any dispatch level lock. IRQL is PASSIVE_LEVEL.
7. Acquire dispatch lock (exclusive) --> Synchronizes access to the client and filter context lists.
8. Insert the new filter context and client context in the corresponding queues.
9. Release dispatch level lock and passive lock.

**Expected flow for program invocation**
1. Acquire dispatch lock (shared). --> Synchronizes access to the client and filter context lists.
2. Invoke programs in a loop.
3. Release dispatch lock (shared).

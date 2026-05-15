# Async Processing at SOCK_ADDR

> **Status:** Working proposal. Goal: a minimal pend/complete
> primitive in netebpfext with no consumer-specific state machine.

## Table of contents

- [Motivation](#motivation)
- [Requirements](#requirements)
- [Design overview](#design-overview)
- [PEND overview](#pend-overview)
- [COMPLETE overview](#complete-overview)
- [Edge cases](#edge-cases)
  - [Notification fails after a successful pend](#notification-fails-after-a-successful-pend)
  - [Stale pends (orchestrator never completes)](#stale-pends-orchestrator-never-completes)
  - [Duplicate completes](#duplicate-completes)
  - [Cross-client complete attempt](#cross-client-complete-attempt)
  - [Pended operations and OS resource handling](#pended-operations-and-os-resource-handling)
- [Async orchestrator integration guide](#async-orchestrator-integration-guide)
  - [Roles](#roles)
  - [Notification mechanism (consumer's choice)](#notification-mechanism-consumers-choice)
  - [Cleanup responsibilities](#cleanup-responsibilities)

## Motivation

Network callout drivers often need to defer a verdict on a connection
or packet while waiting for an asynchronous decision from another
component -- typically a user-mode policy service or a kernel-mode
classification driver. WFP provides several async mechanisms at
different layers (for example `FwpsPendOperation` /
`FwpsCompleteOperation` at ALE authorize layers), but eBPF programs
running through netebpfext have no way to express "pend this
operation and complete it later."

This proposal adds a **pend/complete primitive** to netebpfext so an
eBPF program can:

1. **PEND** a network operation -- absorb it while an external
   orchestrator makes a decision asynchronously.
2. Instruct netebpfext to **resume processing** when the orchestrator
   delivers an action via the complete map; the action determines
   exactly how netebpfext processes the **completion**.

## Requirements

1. An eBPF program attached to a supported hook must be able to
   pend the current operation in netebpfext.
2. An external orchestrator must be able to deliver an action to
   netebpfext asynchronously.
3. The WFP semantics around pend/complete must be fully encapsulated
   in the hook implementation (i.e., no knowledge or consumption of
   any WFP details must leak to the eBPF program or the
   orchestrator).
4. Initial scope is the `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program
   type, attach types `BPF_CGROUP_INET4_CONNECT`,
   `BPF_CGROUP_INET6_CONNECT`, `BPF_CGROUP_INET4_RECV_ACCEPT`, and
   `BPF_CGROUP_INET6_RECV_ACCEPT`. Pend/complete may be extended to
   additional program / attach types in the future. The general
   paradigm documented here is expected to work for future program
   types, though WFP implementation details within netebpfext may
   differ and will be handled at implementation time.
5. Multiple clients attached to the same hook must each be able to
   pend independently. The pend mechanism itself must not cause
   one client's pend to interfere with another's (shared state
   collisions, lost notifications, dropped completions). Normal
   chain semantics still apply -- an earlier client's terminating
   action can end the chain before a later client runs.

## Design overview

The proposal is split into two sections:

1. A `bpf_pend()` helper that lets a program defer its verdict;
   this also lets netebpfext prepare its internal state to
   handle the eventual completion.
2. A bpf custom map **complete_map** that the orchestrator
   writes to deliver a completion action and inform netebpfext
   how to proceed. Initial action types
   (see [COMPLETE overview](#complete-overview) for full
   semantics):
    - `REJECT` -- final verdict = REJECT.
    - `PROCEED_SOFT` / `PROCEED_HARD` -- equivalent to a
      synchronous return of the same verdict from this slot.
    - `REINVOKE` -- re-invoke the pended program.

Two cross-cutting design tenets shape the contract:

- **Program-declared complete map.** The complete map is
  declared by the eBPF program itself (in its `.maps` section),
  not created out-of-band by the orchestrator. Each `bpf_pend()`
  call binds the pend to the specific complete-map instance the
  program passes as an argument.
  See [Complete-map binding](#complete-map-binding).
- **Cross-client validation at complete time.** The pend entry
  records the bound complete map; the preprocess callback
  rejects inserts whose map instance does not match. This
  bounds the blast radius of a leaked pend key to
  denial-of-correlation -- an unrelated client cannot drive a
  completion verdict for someone else's pend.
  See [Cross-client complete attempt](#cross-client-complete-attempt).

## PEND overview

**`bpf_pend()` helper.** A program decides to pend by calling:

```
int bpf_pend(struct bpf_map *complete_map, pend_key_t *out_key);
```

`complete_map` is a pointer to the program-defined complete map
(see [Complete-map binding](#complete-map-binding) below) that the
orchestrator will later use to drive resumption.

The helper returns 0 on success and writes a freshly-generated
pend key to `*out_key`. On failure it returns non-zero and
`*out_key` is left untouched.

> **REINVOKE re-entry.** When the originating program is
> re-invoked via a `REINVOKE` completion and chooses to pend
> again, it calls `bpf_pend()` symmetrically. The helper detects
> (via the internal pend table) that the existing pend entry is
> still alive, reuses it, returns the **original** pend key to
> `*out_key`, and skips a second `FwpsPendOperation()` call.
> The entry's lifecycle transitions back to `PENDED`. If the
> re-invoked program returns a terminal verdict instead, no
> `bpf_pend()` call is needed and the existing entry is
> dispatched normally.

> **Implicit program context.** The helper signature deliberately
> omits an explicit `ctx` parameter. netebpfext recovers the
> calling program's context via an ebpfcore-provided implicit
> accessor (e.g., `ebpf_get_current_program_context()`, set in a
> per-CPU slot before program invocation and cleared on return).
> This accessor must exist as an ebpfcore-side platform
> capability; the same mechanism is reusable by other extension
> helpers that need program context without polluting the
> BPF-visible signature.

The pend key written to `*out_key` is the program's handle to the
pended classify. The program's only obligation is to forward this
key to its orchestrator over whatever notification channel the
consumer chose (BTF-resolved function, ringbuf, etc.) so the
orchestrator can later complete the pend.

**New `PEND` verdict.** After a successful `bpf_pend()`, the
program must return a new verdict (e.g.,
`BPF_SOCK_ADDR_VERDICT_PEND`) added to the existing
`ebpf_sock_addr_verdict_t`. This is the program's signal to
netebpfext to freeze the chain at this slot and wait for the
complete map insert. If the program returns any other verdict
after a successful `bpf_pend()`, netebpfext treats it as the
program signaling that its notification failed: the pend is
aborted (rolled back / fail-safe completed) rather than left
dangling waiting on a complete that will never come. See
[Edge cases](#edge-cases) for details.

**Pend key properties.**

- **Unique per classify instance.** One key per chain invocation,
  shared across all clients that pend that same classify in the
  multi-attach case. The program and its user-mode orchestrator
  can therefore safely use it as a unique identifier for the
  pended connection (e.g., as a map key for per-pend metadata,
  or as a correlation token across components).
- **Opaque handle.** The program and orchestrator should treat it
  as a handle: use it to correlate the pend notification with the
  later complete, but do not interpret or rely on its contents.

**Complete-map binding.** Each pend is bound at install time to
the specific complete-map instance the program passes to
`bpf_pend()`. The map is **declared by the eBPF program** (not
created by the orchestrator out-of-band):

```c
struct {
    __uint(type, BPF_MAP_TYPE_PEND_COMPLETE);
    __type(key, pend_key_t);
    __type(value, complete_entry_t);
    __uint(max_entries, 1024);
} pend_complete_map SEC(".maps");
```

netebpfext resolves the `complete_map` helper argument (an
`ebpf_map_t*` handed to the helper by the runtime) to its
per-map extension context -- the same `map_context` pointer
netebpfext itself allocated in `preprocess_map_create` for that
map (see [eBpfExtensions.md][ebpfext-map-context]) -- using the
standard `map_context_offset` mechanism. It stores that
context pointer in the internal pend entry alongside the rest
of the per-pend state, where it serves as the identity used
later to validate complete-map inserts.

When the orchestrator later inserts into a complete map, the
preprocess callback receives the per-map context for the map
carrying the insert. It compares (pointer equality) against the
context stored in the matching pend entry. A mismatch is
rejected with `EBPF_ACCESS_DENIED` and the pend entry is left
untouched. This prevents an unrelated eBPF client from driving
completion for a pend it did not originate, even if it somehow
learned the opaque pend key.

[ebpfext-map-context]: ./eBpfExtensions.md#29-helper-functions-that-use-custom-maps

The orchestrator obtains its fd to the program-declared complete
map through standard discovery (looking it up by name on the
loaded program object, or via a pinned path) -- no new mechanism
is introduced.

**Proposed `pend_key` structure.** Strawman:

```c
typedef struct _pend_key {
    ebpf_extension_header_t header;  // standard versioning header
    uint64_t pend_id;                // globally unique among live
                                     // pends; generated by
                                     // netebpfext at pend time
} pend_key_t;
```

**Internal pend state.** When `bpf_pend()` runs, netebpfext records
an entry in a kernel-only hash table keyed by the pend key. The following
is the proposed structure of the state:

```c
typedef struct _wfp_completion_state {
    ebpf_attach_type_t layer_id;     // discriminator -- reuses the
                                     // existing attach-type enum
    ULONG classifyfn_cpu;            // CPU at pend time; recorded as
                                     // the target for the eventual WFP
                                     // completion dispatch
    union {
        // CONNECT (outbound) -- FwpsPendOperation / clone-reinject path
        struct {
            HANDLE completion_context;
            PNET_BUFFER_LIST cloned_nbl;
            UINT64 endpoint_handle;
            UINT8 remote_address[16];
            SCOPE_ID remote_scope_id;
            WSACMSGHDR* control_data;   // deep-copied into extension-
                                        // owned storage at pend time
            ULONG control_data_length;
        } connect;

        // RECV_ACCEPT (inbound) -- FwpsPendOperation / clone-reinject path
        struct {
            HANDLE completion_context;
            PNET_BUFFER_LIST cloned_nbl;
            IF_INDEX interface_index;
            IF_INDEX sub_interface_index;
            ULONG ip_header_size;
            ULONG transport_header_size;
            ULONG nbl_offset;
            BOOLEAN ip_sec_protected;
            UINT8 protocol;
            UINT8 local_address[16];
            UINT8 remote_address[16];
        } recv_accept;

        // future arms (BIND / DATAGRAM / STREAM / ...)
    } u;
} wfp_completion_state_t;

// Lifecycle state -- gates ordering between the WFP-pend API call,
// notification, and the orchestrator's complete-map write.
typedef enum _pend_lifecycle {
    PEND_LIFECYCLE_PENDED = 0,             // entry installed and (on
                                           // success) WFP pend API
                                           // issued; awaiting an
                                           // orchestrator action
    PEND_LIFECYCLE_COMPLETION_PENDING = 1, // action received; dispatch
                                           // work item queued. Duplicate
                                           // / late inserts against this
                                           // pend key are rejected. A
                                           // `REINVOKE` dispatch resets
                                           // this back to `PENDED` before
                                           // re-entering the program, so a
                                           // symmetric `bpf_pend()` call
                                           // can reuse the existing entry.
} pend_lifecycle_t;

typedef struct _pend_entry {
    // (1) Program context for re-invocation / helpers.
    // Captured snapshot of the per-attach-type context wrapper (e.g.,
    // net_ebpf_sock_addr_t) holding the program-visible bpf_* context
    // (family, compartment_id, 5-tuple, ...) plus netebpfext-private
    // bookkeeping (token info, hook_id, redirect context, ...). WFP's
    // classify parameters live on the classifyFn stack and disappear
    // once the callback returns, so any classify-time pointers (control
    // data, NBL contents, etc.) are deep-copied into extension-owned
    // storage before classifyFn unwinds. This lets re-entry give the
    // program the same helper-visible state it saw originally.
    void* captured_hook_ctx;

    // (2) WFP completion state (layer-tagged union).
    wfp_completion_state_t wfp_completion;

    // (3) Resumption tracking.
    const ebpf_program_t* originating_program; // program that pended;
                                               // rundown ref held in
                                               // this entry keeps it
                                               // alive. PROCEED_* ->
                                               // resume at next slot
                                               // in the chain;
                                               // REINVOKE -> re-enter
                                               // this slot.
    void* complete_map_context;            // Per-map extension context
                                           // for the complete map the
                                           // program passed to
                                           // bpf_pend(). Used as the
                                           // identity for cross-client
                                           // validation; see
                                           // Complete-map binding.
    uint32_t aggregate_verdict;            // chain-aggregated verdict
                                           // accumulated across prior
                                           // chain slots (priority
                                           // semantics)

    // Bookkeeping
    pend_lifecycle_t lifecycle;
    uint64_t insertion_time;               // KeQueryInterruptTime() at
                                           // pend install (returns
                                           // 100-ns units). Watchdog
                                           // compares against a
                                           // system-wide TTL constant.
                                           // Doubles as pend-age telemetry.
} pend_entry_t;
```

**PEND flow.**

1. **Program decides to pend.** The program is invoked in the
   chain, determines that the operation needs an async decision,
   and calls `bpf_pend(&pend_complete_map, &out_key)`.
2. **netebpfext processes the helper.** Resolves the
   `complete_map` argument to its per-map extension context (via
   the standard `map_context_offset` mechanism), generates the
   pend key, captures the running chain aggregate (from prior
   slots in the current classify invocation) into
   `aggregate_verdict`, builds the internal pend entry
   (recording the resolved map context, the captured hook
   context, etc.), and inserts it into the table **before**
   issuing the WFP pend API (so any synchronous callback from
   inside the WFP API can find the entry), then synchronously
   issues the layer-appropriate WFP pend API. On success,
   returns 0 with the pend key written to `*out_key`, and
   transfers classify's rundown reference on the invoking
   program (acquired via `ExAcquireRundownProtection`) to the
   pend entry rather than releasing it on classify return -- the
   reference is then held until the pend entry is removed in the
   COMPLETE flow, ensuring the program cannot be detached or
   torn down while a pend against it is outstanding (so a later
   `REINVOKE` is always safe to re-enter the program, and detach
   naturally blocks on the rundown drain until outstanding pends
   complete). On WFP failure, removes the just-inserted pend
   entry and returns non-zero; the rundown reference was never
   transferred and is released normally when classify returns.
   The program then falls through to a normal synchronous
   verdict.
3. **Program notifies the orchestrator.** After a successful
   `bpf_pend()`, the program sends its notification (BTF-resolved
   function, ringbuf, etc.) so the orchestrator can later complete
   the pend.
4. **Program returns the `PEND` verdict.** netebpfext stops
   processing the chain of programs at this slot; subsequent
   programs are not invoked for this classify until the
   orchestrator drives a resumption via the complete map.
5. **netebpfext returns from `classifyFn` to WFP.** The classify
   wrapper returns the layer-appropriate action that tells WFP
   the operation has been pended (for example, the absorb-style
   flags used at the ALE layers). Control returns to WFP and the
   thread that initiated the classify; from this point the
   classify is suspended until the complete map flow resumes it.

## COMPLETE overview

**The complete map.** Completion is delivered through a new
custom map type, `BPF_MAP_TYPE_PEND_COMPLETE`, registered by
netebpfext. The map is **declared by the eBPF program** (see
[Complete-map binding](#complete-map-binding)); the orchestrator
obtains an fd to that program-owned map and signals a completion
by inserting an entry. The map is purely an
orchestrator <-> netebpfext channel -- programs neither read nor
write it. Netebpfext registers a
`preprocess_map_update_element` provider callback on the map
type, so each `bpf_map_update_elem` synchronously dispatches
into the extension on the inserting thread.

The complete map type, action enum, and value struct:

```c
// New custom map type registered by netebpfext.
#define BPF_MAP_TYPE_PEND_COMPLETE  /* next free id */

// Orchestrator-supplied action carried in each complete-map entry.
// Mirrors ebpf_sock_addr_verdict_t (the sync chain-of-programs return
// values) plus an async-only REINVOKE.
typedef enum _ebpf_pend_complete_action {
    // Stop processing the chain of programs. Final WFP verdict = BLOCK.
    // Same as a sync BPF_SOCK_ADDR_VERDICT_REJECT.
    EBPF_PEND_COMPLETE_REJECT = 0,
    // Resume processing the chain of programs after originating_program.
    // Same as a sync BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT from this slot.
    EBPF_PEND_COMPLETE_PROCEED_SOFT,
    // Resume processing the chain of programs after originating_program.
    // Same as a sync BPF_SOCK_ADDR_VERDICT_PROCEED_HARD from this slot.
    EBPF_PEND_COMPLETE_PROCEED_HARD,
    // Re-invoke originating_program. No sync equivalent.
    EBPF_PEND_COMPLETE_REINVOKE,
} ebpf_pend_complete_action_t;

// Versioned value struct so the contract can grow without
// rev'ing the map type.
typedef struct _complete_entry {
    ebpf_extension_header_t header; // allows for versioning information
    // fields required to process the completion
    ebpf_pend_complete_action_t action;
} complete_entry_t;
```

**COMPLETE flow.** Focuses on what happens to the two map
entries (internal pend entry, complete map entry) and when WFP
completion fires.

1. **Orchestrator inserts into the complete map.** The orchestrator
   calls `bpf_map_update_elem(complete_map_fd, &key, &value, flags)`
   with the pend key from the notification and a `complete_entry_t`
   carrying the chosen action.
2. **netebpfext's `preprocess_map_update_element` callback runs.**
   It looks up the matching internal pend entry by `key` and
   validates the insert. There are three rejection cases, each
   returned synchronously to the orchestrator's
   `bpf_map_update_elem` call with no side effect:
    - **No entry for `key`** -- returns `EBPF_KEY_NOT_FOUND`.
      Either the key is bogus, or the watchdog already
      force-completed this pend
      (see [Stale pends](#stale-pends-orchestrator-never-completes)).
    - **`map_context` mismatch** -- the per-map context the
      callback received does not equal the one stored in the
      entry. Returns `EBPF_ACCESS_DENIED`. See
      [Cross-client complete attempt](#cross-client-complete-attempt).
    - **Entry already in `COMPLETION_PENDING`** -- a complete
      for this key is already being dispatched. Returns
      `EBPF_OBJECT_ALREADY_EXISTS`. See
      [Duplicate completes](#duplicate-completes).

   On a valid insert, it copies the action and any needed
   state onto a work-item context, transitions the entry's
   lifecycle to `COMPLETION_PENDING`, queues a work item to
   dispatch the action, and returns success. Re-entry cannot
   run inline: the program may immediately re-enter map CRUD
   which would deadlock.
3. **Work item executes** and removes the complete-map entry,
   then dispatches the recorded action. Removing the complete-map
   entry first frees the slot so a `REINVOKE` followed by a
   re-pend (which symmetrically reuses the **same** pend key)
   can land a new entry without a duplicate-key collision. The
   pend entry is **not** removed here. Per-action behavior:
    - `REJECT`: terminal -- proceeds to step 4 with a BLOCK
      verdict. No further programs in the chain are invoked.
    - `PROCEED_SOFT` / `PROCEED_HARD`: scans the current chain for
      `originating_program` and resumes invocation at the next
      slot. Verdicts from resumed slots are combined with the
      entry's `aggregate_verdict` using the standard
      "most restrictive wins" rule (REJECT > PROCEED_HARD >
      PROCEED_SOFT). If chain processing reaches a terminal
      verdict (or runs off the end), proceeds to step 4.
    - `REINVOKE`: re-enters `originating_program`. Before re-entry
      the work item resets `lifecycle` from
      `COMPLETION_PENDING` back to `PENDED` so a symmetric
      `bpf_pend()` call from the re-invoked program (see
      [`bpf_pend()` REINVOKE re-entry](#pend-overview)) reuses the
      existing pend (no second `FwpsPendOperation`). Either
      re-entry yields a terminal verdict (proceeds to step 4) or
      the program pends again (returns to the PEND flow).
4. **Terminal-verdict cleanup.** Once a terminal verdict is
   reached (via any path in step 3), netebpfext drives the
   layer-specific WFP completion API, releases the rundown
   reference on `originating_program`, and removes the internal
   pend entry. Per-pend completion occurs exactly-once.

## Edge cases

The pend/complete mechanism has a few notable edge cases that
need explicit handling.

### Notification fails after a successful pend

`bpf_pend()` succeeded (WFP operation is pended, internal pend
entry exists) but the program's notification call to its orchestrator
returned failure. The program MUST return a non-PEND verdict to surface the
failure. netebpfext's classify wrapper detects the dangling pend
entry attached to this classify and synthesizes the same
dispatch the COMPLETE flow would run for `REJECT`: drives the
layer-specific WFP completion and removes the internal pend entry.
The orchestrator never sees this pend.

### Stale pends (orchestrator never completes)

A pend can sit indefinitely if the orchestrator crashes,
deadlocks, or just takes too long. netebpfext periodically walks
the pend table and force-completes any entry whose age
(`now - insertion_time`) exceeds a configurable maximum,
issuing a `REJECT` verdict. The watchdog is a fail-safe and
should not be shorter than any expected completion latency.

If the orchestrator does eventually issue a complete for a pend
that has already been force-completed by the timeout, the
complete-map insert finds no matching pend entry and is
rejected with `EBPF_KEY_NOT_FOUND`; no side effect.

### Duplicate completes

Nothing prevents an orchestrator from inserting the same pend
key into the complete map twice (retry, duplicate notification).
The second insert finds the pend entry already in
`COMPLETION_PENDING` state (or already removed) and is rejected
with `EBPF_OBJECT_ALREADY_EXISTS` (or `EBPF_KEY_NOT_FOUND` if
already removed); WFP completion runs exactly once per pend.

### Cross-client complete attempt

If an unrelated eBPF client somehow learns a pend key (leaked
through telemetry, log, replay, etc.) and tries to drive
completion through *its own* `BPF_MAP_TYPE_PEND_COMPLETE`
instance, the preprocess callback finds a pend entry for the
key but the `map_context` it receives does not match the one
stored in the entry. The insert is rejected with
`EBPF_ACCESS_DENIED`, the pend entry is left in `PENDED`
state, and only the original program's bound complete map can
drive resumption. This bounds the blast radius of a leaked
pend key to denial-of-correlation: the attacker cannot drive a
completion verdict for someone else's pend.

### Pended operations and OS resource handling

A pend may outlive any single classifyFn invocation and must
remain safe to hold across system events such as modern standby
(Connected Standby / Disconnected Standby) and S0-low-power
transitions. The pend itself is cheap (just an entry in the
internal pend table); what is **not** safe is keeping a reference
to a transient OS resource -- most notably an `NET_BUFFER_LIST`
delivered to a classify callout -- pinned for the duration of the
pend. Holding such resources can stall NDIS / WFP teardown and
block the OS from completing a power transition.

The extension is therefore responsible, **at PEND time**, for
releasing references to any per-callout OS resources that the WFP
layer would otherwise pin. Concrete per-layer requirements live
with the layer integration (see the WESP doc's per-layer sections
for the WFP layers in scope), but the general rule is:

- Layers that carry no transient resource on the pended callout
  (e.g., AUTH_CONNECT for TCP, where there is no `layerData`)
  require nothing extra -- the pend is already safe.
- Layers that carry a transient resource (e.g., AUTH_RECV_ACCEPT,
  DATAGRAM_DATA, or AUTH_CONNECT for UDP, all of which deliver an
  `NET_BUFFER_LIST` via `layerData`) must deep-copy / clone the
  resource (`FwpsAllocateCloneNetBufferList` for NBLs) and release
  the reference to the original before returning from
  `classifyFn`. Any subsequent reinject uses the clone.

There is no separate kernel-side drain mechanism for in-flight
pends across power transitions and no PEND-side power-state error
code -- correctness is achieved by not pinning the OS resource in
the first place. The stale-pend watchdog
([Stale pends](#stale-pends-orchestrator-never-completes)) remains
the only kernel-side cleanup path; orchestrator-driven completion
is otherwise unchanged across power transitions.

## Async orchestrator integration guide

The pend/complete mechanism is **orchestrator-agnostic** -- it
provides WFP lifecycle management, the pend key, the action
vocabulary, and the complete map. The orchestrator owns
everything else.

### Roles

| Component        | Role                                                                           |
|------------------|--------------------------------------------------------------------------------|
| eBPF program     | Declares the complete map, calls `bpf_pend()` with it, dispatches notification, returns `PEND` verdict. |
| Decision-maker   | Receives notification, decides, picks the action.                              |
| Complete-map writer | Holds an fd to the program-declared complete map; inserts `{key, action}` to drive resume. |

The eBPF program runs in-kernel; the decision-maker and
complete-map writer can be the same user-mode process, separate
processes, or a kernel driver.

### Notification mechanism (consumer's choice)

Notification is synchronous from the program's perspective so
failure can be surfaced inline (program falls back to a non-PEND
verdict). Common choices:

| Mechanism            | How it works                                                                                                | Trade-offs                                                                          |
|----------------------|-------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| BTF-resolved function | Orchestrator driver exposes a BTF-resolved function; program calls it with the pend key + per-pend data.    | Synchronous, low-latency. Requires a kernel driver.                                 |
| Ringbuf / perf event | Program writes pend key + data to a consumer-owned ringbuf; orchestrator consumes from user mode.           | No kernel driver. Higher latency; ringbuf-full forces a non-PEND fallback.          |

Per-pend application data (rule context, connection metadata)
lives in consumer-owned regular BPF maps -- not in the
netebpfext-internal pend table or the complete map.

### Cleanup responsibilities

- **Stale pends.** Orchestrator ages out its own tracking and issues `REJECT`; the kernel watchdog is the backstop.
- **Orchestrator restart.** No kernel-side pend enumeration is exposed. In-flight pends remain bound to the original complete map's `map_context`; whether a restarted orchestrator can drive them to completion depends entirely on whether it can re-acquire that same map. Pends it cannot reach are force-completed by the watchdog.

# Epoch based memory management.

## Overview

The eBPF for Windows project uses an epoch based scheme for managing
memory that permits a certain class of lock free operations,
specifically the ability to implement lock free hash tables and other
structures that require "read copy update" aka RCU semantics.

Epoch driven memory management is an area that has been covered extensively by
academic papers (as an example [Interval-Based Memory Reclamation
(rochester.edu)](https://www.cs.rochester.edu/~scott/papers/2018_PPoPP_IBR.pdf)).
The approach taken in this project is a simplification of several
different approaches outlined in various research papers with the result
being a tradeoff between performance and code complexity.

In the context of this project's epoch memory management module
(referred to as epoch module here in), the term epoch is intended to
mean a period of indeterminate length. At the heart of the epoch module
are two clocks:

1)  \_ebpf_current_epoch

2)  \_ebpf_release_epoch

The first clock (\_ebpf_current_epoch) tracks the current "time" in the
system, with this clock that monotonically increases. The second clock
(\_ebpf_release_epoch) tracks the highest epoch that no longer has any
code executing in it.

Every execution context (a thread at passive IRQL or a DPC running at
dispatch IRQL) is associated with the point in time when execution began
(i.e. the value of the \_ebpf_current_epoch clock at the point where it
began execution). All memory that the execution context could touch
during its execution is part of that epoch.

When memory is no longer needed, it is first made non-reachable (all
pointers to it are removed) after which it is stamped with the current
epoch and inserted into a "free list". The timestamp is point in time
when the memory transitioned from visible -\> non-visible and as such
can only be returned to the OS once no active execution context could be
using that memory (i.e. when memory time stamp \<=
\_ebpf_release_epoch).

## Implementation details

Each execution context maintains it's own state in the form of:

```
typedef struct \_ebpf_epoch_state
{
int64_t epoch; // The highest epoch seen by this epoch state.
bool active : 1; // Currently within an entry/exit block.
bool timer_armed : 1; // This state has requested the global timer.
bool stale : 1; // This state has entries that haven\'t been freed.
bool timer_disabled : 1; // Prevent re-arming the timer during shutdown.
} ebpf_epoch_state_t;
```

The epoch state is then embedded into both a per-CPU or per-thread
state, each of which maintains additional metadata that is specific to
that execution context type.

Each execution context then must first call ebpf_epoch_enter prior to
accessing any memory that is under epoch protection and then call
ebpf_epoch_exit once it is done. As a simplification of the epoch memory
management, the ebpf_epoch_enter affinitizes threads to their current
CPU (so thread won't switch CPU's during an epoch bounded execution).

Memory is then allocated via calls to ebpf_epoch_allocate which returns
memory with a private header and memory is freed via calls to
ebpf_epoch_free. The private header is then used to track when the
memory was freed as well as links. On free, the memory is stamped with
the current epoch and the current epoch is atomically incremented. This
ensures that the freed memory always maintains the correct epoch value.
The memory is then enqueued on a per-CPU free list. On epoch exit, the
free list is then scanned to locate entries whose stamp is older than
the release epoch. These entries are then returned to the OS.

Determining the release epoch is necessarily an expensive operation as
it requires scanning the epoch of every active execution context, with
execution contexts being protected by spinlocks. To limit the impact,
the epoch module uses a one-shot timer to schedule a DPC that computes
the release epoch by determining the minimum of all execution context's
epochs. The timer is then re-armed when an execution context calls
ebpf_epoch_exit. The result is that if no execution contexts are active,
the timer will expire and will not be re-armed.

## Exceptional cases

There are a few exceptional cases handled in the epoch module.

### Stale free lists

Memory that has been enqueued to an execution context can become stale
if the execution context calls ebpf_epoch_exit and there is memory in
the free list that hasn't reached the release epoch yet. If no further
calls are made to ebpf_epoch_enter/exit, then the memory will never be
freed. To address this, the timer will set a "stale" flag on an epoch
state each time it runs if there is memory in the free list and the
ebpf_epoch_exit will clear the flag. If the timer observes that the
epoch state is marked a stale (i.e. ebpf_epoch_exit hasn't been called
since the last invocation of the timer), then it will schedule a one-off
DPC to run in that execution context to flush the free list. The flush
then performs an ebpf_epoch_enter/exit, which permits any expired
entries in the free list to be freed.

### Work items

In some cases code that uses the epoch module requires more complex
behavior than simply freeing memory on epoch expiry. To permit this
behavior, the epoch module exposes ebpf_epoch_schedule_work_item which
can be used to run a block of work when the current epoch becomes
inactive (i.e. when no other execution contexts are active in this
epoch). This is implemented as a special entry in the free list that
causes a callback to be invoked instead of freeing the memory.

### Future investigations
The use of a common clock leads to contention when the memory state changes
(i.e. when memory is freed). One possible work around might be to move from a
clock driven by state change to one derived from a hardware clock. Initial
prototyping seems to indicate that the use of "QueryPerformanceCounter" and it's
kernel equivalent are more expensive than using a state driven clock, but more
investigation is probably warranted.

The per-CPU lock does raise the cost of every ebpf_epoch_enter/exit operations
and it might be possible to implement a lock free schema for tracking epoch
state, but current attempts have resulted in various bugs where edge conditions
result in incorrect release epoch computations.
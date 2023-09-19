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
(referred to as epoch module herein), the term epoch is intended to
mean a period of indeterminate length. At the heart of the epoch module
are two clocks:

1)  _ebpf_current_epoch

2)  _ebpf_release_epoch

The first clock (_ebpf_current_epoch) tracks the current "time" in the
system, with this being a clock that monotonically increases. The second clock
(_ebpf_release_epoch) tracks the highest epoch that no longer has any
code executing in it.

Every execution context (a thread at passive IRQL or a DPC running at
dispatch IRQL) is associated with the point in time when execution began
(i.e., the value of the _ebpf_current_epoch clock at the point where it
began execution). All memory that the execution context could touch
during its execution is part of that epoch.

When memory is no longer needed, it is first made non-reachable (all
pointers to it are removed) after which it is stamped with the current
epoch and inserted into a "free list". The timestamp the is point in time
when the memory transitioned from visible -> non-visible and as such
can only be returned to the OS once no active execution context could be
using that memory (i.e., when memory timestamp <=
_ebpf_release_epoch).


## Work items

In some cases code that uses the epoch module requires more complex
behavior than simply freeing memory on epoch expiry. To permit this
behavior, the epoch module exposes ebpf_epoch_schedule_work_item which
can be used to run a block of work when the current epoch becomes
inactive (i.e., when no other execution contexts are active in this
epoch). This is implemented as a special entry in the free list that
causes a callback to be invoked instead of freeing the memory. The callback
can then perform additional cleanup of state as needed.

## Future investigations
The use of a common clock leads to contention when the memory state changes
(i.e., when memory is freed). One possible work around might be to move from a
clock driven by state change to one derived from a hardware clock. Initial
prototyping seems to indicate that the use of "QueryPerformanceCounter" and its
kernel equivalent are more expensive than using a state driven clock, but more
investigation is probably warranted.
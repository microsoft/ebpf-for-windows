# Conformance: `libs/runtime/ebpf_epoch.c` vs `models/epoch_hot_add/EpochHotAddModel.tla`

This note explains how the hot-add topology model relates to the production epoch implementation in `libs/runtime/ebpf_epoch.c`.

The goal of this model is to capture the safety argument for a **quiesce-then-modify** protocol:

1. drain passive `ebpf_epoch_synchronize()` with an SRW lock
2. send a quiesce request to CPU 0 for timer-driven computation
3. splice or roll back the CPU ring
4. resume timer-driven computation only when the new CPU is schedulable

It is intentionally separate from `models/epoch/`, which models reclamation safety.

## What the model is proving

The model checks these core properties:

- **`ElectionCursorSafe`**: if an epoch election is in progress, the CPU currently processing the election is both admitted and schedulable
- **`SchedulableImpliesAdmitted`**: no CPU becomes schedulable before it is admitted
- **`EpochEnterNeverFails`**: a modeled `epoch_enter` never observes a schedulable-but-unadmitted CPU

Together, these capture the intended implementation guarantees:

- a DPC-driven traversal always sees a valid, usable ring
- `ebpf_epoch_enter()` fail-fast should indicate a real bug, not a hot-add timing race

## Refinement mapping (implementation -> model)

| Model concept | TLA+ variable / action | Implementation concept | C symbol(s) / mechanism |
|---|---|---|---|
| Admitted CPU ring | `admitted`, `ring_next` | active CPU participant ring | `_ebpf_epoch_cpu_table[c].admitted`, `_ebpf_epoch_cpu_table[c].next_active_cpu` |
| CPU is schedulable for epoch traffic | `schedulable[c]` | CPU has started and can run queued work / current-CPU epoch APIs | Windows processor-start timing; new CPU becomes schedulable before / at add-complete notification |
| Passive synchronize shared lock | `passive_sync_active` | one or more passive synchronize callers hold the SRW lock shared | proposed SRW lock around passive `ebpf_epoch_synchronize()` |
| Topology modifier exclusive lock | `topology_exclusive` | hot-add / rollback holds the SRW lock exclusive | proposed exclusive SRW lock acquisition in topology modification |
| CPU-0 quiesce request | `quiescent_requested`, `quiesce_waiter_pending`, `RequestQuiesce` | CPU 0 blocks new timer-driven computations and completes a waiter once any in-flight one drains | proposed CPU-0 quiesce control message |
| Timer election request | `RequestTimerElection` | timer DPC wants to start epoch computation | `_ebpf_epoch_timer_worker()` |
| Election traversal | `StartElection`, `AdvanceElection` | inter-CPU propose / commit message walk | `_ebpf_epoch_messenger_propose_release_epoch()`, `_ebpf_epoch_messenger_commit_release_epoch()` |
| Begin hot-add | `BeginHotAdd` | allocate/init per-CPU state and enter topology-modification protocol | processor-change add-start callback plus `_ebpf_epoch_initialize_cpu_entry()` |
| Splice hot CPU | `SpliceHotCpu` | modify the active CPU ring to include the new CPU | ring update messages such as `UPDATE_NEXT_ACTIVE_CPU` / `UPDATE_PREVIOUS_ACTIVE_CPU` |
| Add-complete | `AddComplete` | new CPU is now safe to route epoch traffic to; reopen timer-driven computation | processor-change add-complete callback |
| Add-failure rollback | `AddFailureBeforeSplice`, `AddFailureAfterSplice` | abandon or undo the hot-add sequence | processor-change add-failure callback |
| Resume timer-driven computation | `ResumeAfterTopologyModification` | clear the CPU-0 quiesce state after add-complete / rollback | proposed CPU-0 resume control message |
| `epoch_enter` success/fail-fast | `EpochEnter(c)`, `epoch_enter_failed` | current-CPU epoch entry on a schedulable CPU must not fail because admission lagged | `ebpf_epoch_enter()` and `_ebpf_epoch_fail_fast_if_unadmitted_cpu()` |

## Key modeled assumptions

The model assumes:

1. **One hot-added CPU at a time**
   - This keeps the model small.
   - Concurrent hot-add serialization is left to implementation mechanisms outside this model.

2. **Ring traversal depends on schedulability**
   - Routing an election to a not-yet-started CPU is treated as unsafe.
   - This is modeled by `ElectionCursorSafe`.

3. **CPU 0 owns the timer-side quiesce state**
   - The model abstracts this as `quiescent_requested` plus an optional pending waiter.
   - The real implementation may use a message pointer / `KEVENT` rather than a pure boolean waiter flag.

## Intentional simplifications

This model does **not** attempt to reproduce:

- per-CPU free lists or release epochs
- reader-held objects and reclamation
- explicit DPC / IRQL semantics
- multiple simultaneous hot-added CPUs
- the exact predecessor/successor search logic
- the internal body of passive `ebpf_epoch_synchronize()` once it has taken the shared lock

Those concerns belong either to the main epoch model or to the production implementation details.

## Review checklist for matching code changes

If `libs/runtime/ebpf_epoch.c` changes the hot-add protocol, update this model if any of these change:

1. whether passive synchronize is drained by the SRW lock before topology modification
2. whether CPU 0 blocks new timer-driven computations during topology modification
3. whether an in-flight timer-driven computation is allowed to finish before the ring is changed
4. when the new CPU is considered safe to route election traffic to
5. when `ebpf_epoch_enter()` is allowed to succeed on the hot-added CPU

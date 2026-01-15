# Conformance: `libs/runtime/ebpf_epoch.c` vs `models/epoch/EpochModel.tla`

This note explains how the TLA+ model in `models/epoch/EpochModel.tla` relates to the production implementation in `libs/runtime/ebpf_epoch.c`.

The goal is not to claim the model is a line-by-line reproduction. The goal is to make the abstraction **explicit** so reviewers can tell whether the model still represents the same safety argument as the code.

## What the model is proving

The model checks a single core safety property:

- **No reclamation while a reader can still hold a reference**.

In the model this is expressed as `Safety`:

- If `obj_state = "Reclaimed"` then for all CPUs `c`, `reader_holds[c] = FALSE`.

In the implementation, the analogous claim is:

- An allocation/work-item/synchronization entry on a per-CPU free list is only actually freed/queued/signaled once its stamped `freed_epoch` is `<= released_epoch`, and `released_epoch` is computed such that it lags behind the minimum epoch of any active thread.

## Refinement mapping (implementation → model)

This table is the intended mapping from concrete state to model state.

| Model concept | TLA+ variable(s) | Implementation concept | C symbol(s) / mechanism |
|---|---|---|---|
| Globally published epoch | `published_epoch` | Global “source of truth” epoch used by readers and retire stamping | `_ebpf_epoch_published_current_epoch` read via `_ebpf_epoch_get_published_epoch()`; advanced by CPU0 with `InterlockedIncrement64(&_ebpf_epoch_published_current_epoch)` in `_ebpf_epoch_messenger_propose_release_epoch()` |
| Per-CPU cached epoch | `cpu_epoch[c]` | Per-CPU epoch cache used for local tracking (may lag until it processes the propose message) | `_ebpf_epoch_cpu_table[c].current_epoch` set in `_ebpf_epoch_messenger_propose_release_epoch()` |
| Reader “in epoch” flag | `reader_active[c]` | Thread is currently inside an epoch and is listed on a per-CPU active list | Membership of an `ebpf_epoch_state_t` in `_ebpf_epoch_cpu_table[c].epoch_state_list` (inserted by `ebpf_epoch_enter()`, removed by `ebpf_epoch_exit()`) |
| Reader captured epoch | `reader_epoch[c]` | The epoch a thread recorded on entry | `epoch_state->epoch` set by `ebpf_epoch_enter()` to `_ebpf_epoch_get_published_epoch()` |
| Reader currently “holds” object | `reader_holds[c]` | Abstract “the reader still has a reference to the to-be-freed object” | Not represented directly in C; in the implementation this corresponds to “a thread can still access memory that is protected by having entered the epoch and not yet exited” |
| Retirement stamp (object’s freed_epoch) | `obj_freed_epoch` | When an entry is enqueued for deferred reclamation, it is stamped with an epoch | `header->freed_epoch` in `_ebpf_epoch_insert_in_free_list()`, set to `max(published_epoch, local_epoch)` |
| Release threshold | `released_epoch` | The newest epoch eligible for reclamation | Per-CPU `_ebpf_epoch_cpu_table[c].released_epoch`, computed in `_ebpf_epoch_messenger_commit_release_epoch()` as `message->...released_epoch - 1` |
| Reclamation | `Reclaim` action | Actual free / queue work-item / signal event for eligible entries | `_ebpf_epoch_release_free_list()` drains entries with `header->freed_epoch <= released_epoch` |

### Notes about the mapping

- The model treats “readers” as CPU-indexed for simplicity (one conceptual reader per CPU). The implementation has many threads per CPU.
- The implementation’s `released_epoch` is stored per-CPU, but the protocol is intended to make it converge to the same value on all CPUs each computation cycle. The model uses a single global `released_epoch`.

## Key modeled protocol steps vs code

### 1) Advance the published epoch

- Model: `AdvanceEpoch` (CPU0 advances `published_epoch`, others may lag in `cpu_epoch[c]` until they process an update).
- Code:
  - CPU0 advances global published epoch in `_ebpf_epoch_messenger_propose_release_epoch()`:
    - `InterlockedIncrement64(&_ebpf_epoch_published_current_epoch)`.
  - CPU0 sets its local `current_epoch` and places it into the message.

### 2) Propagate the new epoch to other CPUs

- Model: `ProcessEpochUpdate(c)` updates `cpu_epoch[c]` from the published epoch.
- Code:
  - Non-zero CPUs set their local `current_epoch` from `message->message.propose_epoch.current_epoch` when processing `_ebpf_epoch_messenger_propose_release_epoch()`.

### 3) Readers capture an epoch on enter

- Model: `ReaderEnter(c)` sets `reader_epoch[c]` to either the published epoch (fixed) or the CPU-local epoch (buggy mode).
- Code:
  - `ebpf_epoch_enter()` stamps `epoch_state->epoch = _ebpf_epoch_get_published_epoch()` (fixed design behavior).

### 4) Retirement stamping

- Model: `Retire(c)` stamps `obj_freed_epoch` as either `Max2(published_epoch, cpu_epoch[c])` (fixed) or `cpu_epoch[c]` (buggy mode).
- Code:
  - `_ebpf_epoch_insert_in_free_list()` stamps `header->freed_epoch = max(published_epoch, local_epoch)`.

This is the specific point that prevents the epoch-skew hazard:
- a reader might have observed a newer published epoch,
- while a CPU’s `current_epoch` lags,
- so retirements must not be stamped “too old”.

### 5) Compute and commit a release threshold

- Model: `ComputeRelease` computes a `released_epoch` which never includes the current published epoch.
- Code:
  - `_ebpf_epoch_messenger_propose_release_epoch()` computes `minimum_epoch` across all active `epoch_state->epoch` values.
  - `_ebpf_epoch_messenger_commit_release_epoch()` sets `cpu_entry->released_epoch = minimum_epoch - 1`.

## Shared invariants worth keeping in sync

These are implementation-design invariants that correspond directly to the model’s assumptions/checks.

1) **No release of the current epoch**
- Model: `released_epoch` is computed as at most `published_epoch - 1`.
- Code: commit sets `released_epoch = minimum_epoch - 1`, and `minimum_epoch <= current_epoch == published_epoch`.

2) **Eligibility check is epoch-based**
- Model: `Reclaim` allowed only when `obj_freed_epoch <= released_epoch`.
- Code: `_ebpf_epoch_release_free_list()` frees entries only when `header->freed_epoch <= released_epoch`.

3) **Readers use the published epoch as source of truth**
- Model: in the fixed config, `ReaderEnter` uses `published_epoch`.
- Code: `ebpf_epoch_enter()` reads `_ebpf_epoch_get_published_epoch()`.

4) **Retirements are stamped conservatively**
- Model: in the fixed config, retirement stamping uses `max(published_epoch, cpu_epoch[c])`.
- Code: `_ebpf_epoch_insert_in_free_list()` stamps `max(published_epoch, local_epoch)`.

## Intentional simplifications (where the model does NOT match the code)

These are the abstraction boundaries. If any of these change materially in the implementation, the model may need to be updated.

- **One shared object**: the model tracks a single object; the implementation manages many allocations/work-items/synchronizations.
- **Boolean “holds”**: the model’s `reader_holds[c]` is a single bit; the code has arbitrary memory accesses while in-epoch.
- **One reader per CPU**: the model collapses many threads into one representative “reader” per CPU.
- **Global release threshold**: the model uses one `released_epoch`; the implementation stores it per CPU and updates it via the commit message hop.
- **Scheduling details omitted**: timers, DPCs, work-queues, and IRQL are not represented.
- **CPU migration**: the implementation explicitly handles `ebpf_epoch_exit()` on a different CPU; the model does not.

## Practical ways to keep them matched

When changing `libs/runtime/ebpf_epoch.c`, update the model and this mapping if any of these change:

- How `ebpf_epoch_enter()` chooses the epoch value to store.
- How retirements are stamped (what epoch value is written into `freed_epoch`).
- How the “release epoch” is computed/committed (especially whether it still lags the minimum active epoch).
- The condition under which an item is reclaimed.

Suggested review checklist for changes touching epochs:

1) Does the change preserve the four “Shared invariants” above?
2) Does `EpochModel.cfg` still pass and does `EpochModel_buggy.cfg` still find a counterexample?
3) If the algorithmic intent changed, should the model be updated to represent the new intent?

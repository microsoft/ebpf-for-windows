---------------------------- MODULE EpochModel ----------------------------
EXTENDS Naturals, FiniteSets, TLC
\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

(***************************************************************************
A small model of the eBPF-for-Windows epoch reclamation protocol focused on
safety (no reclamation while a reader may still hold a reference).

This model is intentionally simple:
- One shared object transitions Reachable -> Retired -> Reclaimed.
- Each CPU has a cached epoch (cpu_epoch[c]) that may lag published_epoch.
- Readers capture an epoch on entry and may "hold" the object if it was
  reachable when they read it.
- Retirement stamps obj_freed_epoch either from cpu_epoch (buggy) or using
  the globally published epoch (fixed), mirroring the published-epoch fix.

The key safety invariant is:
  obj_state = "Reclaimed" => no reader_holds[c]

Tune constants in the .cfg files in this folder.
***************************************************************************)

CONSTANTS
    NCPUS,                      \* number of CPUs (>= 2 is interesting)
    MaxEpoch,                   \* bound on epoch increments for finite state
    UsePublishedEpochForReader, \* if TRUE: reader captures published_epoch
    UsePublishedEpochForRetire  \* if TRUE: retire stamps Max(published, cpu)

CPUS == 0 .. (NCPUS - 1)

ObjStates == {"Reachable", "Retired", "Reclaimed"}

VARIABLES
    published_epoch,  \* global single source of truth epoch (monotonic)
    cpu_epoch,        \* per-CPU cached epoch (may lag)
    released_epoch,   \* globally computed safe-to-reclaim threshold

    reader_active,    \* reader_active[c] is TRUE if a reader is in epoch on cpu c
    reader_epoch,     \* reader_epoch[c] is the epoch captured on entry
    reader_holds,     \* reader_holds[c] indicates the reader still holds the object

    obj_state,        \* Reachable / Retired / Reclaimed
    obj_freed_epoch,  \* epoch stamped at retirement
    retire_published_epoch, \* published epoch value observed at retirement time
    retire_cpu_epoch        \* per-CPU cached epoch value observed at retirement time

vars == <<
    published_epoch,
    cpu_epoch,
    released_epoch,
    reader_active,
    reader_epoch,
    reader_holds,
    obj_state,
    obj_freed_epoch,
    retire_published_epoch,
    retire_cpu_epoch
>>

Max2(a, b) == IF a >= b THEN a ELSE b

Min(S) == CHOOSE m \in S : \A x \in S : m <= x

ActiveCPUs == { c \in CPUS : reader_active[c] }

ActiveReaderEpochs == { reader_epoch[c] : c \in ActiveCPUs }

TypeOK ==
    /\ published_epoch \in 1..MaxEpoch
    /\ released_epoch \in 0..MaxEpoch
    /\ cpu_epoch \in [CPUS -> 1..MaxEpoch]
    /\ reader_active \in [CPUS -> BOOLEAN]
    /\ reader_epoch \in [CPUS -> 0..MaxEpoch]
    /\ reader_holds \in [CPUS -> BOOLEAN]
    /\ obj_state \in ObjStates
    /\ obj_freed_epoch \in 0..MaxEpoch
    /\ retire_published_epoch \in 0..MaxEpoch
    /\ retire_cpu_epoch \in 0..MaxEpoch

Init ==
    /\ published_epoch = 1
    /\ cpu_epoch = [c \in CPUS |-> 1]
    /\ released_epoch = 0

    /\ reader_active = [c \in CPUS |-> FALSE]
    /\ reader_epoch = [c \in CPUS |-> 0]
    /\ reader_holds = [c \in CPUS |-> FALSE]

    /\ obj_state = "Reachable"
    /\ obj_freed_epoch = 0
    /\ retire_published_epoch = 0
    /\ retire_cpu_epoch = 0

(***************************************************************************
Protocol steps
***************************************************************************)

\* CPU0 advances the global epoch; other CPUs lag until they process an update.
AdvanceEpoch ==
    /\ published_epoch < MaxEpoch
    /\ published_epoch' = published_epoch + 1
    /\ cpu_epoch' = [cpu_epoch EXCEPT ![0] = published_epoch']
    /\ UNCHANGED << released_epoch, reader_active, reader_epoch, reader_holds, obj_state, obj_freed_epoch, retire_published_epoch, retire_cpu_epoch >>

\* A non-CPU0 core learns the current published epoch (delayed message processing).
ProcessEpochUpdate(c) ==
    /\ c \in CPUS \ {0}
    /\ cpu_epoch' = [cpu_epoch EXCEPT ![c] = published_epoch]
    /\ UNCHANGED << published_epoch, released_epoch, reader_active, reader_epoch, reader_holds, obj_state, obj_freed_epoch, retire_published_epoch, retire_cpu_epoch >>

\* Reader enters epoch on a CPU and captures an epoch value.
ReaderEnter(c) ==
    /\ c \in CPUS
    /\ ~reader_active[c]
    /\ reader_active' = [reader_active EXCEPT ![c] = TRUE]
    /\ reader_epoch' = [reader_epoch EXCEPT ![c] = IF UsePublishedEpochForReader THEN published_epoch ELSE cpu_epoch[c]]
    /\ reader_holds' = [reader_holds EXCEPT ![c] = FALSE]
    /\ UNCHANGED << published_epoch, cpu_epoch, released_epoch, obj_state, obj_freed_epoch, retire_published_epoch, retire_cpu_epoch >>

\* While inside epoch, a reader may load and hold the object if it is reachable.
ReaderRead(c) ==
    /\ c \in CPUS
    /\ reader_active[c]
    /\ obj_state = "Reachable"
    /\ reader_holds' = [reader_holds EXCEPT ![c] = TRUE]
    /\ UNCHANGED << published_epoch, cpu_epoch, released_epoch, reader_active, reader_epoch, obj_state, obj_freed_epoch, retire_published_epoch, retire_cpu_epoch >>

\* Reader exits epoch and drops any reference.
ReaderExit(c) ==
    /\ c \in CPUS
    /\ reader_active[c]
    /\ reader_active' = [reader_active EXCEPT ![c] = FALSE]
    /\ reader_holds' = [reader_holds EXCEPT ![c] = FALSE]
    /\ UNCHANGED << published_epoch, cpu_epoch, released_epoch, reader_epoch, obj_state, obj_freed_epoch, retire_published_epoch, retire_cpu_epoch >>

\* Retire the shared object on some CPU.
Retire(c) ==
    /\ c \in CPUS
    /\ obj_state = "Reachable"
    /\ obj_state' = "Retired"
    /\ retire_published_epoch' = published_epoch
    /\ retire_cpu_epoch' = cpu_epoch[c]
    /\ obj_freed_epoch' =
        IF UsePublishedEpochForRetire
            THEN Max2(published_epoch, cpu_epoch[c])
            ELSE cpu_epoch[c]
    /\ UNCHANGED << published_epoch, cpu_epoch, released_epoch, reader_active, reader_epoch, reader_holds >>

\* CPU0 computes a safe release threshold.
\* If there are active readers with captured epochs, we can only release epochs
\* strictly less than the minimum active reader epoch.
ComputeRelease ==
    /\ LET candidate ==
            IF ActiveReaderEpochs = {}
                THEN published_epoch - 1
                ELSE (Min(ActiveReaderEpochs) - 1)
       IN released_epoch' = Max2(released_epoch, candidate)
    /\ UNCHANGED << published_epoch, cpu_epoch, reader_active, reader_epoch, reader_holds, obj_state, obj_freed_epoch, retire_published_epoch, retire_cpu_epoch >>

\* Reclaim when the release threshold covers the object's retirement epoch.
Reclaim ==
    /\ obj_state = "Retired"
    /\ obj_freed_epoch <= released_epoch
    /\ obj_state' = "Reclaimed"
    /\ UNCHANGED << published_epoch, cpu_epoch, released_epoch, reader_active, reader_epoch, reader_holds, obj_freed_epoch, retire_published_epoch, retire_cpu_epoch >>

Next ==
    \/ AdvanceEpoch
    \/ \E c \in CPUS \ {0} : ProcessEpochUpdate(c)
    \/ \E c \in CPUS : ReaderEnter(c)
    \/ \E c \in CPUS : ReaderRead(c)
    \/ \E c \in CPUS : ReaderExit(c)
    \/ \E c \in CPUS : Retire(c)
    \/ ComputeRelease
    \/ Reclaim

Spec == Init /\ [][Next]_vars

(***************************************************************************
Properties to check with TLC
***************************************************************************)

\* "No use-after-free": once reclaimed, no reader can still be holding it.
Safety == (obj_state = "Reclaimed") => (\A c \in CPUS : ~reader_holds[c])

\* When the published-epoch retirement behavior is enabled, the epoch stamped on
\* the retired object equals the max() of the values observed at the moment of retirement.
\* This corresponds to the implementation's:
\*   header->freed_epoch = max(published_epoch, local_epoch)
RetireStampIsMaxWhenEnabled ==
    UsePublishedEpochForRetire =>
        ((obj_state = "Reachable") =>
            /\ obj_freed_epoch = 0
            /\ retire_published_epoch = 0
            /\ retire_cpu_epoch = 0)
        /\ ((obj_state \in {"Retired", "Reclaimed"}) =>
            obj_freed_epoch = Max2(retire_published_epoch, retire_cpu_epoch))

\* Sanity: release should never exceed published.
ReleaseNeverAhead == released_epoch <= published_epoch

=============================================================================

------------------------- MODULE EpochHotAddModel -------------------------
EXTENDS FiniteSets, Naturals, TLC
\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

(***************************************************************************
A small model of epoch hot-add topology management.

This model focuses on the safety of a "quiesce then modify" protocol with the
responsibilities split in two:

- passive epoch_synchronize is abstracted as taking a shared SRW lock
- topology modification takes that same lock exclusive
- timer-driven epoch computation remains owned by CPU 0
- a quiesce request message to CPU 0 blocks new timer-driven computations and
  completes only once any in-flight timer-driven computation has drained

The key safety properties are:

1) The election walker only runs on admitted, schedulable CPUs.
2) A schedulable CPU is always admitted, so epoch_enter would not fail-fast due
   to a hot-add race.

The model intentionally abstracts away reclamation and reader epochs; the
existing EpochModel covers those concerns separately.
***************************************************************************)

CONSTANTS
    UseQuiesceBeforeModify, \* if TRUE, require CPU-0 quiesce before splicing
    AllowEarlyResume        \* if TRUE, allow clearing quiesce before add-complete

Cpu0 == 0
Cpu1 == 1
HotCpu == 2
CPUS == {Cpu0, Cpu1, HotCpu}

HotStates == {"Offline", "Initializing", "QuiescePending", "Quiesced", "Inserted", "Active", "Failed"}

VARIABLES
    ring_next,            \* next pointer for the admitted CPU ring
    admitted,             \* admitted[c] iff CPU c participates in the ring
    schedulable,          \* schedulable[c] iff CPU c may execute epoch code
    hot_state,            \* lifecycle of the hot-added CPU
    topology_exclusive,   \* topology modifier holds the passive SRW lock exclusively
    passive_sync_active,  \* a passive synchronize caller holds the SRW lock shared
    quiescent_requested,  \* CPU-0-owned flag: do not start new timer computations
    quiesce_waiter_pending, \* CPU 0 owes completion to the current quiesce waiter
    timer_requested,      \* timer path requested an election
    election_in_progress, \* a timer-driven election walk is in flight
    election_cursor,      \* CPU currently processing the election message
    epoch_enter_failed    \* sticky flag: TRUE iff epoch_enter would fail-fast

vars ==
    <<
        ring_next,
        admitted,
        schedulable,
        hot_state,
        topology_exclusive,
        passive_sync_active,
        quiescent_requested,
        quiesce_waiter_pending,
        timer_requested,
        election_in_progress,
        election_cursor,
        epoch_enter_failed
    >>

AdmittedCPUs == {c \in CPUS : admitted[c]}

TypeOK ==
    /\ ring_next \in [CPUS -> CPUS]
    /\ admitted \in [CPUS -> BOOLEAN]
    /\ schedulable \in [CPUS -> BOOLEAN]
    /\ hot_state \in HotStates
    /\ topology_exclusive \in BOOLEAN
    /\ passive_sync_active \in BOOLEAN
    /\ quiescent_requested \in BOOLEAN
    /\ quiesce_waiter_pending \in BOOLEAN
    /\ timer_requested \in BOOLEAN
    /\ election_in_progress \in BOOLEAN
    /\ election_cursor \in CPUS
    /\ epoch_enter_failed \in BOOLEAN

Init ==
    /\ ring_next =
        [c \in CPUS |->
            CASE c = Cpu0 -> Cpu1
              [] c = Cpu1 -> Cpu0
              [] OTHER -> HotCpu]
    /\ admitted =
        [c \in CPUS |->
            CASE c = HotCpu -> FALSE
              [] OTHER -> TRUE]
    /\ schedulable =
        [c \in CPUS |->
            CASE c = HotCpu -> FALSE
              [] OTHER -> TRUE]
    /\ hot_state = "Offline"
    /\ topology_exclusive = FALSE
    /\ passive_sync_active = FALSE
    /\ quiescent_requested = FALSE
    /\ quiesce_waiter_pending = FALSE
    /\ timer_requested = FALSE
    /\ election_in_progress = FALSE
    /\ election_cursor = Cpu0
    /\ epoch_enter_failed = FALSE

(***************************************************************************
Passive synchronize / timer requests / traversal
***************************************************************************)

PassiveSyncStart ==
    /\ ~topology_exclusive
    /\ ~passive_sync_active
    /\ passive_sync_active' = TRUE
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            schedulable,
            hot_state,
            topology_exclusive,
            quiescent_requested,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

PassiveSyncFinish ==
    /\ passive_sync_active
    /\ passive_sync_active' = FALSE
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            schedulable,
            hot_state,
            topology_exclusive,
            quiescent_requested,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

RequestTimerElection ==
    /\ ~timer_requested
    /\ timer_requested' = TRUE
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            schedulable,
            hot_state,
            topology_exclusive,
            passive_sync_active,
            quiescent_requested,
            quiesce_waiter_pending,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

StartElection ==
    /\ ~election_in_progress
    /\ ~quiescent_requested
    /\ timer_requested
    /\ election_in_progress' = TRUE
    /\ election_cursor' = Cpu0
    /\ timer_requested' = FALSE
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            schedulable,
            hot_state,
            topology_exclusive,
            passive_sync_active,
            quiescent_requested,
            quiesce_waiter_pending,
            epoch_enter_failed
        >>

AdvanceElection ==
    /\ election_in_progress
    /\ LET next_cpu == ring_next[election_cursor]
       IN IF next_cpu = Cpu0
            THEN /\ election_in_progress' = FALSE
                 /\ election_cursor' = Cpu0
                 /\ IF quiesce_waiter_pending
                        THEN /\ quiesce_waiter_pending' = FALSE
                             /\ hot_state' = "Quiesced"
                        ELSE /\ quiesce_waiter_pending' = quiesce_waiter_pending
                             /\ hot_state' = hot_state
            ELSE /\ election_in_progress' = TRUE
                 /\ election_cursor' = next_cpu
                 /\ quiesce_waiter_pending' = quiesce_waiter_pending
                 /\ hot_state' = hot_state
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            schedulable,
            topology_exclusive,
            passive_sync_active,
            quiescent_requested,
            timer_requested,
            epoch_enter_failed
        >>

(***************************************************************************
Hot-add lifecycle
***************************************************************************)

BeginHotAdd ==
    /\ hot_state = "Offline"
    /\ ~topology_exclusive
    /\ ~passive_sync_active
    /\ hot_state' = "Initializing"
    /\ topology_exclusive' = TRUE
    /\ admitted' = [admitted EXCEPT ![HotCpu] = TRUE]
    /\ ring_next' = [ring_next EXCEPT ![HotCpu] = Cpu0]
    /\ UNCHANGED
        <<
            schedulable,
            passive_sync_active,
            quiescent_requested,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

RequestQuiesce ==
    /\ topology_exclusive
    /\ hot_state = "Initializing"
    /\ ~quiescent_requested
    /\ quiescent_requested' = TRUE
    /\ IF election_in_progress
        THEN /\ quiesce_waiter_pending' = TRUE
             /\ hot_state' = "QuiescePending"
        ELSE /\ quiesce_waiter_pending' = FALSE
             /\ hot_state' = "Quiesced"
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            schedulable,
            topology_exclusive,
            passive_sync_active,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

SpliceHotCpu ==
    /\ topology_exclusive
    /\ (IF UseQuiesceBeforeModify THEN hot_state = "Quiesced" ELSE hot_state \in {"Initializing", "QuiescePending", "Quiesced"})
    /\ hot_state' = "Inserted"
    /\ ring_next' = [ring_next EXCEPT ![Cpu1] = HotCpu]
    /\ UNCHANGED
        <<
            admitted,
            schedulable,
            topology_exclusive,
            passive_sync_active,
            quiescent_requested,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

AddComplete ==
    /\ hot_state = "Inserted"
    /\ ~schedulable[HotCpu]
    /\ hot_state' = "Active"
    /\ schedulable' = [schedulable EXCEPT ![HotCpu] = TRUE]
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            topology_exclusive,
            passive_sync_active,
            quiescent_requested,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

AddFailureBeforeSplice ==
    /\ topology_exclusive
    /\ hot_state \in {"Initializing", "Quiesced"}
    /\ hot_state' = "Failed"
    /\ admitted' = [admitted EXCEPT ![HotCpu] = FALSE]
    /\ ring_next' = [ring_next EXCEPT ![HotCpu] = HotCpu]
    /\ UNCHANGED
        <<
            schedulable,
            topology_exclusive,
            passive_sync_active,
            quiescent_requested,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

AddFailureAfterSplice ==
    /\ topology_exclusive
    /\ hot_state = "Inserted"
    /\ ~schedulable[HotCpu]
    /\ hot_state' = "Failed"
    /\ admitted' = [admitted EXCEPT ![HotCpu] = FALSE]
    /\ ring_next' = [ring_next EXCEPT ![Cpu1] = Cpu0, ![HotCpu] = HotCpu]
    /\ UNCHANGED
        <<
            schedulable,
            topology_exclusive,
            passive_sync_active,
            quiescent_requested,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

ResumeAfterTopologyModification ==
    /\ topology_exclusive
    /\ quiescent_requested
    /\ hot_state = "Failed" \/ hot_state = "Active" \/ (AllowEarlyResume /\ hot_state = "Inserted")
    /\ topology_exclusive' = FALSE
    /\ quiescent_requested' = FALSE
    /\ UNCHANGED
        <<
            ring_next,
            admitted,
            schedulable,
            hot_state,
            passive_sync_active,
            quiesce_waiter_pending,
            timer_requested,
            election_in_progress,
            election_cursor,
            epoch_enter_failed
        >>

(***************************************************************************
Epoch entry check
***************************************************************************)

EpochEnter(c) ==
    /\ c \in CPUS
    /\ schedulable[c]
    /\ ~epoch_enter_failed
    /\ IF admitted[c]
        THEN /\ UNCHANGED vars
        ELSE /\ epoch_enter_failed' = TRUE
             /\ UNCHANGED
                <<
                    ring_next,
                    admitted,
                    schedulable,
                    hot_state,
                    topology_exclusive,
                    passive_sync_active,
                    quiescent_requested,
                    quiesce_waiter_pending,
                    timer_requested,
                    election_in_progress,
                    election_cursor
                >>

Next ==
    \/ PassiveSyncStart
    \/ PassiveSyncFinish
    \/ RequestTimerElection
    \/ StartElection
    \/ AdvanceElection
    \/ BeginHotAdd
    \/ RequestQuiesce
    \/ SpliceHotCpu
    \/ AddComplete
    \/ AddFailureBeforeSplice
    \/ AddFailureAfterSplice
    \/ ResumeAfterTopologyModification
    \/ \E c \in CPUS : EpochEnter(c)

Spec == Init /\ [][Next]_vars

(***************************************************************************
Properties to check with TLC
***************************************************************************)

\* Admitted CPUs must always point to admitted CPUs.
RingTargetsAdmitted ==
    \A c \in AdmittedCPUs : admitted[ring_next[c]]

\* The stable CPUs are never removed from the epoch subsystem.
BaseCpusAlwaysAvailable ==
    /\ admitted[Cpu0]
    /\ admitted[Cpu1]
    /\ schedulable[Cpu0]
    /\ schedulable[Cpu1]

\* The exclusive topology modifier lock and passive synchronize lock cannot be
\* held simultaneously.
PassiveLockDiscipline ==
    topology_exclusive => ~passive_sync_active

\* If an epoch election is running, its current CPU must be both admitted and
\* schedulable. Hitting an unadmitted or not-yet-started CPU would model an
\* invalid message route or a stalled election.
ElectionCursorSafe ==
    election_in_progress => (admitted[election_cursor] /\ schedulable[election_cursor])

\* A schedulable CPU must already be admitted. This is the model analogue of
\* "epoch_enter should not fail-fast because of a hot-add race."
SchedulableImpliesAdmitted ==
    \A c \in CPUS : schedulable[c] => admitted[c]

\* CPU 0 only remembers a quiesce waiter while quiescence has been requested.
QuiesceWaiterIsConsistent ==
    quiesce_waiter_pending => quiescent_requested

\* Sticky check that an epoch_enter step never observed a schedulable-but-not-
\* admitted CPU.
EpochEnterNeverFails == ~epoch_enter_failed

=============================================================================

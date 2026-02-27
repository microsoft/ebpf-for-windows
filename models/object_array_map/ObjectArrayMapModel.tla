\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

---- MODULE ObjectArrayMapModel ----
EXTENDS Naturals, FiniteSets, TLC

(*****************************************************************
Bounded, executable TLA+ model of the lock-free (no-lock) read of an
object pointer stored in an array map slot, as used by prog-array and
(map-in-map) array variants.

Key implementation pattern (libs/execution_context/ebpf_maps.c):
- Reader: atomically reads a pointer from a map slot with NoFence and
  then uses it without taking the map lock and without taking an extra
  object reference.
- Writer: updates the slot under a lock, releases the old object
  reference, and writes the new pointer.

Correctness relies on a lifetime rule:
- The reader must be executing inside an epoch (or equivalent guard)
  such that objects whose refcount reaches zero are not actually freed
  until after the epoch ends.

This model checks a core safety property:
- A reader must never hold/use an object that has been Freed.

It provides a buggy configuration that permits reads outside an epoch.
*****************************************************************)

CONSTANTS
  ObjIds,                \* Finite set of object identities.
  MaxEpoch,              \* Nat: upper bound for published epoch.
  AllowReadOutsideEpoch  \* BOOLEAN: if TRUE, allow reader to load without entering epoch.

ASSUME ObjIds \subseteq Nat
ASSUME MaxEpoch \in Nat
ASSUME Cardinality(ObjIds) >= 2

Epochs == 0..MaxEpoch
NoEpoch == MaxEpoch + 1
AllEpochVals == Epochs \cup {NoEpoch}

ObjStates == {"Live", "Retired", "Freed"}

VARIABLES
  publishedEpoch,   \* global/published epoch (monotonic).
  readerEpoch,      \* reader's current epoch, or NoEpoch if not in epoch.
  slot,             \* array slot pointer: 0 (NULL) or an ObjId.
  objState,         \* [ObjIds -> ObjStates]
  retireEpoch,      \* [ObjIds -> AllEpochVals]
  held              \* 0 (none) or ObjId the reader is currently using.

TypeOK ==
  /\ publishedEpoch \in Epochs
  /\ readerEpoch \in AllEpochVals
  /\ slot \in (ObjIds \cup {0})
  /\ held \in (ObjIds \cup {0})
  /\ objState \in [ObjIds -> ObjStates]
  /\ retireEpoch \in [ObjIds -> AllEpochVals]

Safety ==
  /\ held = 0 \/ objState[held] # "Freed"

Init ==
  LET o1 == CHOOSE o \in ObjIds: TRUE
      o2 == CHOOSE o \in (ObjIds \ {o1}): TRUE
  IN
  /\ publishedEpoch = 0
  /\ readerEpoch = NoEpoch
  /\ slot = o1
  /\ held = 0
  /\ objState = [o \in ObjIds |-> IF o = o1 THEN "Live" ELSE "Freed"]
  /\ retireEpoch = [o \in ObjIds |-> NoEpoch]

\* Reader operations
ReaderEnter ==
  /\ readerEpoch = NoEpoch
  /\ readerEpoch' = publishedEpoch
  /\ UNCHANGED <<publishedEpoch, slot, objState, retireEpoch, held>>

ReaderExit ==
  /\ readerEpoch # NoEpoch
  /\ held = 0
  /\ readerEpoch' = NoEpoch
  /\ UNCHANGED <<publishedEpoch, slot, objState, retireEpoch, held>>

ReaderLoad ==
  /\ held = 0
  /\ slot # 0
  /\ (AllowReadOutsideEpoch \/ readerEpoch # NoEpoch)
  /\ held' = slot
  /\ UNCHANGED <<publishedEpoch, readerEpoch, slot, objState, retireEpoch>>

ReaderDrop ==
  /\ held # 0
  /\ held' = 0
  /\ UNCHANGED <<publishedEpoch, readerEpoch, slot, objState, retireEpoch>>

\* Writer operations
AllocateNewLiveObject ==
  CHOOSE o \in ObjIds: objState[o] = "Freed"

WriterUpdate ==
  /\ slot # 0
  /\ \E new \in ObjIds:
       /\ objState[new] = "Freed"
       /\ slot' = new
       /\ objState' = [objState EXCEPT
                       ![slot] = "Retired",
                       ![new] = "Live"]
       /\ retireEpoch' = [retireEpoch EXCEPT ![slot] = publishedEpoch]
       /\ UNCHANGED <<publishedEpoch, readerEpoch, held>>

\* Epoch progression + reclamation
AdvanceEpoch ==
  /\ publishedEpoch < MaxEpoch
  /\ publishedEpoch' = publishedEpoch + 1
  /\ UNCHANGED <<readerEpoch, slot, objState, retireEpoch, held>>

MinActiveEpoch == IF readerEpoch = NoEpoch THEN NoEpoch ELSE readerEpoch

CanReclaim(o) ==
  /\ objState[o] = "Retired"
  /\ retireEpoch[o] \in Epochs
  /\ retireEpoch[o] < MinActiveEpoch

ReclaimOne ==
  /\ \E o \in ObjIds: CanReclaim(o)
  /\ LET o == CHOOSE x \in ObjIds: CanReclaim(x)
     IN
     /\ objState' = [objState EXCEPT ![o] = "Freed"]
     /\ retireEpoch' = [retireEpoch EXCEPT ![o] = NoEpoch]
     /\ UNCHANGED <<publishedEpoch, readerEpoch, slot, held>>

vars == <<publishedEpoch, readerEpoch, slot, objState, retireEpoch, held>>

Next ==
  ReaderEnter
  \/ ReaderExit
  \/ ReaderLoad
  \/ ReaderDrop
  \/ WriterUpdate
  \/ AdvanceEpoch
  \/ ReclaimOne

Spec == Init /\ [][Next]_vars

====

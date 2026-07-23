------------------------- MODULE EpochModelProofs -------------------------
EXTENDS EpochModel, Naturals, TLAPS
\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

(***************************************************************************
Proof entrypoint for EpochModel.

Goal: prove the fixed configuration is always safe.

Concretely, we prove:
  FixedAssumptions => (Spec => []Safety)

We do this by proving a strengthened inductive invariant (FixedInv) that
contains Safety plus the extra facts needed to make the Safety step provable.

Notes:
- These ASSUME clauses are the "type" assumptions that TLC gets implicitly via
  the concrete constant assignments in the *.cfg files.
- TLAPS's PTL step expects the step lemma over [Next]_vars (includes stuttering).
***************************************************************************)

CfgAssumptions ==
  \* Basic well-typedness / bounds for constants.
  /\ NCPUS \in Nat
  /\ NCPUS >= 1
  /\ MaxEpoch \in Nat /\ MaxEpoch >= 1
  /\ UsePublishedEpochForReader \in BOOLEAN
  /\ UsePublishedEpochForRetire \in BOOLEAN

FixedAssumptions ==
  \* The configuration we want to prove safe (the "fixed" behavior).
  /\ CfgAssumptions
  /\ UsePublishedEpochForReader = TRUE
  /\ UsePublishedEpochForRetire = TRUE

\* --- Strengthening invariants used in FixedInv ---
\*
\* These are not "the goal" themselves; they're the extra facts we need to
\* make the Safety preservation proof go through (especially in the Reclaim case).

\* CPU local epochs never get ahead of the published epoch.
CpuEpochNeverAhead ==
  \A c \in CPUS : cpu_epoch[c] <= published_epoch

\* Reader-captured epochs never get ahead of the published epoch.
ReaderEpochNeverAhead ==
  \A c \in CPUS : reader_epoch[c] <= published_epoch

\* Any reader that still "holds" must have read while the object was reachable.
\* After retirement, such a holder must have entered no later than retirement.
HolderEpochBoundedByRetire ==
  \A c \in CPUS :
    reader_holds[c] => (obj_state = "Reachable" \/ reader_epoch[c] <= retire_published_epoch)

\* A reader can only hold while active (ReaderExit always clears holds).
HoldsImpliesActive ==
  \A c \in CPUS : reader_holds[c] => reader_active[c]

\* Release epoch always strictly lags the published epoch.
\* This is used to preserve ReleaseBelowActiveReaderEpoch across ReaderEnter
\* when UsePublishedEpochForReader=TRUE (new active reader captures published_epoch).
ReleasedStrictlyBehind ==
  released_epoch < published_epoch

\* The release epoch must remain strictly less than the epoch of any active reader.
\* (This is the key strengthening we use to prove Safety at reclaim time.)
ReleaseBelowActiveReaderEpoch ==
  \A c \in ActiveCPUs : released_epoch < reader_epoch[c]

\* --- Preservation lemmas for the strengthening invariants ---
\*
\* We keep these as separate theorems because they are reused when proving
\* FixedInv is inductive.

THEOREM RetireStampIsMaxWhenEnabledPreservedByNext ==
  \* Purpose: show the retirement stamping invariant is inductive.
  \* Needed: Safety preservation uses it to relate obj_freed_epoch to the retirement snapshot.
  ASSUME
    CfgAssumptions
  PROVE RetireStampIsMaxWhenEnabled /\ Next => RetireStampIsMaxWhenEnabled'
PROOF
  BY DEF CfgAssumptions,
        Next,
        RetireStampIsMaxWhenEnabled,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim,
        Max2

LEMMA TypeOKPreservedByAdvanceEpoch ==
  \* Purpose: TypeOK is preserved by AdvanceEpoch.
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ AdvanceEpoch => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, AdvanceEpoch, CPUS, ObjStates

LEMMA TypeOKPreservedByProcessEpochUpdate ==
  \* Purpose: TypeOK is preserved by ProcessEpochUpdate(c).
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE (TypeOK /\ (\E c \in CPUS \ {0} : ProcessEpochUpdate(c))) => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, ProcessEpochUpdate, CPUS, ObjStates

LEMMA TypeOKPreservedByReaderEnter ==
  \* Purpose: TypeOK is preserved by ReaderEnter(c).
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE (TypeOK /\ (\E c \in CPUS : ReaderEnter(c))) => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, ReaderEnter, CPUS, ObjStates

LEMMA TypeOKPreservedByReaderRead ==
  \* Purpose: TypeOK is preserved by ReaderRead(c).
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE (TypeOK /\ (\E c \in CPUS : ReaderRead(c))) => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, ReaderRead, CPUS, ObjStates

LEMMA TypeOKPreservedByReaderExit ==
  \* Purpose: TypeOK is preserved by ReaderExit(c).
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE (TypeOK /\ (\E c \in CPUS : ReaderExit(c))) => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, ReaderExit, CPUS, ObjStates

LEMMA TypeOKPreservedByRetire ==
  \* Purpose: TypeOK is preserved by Retire(c).
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE (TypeOK /\ (\E c \in CPUS : Retire(c))) => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, Retire, CPUS, ObjStates, Max2

LEMMA TypeOKPreservedByComputeRelease ==
  \* Purpose: TypeOK is preserved by ComputeRelease.
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ ComputeRelease => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, ComputeRelease, CPUS, ObjStates, Max2, ActiveCPUs

LEMMA TypeOKPreservedByReclaim ==
  \* Purpose: TypeOK is preserved by Reclaim.
  \* Needed: part of TypeOKPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ Reclaim => TypeOK'
PROOF
  BY DEF CfgAssumptions, TypeOK, Reclaim, CPUS, ObjStates

\* TypeOK is preserved by any Next step.
\* This is written as a case split to keep SMT obligations small.
THEOREM TypeOKPreservedByNext ==
  \* Purpose: TypeOK is preserved by any Next step.
  \* Needed: almost every other preservation theorem assumes TypeOK.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ Next => TypeOK'
PROOF
  <1>1. TypeOK /\ Next
        => \/ (TypeOK /\ AdvanceEpoch)
           \/ (TypeOK /\ (\E c \in CPUS \ {0} : ProcessEpochUpdate(c)))
           \/ (TypeOK /\ (\E c \in CPUS : ReaderEnter(c)))
           \/ (TypeOK /\ (\E c \in CPUS : ReaderRead(c)))
           \/ (TypeOK /\ (\E c \in CPUS : ReaderExit(c)))
           \/ (TypeOK /\ (\E c \in CPUS : Retire(c)))
           \/ (TypeOK /\ ComputeRelease)
           \/ (TypeOK /\ Reclaim)
     BY DEF Next
  <1>2. (\/(TypeOK /\ AdvanceEpoch)
         \/ (TypeOK /\ (\E c \in CPUS \ {0} : ProcessEpochUpdate(c)))
         \/ (TypeOK /\ (\E c \in CPUS : ReaderEnter(c)))
         \/ (TypeOK /\ (\E c \in CPUS : ReaderRead(c)))
         \/ (TypeOK /\ (\E c \in CPUS : ReaderExit(c)))
         \/ (TypeOK /\ (\E c \in CPUS : Retire(c)))
         \/ (TypeOK /\ ComputeRelease)
         \/ (TypeOK /\ Reclaim))
        => TypeOK'
     BY TypeOKPreservedByAdvanceEpoch,
        TypeOKPreservedByProcessEpochUpdate,
        TypeOKPreservedByReaderEnter,
        TypeOKPreservedByReaderRead,
        TypeOKPreservedByReaderExit,
        TypeOKPreservedByRetire,
        TypeOKPreservedByComputeRelease,
        TypeOKPreservedByReclaim
  <1> QED

THEOREM ReleaseNeverAheadPreservedByNext ==
  \* Purpose: released_epoch never exceeds published_epoch.
  \* Needed: supports ReleasedStrictlyBehind and helps bound release growth.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ ReleaseNeverAhead /\ Next => ReleaseNeverAhead'
PROOF
  BY DEF CfgAssumptions,
        TypeOK,
        ReleaseNeverAhead,
        Next,
        CPUS,
        ObjStates,
        Max2,
        ActiveCPUs,
        ActiveReaderEpochs,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim

THEOREM ReleasedStrictlyBehindPreservedByNext ==
  \* Purpose: released_epoch stays strictly behind published_epoch.
  \* Needed: preserves ReleaseBelowActiveReaderEpoch across ReaderEnter in fixed config.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ ReleaseNeverAhead /\ ReleasedStrictlyBehind /\ Next => ReleasedStrictlyBehind'
PROOF
  BY DEF CfgAssumptions,
        TypeOK,
        ReleaseNeverAhead,
        ReleasedStrictlyBehind,
        Next,
        CPUS,
        ObjStates,
        Max2,
        ActiveCPUs,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim

THEOREM HoldsImpliesActivePreservedByNext ==
  \* Purpose: holding implies being active stays true.
  \* Needed: Safety preservation relies on ReaderExit clearing holds.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ HoldsImpliesActive /\ Next => HoldsImpliesActive'
PROOF
  BY DEF CfgAssumptions,
        TypeOK,
        HoldsImpliesActive,
        Next,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim

THEOREM ReleaseBelowActiveReaderEpochPreservedByNext ==
  \* Purpose: release threshold stays below every active reader's captured epoch.
  \* Needed: core fact that prevents reclaim while any reader can still be holding.
  ASSUME
    FixedAssumptions
  PROVE TypeOK /\ ReleaseNeverAhead /\ ReleasedStrictlyBehind /\ ReleaseBelowActiveReaderEpoch /\ Next => ReleaseBelowActiveReaderEpoch'
PROOF
  BY DEF FixedAssumptions,
        CfgAssumptions,
        TypeOK,
        ReleaseNeverAhead,
        ReleasedStrictlyBehind,
        ReleaseBelowActiveReaderEpoch,
        Next,
        ActiveCPUs,
        ActiveReaderEpochs,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim,
        Max2

THEOREM SafetyPreservedByNext ==
  \* Purpose: show Safety is preserved by Next, assuming the strengthening invariants.
  \* Needed: this is the key step for proving []Safety (via []FixedInv).
  ASSUME
    FixedAssumptions
  PROVE TypeOK /\ RetireStampIsMaxWhenEnabled /\ HolderEpochBoundedByRetire /\ HoldsImpliesActive /\ ReleaseBelowActiveReaderEpoch /\ Safety /\ Next => Safety'
PROOF
  BY DEF FixedAssumptions,
        CfgAssumptions,
        TypeOK,
        RetireStampIsMaxWhenEnabled,
        HolderEpochBoundedByRetire,
        HoldsImpliesActive,
        ReleaseBelowActiveReaderEpoch,
        Safety,
        Next,
        ActiveCPUs,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim,
        Max2

THEOREM ReaderEpochNeverAheadPreservedByNext ==
  \* Purpose: readers' captured epochs stay <= published_epoch.
  \* Needed: supports HolderEpochBoundedByRetire preservation.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ CpuEpochNeverAhead /\ ReaderEpochNeverAhead /\ Next => ReaderEpochNeverAhead'
PROOF
  BY DEF CfgAssumptions,
        TypeOK,
        CpuEpochNeverAhead,
        ReaderEpochNeverAhead,
        Next,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim

THEOREM CpuEpochNeverAheadPreservedByNext ==
  \* Purpose: cpu epochs stay <= published_epoch.
  \* Needed: required hypothesis for ReaderEpochNeverAheadPreservedByNext.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ CpuEpochNeverAhead /\ Next => CpuEpochNeverAhead'
PROOF
  BY DEF CfgAssumptions,
        TypeOK,
        CpuEpochNeverAhead,
        Next,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim

THEOREM HolderEpochBoundedByRetirePreservedByNext ==
  \* Purpose: if a reader holds, its captured epoch is bounded by retirement snapshot.
  \* Needed: part of the argument that any holder implies a still-active reader with epoch > released_epoch.
  ASSUME
    CfgAssumptions
  PROVE TypeOK /\ HolderEpochBoundedByRetire /\ ReaderEpochNeverAhead /\ Next => HolderEpochBoundedByRetire'
PROOF
  BY DEF CfgAssumptions,
        TypeOK,
        HolderEpochBoundedByRetire,
        ReaderEpochNeverAhead,
        Next,
        AdvanceEpoch,
        ProcessEpochUpdate,
        ReaderEnter,
        ReaderRead,
        ReaderExit,
        Retire,
        ComputeRelease,
        Reclaim

\* --- The strengthened inductive invariant for the fixed configuration ---

FixedInv ==
  \* FixedInv bundles Safety plus the supporting invariants needed to prove
  \* that Safety is preserved by Reclaim.
  /\ TypeOK
  /\ RetireStampIsMaxWhenEnabled
  /\ ReleaseNeverAhead
  /\ ReleasedStrictlyBehind
  /\ CpuEpochNeverAhead
  /\ ReaderEpochNeverAhead
  /\ HolderEpochBoundedByRetire
  /\ HoldsImpliesActive
  /\ ReleaseBelowActiveReaderEpoch
  /\ Safety

THEOREM InitImpliesFixedInv ==
  \* Purpose: establish the strengthened invariant initially (fixed config).
  \* Needed: base case for the PTL invariant proof.
  ASSUME
    FixedAssumptions
  PROVE Init => FixedInv
PROOF
  BY DEF FixedAssumptions, FixedInv,
        CfgAssumptions,
      Init, TypeOK, RetireStampIsMaxWhenEnabled, ReleaseNeverAhead, ReleasedStrictlyBehind,
        CpuEpochNeverAhead, ReaderEpochNeverAhead, HolderEpochBoundedByRetire,
        HoldsImpliesActive, ReleaseBelowActiveReaderEpoch,
        ActiveCPUs,
        Safety,
        CPUS, ObjStates, Max2

THEOREM FixedInvPreservedByNext ==
  \* Purpose: show the strengthened invariant is preserved by Next.
  \* Needed: inductive step for the PTL invariant proof (non-stuttering case).
  ASSUME
    FixedAssumptions
  PROVE FixedInv /\ Next => FixedInv'
PROOF
  <1>1. FixedInv /\ Next => TypeOK'
    BY TypeOKPreservedByNext DEF FixedAssumptions, FixedInv
  <1>2. FixedInv /\ Next => RetireStampIsMaxWhenEnabled'
    BY RetireStampIsMaxWhenEnabledPreservedByNext DEF FixedAssumptions, FixedInv
  <1>3. FixedInv /\ Next => ReleaseNeverAhead'
    BY ReleaseNeverAheadPreservedByNext DEF FixedAssumptions, FixedInv
  <1>4. FixedInv /\ Next => ReleasedStrictlyBehind'
    BY ReleasedStrictlyBehindPreservedByNext DEF FixedAssumptions, FixedInv
  <1>5. FixedInv /\ Next => CpuEpochNeverAhead'
    BY CpuEpochNeverAheadPreservedByNext DEF FixedAssumptions, FixedInv
  <1>6. FixedInv /\ Next => ReaderEpochNeverAhead'
    BY ReaderEpochNeverAheadPreservedByNext DEF FixedAssumptions, FixedInv
  <1>7. FixedInv /\ Next => HolderEpochBoundedByRetire'
    BY HolderEpochBoundedByRetirePreservedByNext DEF FixedAssumptions, FixedInv
  <1>8. FixedInv /\ Next => HoldsImpliesActive'
    BY HoldsImpliesActivePreservedByNext DEF FixedAssumptions, FixedInv
  <1>9. FixedInv /\ Next => ReleaseBelowActiveReaderEpoch'
    BY ReleaseBelowActiveReaderEpochPreservedByNext DEF FixedAssumptions, FixedInv
  <1>10. FixedInv /\ Next => Safety'
    BY SafetyPreservedByNext DEF FixedAssumptions, FixedInv
  <1> QED
    BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8, <1>9, <1>10
       DEF FixedAssumptions, FixedInv

LEMMA NextFixedInv ==
  \* Purpose: lift preservation from Next to [Next]_vars by handling stuttering (UNCHANGED vars).
  \* Needed: PTL expects the step lemma over [Next]_vars.
  ASSUME
    FixedAssumptions
  PROVE FixedInv /\ [Next]_vars => FixedInv'
PROOF
  <1>1. FixedInv /\ Next => FixedInv'
    BY FixedInvPreservedByNext DEF FixedAssumptions

  <1>2. FixedInv /\ UNCHANGED vars => FixedInv'
  PROOF
    <2>1. FixedInv /\ UNCHANGED vars => TypeOK'
      BY DEF FixedInv, TypeOK, vars
    <2>2. FixedInv /\ UNCHANGED vars => RetireStampIsMaxWhenEnabled'
      BY DEF FixedInv, RetireStampIsMaxWhenEnabled, vars, Max2
    <2>3. FixedInv /\ UNCHANGED vars => ReleaseNeverAhead'
      BY DEF FixedInv, ReleaseNeverAhead, vars
    <2>4. FixedInv /\ UNCHANGED vars => ReleasedStrictlyBehind'
      BY DEF FixedInv, ReleasedStrictlyBehind, vars
    <2>5. FixedInv /\ UNCHANGED vars => CpuEpochNeverAhead'
      BY DEF FixedInv, CpuEpochNeverAhead, vars
    <2>6. FixedInv /\ UNCHANGED vars => ReaderEpochNeverAhead'
      BY DEF FixedInv, ReaderEpochNeverAhead, vars
    <2>7. FixedInv /\ UNCHANGED vars => HolderEpochBoundedByRetire'
      BY DEF FixedInv, HolderEpochBoundedByRetire, vars
    <2>8. FixedInv /\ UNCHANGED vars => HoldsImpliesActive'
      BY DEF FixedInv, HoldsImpliesActive, vars
    <2>9. FixedInv /\ UNCHANGED vars => ReleaseBelowActiveReaderEpoch'
      BY DEF FixedInv, ReleaseBelowActiveReaderEpoch, ActiveCPUs, vars
    <2>10. FixedInv /\ UNCHANGED vars => Safety'
      BY DEF FixedInv, Safety, vars
    <2> QED
      BY <2>1, <2>2, <2>3, <2>4, <2>5, <2>6, <2>7, <2>8, <2>9, <2>10
         DEF FixedInv

  <1> QED
    BY <1>1, <1>2

THEOREM FixedInvInvariant ==
  \* Purpose: conclude the temporal invariant: Spec => []FixedInv (and thus []Safety).
  \* Needed: this is the final theorem establishing always-safe for the fixed configuration.
  ASSUME
    FixedAssumptions
  PROVE Spec => []FixedInv
PROOF
  BY InitImpliesFixedInv,
     NextFixedInv,
     PTL DEF Spec

=============================================================================

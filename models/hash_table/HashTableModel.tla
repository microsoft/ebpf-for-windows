\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

---- MODULE HashTableModel ----
EXTENDS Naturals, FiniteSets, TLC

(*****************************************************************
This is a bounded, executable TLA+ model of the key concurrency and
lifetime aspects of libs/runtime/ebpf_hash_table.c.

High-level intent:
- Writers replace an immutable bucket by swapping a pointer.
- Readers take a snapshot of the bucket pointer and then read entries.
- Old buckets and old values are "retired" and later "reclaimed" via a
  simplified epoch-based reclamation scheme.

The model checks a core safety property:
- While a reader is in an epoch, it must never observe a reclaimed
  (Freed) bucket/value it is using.

This is NOT a full linearizability model of all APIs (iterate/next_key,
notifications, allocator failures, etc.). See CONFORMANCE.md.
*****************************************************************)

CONSTANTS
  CPUs,              \* Finite set of reader CPUs/threads.
  Keys,              \* Finite set of keys.
  Values,            \* Finite set of values.
  BucketIds,         \* Finite set of bucket indices.
  ObjIds,            \* Finite set of value-object identifiers.
  BucketObjs,        \* Finite set of bucket-object identifiers.
  MaxEntries,        \* Nat, max #keys allowed in table.
  MaxEpoch,          \* Nat, upper bound to keep TLC finite.

  ReadersUsePublishedEpoch,       \* BOOLEAN
  RetireStampUsesPublishedEpoch,  \* BOOLEAN
  AllowUseAfterExit               \* BOOLEAN

ASSUME MaxEntries \in Nat
ASSUME MaxEpoch \in Nat
ASSUME ReadersUsePublishedEpoch \in BOOLEAN
ASSUME RetireStampUsesPublishedEpoch \in BOOLEAN
ASSUME AllowUseAfterExit \in BOOLEAN

ObjStates == {"Unused", "Live", "Retired", "Freed"}

(*****************************************************************
Helpers
*****************************************************************)

Max2(a, b) == IF a >= b THEN a ELSE b

MinSet(S) == CHOOSE m \in S : \A x \in S : m <= x

StampEpoch(published_epoch) ==
  IF RetireStampUsesPublishedEpoch
  THEN published_epoch
  ELSE IF published_epoch = 0 THEN 0 ELSE published_epoch - 1

EnterEpochValue(published_epoch) ==
  IF ReadersUsePublishedEpoch
  THEN published_epoch
  ELSE IF published_epoch = 0 THEN 0 ELSE published_epoch - 1

ActiveEpochs(cpu_epoch) ==
  {e \in 0..MaxEpoch : (e # 0) /\ (\E c \in CPUs : cpu_epoch[c] = e)}

\* Map a key to a bucket index.
\* Configs typically use a single bucket, making this deterministic.
BucketOfKey(k) == CHOOSE b \in BucketIds : TRUE

BucketKeyCount(bucketPtr, bucketContents) ==
  Cardinality({k \in Keys : LET b == BucketOfKey(k) IN
      /\ bucketPtr[b] # 0
      /\ bucketContents[bucketPtr[b]][k] # 0})

(*****************************************************************
State
*****************************************************************)

VARIABLES
  \* Epoch state.
  published_epoch,
  released_epoch,
  cpu_epoch,

  \* Heap objects.
  obj_state,
  obj_key,
  obj_val,
  obj_freed_epoch,

  bucket_state,
  bucket_contents,
  bucket_freed_epoch,
  bucket_ptr,

  \* Reader local state.
  reader_key,
  snapshot_bucket,
  held_bucket,
  held_obj,

  \* Error latch.
  bad

TypeOK ==
  /\ published_epoch \in Nat
  /\ released_epoch \in Nat
  /\ cpu_epoch \in [CPUs -> Nat]

  /\ obj_state \in [ObjIds -> ObjStates]
  /\ obj_key \in [ObjIds -> Keys]
  /\ obj_val \in [ObjIds -> Values]
  /\ obj_freed_epoch \in [ObjIds -> Nat]

  /\ bucket_state \in [BucketObjs -> ObjStates]
  /\ bucket_contents \in [BucketObjs -> [Keys -> ObjIds \cup {0}]]
  /\ bucket_freed_epoch \in [BucketObjs -> Nat]
  /\ bucket_ptr \in [BucketIds -> BucketObjs \cup {0}]

  /\ reader_key \in [CPUs -> Keys]
  /\ snapshot_bucket \in [CPUs -> BucketObjs \cup {0}]
  /\ held_bucket \in [CPUs -> BucketObjs \cup {0}]
  /\ held_obj \in [CPUs -> ObjIds \cup {0}]

  /\ bad \in BOOLEAN

BucketContentsWellFormed ==
  \A bo \in BucketObjs :
    \A k \in Keys :
      LET o == bucket_contents[bo][k] IN
        o = 0 \/ (o \in ObjIds /\ obj_key[o] = k)

BucketPtrPointsToLiveOrEmpty ==
  \A b \in BucketIds : bucket_ptr[b] = 0 \/ bucket_state[bucket_ptr[b]] = "Live"

NoFreedBeforeRetired ==
  \A o \in ObjIds : (obj_state[o] = "Freed") => (obj_freed_epoch[o] <= released_epoch)


(*****************************************************************
Initialization
*****************************************************************)

Init ==
  /\ published_epoch = 1
  /\ released_epoch = 0
  /\ cpu_epoch = [c \in CPUs |-> 0]

  /\ obj_state = [o \in ObjIds |-> "Unused"]
  /\ obj_key = [o \in ObjIds |-> CHOOSE k \in Keys : TRUE]
  /\ obj_val = [o \in ObjIds |-> CHOOSE v \in Values : TRUE]
  /\ obj_freed_epoch = [o \in ObjIds |-> 0]

  /\ bucket_state = [bo \in BucketObjs |-> "Unused"]
  /\ bucket_contents = [bo \in BucketObjs |-> [k \in Keys |-> 0]]
  /\ bucket_freed_epoch = [bo \in BucketObjs |-> 0]
  /\ bucket_ptr = [b \in BucketIds |-> 0]

  /\ reader_key = [c \in CPUs |-> CHOOSE k \in Keys : TRUE]
  /\ snapshot_bucket = [c \in CPUs |-> 0]
  /\ held_bucket = [c \in CPUs |-> 0]
  /\ held_obj = [c \in CPUs |-> 0]

  /\ bad = FALSE

(*****************************************************************
Reader steps (modeling ebpf_hash_table_find snapshot + dereference)
*****************************************************************)

ReaderEnter(c) ==
  /\ cpu_epoch[c] = 0
  /\ cpu_epoch' = [cpu_epoch EXCEPT ![c] = EnterEpochValue(published_epoch)]
  /\ UNCHANGED <<published_epoch, released_epoch,
                obj_state, obj_key, obj_val, obj_freed_epoch,
                bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                reader_key, snapshot_bucket, held_bucket, held_obj,
                bad>>

ReaderExit(c) ==
  /\ cpu_epoch[c] # 0
  /\ cpu_epoch' = [cpu_epoch EXCEPT ![c] = 0]
  /\ IF AllowUseAfterExit
     THEN UNCHANGED <<snapshot_bucket, held_bucket, held_obj>>
     ELSE /\ snapshot_bucket' = [snapshot_bucket EXCEPT ![c] = 0]
          /\ held_bucket' = [held_bucket EXCEPT ![c] = 0]
          /\ held_obj' = [held_obj EXCEPT ![c] = 0]
  /\ UNCHANGED <<published_epoch, released_epoch,
                obj_state, obj_key, obj_val, obj_freed_epoch,
                bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                reader_key,
                bad>>

ReaderBeginFind(c, k) ==
  /\ cpu_epoch[c] # 0
  /\ reader_key' = [reader_key EXCEPT ![c] = k]
  /\ LET b == BucketOfKey(k) IN
       snapshot_bucket' = [snapshot_bucket EXCEPT ![c] = bucket_ptr[b]]
  /\ UNCHANGED <<published_epoch, released_epoch, cpu_epoch,
                obj_state, obj_key, obj_val, obj_freed_epoch,
                bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                held_bucket, held_obj,
                bad>>

ReaderFinishFind(c) ==
  /\ cpu_epoch[c] # 0
  /\ LET bo == snapshot_bucket[c]
         k  == reader_key[c]
         o  == IF bo = 0 THEN 0 ELSE bucket_contents[bo][k]
     IN
     /\ held_bucket' = [held_bucket EXCEPT ![c] = bo]
     /\ held_obj' = [held_obj EXCEPT ![c] = o]
     /\ bad' = bad \/
         ((bo # 0) /\ bucket_state[bo] = "Freed") \/
         ((o  # 0) /\ obj_state[o] = "Freed")
  /\ UNCHANGED <<published_epoch, released_epoch, cpu_epoch,
                obj_state, obj_key, obj_val, obj_freed_epoch,
                bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                reader_key, snapshot_bucket>>

ReaderUseHeld(c) ==
  /\ held_obj[c] # 0
  /\ bad' = bad \/
      (held_bucket[c] # 0 /\ bucket_state[held_bucket[c]] = "Freed") \/
      (obj_state[held_obj[c]] = "Freed")
  /\ UNCHANGED <<published_epoch, released_epoch, cpu_epoch,
                obj_state, obj_key, obj_val, obj_freed_epoch,
                bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                reader_key, snapshot_bucket, held_bucket, held_obj>>

(*****************************************************************
Writer step (modeling immutable bucket replacement + retiring old)
*****************************************************************)

AllocateUnusedObj(o) == obj_state[o] = "Unused"
AllocateUnusedBucket(bo) == bucket_state[bo] = "Unused"

HasUnusedObj == \E o \in ObjIds : AllocateUnusedObj(o)
HasUnusedBucket == \E bo \in BucketObjs : AllocateUnusedBucket(bo)

ChooseUnusedObj == CHOOSE o \in ObjIds : AllocateUnusedObj(o)
ChooseUnusedBucket == CHOOSE bo \in BucketObjs : AllocateUnusedBucket(bo)

RetiredObjs == {o \in ObjIds : obj_state[o] = "Retired" /\ obj_freed_epoch[o] <= released_epoch}
RetiredBuckets == {bo \in BucketObjs : bucket_state[bo] = "Retired" /\ bucket_freed_epoch[bo] <= released_epoch}

WriterUpsert(k, v) ==
  /\ HasUnusedObj
  /\ HasUnusedBucket
  /\ LET new_obj == ChooseUnusedObj
         new_bo  == ChooseUnusedBucket
         b == BucketOfKey(k)
         old_bo == bucket_ptr[b]
         old_obj == IF old_bo = 0 THEN 0 ELSE bucket_contents[old_bo][k]
         key_is_new == (old_obj = 0)
         can_insert == (BucketKeyCount(bucket_ptr, bucket_contents) < MaxEntries)
     IN
     /\ (\lnot key_is_new) \/ can_insert

     /\ LET
           base_obj_state == [obj_state EXCEPT ![new_obj] = "Live"]
           base_obj_freed == [obj_freed_epoch EXCEPT ![new_obj] = 0]
           final_obj_state ==
             IF old_obj = 0 THEN base_obj_state ELSE [base_obj_state EXCEPT ![old_obj] = "Retired"]
           final_obj_freed ==
             IF old_obj = 0
             THEN base_obj_freed
             ELSE [base_obj_freed EXCEPT ![old_obj] = StampEpoch(published_epoch)]

           base_bucket_state == [bucket_state EXCEPT ![new_bo] = "Live"]
           base_bucket_freed == [bucket_freed_epoch EXCEPT ![new_bo] = 0]
           final_bucket_state ==
             IF old_bo = 0 THEN base_bucket_state ELSE [base_bucket_state EXCEPT ![old_bo] = "Retired"]
           final_bucket_freed ==
             IF old_bo = 0
             THEN base_bucket_freed
             ELSE [base_bucket_freed EXCEPT ![old_bo] = StampEpoch(published_epoch)]
         IN
         /\ obj_state' = final_obj_state
         /\ obj_key' = [obj_key EXCEPT ![new_obj] = k]
         /\ obj_val' = [obj_val EXCEPT ![new_obj] = v]
         /\ obj_freed_epoch' = final_obj_freed

         /\ bucket_state' = final_bucket_state
         /\ bucket_freed_epoch' = final_bucket_freed
         /\ bucket_contents' =
              [bucket_contents EXCEPT ![new_bo] =
                IF old_bo = 0
                THEN [x \in Keys |-> IF x = k THEN new_obj ELSE 0]
                ELSE [x \in Keys |-> IF x = k THEN new_obj ELSE bucket_contents[old_bo][x]]]

         /\ bucket_ptr' = [bucket_ptr EXCEPT ![b] = new_bo]

         /\ UNCHANGED <<published_epoch, released_epoch, cpu_epoch,
                       reader_key, snapshot_bucket, held_bucket, held_obj,
                       bad>>

WriterDelete(k) ==
  /\ HasUnusedBucket
  /\ LET new_bo == ChooseUnusedBucket
         b == BucketOfKey(k)
         old_bo == bucket_ptr[b]
     IN
     /\ old_bo # 0
     /\ LET old_obj == bucket_contents[old_bo][k] IN
        /\ old_obj # 0

          \* New bucket is copy of old, with key removed.
          /\ bucket_state' = [bucket_state EXCEPT ![new_bo] = "Live"]
          /\ bucket_freed_epoch' = [bucket_freed_epoch EXCEPT ![new_bo] = 0]
          /\ bucket_contents' =
               [bucket_contents EXCEPT ![new_bo] =
                 [x \in Keys |-> IF x = k THEN 0 ELSE bucket_contents[old_bo][x]]]
          /\ bucket_ptr' = [bucket_ptr EXCEPT ![b] = new_bo]

          \* Retire old bucket and old value.
          /\ bucket_state' = [bucket_state' EXCEPT ![old_bo] = "Retired"]
          /\ bucket_freed_epoch' = [bucket_freed_epoch' EXCEPT ![old_bo] = StampEpoch(published_epoch)]

          /\ obj_state' = [obj_state EXCEPT ![old_obj] = "Retired"]
          /\ obj_freed_epoch' = [obj_freed_epoch EXCEPT ![old_obj] = StampEpoch(published_epoch)]

          /\ UNCHANGED <<published_epoch, released_epoch, cpu_epoch,
                        obj_key, obj_val,
                        reader_key, snapshot_bucket, held_bucket, held_obj,
                        bad>>

(*****************************************************************
Epoch progression + reclamation
*****************************************************************)

AdvancePublishedEpoch ==
  /\ published_epoch < MaxEpoch
  /\ published_epoch' = published_epoch + 1
  /\ UNCHANGED <<released_epoch, cpu_epoch,
                obj_state, obj_key, obj_val, obj_freed_epoch,
                bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                reader_key, snapshot_bucket, held_bucket, held_obj,
                bad>>

ComputeReleasedEpoch ==
  /\ LET active == ActiveEpochs(cpu_epoch)
         candidate ==
           IF active = {}
           THEN IF published_epoch = 0 THEN 0 ELSE published_epoch - 1
           ELSE LET m == MinSet(active) IN IF m = 0 THEN 0 ELSE m - 1
     IN
     released_epoch' = Max2(released_epoch, candidate)
  /\ UNCHANGED <<published_epoch, cpu_epoch,
                obj_state, obj_key, obj_val, obj_freed_epoch,
                bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                reader_key, snapshot_bucket, held_bucket, held_obj,
                bad>>

ReclaimOne ==
  \/ /\ RetiredObjs # {}
    /\ LET o == CHOOSE x \in RetiredObjs : TRUE IN
      /\ obj_state' = [obj_state EXCEPT ![o] = "Freed"]
      /\ UNCHANGED <<published_epoch, released_epoch, cpu_epoch,
               obj_key, obj_val, obj_freed_epoch,
               bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
               reader_key, snapshot_bucket, held_bucket, held_obj,
               bad>>
  \/ /\ RetiredBuckets # {}
    /\ LET bo == CHOOSE x \in RetiredBuckets : TRUE IN
      /\ bucket_state' = [bucket_state EXCEPT ![bo] = "Freed"]
      /\ UNCHANGED <<published_epoch, released_epoch, cpu_epoch,
               obj_state, obj_key, obj_val, obj_freed_epoch,
               bucket_contents, bucket_freed_epoch, bucket_ptr,
               reader_key, snapshot_bucket, held_bucket, held_obj,
               bad>>

(*****************************************************************
Next-state relation
*****************************************************************)

Next ==
  \/ \E c \in CPUs : ReaderEnter(c)
  \/ \E c \in CPUs : ReaderExit(c)
  \/ \E c \in CPUs : \E k \in Keys : ReaderBeginFind(c, k)
  \/ \E c \in CPUs : ReaderFinishFind(c)
  \/ \E c \in CPUs : ReaderUseHeld(c)

  \/ \E k \in Keys : \E v \in Values : WriterUpsert(k, v)
  \/ \E k \in Keys : WriterDelete(k)

  \/ AdvancePublishedEpoch
  \/ ComputeReleasedEpoch
  \/ ReclaimOne

(*****************************************************************
Invariants
*****************************************************************)

Safety ==
  /\ ~bad
  /\ released_epoch <= published_epoch

  \* While in an epoch, held objects/buckets must not be reclaimed.
  /\ \A c \in CPUs :
       (cpu_epoch[c] # 0 /\ held_obj[c] # 0) => obj_state[held_obj[c]] # "Freed"
  /\ \A c \in CPUs :
       (cpu_epoch[c] # 0 /\ held_bucket[c] # 0) => bucket_state[held_bucket[c]] # "Freed"

Spec == Init /\ [][Next]_<<published_epoch, released_epoch, cpu_epoch,
                   obj_state, obj_key, obj_val, obj_freed_epoch,
                   bucket_state, bucket_contents, bucket_freed_epoch, bucket_ptr,
                   reader_key, snapshot_bucket, held_bucket, held_obj,
                   bad>>

====

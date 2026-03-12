\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

---- MODULE RingBufferModel ----
EXTENDS Naturals, Sequences, TLC

(*****************************************************************
Bounded, executable TLA+ model of the core ring-buffer behaviors
that are exposed via libs/execution_context/ebpf_maps.c.

Focus:
- Producer reserves space (publishes producer offset).
- Producer submits or discards a record (clears lock bit).
- Consumer reads the next record in order, skipping discarded records.
- Consumer returns buffers by advancing consumer offset.
- Async query is completed when producer has advanced beyond consumer.

This model is intentionally small and does not model:
- actual byte contents, alignment details, page_offset, or mmap pages
- kernel wait handle semantics
- multiple producers / full reserve loop serialization

See CONFORMANCE.md for mapping to C sources.
*****************************************************************)

CONSTANTS
  Capacity,               \* Nat: ring capacity in abstract "units".
  Sizes,                  \* Finite set of Nat record sizes (in units).
  MaxOffset,              \* Nat: max reserve/producer offset to keep TLC finite.
  MaxLiveRecords,         \* Nat: bound on number of live (unreturned) records.
  BuggyPublishBeforeLock  \* BOOLEAN: if TRUE, allow producer to publish offset before locking record.

ASSUME Capacity \in Nat
ASSUME MaxOffset \in Nat
ASSUME MaxLiveRecords \in Nat
ASSUME Sizes \subseteq Nat
ASSUME \A s \in Sizes: s > 0

States == {"Uninit", "Locked", "Submitted", "Discarded"}

Record == [size: Sizes, state: States]

VARIABLES
  consumer,        \* Consumer offset (monotonic).
  producer,        \* Published producer offset.
  reserve,         \* Producer reserve offset (end of last reserved record).
  liveSize,        \* reserve - consumer
  records,         \* Sequence of live records in order.
  held,            \* [active, size, state] representing a currently "read" record.
  asyncPending,    \* Whether an async query is queued.
  asyncCompleted,  \* Sticky flag: an async query completed at least once.
  asyncResult,     \* [consumer, producer] captured on completion.
  tripWire         \* Sticky: TRUE after first async query is queued.

Held == [active: BOOLEAN, size: 0..MaxOffset, state: States]

TypeOK ==
  /\ consumer \in 0..MaxOffset
  /\ producer \in 0..MaxOffset
  /\ reserve \in 0..MaxOffset
  /\ liveSize \in 0..Capacity
  /\ records \in Seq(Record)
  /\ Len(records) \leq MaxLiveRecords
  /\ held \in Held
  /\ asyncPending \in BOOLEAN
  /\ asyncCompleted \in BOOLEAN
  /\ asyncResult \in [consumer: 0..MaxOffset, producer: 0..MaxOffset]
  /\ tripWire \in BOOLEAN

OffsetsConsistent ==
  /\ consumer \leq producer
  /\ producer \leq reserve
  /\ reserve = consumer + liveSize
  /\ liveSize \leq Capacity

Safety ==
  \* Consumer must never "hold" an unsubmitted record.
  held.active => held.state = "Submitted"

Init ==
  /\ consumer = 0
  /\ producer = 0
  /\ reserve = 0
  /\ liveSize = 0
  /\ records = <<>>
  /\ held = [active |-> FALSE, size |-> 0, state |-> "Locked"]
  /\ asyncPending = FALSE
  /\ asyncCompleted = FALSE
  /\ asyncResult = [consumer |-> 0, producer |-> 0]
  /\ tripWire = FALSE

CanReserve(sz) ==
  /\ sz \in Sizes
  /\ liveSize + sz \leq Capacity
  /\ reserve + sz \leq MaxOffset
  /\ Len(records) < MaxLiveRecords

ProducerReserve ==
  \E sz \in Sizes:
    /\ CanReserve(sz)
    /\ ~BuggyPublishBeforeLock
    /\ records' = Append(records, [size |-> sz, state |-> "Locked"])
    /\ reserve' = reserve + sz
    /\ producer' = reserve'
    /\ liveSize' = liveSize + sz
    /\ UNCHANGED <<consumer, held, asyncPending, asyncCompleted, asyncResult, tripWire>>

ProducerReserveBuggyPublish ==
  \E sz \in Sizes:
    /\ CanReserve(sz)
    /\ BuggyPublishBeforeLock
    \* Publish the offsets before the record is locked/initialized.
    /\ records' = Append(records, [size |-> sz, state |-> "Uninit"])
    /\ reserve' = reserve + sz
    /\ producer' = reserve'
    /\ liveSize' = liveSize + sz
    /\ UNCHANGED <<consumer, held, asyncPending, asyncCompleted, asyncResult, tripWire>>

ProducerFinalizeLock ==
  /\ BuggyPublishBeforeLock
  /\ Len(records) > 0
  /\ Head(records).state = "Uninit"
  /\ records' = << [size |-> Head(records).size, state |-> "Locked"] >> \o Tail(records)
  /\ UNCHANGED <<consumer, producer, reserve, liveSize, held, asyncPending, asyncCompleted, asyncResult, tripWire>>

ProducerSubmit ==
  /\ Len(records) > 0
  /\ Head(records).state = "Locked"
  /\ records' = << [size |-> Head(records).size, state |-> "Submitted"] >> \o Tail(records)
  /\ UNCHANGED <<consumer, producer, reserve, liveSize, held, asyncPending, asyncCompleted, asyncResult, tripWire>>

ProducerDiscard ==
  /\ Len(records) > 0
  /\ Head(records).state = "Locked"
  /\ records' = << [size |-> Head(records).size, state |-> "Discarded"] >> \o Tail(records)
  /\ UNCHANGED <<consumer, producer, reserve, liveSize, held, asyncPending, asyncCompleted, asyncResult, tripWire>>

ConsumerNext ==
  /\ held.active = FALSE
  /\ Len(records) > 0
  /\ IF Head(records).state = "Locked" THEN
       \* Cannot pass a locked record.
       UNCHANGED <<consumer, producer, reserve, liveSize, records, held, asyncPending, asyncCompleted, asyncResult, tripWire>>
     ELSE IF Head(records).state = "Discarded" THEN
       \* Skip discarded records and immediately return their space.
       /\ consumer' = consumer + Head(records).size
       /\ liveSize' = liveSize - Head(records).size
       /\ records' = Tail(records)
       /\ UNCHANGED <<producer, reserve, held, asyncPending, asyncCompleted, asyncResult, tripWire>>
     ELSE
       \* Any unlocked record is treated as consumable.
       /\ held' = [active |-> TRUE, size |-> Head(records).size, state |-> Head(records).state]
       /\ UNCHANGED <<consumer, producer, reserve, liveSize, records, asyncPending, asyncCompleted, asyncResult, tripWire>>

ConsumerReturn ==
  /\ held.active = TRUE
  /\ Len(records) > 0
  /\ Head(records).size = held.size
  /\ Head(records).state = held.state
  /\ consumer' = consumer + held.size
  /\ liveSize' = liveSize - held.size
  /\ records' = Tail(records)
  /\ held' = [active |-> FALSE, size |-> 0, state |-> "Locked"]
  /\ UNCHANGED <<producer, reserve, asyncPending, asyncCompleted, asyncResult, tripWire>>

AsyncQuery ==
  /\ asyncPending = FALSE
  /\ asyncPending' = TRUE
  /\ tripWire' = TRUE
  /\ UNCHANGED <<consumer, producer, reserve, liveSize, records, held, asyncCompleted, asyncResult>>

AsyncCancel ==
  /\ asyncPending = TRUE
  /\ asyncPending' = FALSE
  /\ UNCHANGED <<consumer, producer, reserve, liveSize, records, held, asyncCompleted, asyncResult, tripWire>>

AsyncComplete ==
  /\ asyncPending = TRUE
  /\ producer > consumer
  /\ asyncPending' = FALSE
  /\ asyncCompleted' = TRUE
  /\ asyncResult' = [consumer |-> consumer, producer |-> producer]
  /\ UNCHANGED <<consumer, producer, reserve, liveSize, records, held, tripWire>>

vars == <<consumer, producer, reserve, liveSize, records, held, asyncPending, asyncCompleted, asyncResult, tripWire>>

Next ==
  ProducerReserve
  \/ ProducerReserveBuggyPublish
  \/ ProducerFinalizeLock
  \/ ProducerSubmit
  \/ ProducerDiscard
  \/ ConsumerNext
  \/ ConsumerReturn
  \/ AsyncQuery
  \/ AsyncCancel
  \/ AsyncComplete

Spec == Init /\ [][Next]_vars

====

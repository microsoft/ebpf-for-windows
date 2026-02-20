\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

---- MODULE Counter ----
EXTENDS Naturals

(***************************************************************************)
(* A very small TLA+ model intended for beginners.                         *)
(*                                                                         *)
(* State: a single integer variable x.                                     *)
(* Behavior: on each step, x either increments or decrements, but never    *)
(* leaves the range [Min, Max].                                            *)
(***************************************************************************)

CONSTANTS Min, Max
VARIABLE x

TypeOK == x \in Min..Max

Init == x = Min

Inc == /\ x < Max
       /\ x' = x + 1

Dec == /\ x > Min
       /\ x' = x - 1

Next == Inc \/ Dec

Spec == Init /\ [][Next]_<<x>>

Invariant == TypeOK

====
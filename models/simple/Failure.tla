\* Copyright (c) eBPF for Windows contributors
\* SPDX-License-Identifier: MIT

---- MODULE Failure ----
EXTENDS Naturals

(***************************************************************************)
(* A deliberately broken version of the simple counter model.              *)
(*                                                                         *)
(* It violates the invariant by allowing x to increment past Max.          *)
(* TLC should find an invariant violation and produce a counterexample.    *)
(***************************************************************************)

CONSTANTS Min, Max
VARIABLE x

TypeOK == x \in Min..Max

Init == x = Min

\* BUG: no guard to stop x from exceeding Max.
Inc == x' = x + 1

\* Keep it minimal: only increments.
Next == Inc

Spec == Init /\ [][Next]_<<x>>

Invariant == TypeOK

====

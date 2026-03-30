<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Epoch Module — Consistency Audit Report

## 1. Executive Summary

This audit examines the three specification documents extracted for the `ebpf_epoch`
module: **requirements.md** (57 requirements), **design.md** (10 design sections),
and **validation.md** (17 test cases, 10 coverage gaps).

**Overall assessment**: The specification set has **good coverage** with
**moderate traceability gaps**. The requirements and design documents are
internally strong, but the three documents were drafted independently, leading
to REQ-ID mismatches between the requirements and validation documents, and the
design document defining its own parallel requirement IDs instead of referencing
the canonical ones. No critical semantic conflicts were found.

**Verdict: REVISE** — specific traceability issues must be resolved before the
baseline is finalized.

## 2. Problem Statement

The `ebpf_epoch` module had no formal specification documents. Three documents
were extracted from the codebase in a single pass:

- **requirements.md** — 57 requirements across 9 categories
- **design.md** — architecture, detailed design, tradeoff analysis
- **validation.md** — 17 test cases (6 existing, 11 proposed), coverage analysis

This audit verifies forward/backward traceability, cross-document consistency,
and acceptance criteria coverage per the traceability-audit protocol.

## 3. Investigation Scope

### 3.1 Documents Examined

| Document | Location | Size |
|----------|----------|------|
| Requirements | `specs/epoch/requirements.md` | 731 lines |
| Design | `specs/epoch/design.md` | 571 lines |
| Validation | `specs/epoch/validation.md` | 696 lines |

### 3.2 Source Files Consulted

- `libs/runtime/ebpf_epoch.h` (141 lines)
- `libs/runtime/ebpf_epoch.c` (1062 lines)
- `libs/runtime/unit/platform_unit_test.cpp` (epoch-related tests, lines 97–1244)

### 3.3 Method

1. Extracted all REQ-IDs from requirements.md.
2. Searched design.md for REQ-ID references.
3. Extracted all REQ-IDs and TC-IDs from validation.md traceability matrices.
4. Cross-referenced for forward and backward traceability.
5. Checked terminology, assumptions, and scope alignment.

## 4. Findings

### F-001: Design document uses parallel requirement IDs [D3 — Orphaned Design Decision]

**Severity**: Medium

**Evidence**: The design document (§2) states *"No formal requirement-ID document
(REQ-\*) was found in the repository"* and defines 8 ad-hoc "inferred" requirement
IDs (REQ-LIFE-001 through REQ-ECS-005) that overlap with but differ from the
canonical IDs in the requirements document.

For example:
- Design's `REQ-LIFE-001` = "Memory freed via `ebpf_epoch_free` must not be reclaimed
  while any reader is in an epoch" (maps to requirements' `REQ-ROB-007`)
- Design's `REQ-ECS-001` = "Epoch state must be per-CPU" (maps to requirements'
  `REQ-TS-001` / `REQ-TS-002`)

**Impact**: A reader cross-referencing design decisions to requirements will find
conflicting ID assignments.

**Recommended resolution**: Replace the design document's §2 table with references
to the canonical REQ-IDs from requirements.md.

---

### F-002: Validation plan references REQ-IDs not in requirements document [D4 — Orphaned Test Case]

**Severity**: Medium

**Evidence**: The validation document's traceability matrices reference the following
REQ-IDs that do not exist in the requirements document:

| Phantom REQ-ID | Used in Validation | Nearest Match in Requirements |
|----------------|-------------------|-------------------------------|
| REQ-LIFE-004 | TC-LIFE-003 | Not present (requirements has REQ-LIFE-001..006 but REQ-LIFE-004 is about return values, not free-list draining) |
| REQ-DIAG-002 | §4.7 RTM | Not present (requirements has only REQ-DIAG-001) |
| REQ-ROB-004 | TC-LIFE-002 | Requirements' REQ-ROB-004 is about timer delay, not init failure |

**Impact**: Test cases appear traced but reference nonexistent or mismatched
requirements, creating a false sense of coverage.

**Recommended resolution**: Align the validation plan's REQ-IDs with the canonical
requirements document. Add missing requirements if the validation plan identified
genuine gaps.

---

### F-003: Requirements with no test coverage in validation plan [D1 — Untested Requirement]

**Severity**: Medium

**Evidence**: The following requirements from the requirements document have no
corresponding TC-ID in the validation plan's traceability matrices:

| REQ-ID | Summary | Status |
|--------|---------|--------|
| REQ-LIFE-005 | Complete rundown sequence (6-step shutdown) | Not traced |
| REQ-LIFE-006 | Rundown protection for work items | Not traced |
| REQ-ECS-005 | Fail-fast on cross-CPU exit at DISPATCH | Not traced |
| REQ-ECS-006 | Arm timer after epoch exit | Not traced |
| REQ-MEM-008 | free_cache_aligned(NULL) no-op | Not traced |
| REQ-MEM-009 | Reclaim only when freed_epoch ≤ released_epoch | Partially (covered by TC-COMP-001/TC-ROB-002) |
| REQ-MEM-010 | Correct deallocation function per entry type | Not traced |
| REQ-COMP-006 | Clear timer_armed during COMMIT | Not traced |
| REQ-COMP-007 | Clear epoch_computation_in_progress on COMPLETE (timer) | Not traced |
| REQ-COMP-008 | Signal KEVENT on COMPLETE (synchronize) | Not traced |
| REQ-WI-006 | cancel_work_item frees without callback | TC-WI-002 (proposed) |
| REQ-WI-007 | cancel_work_item(NULL) no-op | Not traced |
| REQ-WI-008 | Assert not-already-scheduled on cancel | Not traced |
| REQ-SYNC-003 | Stack-allocated synchronization entry | Not traced |
| REQ-SYNC-004 | Synchronize triggers immediate PROPOSE | Not traced |
| REQ-TS-005 | Epoch computation serialized (one at a time) | Not traced |
| REQ-ROB-001 | Double-free detection (epoch_free) | Not traced |
| REQ-ROB-002 | Double-free detection (free_cache_aligned) | Not traced |
| REQ-ROB-003 | Fail-fast on corrupt entry type | Not traced |
| REQ-ROB-005 | Timer arming guard conditions | Not traced |
| REQ-ROB-006 | MAXINT64 release during terminate | Not traced |

**Count**: 21 of 57 requirements (37%) have no explicit test coverage in the
validation plan.

**Impact**: Over a third of requirements cannot be verified against test cases.
Many of these are internal mechanism requirements that are implicitly covered
by integration tests, but the traceability is not documented.

**Recommended resolution**: For each untested requirement, either:
(a) Map it to an existing test case that implicitly covers it, or
(b) Propose a new test case, or
(c) Mark as "verified by inspection" with justification.

---

### F-004: Validation plan defines requirements not in requirements document [D4 — Orphaned Test Case]

**Severity**: Low

**Evidence**: The validation plan's RTM includes `REQ-DIAG-002` ("Skipped-timer
counter tracks epoch computation contention") which has no corresponding requirement
in the requirements document. The `_ebpf_epoch_skipped_timers` counter is an
internal diagnostic variable not exposed through any public API.

**Impact**: The validation plan traces a test gap to a requirement that doesn't
exist, creating noise.

**Recommended resolution**: Either add REQ-DIAG-002 to the requirements document
(if the counter is considered part of the module's contract) or remove it from
the validation plan.

---

### F-005: Date inconsistency across documents [D5 — Assumption Drift]

**Severity**: Low

**Evidence**: The requirements and validation documents use the date `2025-07-14`
in their revision history, while the design document uses `2026-03-30`. All three
documents were created in the same extraction session (2026-03-30).

**Impact**: Cosmetic. Could confuse future reviewers about document provenance.

**Recommended resolution**: Normalize all revision history dates to `2026-03-30`.

---

### F-006: Terminology alignment — "released epoch" definition [D5 — Assumption Drift]

**Severity**: Low

**Evidence**: The requirements document (§3 Glossary) defines `released_epoch` as
*"the newest epoch whose freed items MAY safely be reclaimed"* and states it is set
to `proposed_release_epoch - 1`. The design document (§4.4) states the same
formula. However, the validation plan (§4.4 RTM, REQ-COMP-002) describes it as
*"Release epoch = min(all CPUs' thread epochs) − 1"* which is the fully reduced
formula but could be confused with the intermediate PROPOSE result.

**Impact**: Minor. A careful reader would resolve this, but the compression
could mislead.

**Recommended resolution**: Use consistent phrasing across all three documents.

---

### F-007: Design document references external spec not provided [D5 — Assumption Drift]

**Severity**: Low

**Evidence**: The design document references `docs/EpochBasedMemoryManagement.md`
and `include/ebpf_extension.h` as sources. Neither was included in the extraction
scope (the user specified only `ebpf_epoch.c`, `ebpf_epoch.h`, and
`platform_unit_test.cpp`). The requirements and validation documents correctly
stay within scope.

**Impact**: Some design claims may reference context not available for verification.

**Recommended resolution**: Either include these files in the extraction scope or
mark the relevant design claims as `[ASSUMPTION]`.

## 5. Root Cause Analysis

The findings stem from two systemic causes:

1. **Independent drafting**: The three documents were produced by separate agents
   without a shared REQ-ID registry. This caused the design document to invent
   parallel IDs and the validation document to partially diverge from the
   requirements document's ID scheme.

2. **Granularity mismatch**: The requirements document has 57 fine-grained
   requirements, while the validation document's RTM covers ~30 higher-level
   requirement groups. The remaining 21 requirements are mechanistic (timer flags,
   KEVENT signaling, fail-fast guards) that are implicitly exercised by integration
   tests but not explicitly traced.

## 6. Remediation Plan

| Priority | Finding | Action | Effort |
|----------|---------|--------|--------|
| **P1** | F-001 | Replace design §2 with canonical REQ-ID references | Small |
| **P1** | F-002 | Align validation RTM REQ-IDs with requirements.md | Small |
| **P1** | F-003 | Add traceability for 21 untested requirements (map to existing tests or mark inspection-verified) | Medium |
| **P2** | F-004 | Add REQ-DIAG-002 to requirements or remove from validation | Small |
| **P2** | F-005 | Fix dates in revision history | Trivial |
| **P2** | F-006 | Standardize "released epoch" phrasing | Small |
| **P3** | F-007 | Note out-of-scope references in design doc | Small |

## 7. Prevention

1. **Shared REQ-ID registry**: When extracting specs in parallel, establish the
   canonical REQ-ID list first (Phase 2a) and share it with the design and
   validation extraction passes.

2. **Cross-reference validation step**: Before finalizing, run a mechanical check
   that every REQ-ID in validation and design exists in the requirements document.

3. **Explicit "verified by" column**: For mechanistic requirements that are
   implicitly tested, add a "Verified by: TC-XXX (implicit)" column to prevent
   them from appearing as untested.

## 8. Open Questions

| # | Question |
|---|----------|
| 1 | Should internal mechanistic requirements (timer flags, KEVENT signaling) be split into a separate "implementation constraints" section rather than treated as testable requirements? |
| 2 | Should the design document reference `docs/EpochBasedMemoryManagement.md` content, or should that content be incorporated into the design spec directly? |
| 3 | Should `_ebpf_epoch_skipped_timers` (REQ-DIAG-002 candidate) be elevated to a formal requirement? |

**Verdict: REVISE** — The traceability gaps in F-001, F-002, and F-003 should be
addressed before proceeding to approval. No fundamental issues with the extracted
specifications were found; the corrections are alignment and traceability fixes.

## 9. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-30 | Copilot (spec-extraction) | Initial audit of extracted specification set |

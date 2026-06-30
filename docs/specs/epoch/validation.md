# Epoch Subsystem Validation

## 1. Overview
- [KNOWN] This validation draft is a **target validation plan**: it maps the extracted requirements to both existing tests and planned tests that are not yet implemented in the current scoped codebase. Evidence: the implemented/planned split in `docs\specs\epoch\validation.md:17-27,79-119`; existing test assets in `libs\runtime\unit\platform_unit_test.cpp:634-1244`, `tests\performance\platform.cpp:8-69`.
- [KNOWN] The current implemented assets are strongest for deferred-reclamation safety and weaker for lifecycle, cancellation, nested entry/exit, cross-CPU exit, and extension-facing contract enforcement. Evidence: implemented test coverage in `libs\runtime\unit\platform_unit_test.cpp:634-1244` versus API surface in `libs\runtime\ebpf_epoch.h:23-136` and extension contract in `include\ebpf_extension.h:455-489`.

## 2. Scope of Validation
- [KNOWN] In scope: runtime unit tests named `epoch_test_*` and performance probes that exercise epoch entry/exit and allocation/free paths. Evidence: `libs\runtime\unit\platform_unit_test.cpp:634-1244`, `tests\performance\platform.cpp:8-31`.
- [KNOWN] Out of scope: end-to-end uses of `ebpf_epoch_synchronize` in unrelated subsystems, and downstream consumer-specific semantics in object/program/map code. Evidence: `tests\end_to_end\netsh_test.cpp:677,887,930`, `libs\runtime\ebpf_object.c:219-257,348-355`, `libs\execution_context\ebpf_program.c:828-983`.

## 3. Test Strategy
- [KNOWN] **Unit/regression**: direct API tests validate single-thread, multi-thread, stale-item, skew-regression, and long-run stress behavior. Evidence: `libs\runtime\unit\platform_unit_test.cpp:634-1244`.
- [KNOWN] **Performance**: microbenchmarks measure epoch hot paths but do not assert pass/fail thresholds in the scoped artifacts. Evidence: `tests\performance\platform.cpp:8-31`.
- [INFERRED] **Technique**: the skew and spin tests are adversarial concurrency tests intended to turn premature reclamation into observable failures. Evidence: `libs\runtime\unit\platform_unit_test.cpp:743-748,989-993`.

## 4. Requirements Traceability Matrix
| REQ-ID | Validation coverage | TC-ID(s) | Coverage status |
|---|---|---|---|
| REQ-EPOCH-001 | Planned lifecycle coverage | TC-EPOCH-007 | Planned |
| REQ-EPOCH-002 | Existing functional use plus planned nested-contract coverage | TC-EPOCH-001, TC-EPOCH-003, TC-EPOCH-005, TC-EPOCH-006, TC-EPOCH-008 | Implemented + Planned |
| REQ-EPOCH-003 | Direct reclamation safety coverage | TC-EPOCH-001, TC-EPOCH-003, TC-EPOCH-004, TC-EPOCH-005, TC-EPOCH-006 | Implemented |
| REQ-EPOCH-004 | Direct alignment and free-path coverage | TC-EPOCH-002 | Implemented |
| REQ-EPOCH-005 | Synchronization barrier coverage | TC-EPOCH-001, TC-EPOCH-003, TC-EPOCH-005, TC-EPOCH-006 | Implemented |
| REQ-EPOCH-006 | Existing scheduled-callback timing plus planned cancel/context coverage | TC-EPOCH-005, TC-EPOCH-006, TC-EPOCH-009, TC-EPOCH-010 | Implemented + Planned |
| REQ-EPOCH-007 | Planned cross-CPU exit forwarding coverage | TC-EPOCH-011 | Planned |
| REQ-EPOCH-008 | Planned extension-facing contract coverage | TC-EPOCH-012 | Planned |
| REQ-EPOCH-009 | Free-list drain query is exercised directly | TC-EPOCH-004 | Implemented |

## 5. Test Cases
- [KNOWN] **TC-EPOCH-001 — Single epoch retirement round-trip**  
  **Linked requirements**: REQ-EPOCH-003, REQ-EPOCH-005.  
  **Level**: Unit.  
  **Evidence**: `libs\runtime\unit\platform_unit_test.cpp:634-644`.  
  **Pass/fail**: enters an epoch, retires an allocation, exits, then synchronizes without failure.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-002 — Cache-aligned epoch allocation**  
  **Linked requirements**: REQ-EPOCH-004.  
  **Level**: Unit.  
  **Evidence**: `libs\runtime\unit\platform_unit_test.cpp:646-660`.  
  **Pass/fail**: allocation is cache-line aligned, free path completes, synchronize completes.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-003 — Two-thread epoch usage**  
  **Linked requirements**: REQ-EPOCH-003, REQ-EPOCH-005.  
  **Level**: Unit/concurrency.  
  **Evidence**: `libs\runtime\unit\platform_unit_test.cpp:663-682`.  
  **Pass/fail**: both threads complete allocate/free/exit/synchronize without failure.  
  **Confidence**: Medium.

- [KNOWN] **TC-EPOCH-004 — Stale free-list draining**  
  **Linked requirements**: REQ-EPOCH-003, REQ-EPOCH-009.  
  **Level**: Unit/concurrency.  
  **Evidence**: `libs\runtime\unit\platform_unit_test.cpp:684-740`.  
  **Pass/fail**: after coordinated activity on two CPUs, both free-list queries eventually report empty.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-005 — Epoch skew reclamation hazard regression**  
  **Linked requirements**: REQ-EPOCH-003, REQ-EPOCH-006.  
  **Level**: Regression/concurrency.  
  **Evidence**: `libs\runtime\unit\platform_unit_test.cpp:743-977`.  
  **Pass/fail**: a work-item callback never fires while a reader remains active in a newer epoch; the test ends with `REQUIRE_FALSE(hazard_observed)`.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-006 — Sustained reclamation stress**  
  **Linked requirements**: REQ-EPOCH-003, REQ-EPOCH-006.  
  **Level**: Stress/concurrency.  
  **Evidence**: `libs\runtime\unit\platform_unit_test.cpp:994-1244`.  
  **Pass/fail**: scheduled callbacks are eventually invoked, thread error remains false, and callbacks do not expose reclamation bugs during sustained load.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-PERF-001 — Entry/exit and allocate/free probes**  
  **Linked requirements**: REQ-EPOCH-002, REQ-EPOCH-003.  
  **Level**: Performance/observational.  
  **Evidence**: `tests\performance\platform.cpp:8-31`.  
  **Pass/fail**: None identified in the scoped source; these are measurement probes rather than validation assertions.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-007 — Lifecycle initiate/terminate contract**  
  **Linked requirements**: REQ-EPOCH-001.  
  **Level**: Unit.  
  **Implementation status**: Planned / not yet implemented in scoped tests.  
  **Pass/fail**: successful initiation creates usable epoch state; termination is safe after initiation and is a no-op when the subsystem is already terminated.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-008 — Nested epoch entry/exit pairing**  
  **Linked requirements**: REQ-EPOCH-002.  
  **Level**: Unit/concurrency.  
  **Implementation status**: Planned / not yet implemented in scoped tests.  
  **Pass/fail**: two nested `ebpf_epoch_enter` calls with distinct state objects can be exited in matching pairs without corrupting reclamation behavior.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-009 — Work-item cancellation suppresses callback**  
  **Linked requirements**: REQ-EPOCH-006.  
  **Level**: Unit.  
  **Implementation status**: Planned / not yet implemented in scoped tests.  
  **Pass/fail**: canceling an allocated work item prevents callback execution and releases work-item resources.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-010 — Callback epoch context rule**  
  **Linked requirements**: REQ-EPOCH-006.  
  **Level**: Unit/regression.  
  **Implementation status**: Planned / not yet implemented in scoped tests.  
  **Pass/fail**: a callback that needs epoch-managed access must explicitly enter an epoch; the validation artifact should assert that no implicit callback epoch is assumed.  
  **Confidence**: Medium.

- [KNOWN] **TC-EPOCH-011 — Cross-CPU exit forwarding**  
  **Linked requirements**: REQ-EPOCH-007.  
  **Level**: Unit/concurrency.  
  **Implementation status**: Planned / not yet implemented in scoped tests.  
  **Pass/fail**: entering on one CPU and exiting on another below `DISPATCH_LEVEL` removes the participant from the owner CPU and allows reclamation to complete.  
  **Confidence**: High.

- [KNOWN] **TC-EPOCH-012 — Extension-facing protected-region contract**  
  **Linked requirements**: REQ-EPOCH-008.  
  **Level**: Integration/manual or automated extension test.  
  **Implementation status**: Planned / not yet implemented in scoped tests.  
  **Pass/fail**: extension-facing epoch memory operations and `find_element_function` are exercised both in already-protected provider/helper contexts and in explicitly bracketed contexts.  
  **Confidence**: Medium.

## 6. Risk-Based Test Prioritization
- [KNOWN] **Priority High**: REQ-EPOCH-003 and REQ-EPOCH-006 because premature reclamation or mistimed callback execution can become kernel use-after-free defects. Evidence: `libs\runtime\unit\platform_unit_test.cpp:743-977,994-1244`.
- [KNOWN] **Priority Medium**: REQ-EPOCH-007 because cross-CPU exit correctness protects per-CPU participant list integrity and currently needs a planned targeted test. Evidence: `libs\runtime\ebpf_epoch.c:383-411`.
- [KNOWN] **Priority Medium**: REQ-EPOCH-008 because the extension-facing contract is documented and planned for validation, but not yet implemented in the scoped test set. Evidence: `include\ebpf_extension.h:459-477`, `docs\CustomMaps.md:302-305`.
- [KNOWN] **Priority Low**: performance probes are useful for regressions but do not currently establish pass/fail thresholds. Evidence: `tests\performance\platform.cpp:8-31`.

## 7. Pass/Fail Criteria
- [KNOWN] Unit, regression, and stress tests pass when their `REQUIRE` assertions succeed and no hazard/`thread_error` flags are set. Evidence: `libs\runtime\unit\platform_unit_test.cpp:738-739,965,976,1242-1243`.
- [KNOWN] Planned test cases remain part of the validation baseline even when they are not yet implemented; their implementation status must be tracked separately from requirement-to-validation traceability. Evidence: `docs\specs\epoch\validation.md:17-27,79-119`.
- [KNOWN] No overall numeric performance acceptance threshold is defined in the scoped performance assets. Evidence: `tests\performance\platform.cpp:8-31`.

## 8. Revision History
- [KNOWN] Version 0.2 — 2026-06-30 — Reissued with repository-backed target-plan rationale and implementation-status traceability.

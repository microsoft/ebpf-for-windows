<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Ring Buffer and Perf Event Array — Validation Specification

## 1. Purpose

This specification defines how `ebpf-for-windows` validates the ring-buffer and perf-event-array requirements.

Validation is requirement-driven. Existing tests provide the initial baseline, but this specification also defines
required validation cases that do not yet exist in the current test suite.

## 2. Validation Objectives

Validation must:

1. prove every requirement through an existing or planned test case
2. distinguish public API conformance from internal execution-context behavior
3. cover success paths, negative paths, overflow behavior, and reopen behavior
4. preserve Linux-aligned default semantics where the requirements demand them

## 3. Validation Scope

### 3.1 Covered Layers

- runtime ring-buffer primitive behavior
- execution-context map behavior
- eBPF helper behavior
- user-mode eBPF API behavior
- libbpf-compatible ring-buffer and perf-buffer managers
- supported and intentionally unsupported public API surface

### 3.2 Evidence Classes

- unit tests
- API tests
- execution-context tests
- sample-program-based integration tests
- review-based API-surface conformance checks where runtime execution is not applicable

## 4. Validation Matrix

| TC ID | Requirement(s) | Existing coverage | Validation obligation |
| --- | --- | --- | --- |
| `TC-RB-001` | `REQ-RB-001` | Yes | Validate ring-buffer map creation, map info, and rejection of generic CRUD/traversal. |
| `TC-RB-002` | `REQ-RB-005`, `REQ-RB-006`, `REQ-RB-007` | Yes | Validate synchronous default mode, async opt-in mode, wait-handle availability, and rejection of sync-only operations in async mode. |
| `TC-RB-003` | `REQ-RB-008` | Yes | Validate attaching multiple ring-buffer maps to one synchronous manager and resolving buffers by manager slot index. |
| `TC-RB-004` | `REQ-RB-009`, `REQ-RB-018` | Yes | Validate mapped-memory ring-buffer consumption, unchanged public APIs, wait-handle notification, protected region mappings, and explicit consumer-offset advancement. |
| `TC-RB-005` | `REQ-RB-002`, `REQ-RB-003` | Yes | Validate exact payload preservation and skipping of discarded records. |
| `TC-RB-006` | `REQ-RB-011` | Yes | Validate `NO_WAKEUP`, `FORCE_WAKEUP`, and default adaptive wakeup semantics. |
| `TC-RB-007` | `REQ-RB-004` | Partial | Validate public ring-buffer error surface for zero-length, oversize, full-buffer, and post-full recovery behavior. |
| `TC-RB-008` | `REQ-RB-010` | Yes | Validate sync reopen, async reopen, and explicit unmap/remap behavior on the same ring-buffer map without requiring a kernel-side unmap protocol. |
| `TC-RB-009` | `REQ-RB-007` | Missing | Validate that a negative ring-buffer sample callback result stops further synchronous consumption and leaves later records consumable by a subsequent call. |
| `TC-PEA-001` | `REQ-PEA-001`, `REQ-PEA-004`, `REQ-PEA-006`, `REQ-PEA-012` | Yes | Validate perf-buffer creation, CPU buffer count, synchronous consume paths, and creation preconditions. |
| `TC-PEA-002` | `REQ-PEA-001`, `REQ-PEA-002`, `REQ-PEA-006` | Yes | Validate per-CPU internal query/return behavior and per-CPU public consume behavior. |
| `TC-PEA-003` | `REQ-PEA-005`, `REQ-PEA-006` | Yes | Validate async opt-in mode, wait-handle behavior, and rejection of sync-only operations in async mode. |
| `TC-PEA-004` | `REQ-PEA-009` | Yes | Validate current-CPU success and explicit non-current CPU failure for `bpf_perf_event_output`. |
| `TC-PEA-005` | `REQ-PEA-010` | Yes | Validate payload-plus-capture layout and record sizing for context capture. |
| `TC-PEA-006` | `REQ-PEA-010` | Missing | Validate failure when capture is requested for a context with no data pointer and failure when requested capture exceeds available context data. |
| `TC-PEA-007` | `REQ-PEA-011` | Yes | Validate lost-record accounting and lost-callback delivery in synchronous mode. |
| `TC-PEA-008` | `REQ-PEA-011` | Yes | Validate lost-record accounting and lost-callback delivery in asynchronous mode. |
| `TC-PEA-009` | `REQ-PEA-007` | Yes | Validate sync and async reopen of the same perf-event-array map after prior teardown or prior consumer termination. |
| `TC-PEA-010` | `REQ-PEA-008` | Review-based today | Validate public API-surface conformance for intentionally unsupported Linux raw/direct perf-buffer APIs and confirm that protected-region handle issuance does not widen the public perf API. |
| `TC-PEA-011` | `REQ-PEA-001` | Partial | Validate explicitly that `max_entries` is per-CPU ring capacity while ring count derives from CPU count. |

## 5. Detailed Validation Requirements

### 5.1 Ring Buffer Validation

#### `TC-RB-001` — Ring-buffer map creation and map semantics

Validation must prove:

1. invalid non-zero key/value creation is rejected
2. valid zero-key/zero-value creation succeeds
3. object info reports the expected map type and dimensions
4. generic lookup, update, delete, and traversal operations are rejected

Primary evidence:

- `tests\unit\libbpf_test.cpp`

#### `TC-RB-002` — Consumer-mode selection

Validation must prove:

1. `ring_buffer__new()` is synchronous by default
2. `ebpf_ring_buffer__new()` with zero flags is synchronous
3. `EBPF_RINGBUF_FLAG_AUTO_CALLBACK` enables asynchronous mode
4. async mode rejects synchronous-only drain operations
5. synchronous mode exposes a valid wait handle

Primary evidence:

- `tests\unit\libbpf_test.cpp`
- `tests\api_test\api_test.cpp`

#### `TC-RB-003` — Multi-map synchronous manager behavior

Validation must prove:

1. an additional ring-buffer map can be attached to a synchronous manager
2. data from each attached map can be consumed through one manager
3. `ebpf_ring_buffer_get_buffer()` addresses attached maps by manager slot index

Primary evidence:

- `tests\unit\libbpf_test.cpp`
- `tests\api_test\api_test.cpp`

#### `TC-RB-004` — Mapped-memory consumption

Validation must prove:

1. the consumer page, producer page, and data region can be mapped
2. a wait handle can be installed and observed
3. direct record iteration works
4. advancing the consumer offset returns space correctly
5. producer and data mappings are read-only
6. repeated mappings of the same ring succeed without changing the public API call pattern

Primary evidence:

- `tests\api_test\api_test.cpp`
- `libs\execution_context\unit\execution_context_unit_test.cpp`

#### `TC-RB-005` — Payload fidelity and discard skipping

Validation must prove:

1. submitted payload bytes are preserved exactly
2. discarded records are not surfaced as samples
3. direct readers also skip discarded records

Primary evidence:

- `tests\api_test\api_test.cpp`
- `libs\runtime\unit\platform_unit_test.cpp`

#### `TC-RB-006` — Wakeup flags

Validation must prove:

1. submit with `NO_WAKEUP` does not signal
2. discard with `NO_WAKEUP` does not signal
3. discard with `FORCE_WAKEUP` signals
4. mixed submit/discard behavior remains correct

Primary evidence:

- `libs\runtime\unit\platform_unit_test.cpp`

#### `TC-RB-007` — Public error surface

Validation must prove:

1. zero-length write is rejected
2. oversized write is rejected
3. a full ring rejects additional writes cleanly
4. after consumption returns space, later writes can succeed again

Current status:

- partially evidenced by runtime-path and API-path tests
- requires explicit public API coverage for full conformance

#### `TC-RB-008` — Reopen and remap behavior

Validation must prove:

1. a mapped ring can be unmapped and remapped
2. a synchronous consumer can be freed and recreated on the same map
3. an asynchronous consumer can be unsubscribed and recreated on the same map
4. mapped-view teardown succeeds without a kernel-side unmap prerequisite

Primary evidence:

- `tests\api_test\api_test.cpp`
- `libs\execution_context\unit\execution_context_unit_test.cpp`

#### `TC-RB-009` — Negative callback termination

Validation must prove:

1. a negative ring-buffer callback result stops further consumption in the current drain call
2. already-consumed records are committed as consumed
3. later records remain available for a subsequent consume or poll

Current status:

- planned test required

### 5.2 Perf Event Array Validation

#### `TC-PEA-001` — Base perf-buffer creation and synchronous semantics

Validation must prove:

1. perf-buffer creation requires valid callbacks and `page_cnt == 0`
2. synchronous mode is the default
3. `perf_buffer__buffer_cnt()` equals CPU count
4. `perf_buffer__poll()` and `perf_buffer__consume()` function over all per-CPU buffers

Primary evidence:

- `tests\unit\libbpf_test.cpp`
- `tests\api_test\api_test.cpp`

#### `TC-PEA-002` — Per-CPU internal and public behavior

Validation must prove:

1. internal query/map/return behavior rejects out-of-range CPU indices
2. public `perf_buffer__consume_buffer()` drains a single per-CPU buffer
3. data written on one CPU is observed from that CPU's ring

Primary evidence:

- `libs\execution_context\unit\execution_context_unit_test.cpp`
- `tests\api_test\api_test.cpp`

#### `TC-PEA-003` — Async perf-buffer mode

Validation must prove:

1. async mode requires `EBPF_PERFBUF_FLAG_AUTO_CALLBACK`
2. async mode exposes no wait handle
3. async mode rejects synchronous-only drain operations

Primary evidence:

- `tests\unit\libbpf_test.cpp`
- `tests\api_test\api_test.cpp`

#### `TC-PEA-004` — Current-CPU-only helper semantics

Validation must prove:

1. targeting the current CPU succeeds
2. targeting a different CPU fails
3. no stray records are produced on mismatched targets

Primary evidence:

- `tests\api_test\api_test.cpp`
- `tests\sample\undocked\perf_event_cpu_target.c`

#### `TC-PEA-005` — Context capture success path

Validation must prove:

1. the explicit payload appears first in the record
2. captured context bytes immediately follow it
3. total record length matches payload plus captured bytes

Primary evidence:

- `libs\execution_context\unit\execution_context_unit_test.cpp`
- `tests\sample\bindmonitor_perf_event_array.c`

#### `TC-PEA-006` — Context capture failure paths

Validation must prove:

1. capture is rejected for program contexts without a data pointer
2. capture is rejected when the requested capture length exceeds available context data

Current status:

- planned test required

#### `TC-PEA-007` and `TC-PEA-008` — Lost-record accounting

Validation must prove:

1. overflow increments lost-record accounting instead of producing discarded data records
2. synchronous lost callbacks report the correct deltas
3. asynchronous lost callbacks report the correct deltas
4. observed event and lost totals match attempted writes

Primary evidence:

- `tests\api_test\api_test.cpp`
- `tests\sample\undocked\perf_event_burst.c`

#### `TC-PEA-009` — Reopen behavior

Validation must prove:

1. a synchronous perf buffer can be recreated on the same map
2. an asynchronous perf buffer can be recreated on the same map
3. teardown clears mappings sufficiently for later recreation

Primary evidence:

- `tests\api_test\api_test.cpp`
- `libs\execution_context\unit\execution_context_unit_test.cpp`

#### `TC-PEA-010` — Unsupported public API-surface conformance

Validation must prove:

1. the supported public header surface contains only the intended perf-buffer APIs
2. Linux raw/direct APIs such as `perf_buffer__new_raw()` and perf epoll/direct-buffer accessors are not part of the
   implemented Windows public surface

Current status:

- review-based conformance check required today
- runtime automation is optional, but the validation obligation is mandatory

#### `TC-PEA-011` — Explicit sizing semantics

Validation must prove:

1. `max_entries` configures per-CPU ring capacity
2. ring count derives from the system CPU count
3. buffer count observed by the userspace manager matches CPU count rather than `max_entries`

Current status:

- partially evidenced
- requires explicit requirement-focused test or assertion coverage

## 6. Acceptance Mapping

| Requirement | Validation |
| --- | --- |
| `REQ-RB-001` | `TC-RB-001` |
| `REQ-RB-002` | `TC-RB-005` |
| `REQ-RB-003` | `TC-RB-005` |
| `REQ-RB-004` | `TC-RB-007` |
| `REQ-RB-005` | `TC-RB-002` |
| `REQ-RB-006` | `TC-RB-002` |
| `REQ-RB-007` | `TC-RB-002`, `TC-RB-009` |
| `REQ-RB-008` | `TC-RB-003` |
| `REQ-RB-009` | `TC-RB-004` |
| `REQ-RB-010` | `TC-RB-008` |
| `REQ-RB-011` | `TC-RB-006` |
| `REQ-PEA-001` | `TC-PEA-001`, `TC-PEA-002`, `TC-PEA-011` |
| `REQ-PEA-002` | `TC-PEA-002` |
| `REQ-PEA-003` | `TC-PEA-007`, `TC-PEA-008` |
| `REQ-PEA-004` | `TC-PEA-001` |
| `REQ-PEA-005` | `TC-PEA-003` |
| `REQ-PEA-006` | `TC-PEA-001`, `TC-PEA-002` |
| `REQ-PEA-007` | `TC-PEA-009` |
| `REQ-PEA-008` | `TC-PEA-010` |
| `REQ-PEA-009` | `TC-PEA-004` |
| `REQ-PEA-010` | `TC-PEA-005`, `TC-PEA-006` |
| `REQ-PEA-011` | `TC-PEA-007`, `TC-PEA-008` |
| `REQ-PEA-012` | `TC-PEA-001` |

## 7. Coverage Gaps

The current implementation baseline is missing or only partially covers:

1. full public ring-buffer API error-surface validation
2. explicit negative ring-buffer callback termination behavior
3. explicit negative context-capture cases for perf-event output
4. explicit requirement-focused coverage for perf-event-array `max_entries` sizing semantics
5. automated conformance checking for intentionally unsupported Linux raw/direct perf-buffer APIs

These gaps do not change the requirements. They identify validation work needed to make the test suite fully cover the
authoritative specification.

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.2 | 2026-07-10 | Copilot | Added protected-region mapping, unchanged API, and rundown-safe reopen validation requirements. |
| 0.1 | 2026-07-10 | Copilot | Initial validation specification for ring buffer and perf event array behavior. |

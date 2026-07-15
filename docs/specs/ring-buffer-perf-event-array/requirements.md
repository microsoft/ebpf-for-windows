<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Ring Buffer and Perf Event Array — Requirements Specification

## 1. Overview

This specification defines the authoritative requirements for the `BPF_MAP_TYPE_RINGBUF` and
`BPF_MAP_TYPE_PERF_EVENT_ARRAY` facilities in `ebpf-for-windows`.

The specification covers:

- kernel-mode map behavior
- helper semantics
- user-mode and libbpf-facing consumption APIs
- Windows-specific extensions
- Linux-aligned behavior that the current implementation intentionally preserves

This specification is authoritative for the behavior of these facilities, regardless of whether the
behavior was originally introduced by implementation-first development.

## 2. Goals

The ring buffer and perf event array design must:

1. Provide efficient one-way event delivery from eBPF producers to user-mode consumers.
2. Preserve Linux-compatible default libbpf consumption behavior where practical.
3. Provide Windows-specific extensions only where Linux-compatible APIs are not sufficient.
4. Keep kernel/user synchronization explicit and safe.
5. Surface overflow, invalid usage, and unsupported behavior deterministically.

## 3. Scope

### 3.1 In Scope

- `BPF_MAP_TYPE_RINGBUF`
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY`
- `bpf_ringbuf_output`
- `bpf_perf_event_output`
- libbpf-style ring-buffer and perf-buffer managers
- Windows-specific wait-handle and mapped-memory extensions
- async query and callback behavior used by these map types

### 3.2 Out of Scope

- Linux perf subsystem features unrelated to event transport
- perf counters and hardware-generated perf events
- user-mode production of events into perf event arrays
- Linux-only raw perf-buffer APIs not implemented in this repository

## 4. Definitions

| Term | Definition |
| --- | --- |
| ring buffer map | A `BPF_MAP_TYPE_RINGBUF` map containing one shared event stream. |
| perf event array map | A `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map implemented as one ring per CPU. |
| synchronous consumer | A consumer that waits or polls, then explicitly drains records. |
| asynchronous consumer | A Windows-specific consumer mode in which callbacks are invoked automatically. |
| map index | The kernel-facing buffer index used by map operations. |
| manager slot index | The user-mode index of a map attached to a ring-buffer manager. |
| lost record | A perf-event-array record that could not be reserved and is counted out-of-band. |

## 5. Functional Requirements

### 5.1 Ring Buffer Map Semantics

- **REQ-RB-001**: A `BPF_MAP_TYPE_RINGBUF` map **MUST** expose a single logical ring-buffer stream and **MUST**
  use zero-length key and value semantics.
  - **AC-1**: Creation succeeds only when key size and value size are zero.
  - **AC-2**: The resulting map reports type `BPF_MAP_TYPE_RINGBUF`.
  - **AC-3**: Generic keyed CRUD operations are rejected.
  - **AC-4**: Kernel-facing ring-buffer query, map, unmap, wait-handle, async-query, and return operations accept
    only map index `0`.

- **REQ-RB-002**: Ring-buffer records **MUST** preserve submitted payload bytes exactly.
  - **AC-1**: `bpf_ringbuf_output` writes one record containing exactly the supplied payload bytes.
  - **AC-2**: direct ring-buffer map write APIs write one record containing exactly the supplied payload bytes.

- **REQ-RB-003**: Ring-buffer consumers **MUST** skip discarded records rather than surface them as ordinary samples.
  - **AC-1**: discarded records do not invoke ring-buffer sample callbacks.
  - **AC-2**: discarded records are skipped by direct record iteration.

- **REQ-RB-004**: Ring-buffer reservation **MUST** reject invalid record lengths and lack of capacity without exposing
  a partially published record.
  - **AC-1**: zero-length records are rejected.
  - **AC-2**: records larger than the supported record-size bound are rejected.
  - **AC-3**: records that do not fit in available space are rejected.
  - **AC-4**: rejected writes do not advance the visible producer position.

### 5.2 Ring Buffer Consumer APIs

- **REQ-RB-005**: The Linux-compatible ring-buffer consumer API **MUST** use synchronous callbacks by default.
  - **AC-1**: `ring_buffer__new()` creates a synchronous consumer manager.
  - **AC-2**: `ebpf_ring_buffer__new()` creates a synchronous consumer manager when
    `EBPF_RINGBUF_FLAG_AUTO_CALLBACK` is not set.

- **REQ-RB-006**: Windows-specific asynchronous ring-buffer callbacks **MUST** be opt-in.
  - **AC-1**: `EBPF_RINGBUF_FLAG_AUTO_CALLBACK` enables automatic callback delivery.
  - **AC-2**: synchronous-only operations such as `ring_buffer__poll()` and `ring_buffer__consume()` are rejected in
    async mode.

- **REQ-RB-007**: A synchronous ring-buffer manager **MUST** support explicit waiting and draining.
  - **AC-1**: `ring_buffer__poll()` waits for data subject to timeout and then consumes available records.
  - **AC-2**: `ring_buffer__consume()` consumes available records without waiting.
  - **AC-3**: a synchronous manager exposes a valid wait handle.

- **REQ-RB-008**: A synchronous ring-buffer manager **MAY** aggregate multiple ring-buffer maps behind one manager.
  - **AC-1**: `ring_buffer__add()` attaches an additional ring-buffer map to an existing synchronous manager.
  - **AC-2**: manager slot indices range from `0` to `N-1` over attached maps.
  - **AC-3**: `ebpf_ring_buffer_get_buffer()` resolves attached maps by manager slot index, not by kernel map index.

- **REQ-RB-009**: Ring-buffer maps **MUST** support a mapped-memory consumption mode.
  - **AC-1**: user mode can map the consumer page, producer page, and data region without changing the public libbpf or
    eBPF API signatures.
  - **AC-2**: the consumer page is writable from user mode, while the producer page and data region are read-only from
    user mode.
  - **AC-3**: the kernel issues at most one user handle per logical region request and validates the map index and
    requested region.
  - **AC-4**: user mode can install a wait handle for notification.
  - **AC-5**: user mode advances the consumer offset explicitly to return consumed space.

- **REQ-RB-010**: Releasing a ring-buffer consumer **MUST** allow the same map to be reopened later in the same
  process without requiring a ring-specific kernel unmap step.
  - **AC-1**: sync reopen succeeds after freeing a prior sync consumer.
  - **AC-2**: async reopen succeeds after unsubscribing a prior async consumer.
  - **AC-3**: explicit unmap/remap cycles succeed for mapped ring buffers.
  - **AC-4**: abandoning a mapped view by process termination does not strand the map in an unmappable state.

### 5.3 Ring Buffer Notification Semantics

- **REQ-RB-011**: Ring-buffer submit and discard operations **MUST** honor wakeup policy flags.
  - **AC-1**: `NO_WAKEUP` suppresses notification.
  - **AC-2**: `FORCE_WAKEUP` notifies unconditionally.
  - **AC-3**: default behavior performs adaptive notification when data is available for a waiting consumer.

### 5.4 Perf Event Array Map Semantics

- **REQ-PEA-001**: A `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map **MUST** allocate one per-CPU ring and one per-CPU lost-record
  counter.
  - **AC-1**: ring count equals the current CPU count.
  - **AC-2**: each CPU ring has independent producer/consumer state.
  - **AC-3**: each CPU ring has an associated lost-record counter.
  - **AC-4**: `max_entries` defines per-CPU ring capacity, not ring count.

- **REQ-PEA-002**: A perf event array map **MUST** behave as an event transport map rather than a generic keyed map.
  - **AC-1**: ordinary keyed CRUD and traversal operations are rejected.
  - **AC-2**: internal query, async-query, return-buffer, map, and unmap operations require a valid CPU index.

- **REQ-PEA-003**: Perf event arrays **MUST** use ring-buffer storage semantics for delivered records.
  - **AC-1**: delivered records use the same record framing model as ring buffers.
  - **AC-2**: discarded records are not used to represent overflow.
  - **AC-3**: overflow is represented by lost-record accounting.

### 5.5 Perf Buffer Consumer APIs

- **REQ-PEA-004**: The Linux-compatible perf-buffer consumer API **MUST** use synchronous callbacks by default.
  - **AC-1**: `perf_buffer__new()` creates a synchronous consumer manager.
  - **AC-2**: `ebpf_perf_buffer__new()` creates a synchronous consumer manager when
    `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` is not set.

- **REQ-PEA-005**: Windows-specific asynchronous perf-buffer callbacks **MUST** be opt-in.
  - **AC-1**: `EBPF_PERFBUF_FLAG_AUTO_CALLBACK` enables automatic callback delivery.
  - **AC-2**: synchronous-only operations such as `perf_buffer__poll()`, `perf_buffer__consume()`, and
    `perf_buffer__consume_buffer()` are rejected in async mode.

- **REQ-PEA-006**: A synchronous perf-buffer manager **MUST** attach one consumer mapping per CPU and support explicit
  draining.
  - **AC-1**: `perf_buffer__buffer_cnt()` returns the number of per-CPU buffers.
  - **AC-2**: `perf_buffer__poll()` waits for data subject to timeout and then drains available records.
  - **AC-3**: `perf_buffer__consume()` drains all available per-CPU records.
  - **AC-4**: `perf_buffer__consume_buffer()` drains a specific per-CPU buffer by manager CPU index.
  - **AC-5**: a synchronous perf-buffer manager exposes a valid wait handle.

- **REQ-PEA-007**: Releasing a perf-buffer consumer **MUST** release per-CPU user-mode mappings so the same map can be
  reopened later in the same process.
  - **AC-1**: sync reopen succeeds after freeing a prior sync consumer.
  - **AC-2**: async reopen succeeds after unsubscribing a prior async consumer.
  - **AC-3**: per-CPU mappings abandoned by process termination do not block a later process instance from reopening the
    same map.

- **REQ-PEA-008**: The Windows public perf-buffer API surface **MUST NOT** expose Linux raw/direct perf-buffer APIs that
  depend on Linux perf memory layout or epoll.
  - **AC-1**: supported public APIs are limited to the implemented perf-buffer manager, poll/consume operations,
    wait-handle access, and related helpers.
  - **AC-2**: `perf_buffer__new_raw()` CPU-subset selection is not part of the Windows public API surface.
  - **AC-3**: direct Linux per-buffer memory accessors and epoll-fd APIs are not part of the Windows public API surface.
  - **AC-4**: internal per-CPU protected-region handle issuance does not add a new public direct-memory perf-buffer API.

### 5.6 Perf Event Output Helper Semantics

- **REQ-PEA-009**: `bpf_perf_event_output` **MUST** write only to the current CPU's ring.
  - **AC-1**: `CURRENT_CPU` selection succeeds.
  - **AC-2**: an explicit CPU index succeeds only when it matches the CPU executing at dispatch.
  - **AC-3**: below dispatch, an explicit non-current CPU target is rejected.

- **REQ-PEA-010**: Perf-event-array output **MUST** support optional payload capture from the program context when a
  context data pointer is available.
  - **AC-1**: requested context bytes are appended after the caller-supplied payload in the same record.
  - **AC-2**: when the program type has no context data pointer, capture is rejected with operation-not-supported.
  - **AC-3**: when the requested capture length exceeds available context data, the write is rejected as invalid.

- **REQ-PEA-011**: Perf-event-array overflow **MUST** be accounted as lost records.
  - **AC-1**: a failed reserve increments the target CPU's lost-record counter.
  - **AC-2**: sync consumers observe lost-record deltas through the lost callback.
  - **AC-3**: async consumers observe lost-record deltas through the lost callback.

### 5.7 API Preconditions

- **REQ-PEA-012**: Perf-buffer manager creation **MUST** require a non-null sample callback, a non-null lost callback,
  and `page_cnt == 0`.
  - **AC-1**: creation fails when the sample callback is null.
  - **AC-2**: creation fails when the lost callback is null.
  - **AC-3**: creation fails when `page_cnt` is non-zero.

- **REQ-RB-018**: The libbpf-facing and eBPF API-facing user-mode ring-buffer and perf-buffer entry points **MUST**
  remain signature-compatible across this mapping migration.
  - **AC-1**: supported libbpf-facing creation, consume, poll, buffer-count, wait-handle, and teardown entry points keep
    their current signatures.
  - **AC-2**: mapped-memory consumers continue to use the same public `ebpf_ring_buffer_map_map_buffer()` and
    `ebpf_ring_buffer_map_unmap_buffer()` signatures.
  - **AC-3**: protected region-handle issuance remains an internal kernel/user implementation detail behind the existing
    user-mode API layer.

## 6. Design Background

The ring-buffer and perf-buffer consumption model is Linux-aligned in its default synchronous behavior and in its use
of shared consumer positions for mapped buffers. This section is explanatory background, not a separate normative
requirement requiring explicit rejection of additional concurrent user-mode attachments.

## 7. Constraints

- **CON-001**: Ring-buffer default callback behavior must remain Linux-compatible.
- **CON-002**: Perf-buffer default callback behavior must remain Linux-compatible.
- **CON-003**: Windows-only extensions must be explicit and opt-in where they diverge from Linux behavior.
- **CON-004**: Kernel/user synchronization must be safe across mapped memory, wait handles, and callback modes.

## 8. Open Questions

1. Should a future iteration add a supported Windows equivalent of Linux `perf_buffer__new_raw()` CPU-subset
   selection, or should full-CPU manager attachment remain the long-term API boundary?

## 9. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-07-10 | Copilot | Initial requirements specification for ring buffer and perf event array behavior. |
| 0.2 | 2026-07-10 | Copilot | Added protected region-handle mapping, rundown-safe reopen, and unchanged user-mode API requirements. |

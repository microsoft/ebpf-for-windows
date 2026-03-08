# eBPF Latency Tracking Design — Per-CPU Ring Buffer

## 1. Overview

This document proposes replacing the current ETW-based latency tracking with a **per-CPU ring buffer** approach. The goal is to minimize the observer effect — the overhead that the tracing infrastructure itself adds to the measurements.

### 1.1 Problem Statement

The current ETW-based implementation emits a `TraceLoggingWrite` event for every program invocation and every map helper call. For `cil_from_container` (a Cilium program that makes 25 helper calls per invocation), this produces **27 ETW events per invocation**. Each event costs ~300–650 ns, adding **~8–16 µs of tracing overhead** to a program whose P50 execution time is ~22 µs. The tracing changes the thing being measured.

Additionally, the current implementation:
- Copies the program/map **name string** (up to 64 bytes) on every event.
- Calls `ebpf_platform_process_id()` and `ebpf_platform_thread_id()` on every helper event.
- Uses a global `InterlockedIncrement64` for correlation ID generation, which causes cache-line bouncing across CPUs.

### 1.2 Goals

| # | Goal |
|---|------|
| G1 | Per-event overhead ≤ 30 ns (currently ~300–650 ns). |
| G2 | No interlocked operations in the hot path. |
| G3 | No string copies in the hot path. |
| G4 | Safe at DISPATCH_LEVEL (majority of eBPF programs). |
| G5 | Safe at PASSIVE_LEVEL (some eBPF programs, e.g., `cil_sock4_connect`). |
| G6 | Name resolution deferred to user-mode consumer. |

### 1.3 Non-Goals

- Real-time streaming of events to user mode. The ring buffer is drained on demand.
- Cross-provider correlation with other ETW providers (WPA, xperf). If needed, the ETW path remains available as an option.

---

## 2. Design Summary

Replace inline `TraceLoggingWrite` calls with writes to **per-CPU ring buffers** in non-paged memory. The hot path becomes:

```
rdtsc → write 24-byte record to per-CPU ring buffer
```

User mode drains the ring buffers via IOCTL when the session is stopped.

---

## 3. Per-CPU vs Global Ring Buffer

### 3.1 Analysis

| Aspect | Per-CPU Ring Buffer | Global Ring Buffer |
|--------|--------------------|--------------------|
| **Synchronization at DISPATCH** | **None** — DISPATCH_LEVEL code cannot be preempted by another thread on the same CPU. A simple write pointer increment (no atomic/interlock) is sufficient. | Requires `InterlockedCompareExchange` loop or spin lock on every write. |
| **Synchronization at PASSIVE** | Must raise IRQL to DISPATCH or disable preemption before writing to prevent a race if the thread migrates to another CPU or is preempted by a DPC that also writes. | Same interlocked operation — no difference from DISPATCH. |
| **Cache behavior** | Each CPU writes to its own cache lines. **No false sharing, no cross-CPU cache invalidation.** | All CPUs compete for the same cache lines (write pointer, buffer head). Severe contention at high event rates. |
| **Ordering** | Events are ordered within each CPU. Cross-CPU ordering requires merging by timestamp during drain. | Events are globally ordered (at the cost of contention). |
| **Memory** | `N_cpus × buffer_size`. E.g., 8 CPUs × 256 KB = 2 MB. | Single buffer, e.g., 2 MB. Less total memory but worse contention. |
| **Drain complexity** | Must iterate all per-CPU buffers and merge-sort by timestamp. | Single sequential read. |

### 3.2 Decision: Per-CPU Ring Buffers

**Per-CPU is the clear choice** for these reasons:

1. **Zero synchronization at DISPATCH_LEVEL** — The majority of eBPF program invocations (XDP, TC, WFP classify hooks) run at DISPATCH_LEVEL. At DISPATCH, a CPU cannot be preempted by another thread, so the per-CPU buffer write is a plain store — no atomics, no locks, no interlocked operations. This achieves G1 and G2.

2. **No false sharing** — With a global buffer, every CPU's write invalidates the cache line for every other CPU. With per-CPU buffers, each CPU writes exclusively to its own memory. On a busy 8-core system processing 60K packets/sec per program, this avoids millions of cache-coherency transactions.

3. **Passive-level programs are rare and low-volume** — Programs like `cil_sock4_connect` (61 invocations in 52 seconds) are infrequent enough that the small cost of raising IRQL is negligible.

---

## 4. Data Structures

### 4.1 Ring Buffer Record

```c
// Compact latency event record. No strings — IDs only.
typedef struct _ebpf_latency_record {
    uint64_t timestamp;         // 8 B — rdtsc value (raw cycles)
    uint32_t correlation_id;    // 4 B — per-CPU monotonic counter (see §5)
    uint32_t program_id;        // 4 B — ebpf_core_object_t.id
    uint16_t helper_function_id;// 2 B — BPF_FUNC_xxx (0 = program start/end)
    uint16_t map_id;            // 2 B — ebpf_map_t.id (0 if N/A)
    uint8_t  event_type;        // 1 B — 0=program_start, 1=program_end,
                                //        2=helper_start, 3=helper_end
    uint8_t  cpu_id;            // 1 B — processor number
    uint8_t  reserved[2];       // 2 B — padding to 24 bytes
} ebpf_latency_record_t;
```

**Record size: 24 bytes** (aligned, no padding waste).

Comparison with current ETW approach:

| | Current (ETW) | Proposed (Ring Buffer) |
|---|---|---|
| Record size | ~128 bytes (42 payload + 80+ ETW header) | **24 bytes** |
| Contains strings | Yes (program name, map name) | **No** (IDs only) |
| Contains PID/TID | Yes (per event) | **No** (not needed — program runs in known context) |

### 4.2 Per-CPU Ring Buffer

```c
#define EBPF_LATENCY_DEFAULT_RECORDS_PER_CPU  100000  // Default: 100,000 records per CPU (~2.3 MB)
#define EBPF_LATENCY_MIN_RECORDS_PER_CPU      1000    // Minimum: 1,000 records
#define EBPF_LATENCY_MAX_RECORDS_PER_CPU      10000000 // Maximum: 10,000,000 records (~229 MB)

typedef struct _ebpf_latency_ring_buffer {
    // Write index — only written by the owning CPU (at DISPATCH_LEVEL).
    // No atomic needed. Volatile to prevent compiler reordering.
    volatile uint32_t write_index;

    // Count of records dropped (buffer full and overwrite not enabled).
    volatile uint32_t dropped_count;

    // Per-CPU correlation ID counter — plain increment, no interlocked.
    uint32_t next_correlation_id;

    // Number of records in this ring buffer (configurable at enable time).
    uint32_t records_count;

    // Padding to ensure the record array starts on a cache line boundary.
    uint8_t _padding[64 - 16];  // Align to 64-byte cache line.

    // The record array (variable length, allocated based on records_count).
    ebpf_latency_record_t records[0];  // Flexible array member.
} ebpf_latency_ring_buffer_t;
```

### 4.3 Global State

```c
typedef struct _ebpf_latency_state {
    volatile long enabled;          // 0 = off, 1 = program only, 2 = program + helpers
    volatile long session_active;   // 0 = no active session, 1 = session in progress
    volatile long correlation_enabled; // 0 = no correlation IDs, 1 = generate per-invocation correlation IDs

    // TSC calibration — captured once at enable time.
    uint64_t tsc_frequency;         // TSC ticks per second.
    uint64_t tsc_at_enable;         // rdtsc value at enable time.
    uint64_t qpc_at_enable;         // QPC value at enable time (for correlation with ETW).

    // Program ID filter list.
    uint32_t program_id_count;
    uint32_t program_ids[EBPF_LATENCY_MAX_PROGRAM_FILTER];

    // Per-CPU ring buffers. Allocated at enable, freed at disable.
    uint32_t cpu_count;
    ebpf_latency_ring_buffer_t** per_cpu_buffers;  // Array of pointers, one per CPU.
} ebpf_latency_state_t;
```

---

## 5. Per-CPU Correlation ID (Optional)

Correlation IDs allow grouping a program invocation with all its helper calls for per-invocation timeline analysis. This is **opt-in** via the `EBPF_LATENCY_FLAG_CORRELATION_ID` flag (or `correlation=yes` in netsh), matching the behavior of the current ETW design.

When correlation is **disabled** (the default), `correlation_id` is 0 in all records. The consumer can still compute aggregate statistics (P50, P90, P99) per program and per helper, but cannot reconstruct per-invocation timelines. This avoids the per-CPU counter increment cost (~2 ns) and the context-header write for each invocation.

When correlation is **enabled**, a per-CPU counter generates unique IDs with no interlocked operations.

### 5.1 Current Problem

The current implementation uses a global `InterlockedIncrement64` to generate correlation IDs:

```c
static volatile int64_t _ebpf_correlation_id_counter = 0;

uint64_t ebpf_program_next_correlation_id()
{
    return (uint64_t)InterlockedIncrement64(&_ebpf_correlation_id_counter);
}
```

`InterlockedIncrement64` requires exclusive ownership of the cache line containing the counter. On an 8-CPU system with all CPUs generating correlation IDs, this means the cache line bounces between L1 caches on every invocation — costing ~40–100 ns per increment due to cache-coherency protocol (MESI/MOESI) round-trips.

### 5.2 Proposed: Per-CPU Counter

Each per-CPU ring buffer has its own `next_correlation_id` counter. Since writes only happen at DISPATCH_LEVEL (where the CPU cannot be preempted), a plain increment is safe:

```c
EBPF_INLINE_HINT
uint32_t
ebpf_latency_next_correlation_id(_In_ ebpf_latency_ring_buffer_t* ring)
{
    return ++ring->next_correlation_id;
}
```

**Uniqueness scheme:** The correlation ID is 32 bits, composed of:

```
┌──────────────────┬──────────────────────────────┐
│   cpu_id (8 bits) │   per_cpu_counter (24 bits)  │
└──────────────────┴──────────────────────────────┘
```

```c
EBPF_INLINE_HINT
uint32_t
ebpf_latency_next_correlation_id(_In_ ebpf_latency_ring_buffer_t* ring, uint8_t cpu_id)
{
    uint32_t seq = ++ring->next_correlation_id & 0x00FFFFFF;
    return ((uint32_t)cpu_id << 24) | seq;
}
```

This provides:
- **Global uniqueness** — The CPU ID prefix guarantees no two CPUs produce the same correlation ID.
- **16.7 million IDs per CPU** before wrap-around — sufficient for any reasonable trace session.
- **No interlocked operation** — Plain increment under DISPATCH_LEVEL guarantee.

### 5.3 Passive-Level Programs

Programs running at PASSIVE_LEVEL (e.g., `cil_sock4_connect`) can be preempted or migrate to a different CPU between the correlation ID assignment and the helper calls. This means:

1. The `cpu_id` prefix might not match the CPU where helper events land.
2. A preempting DPC could interleave its own events on the same CPU buffer.

**Mitigation:** For PASSIVE_LEVEL callers, raise IRQL to DISPATCH_LEVEL before writing to the ring buffer:

```c
EBPF_INLINE_HINT
void
ebpf_latency_write_record(
    _In_ ebpf_latency_record_t* record)
{
    // Raise to DISPATCH to prevent preemption and CPU migration.
    KIRQL old_irql;
    KeRaiseIrql(DISPATCH_LEVEL, &old_irql);

    uint32_t cpu = KeGetCurrentProcessorNumber();
    ebpf_latency_ring_buffer_t* ring = _ebpf_latency_state.per_cpu_buffers[cpu];

    uint32_t idx = ring->write_index % ring->records_count;
    ring->records[idx] = *record;
    ring->write_index++;

    KeLowerIrql(old_irql);
}
```

For programs already at DISPATCH_LEVEL (the common case), `KeRaiseIrql` is a no-op (IRQL is already at DISPATCH). The cost is a single comparison — effectively zero.

**Accepted trade-off:** For PASSIVE_LEVEL programs, the correlation ID is assigned after raising to DISPATCH. If the program is preempted between helper calls (back at PASSIVE after the raise/lower), the subsequent helper events may appear on a different CPU's ring buffer, but they share the same correlation ID, so the consumer can still correlate them. The per-CPU ordering within each buffer is preserved; global ordering is reconstructed by timestamp during drain.

---

## 6. Timestamp: `rdtsc` vs `KeQueryPerformanceCounter`

### 6.1 Comparison

| | `__rdtsc()` | `cxplat_query_time_since_boot_precise()` |
|---|---|---|
| Cost | ~5–7 ns | ~20–30 ns |
| Unit | Raw CPU cycles | 100-ns ticks |
| Needs calibration | Yes | No |
| Cross-CPU comparable | Yes (invariant TSC on modern CPUs) | Yes |
| Hypervisor-safe | Yes (paravirtualized TSC on Hyper-V/VMware) | Yes |

### 6.2 Decision: Use `__rdtsc()`

Use `__rdtsc()` in the hot path and capture the TSC-to-nanosecond calibration factor once at enable time:

```c
#include <intrin.h>

// At enable time:
LARGE_INTEGER freq;
KeQueryPerformanceCounter(&freq);
state->tsc_frequency = freq.QuadPart;   // For TSC→ns conversion.
state->tsc_at_enable = __rdtsc();
state->qpc_at_enable = cxplat_query_time_since_boot_precise(false);
```

User-mode consumer converts: `nanoseconds = (tsc_delta * 1,000,000,000) / tsc_frequency`.

This saves ~15–25 ns per timestamp × 2 timestamps per event × 27 events = **~0.8–1.4 µs per invocation**.

### 6.3 TSC Invariance Check

At enable time, verify that the CPU supports invariant TSC:

```c
int cpuid_info[4];
__cpuid(cpuid_info, 0x80000007);
bool invariant_tsc = (cpuid_info[3] & (1 << 8)) != 0;
if (!invariant_tsc) {
    // Fall back to cxplat_query_time_since_boot_precise.
}
```

All modern Intel (Nehalem+) and AMD (Bulldozer+) CPUs support invariant TSC. This is a safety check for exotic hardware.

---

## 7. Hot-Path Instrumentation

### 7.1 Program Invocation

```c
_Must_inspect_result_ ebpf_result_t
ebpf_program_invoke(
    _In_ const ebpf_program_t* program,
    _Inout_ void* context,
    _Out_ uint32_t* result,
    _Inout_ ebpf_execution_context_state_t* execution_state)
{
    // --- existing early-exit checks ---

    uint64_t latency_tsc = 0;
    uint32_t correlation_id = 0;
    long latency_mode = ReadNoFence(&_ebpf_latency_state.enabled);
    if (latency_mode > 0 &&
        ebpf_latency_should_track_program((uint32_t)program->object.id)) {
        KIRQL old_irql;
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);  // No-op if already DISPATCH.

        uint32_t cpu = KeGetCurrentProcessorNumber();
        ebpf_latency_ring_buffer_t* ring = _ebpf_latency_state.per_cpu_buffers[cpu];

        // Generate correlation ID only if enabled (opt-in via EBPF_LATENCY_FLAG_CORRELATION_ID).
        if (ReadNoFence(&_ebpf_latency_state.correlation_enabled)) {
            correlation_id = ebpf_latency_next_correlation_id(ring, (uint8_t)cpu);
        }
        latency_tsc = __rdtsc();

        // Write program-start record.
        ebpf_latency_record_t rec = {
            .timestamp = latency_tsc,
            .correlation_id = correlation_id,
            .program_id = (uint32_t)program->object.id,
            .helper_function_id = 0,
            .map_id = 0,
            .event_type = 0,  // program_start
            .cpu_id = (uint8_t)cpu,
        };
        uint32_t idx = ring->write_index % ring->records_count;
        ring->records[idx] = rec;
        ring->write_index++;

        KeLowerIrql(old_irql);
    }

    // Store correlation_id in context header for helpers to read.
    ebpf_program_set_correlation_id(correlation_id, context);

    // --- existing program invocation + tail call loop ---

    if (latency_tsc != 0) {
        KIRQL old_irql;
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);

        uint32_t cpu = KeGetCurrentProcessorNumber();
        ebpf_latency_ring_buffer_t* ring = _ebpf_latency_state.per_cpu_buffers[cpu];

        ebpf_latency_record_t rec = {
            .timestamp = __rdtsc(),
            .correlation_id = correlation_id,
            .program_id = (uint32_t)program->object.id,
            .helper_function_id = 0,
            .map_id = 0,
            .event_type = 1,  // program_end
            .cpu_id = (uint8_t)cpu,
        };
        uint32_t idx = ring->write_index % ring->records_count;
        ring->records[idx] = rec;
        ring->write_index++;

        KeLowerIrql(old_irql);
    }

    return EBPF_SUCCESS;
}
```

### 7.2 Map Helper Functions

```c
static void*
_ebpf_core_map_find_element(
    ebpf_map_t* map, const uint8_t* key, ..., _In_ const void* ctx)
{
    const ebpf_program_t* program = ebpf_program_get_program_pointer(ctx);
    uint32_t program_id = program ? (uint32_t)((ebpf_core_object_t*)program)->id : 0;

    uint64_t latency_tsc = 0;
    long latency_mode = ReadNoFence(&_ebpf_latency_state.enabled);
    if (latency_mode >= EBPF_LATENCY_MODE_ALL &&
        ebpf_latency_should_track_program(program_id)) {
        latency_tsc = __rdtsc();  // Already at DISPATCH for most programs.
    }

    // --- actual helper work ---
    ebpf_result_t retval;
    uint8_t* value;
    retval = ebpf_map_find_entry(map, 0, key, sizeof(&value), (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);

    if (latency_tsc != 0) {
        uint64_t end_tsc = __rdtsc();
        uint32_t correlation_id = (uint32_t)ebpf_program_get_correlation_id(ctx);

        // Write two records: helper_start and helper_end.
        KIRQL old_irql;
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);

        uint32_t cpu = KeGetCurrentProcessorNumber();
        ebpf_latency_ring_buffer_t* ring = _ebpf_latency_state.per_cpu_buffers[cpu];
        uint16_t map_id = (uint16_t)ebpf_map_get_id(map);

        ebpf_latency_record_t start_rec = {
            .timestamp = latency_tsc,
            .correlation_id = correlation_id,
            .program_id = program_id,
            .helper_function_id = BPF_FUNC_map_lookup_elem,
            .map_id = map_id,
            .event_type = 2,  // helper_start
            .cpu_id = (uint8_t)cpu,
        };
        ebpf_latency_record_t end_rec = {
            .timestamp = end_tsc,
            .correlation_id = correlation_id,
            .program_id = program_id,
            .helper_function_id = BPF_FUNC_map_lookup_elem,
            .map_id = map_id,
            .event_type = 3,  // helper_end
            .cpu_id = (uint8_t)cpu,
        };

        uint32_t idx = ring->write_index % ring->records_count;
        ring->records[idx] = start_rec;
        ring->write_index++;
        idx = ring->write_index % ring->records_count;
        ring->records[idx] = end_rec;
        ring->write_index++;

        KeLowerIrql(old_irql);
    }

    if (retval != EBPF_SUCCESS) {
        return NULL;
    }
    return value;
}
```

### 7.3 Cost Analysis

Per-helper overhead (hot path, DISPATCH_LEVEL):

```
ReadNoFence                      ~1 ns    (latency mode check)
ebpf_latency_should_track_program ~5 ns   (filter check)
__rdtsc()                        ~7 ns    (start timestamp)
--- actual helper work ---
__rdtsc()                        ~7 ns    (end timestamp)
ebpf_program_get_correlation_id  ~1 ns    (read from context)
KeGetCurrentProcessorNumber      ~1 ns    (already at DISPATCH, inlined)
2 × struct assignment (24 B)     ~4 ns    (write to ring buffer)
2 × write_index++                ~1 ns    (plain increment)
─────────────────────────────────────
Total per-helper:               ~27 ns
```

Per program invocation (25 helpers + program start/end):

| Component | Current (ETW) | Proposed (Ring Buffer) |
|---|---|---|
| Program start/end events | ~600–1300 ns | **~30 ns** |
| 25 helper events | ~7500–16250 ns | **~675 ns** |
| Correlation ID | ~40–100 ns (InterlockedIncrement64) | **~2 ns** (plain increment) |
| **Total per invocation** | **~8–17.5 µs** | **~700 ns** |
| **Overhead as % of P50 (22 µs)** | **36–80%** | **~3%** |

---

## 8. Ring Buffer Overflow Policy

**Decision: Stop-on-full.**

When the ring buffer is full (`write_index == records_count`), new records are **dropped** and `dropped_count` is incremented. The buffer does **not** wrap. This ensures:

1. **Clean data** — User mode reads a contiguous, complete sequence of records from index 0 to `write_index - 1`. No need to handle circular wrap-around offsets.
2. **Predictable behavior** — The buffer captures the **first N events** after enabling. If the buffer fills before the user stops tracking, the `dropped_count` tells exactly how many events were lost.
3. **Simpler drain** — Records are in insertion order per-CPU. User mode can read them sequentially.

The hot-path write check becomes:

```c
if (ring->write_index < ring->records_count) {
    ring->records[ring->write_index] = *record;
    ring->write_index++;
} else {
    ring->dropped_count++;
}
```

**Sizing guidance:** With the default 100,000 records per CPU and 27 records per program invocation, the buffer holds ~3,703 invocations per CPU. At 1,200 invocations/sec/CPU, this covers ~3.1 seconds. Users should size the buffer (`events=` parameter) based on their expected workload duration.

---

## 9. Drain and Consumption

### 9.1 State Machine

Latency tracking follows a strict **start → stop → drain → free** lifecycle:

```
                  set mode=all          set mode=off
    ┌──────┐    ──────────────►    ┌──────────┐
    │  OFF │                       │ STOPPED  │
    └──────┘    ◄──────────────    └─────┬────┘
                  (after drain             │
                   completes)              │ show latencytrace
                                           │ (repeated IOCTL calls)
                                           ▼
                                    ┌──────────┐
                                    │ DRAINING │
                                    └──────────┘
```

**Key rules:**

| State | Writing to ring buffer | Reading from ring buffer | Allowed transitions |
|---|---|---|---|
| **OFF** | No | No | → ENABLED (via `set mode=all`) |
| **ENABLED** | Yes (hot path active) | **No** — drain IOCTL must fail with `EBPF_INVALID_STATE` | → STOPPED (via `set mode=off`) |
| **STOPPED** | No (writes cease immediately) | Yes (drain IOCTL allowed) | → OFF (after drain + free) |

The user **must** stop tracking before reading. This eliminates all race conditions between producers and the drain consumer — once tracking is stopped and a memory barrier is issued, no CPU will write to the ring buffers, so user mode can safely read them.

### 9.2 IOCTL: Chunked Per-CPU Drain

Since the ring buffer data can be many megabytes (100K records × 24 bytes = 2.3 MB per CPU), and the IOCTL protocol header uses `uint16_t` for length (max 65535 bytes), the drain must be **chunked**. User mode drains one chunk at a time in a loop.

#### Request

```c
typedef struct _ebpf_operation_latency_drain_request {
    ebpf_operation_header_t header;
    uint32_t cpu_index;        // Which CPU's ring buffer to drain (0-based).
    uint32_t record_offset;    // Starting record index within that CPU's buffer.
} ebpf_operation_latency_drain_request_t;
```

#### Reply

```c
typedef struct _ebpf_operation_latency_drain_reply {
    ebpf_operation_header_t header;
    uint64_t tsc_frequency;      // TSC ticks per second.
    uint64_t tsc_at_enable;      // TSC baseline.
    uint64_t qpc_at_enable;      // QPC baseline.
    uint32_t cpu_count;          // Total number of CPUs.
    uint32_t records_per_cpu;    // Configured buffer size.
    uint32_t total_records;      // write_index for this CPU (total valid records).
    uint32_t dropped_count;      // Records dropped (buffer was full).
    uint32_t records_returned;   // Number of records in this reply.
    uint32_t _padding;
    ebpf_latency_record_t records[1];  // Variable-length: up to records_returned entries.
} ebpf_operation_latency_drain_reply_t;
```

The maximum records per IOCTL reply is:
```
max_records = (65535 - sizeof(header_fields)) / sizeof(ebpf_latency_record_t)
            = (65535 - 64) / 24
            ≈ 2728 records per call
```

#### Drain Loop (User Mode)

```
for each cpu in 0..cpu_count-1:
    offset = 0
    loop:
        send drain IOCTL(cpu_index=cpu, record_offset=offset)
        receive reply with records_returned records
        append records to per-cpu output list
        offset += records_returned
        if records_returned == 0 or offset >= total_records:
            break
    write per-cpu records to file
merge-sort all per-cpu files by timestamp
write final sorted output file
```

### 9.3 User-Mode Processing Flow

The complete flow for `netsh ebpf show latencytrace`:

1. **Verify stopped:** Check that latency tracking mode is OFF (or STOPPED). If still ENABLED, print error telling user to run `set latency mode=off` first.

2. **Query metadata:** Call existing APIs to build ID → name lookup tables:
   - `ebpf_get_next_program_id` / `ebpf_get_program_info_by_id` → program names
   - `ebpf_get_next_map_id` / `ebpf_get_map_info_by_id` → map names

3. **Drain per-CPU:** For each CPU (0 to `cpu_count - 1`):
   - Issue drain IOCTLs in a loop with incrementing `record_offset`
   - Collect all records for that CPU into an in-memory vector
   - Records are already in chronological order (insertion order, since buffer is stop-on-full)

4. **Merge-sort:** Merge all per-CPU record vectors into a single globally-sorted list by `timestamp`.

5. **Write to file:** Write the sorted records to a binary file on disk:
   ```
   File header:
     magic: "EBLT" (4 bytes)
     version: 1 (uint32_t)
     tsc_frequency (uint64_t)
     tsc_at_enable (uint64_t)
     qpc_at_enable (uint64_t)
     cpu_count (uint32_t)
     total_records (uint32_t)
   Records:
     ebpf_latency_record_t[total_records]  (24 bytes each, sorted by timestamp)
   ```

6. **Display summary** (optional, after writing file):
   - Pair `PROGRAM_START` / `PROGRAM_END` events to compute per-program statistics
   - Pair `HELPER_START` / `HELPER_END` events for per-helper statistics
   - Print table with count, avg, P50, P90, P95, P99, max

### 9.4 Name Resolution

The ring buffer records contain only `program_id` and `map_id`. The user-mode consumer resolves names by calling existing APIs:

```c
// Already available in ebpf_api.h:
ebpf_result_t ebpf_get_next_program_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id);
ebpf_result_t ebpf_get_next_map_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id);
// + ebpf_get_program_info_by_id / ebpf_get_map_info_by_id for names.
```

This is done **once** at drain time, not on every event — eliminating all string manipulation from the hot path.

---

## 10. Control Plane Changes

### 10.1 Enable IOCTL

Extends the existing `EBPF_OPERATION_LATENCY_ENABLE` to accept a buffer size parameter:

```c
typedef struct _ebpf_operation_latency_enable_request {
    ebpf_operation_header_t header;
    uint32_t mode;                // 1 = program only, 2 = program + helpers
    uint32_t flags;               // Bitmask: EBPF_LATENCY_FLAG_CORRELATION_ID, etc.
    uint32_t records_per_cpu;      // Per-CPU record count (0 = default 100,000). Range: 1,000–10,000,000.
    uint32_t program_id_count;    // 0 = track all; >0 = filter list.
    uint32_t program_ids[0];      // Variable-length.
} ebpf_operation_latency_enable_request_t;
```

### 10.2 Enable Handler

```c
static ebpf_result_t
_ebpf_core_handle_latency_enable(
    _In_ const ebpf_operation_latency_enable_request_t* request)
{
    // Validate, claim session (same as current).
    // ...

    // Determine record count.
    uint32_t records_per_cpu = request->records_per_cpu;
    if (records_per_cpu == 0) {
        records_per_cpu = EBPF_LATENCY_DEFAULT_RECORDS_PER_CPU;  // Default: 100,000.
    }
    if (records_per_cpu < EBPF_LATENCY_MIN_RECORDS_PER_CPU ||
        records_per_cpu > EBPF_LATENCY_MAX_RECORDS_PER_CPU) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Allocate per-CPU ring buffers from non-paged pool.
    uint32_t cpu_count = KeQueryActiveProcessorCount(NULL);
    _ebpf_latency_state.cpu_count = cpu_count;
    _ebpf_latency_state.per_cpu_buffers = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, cpu_count * sizeof(void*), 'taLe');
    if (_ebpf_latency_state.per_cpu_buffers == NULL) {
        return EBPF_NO_MEMORY;
    }

    for (uint32_t i = 0; i < cpu_count; i++) {
        size_t alloc_size = sizeof(ebpf_latency_ring_buffer_t) +
            (size_t)records_per_cpu * sizeof(ebpf_latency_record_t);
        _ebpf_latency_state.per_cpu_buffers[i] = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            alloc_size,
            'taLe');
        if (_ebpf_latency_state.per_cpu_buffers[i] == NULL) {
            // Clean up and return EBPF_NO_MEMORY.
        }
        memset(_ebpf_latency_state.per_cpu_buffers[i], 0, alloc_size);
        _ebpf_latency_state.per_cpu_buffers[i]->records_count = records_per_cpu;
    }

    // Capture TSC calibration.
    LARGE_INTEGER freq;
    KeQueryPerformanceCounter(&freq);
    _ebpf_latency_state.tsc_frequency = freq.QuadPart;
    _ebpf_latency_state.tsc_at_enable = __rdtsc();
    _ebpf_latency_state.qpc_at_enable =
        cxplat_query_time_since_boot_precise(false);

    // Store correlation flag.
    InterlockedExchange(
        &_ebpf_latency_state.correlation_enabled,
        (request->flags & EBPF_LATENCY_FLAG_CORRELATION_ID) ? 1 : 0);

    // Enable (write-release).
    InterlockedExchange(&_ebpf_latency_state.enabled, (long)request->mode);
    return EBPF_SUCCESS;
}
```

### 10.3 Disable Handler (Stop Writes)

Disabling transitions from ENABLED → STOPPED. Writes cease but buffers are **not freed** — they remain available for drain.

```c
static ebpf_result_t
_ebpf_core_handle_latency_disable(void)
{
    // Disable tracking first — all CPUs will see this and stop writing.
    InterlockedExchange(&_ebpf_latency_state.enabled, 0);

    // Clear correlation flag.
    InterlockedExchange(&_ebpf_latency_state.correlation_enabled, 0);

    // Memory barrier to ensure all in-flight writes complete before
    // user mode starts reading.
    MemoryBarrier();

    // Do NOT free buffers here — they must remain readable for drain IOCTLs.
    // Buffers are freed when the session is fully released (after drain completes
    // or on explicit session release).

    return EBPF_SUCCESS;
}
```

### 10.3.1 Session Release (Free Buffers)

After draining (or if the user wants to abandon the data), a separate release operation frees the ring buffers:

```c
static ebpf_result_t
_ebpf_core_handle_latency_release(void)
{
    // Ensure tracking is disabled.
    InterlockedExchange(&_ebpf_latency_state.enabled, 0);

    // Free per-CPU ring buffers.
    if (_ebpf_latency_state.per_cpu_buffers != NULL) {
        for (uint32_t i = 0; i < _ebpf_latency_state.cpu_count; i++) {
            if (_ebpf_latency_state.per_cpu_buffers[i] != NULL) {
                ebpf_free(_ebpf_latency_state.per_cpu_buffers[i]);
            }
        }
        ebpf_free(_ebpf_latency_state.per_cpu_buffers);
        _ebpf_latency_state.per_cpu_buffers = NULL;
    }

    _ebpf_latency_state.cpu_count = 0;
    _ebpf_latency_state.records_per_cpu = 0;

    // Release the session — allows a new session to start.
    InterlockedExchange(&_ebpf_latency_state.session_active, 0);
    return EBPF_SUCCESS;
}
```

> **Note:** The netsh `set latency mode=off` command should: (1) disable writes, (2) drain all data, (3) write to file, (4) release the session. Alternatively, the user can stop now, drain later, and release explicitly.

### 10.4 Netsh CLI Commands

| Command | Description |
|---------|-------------|
| `netsh ebpf set latency mode=all [...]` | **Start** tracking. Allocates per-CPU ring buffers. |
| `netsh ebpf set latency mode=off` | **Stop** tracking. Writes cease. Buffers preserved for drain. |
| `netsh ebpf show latencytrace [file=<path>]` | **Drain** per-CPU ring buffers via chunked IOCTLs, merge-sort by timestamp, write to file, display summary, then release session. Fails if tracking is still enabled. When `file=*.etl`, parses ETL instead (legacy). |

**Complete workflow:**

```bash
# 1. Start tracking
netsh ebpf set latency mode=all correlation=yes events=500000

# 2. Run workload for desired duration...

# 3. Stop tracking (writes stop, buffers preserved)
netsh ebpf set latency mode=off

# 4. Drain, sort, write to file, display summary, release session
netsh ebpf show latencytrace file=latency_data.bin
```

**Why stop and drain are separate commands:**

1. **Stop must be fast** — runs while workload is active, returns immediately.
2. **Drain can be slow** — reads millions of records, merge-sorts, writes to disk.
3. **User controls timing** — stop at the precise moment, drain at leisure.

---

## 11. Interaction with Existing ETW Path

The ring buffer approach **replaces** the inline `TraceLoggingWrite` calls for latency events. However, the existing ETW infrastructure remains for:

- Diagnostic/error logging (`EBPF_TRACELOG_KEYWORD_ERROR`, etc.).
- Non-latency operational events.

The `EBPF_TRACELOG_KEYWORD_LATENCY` keyword is retained. If both ring buffer and ETW are desired simultaneously (e.g., for correlation with other ETW providers), the enable request can include a flag:

```c
#define EBPF_LATENCY_FLAG_ALSO_ETW 0x4  // Emit to both ring buffer and ETW.
```

When this flag is set, the hot path writes to the ring buffer AND emits the ETW event. This is opt-in and understood to have higher overhead.

---

## 12. Thread Safety Summary

| Operation | IRQL | Synchronization |
|-----------|------|-----------------|
| Ring buffer write (DISPATCH) | DISPATCH_LEVEL | **None** — single-producer per CPU, stop-on-full. |
| Ring buffer write (PASSIVE) | Raised to DISPATCH | **ebpf_raise_irql** — prevents preemption. |
| Correlation ID increment | DISPATCH_LEVEL | **None** — per-CPU counter. |
| Enable (start) | PASSIVE_LEVEL | `InterlockedCompareExchange` on `session_active`. |
| Disable (stop writes) | PASSIVE_LEVEL | `InterlockedExchange` on `enabled` + `MemoryBarrier`. |
| Drain (read records) | PASSIVE_LEVEL | **Safe** — only allowed after stop. No concurrent writers. |
| Release (free buffers) | PASSIVE_LEVEL | Only after drain completes. Releases `session_active`. |

---

## 13. Memory Requirements

| Configuration | Per-CPU Buffer | 8 CPUs | 64 CPUs | Coverage at 1,200 inv/sec |
|---|---|---|---|---|
| Small (10K records) | ~234 KB | ~1.8 MB | ~14.6 MB | ~0.3 s |
| **Default (100K records)** | **~2.3 MB** | **~18.3 MB** | **~146.5 MB** | **~3.1 s** |
| Large (1M records) | ~22.9 MB | ~183 MB | ~1.4 GB | ~30.9 s |
| Max (10M records) | ~229 MB | ~1.8 GB | ~14.3 GB | ~309 s |

All allocated from non-paged pool (required for DISPATCH_LEVEL access). Memory is allocated at enable time and freed at disable time — zero cost when latency tracking is off.

---

## 14. Implementation Plan

| Phase | Work Items |
|-------|-----------|
| **Phase 1: Ring buffer core** | Define `ebpf_latency_record_t` and `ebpf_latency_ring_buffer_t`. Implement per-CPU allocation/deallocation. Implement `ebpf_latency_write_record()` with IRQL handling. |
| **Phase 2: Per-CPU correlation ID** | Replace `InterlockedIncrement64` with per-CPU `(cpu_id << 24) | seq++`. Update `ebpf_program_set_correlation_id` / `ebpf_program_get_correlation_id` to use `uint32_t`. |
| **Phase 3: Replace ETW emission** | Replace `ebpf_latency_emit_program_event()` and `ebpf_latency_emit_helper_event()` with ring buffer writes. Switch from `cxplat_query_time_since_boot_precise` to `__rdtsc()`. Remove string name parameters from helper signatures. Add `map_id` lookup (via `ebpf_map_get_id()`). |
| **Phase 4: Drain IOCTL** | Implement `EBPF_OPERATION_LATENCY_DRAIN` handler. Copy per-CPU buffers to user-mode output buffer. Include TSC calibration data in reply. |
| **Phase 5: User-mode consumer** | Update `netsh ebpf show latencytrace` to drain ring buffers, resolve IDs to names, merge-sort by timestamp, compute statistics. |
| **Phase 6: Safe disable** | Integrate with ebpfcore epoch mechanism or use `KeFlushQueuedDpcs()` to ensure all in-flight producers complete before freeing ring buffers. |

---

## 15. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| **`rdtsc` not invariant on exotic hardware** | Check `CPUID.80000007H:EDX[8]` at enable time; fall back to QPC. |
| **Buffer overflow at very high event rates** | Circular overwrite ensures most recent data is always available. User can increase buffer size. `dropped_count` provides diagnostics. |
| **Race on disable (free while writer in-flight)** | Use `KeFlushQueuedDpcs()` + epoch mechanism before freeing buffers. |
| **Passive-level programs may see cross-CPU events** | Correlation ID still links events. Consumer merges by correlation_id, not by CPU. |
| **Non-paged pool pressure** | Default 256 KB/CPU is modest. Free immediately on disable. Support configurable size. |
| **24-bit per-CPU correlation ID wrap** | 16.7M IDs per CPU. At 1,200 invocations/sec, wraps after ~3.9 hours. Sufficient for diagnostic sessions. Consumer detects wrap by checking for non-monotonic IDs. |

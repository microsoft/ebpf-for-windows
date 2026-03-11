# Latency Tracking Design — Solving Ring Buffer Drops Under Skewed CPU Load

## 1. Problem Statement

The current per-CPU ring buffer design allocates `records_per_cpu` slots (default 100K) to each CPU with **stop-on-full** semantics. Network workloads are rarely evenly distributed — interrupt affinity, RSS, and flow steering concentrate traffic on a subset of CPUs. The "hot" CPUs fill their buffers and start dropping while "cold" CPUs' buffers sit nearly empty.

**Example** on an 8-CPU system with 800K total capacity (100K × 8):

| CPUs | Traffic share | Records captured | Buffer state |
|------|--------------|-----------------|--------------|
| 0–2 | ~95% | 100K each (capped) | **Full — drops begin** |
| 3–7 | ~5% | ~5K each | **~485K slots wasted** |

Increasing `records_per_cpu` helps but scales memory linearly across *all* CPUs, most of which don't need it.

### 1.1 Current Architecture (Summary)

- **Per-CPU ring buffers** — one independent linear buffer per processor.
- **Stop-on-full** — when `write_index >= records_count`, the record is dropped and `dropped_count` is incremented.
- **No drain-while-active** — buffers are drained only after tracking is disabled (`EBPF_BLOCKED_BY_POLICY` otherwise).
- **Zero synchronization on fast path** — at DISPATCH_LEVEL the per-CPU write is a plain store (~4 ns), no atomics.

---

## 2. Design Options

### 2.1 Design A: Shared Overflow Pool (Hybrid Per-CPU + Global)

**Concept:** Keep per-CPU primary buffers for the zero-synchronization fast path, but add a single shared overflow buffer that hot CPUs spill into when their primary fills.

```
 CPU 0 [primary: 32K slots]──┐
 CPU 1 [primary: 32K slots]──┤──overflow──▶ [shared: 512K slots]
 CPU 2 [primary: 32K slots]──┤              (InterlockedIncrement
 ...                          │               reservation)
 CPU 7 [primary: 32K slots]──┘
```

#### Write Path (Pseudo-Code)

```c
void write_record(record) {
    raise_irql(DISPATCH);
    cpu = get_current_cpu();
    ring = per_cpu_buffers[cpu];

    if (ring->write_index < ring->records_count) {
        // Fast path: per-CPU, no atomics. Cost: ~4 ns.
        ring->records[ring->write_index++] = *record;
    } else if (overflow_buffer != NULL) {
        // Slow path: shared buffer, one atomic. Cost: ~15–40 ns.
        uint32_t slot = InterlockedIncrement(&overflow->write_index) - 1;
        if (slot < overflow->records_count) {
            overflow->records[slot] = *record;
        } else {
            InterlockedIncrement(&overflow->dropped_count);
        }
    } else {
        ring->dropped_count++;
    }
    lower_irql(old_irql);
}
```

#### Properties

| Aspect | Value |
|--------|-------|
| **Fast-path overhead** | **Unchanged (~4 ns)** — identical to current per-CPU path |
| **Overflow-path overhead** | ~15–40 ns (one `InterlockedIncrement` for slot reservation) |
| **Memory efficiency** | Configurable: small per-CPU (32K) + large shared (512K) = same total, better utilization |
| **Drain complexity** | Drain per-CPU buffers + one overflow buffer, then merge-sort |
| **Implementation complexity** | **Low** — only the write function changes + one extra buffer allocation |

#### Why This Works for Overhead

95%+ of records in a balanced run still hit the per-CPU fast path. The overflow path only fires after a CPU's primary fills — and even at ~30 ns, it's still 10–20× cheaper than ETW.

#### Configuration

```
set latency mode=all records_per_cpu=32000 overflow_records=512000
```

Or auto-compute: `overflow_records = cpu_count × records_per_cpu / 2`.

---

### 2.2 Design B: Circular Buffers with Async Continuous Drain

**Concept:** Convert the current stop-on-full linear buffers into true circular ring buffers with a `read_index`. Allow draining while tracking is still active. A user-mode polling thread (or kernel work item) continuously consumes records before they're overwritten.

#### Data Structure Change

```c
typedef struct _ebpf_latency_ring_buffer {
    volatile uint32_t write_index;   // Monotonically increasing (writer, owning CPU only).
    volatile uint32_t read_index;    // Monotonically increasing (reader, single consumer).
    volatile uint32_t dropped_count;
    uint32_t records_count;          // Power-of-2 for fast modulo.
    uint8_t _padding[64 - 16];
    ebpf_latency_record_t records[]; // Circular: index % records_count.
} ebpf_latency_ring_buffer_t;
```

#### Write Path

```c
void write_record(record) {
    raise_irql(DISPATCH);
    cpu = get_current_cpu();
    ring = per_cpu_buffers[cpu];

    // Check if buffer is full: (write - read) >= capacity.
    if ((ring->write_index - ring->read_index) < ring->records_count) {
        uint32_t slot = ring->write_index & (ring->records_count - 1);  // Bitwise AND (power-of-2).
        ring->records[slot] = *record;
        // Compiler barrier — x86 TSO provides store ordering for free.
        WriteNoFence(&ring->write_index, ring->write_index + 1);
    } else {
        ring->dropped_count++;
    }
    lower_irql(old_irql);
}
```

#### Consumer (Reader) — Two Sub-Options

**B1: User-mode polling thread**

```
Thread in eBPFSvc or netsh:
  loop every 10–50 ms:
    for each cpu 0..N-1:
      IOCTL_DRAIN(cpu, read_index)   // Returns records from read_index to write_index.
      write records to memory-mapped file or append to output
      advance read_index via IOCTL or shared memory
```

**B2: Kernel work item with watermark trigger**

```c
// In write_record, after successful write:
uint32_t fill = ring->write_index - ring->read_index;
if (fill >= ring->records_count * 3 / 4 && !ring->flush_pending) {
    ring->flush_pending = 1;
    queue_work_item(flush_ring_buffer, cpu);  // Runs at PASSIVE_LEVEL.
}
```

The work item copies records to a staging buffer and signals user mode (via event or completion port).

#### Properties

| Aspect | Value |
|--------|-------|
| **Write-path overhead** | **~5–6 ns** — one extra subtraction + comparison vs current ~4 ns |
| **Capacity** | **Effectively unlimited** for steady-state drain rate > write rate |
| **Drops only when** | Consumer can't keep up (burst > buffer size between drain intervals) |
| **Memory** | Same as current (or smaller, since continuous drain empties buffers) |
| **Implementation complexity** | **Medium** — circular index logic, drain-while-active IOCTL, consumer thread |
| **`records_count` constraint** | Must be power-of-2 (for fast `& (count - 1)` instead of `%`) |

#### Memory Ordering on x86 (Critical Correctness Note)

- **Writer:** store record, then store `write_index`. x86 TSO guarantees stores are visible in program order. A compiler barrier (`_ReadWriteBarrier()` / `MemoryBarrier()`) suffices — no hardware fence needed.
- **Reader:** read `write_index`, then read records. x86 TSO guarantees loads are visible in program order. Compiler barrier suffices.
- **SPSC guarantee:** Single-producer (owning CPU at DISPATCH) / single-consumer (drain thread) — **no CAS or interlocked operations needed**.

---

### 2.3 Design C: Double-Buffer Ping-Pong with Background Flush

**Concept:** Each CPU has two buffers. The writer fills the "active" buffer. When it's full (or a timer fires), atomically swap to the standby buffer and queue a flush of the just-filled buffer.

```
CPU 0:  [Buffer A ← active] [Buffer B ← standby/flushing]
         write_index: 87432   state: being drained to disk

         ──── buffer A fills ────
         swap: active → B, queue flush(A)

CPU 0:  [Buffer A ← flushing] [Buffer B ← active]
```

#### Write Path

```c
void write_record(record) {
    raise_irql(DISPATCH);
    cpu = get_current_cpu();
    ring = active_buffers[cpu];  // Single volatile pointer read.

    if (ring->write_index < ring->records_count) {
        ring->records[ring->write_index++] = *record;
    } else {
        // Active buffer full — try to swap.
        ebpf_latency_ring_buffer_t* standby = standby_buffers[cpu];
        if (standby != NULL && standby->state == BUFFER_READY) {
            // Swap active ↔ standby.
            active_buffers[cpu] = standby;
            standby_buffers[cpu] = ring;
            ring->state = BUFFER_FLUSHING;
            queue_work_item(flush_buffer, ring);  // PASSIVE_LEVEL flush.
            // Write to new active buffer.
            standby->records[standby->write_index++] = *record;
        } else {
            // Both buffers full (flush can't keep up). Drop.
            ring->dropped_count++;
        }
    }
    lower_irql(old_irql);
}
```

#### Flush Work Item (Runs at PASSIVE_LEVEL)

```c
void flush_buffer(ring) {
    // Write ring->records[0..write_index] to file or user-mode staging area.
    write_to_file_or_staging(ring->records, ring->write_index);
    ring->write_index = 0;
    ring->state = BUFFER_READY;  // Available for reuse.
}
```

#### Properties

| Aspect | Value |
|--------|-------|
| **Fast-path overhead** | **~4 ns** — identical to current (same linear write) |
| **Swap-path overhead** | ~50–100 ns (pointer swap + work item queue, **amortized to ~0** since it happens once per buffer fill) |
| **Capacity** | Unlimited if flush rate > fill rate; 2× buffer otherwise |
| **Memory** | 2× current per-CPU allocation (two buffers per CPU) |
| **Implementation complexity** | **Medium-High** — buffer state machine, work item management, file I/O |
| **File output** | Produces append-only binary stream (records in chronological order within each CPU) |

---

## 3. Comparison Matrix

| Criterion | A: Hybrid Overflow | B: Circular + Async Drain | C: Double-Buffer Ping-Pong |
|-----------|-------------------|--------------------------|---------------------------|
| **Hot-path overhead** | ~4 ns (same) | ~5–6 ns (+1–2 ns) | ~4 ns (same) |
| **Solves uneven CPU fill** | **Yes** — overflow absorbs skew | **Yes** — continuous drain prevents fill | Partial — 2× capacity per CPU, still finite |
| **Continuous tracing** | No — still stop-on-full (larger total) | **Yes** — drain while active | **Yes** — flush while active |
| **Implementation effort** | **Low** — minimal code change | Medium | Medium-High |
| **Memory efficiency** | Good — shared pool | **Best** — buffers turn over | Worst — 2× per-CPU |
| **Ordering** | Merge per-CPU + overflow | Merge per-CPU streams | Merge per-CPU flush segments |
| **Kernel file I/O needed** | No | Optional (B2 only) | Yes (or user-mode staging) |

---

## 4. Recommendation: Combine A + B (Phased)

### Phase 1 — Shared Overflow Pool (Design A)

This is the **lowest-effort, highest-impact** change. It directly addresses the "hot CPUs fill, cold CPUs waste" problem with minimal hot-path overhead change.

- Reduce per-CPU default to ~32K records.
- Add a shared overflow buffer of ~512K records.
- The fast path is **byte-for-byte identical** to today.
- Only the overflow path (which fires rarely) uses one `InterlockedIncrement`.

### Phase 2 — Circular Buffers with Async Drain (Design B)

This enables **indefinite-duration tracing** without any drops, which is the real end-state goal.

The circular + SPSC (single-producer single-consumer) design adds ~1–2 ns to the write path (one extra subtraction for fullness check) but eliminates drops entirely when the user-mode consumer keeps up.

**Key design property:** No interlocked operations in the writer — the SPSC ring between one CPU (producer at DISPATCH) and one drain thread (consumer at PASSIVE) needs only compiler barriers on x86.

#### Phase 2 — Implementation Steps

1. Change `records_count` to power-of-2 (round up at allocation).
2. Add `read_index` to the ring buffer struct.
3. Change write from `write_index++` to slot access via bitmask `& (records_count - 1)`.
4. Check `(write_index - read_index) < records_count` instead of `write_index < records_count`.
5. Remove `EBPF_BLOCKED_BY_POLICY` guard in drain IOCTL — allow drain while active.
6. Add a user-mode drain thread in `ebpfsvc` that polls every 20–50 ms and writes to a binary file.
7. Consumer advances `read_index` after consuming — single atomic store visible to the writer.

### Why Not Design C?

Design C (double-buffer ping-pong) provides **no advantage over B** while using 2× memory and requiring more complex state management. The ping-pong swap at buffer-full time is also marginally more expensive than the continuous circular approach since it requires a work item queue per swap.

# eBPF Latency Tracking Design (ETW-Based)

## 1. Overview

This document proposes a latency tracking subsystem for **ebpfcore** that measures:

1. **Program invocation latency** — time spent inside `ebpf_program_invoke()`.
2. **Map helper function latency** — time spent inside map-related helper functions (`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`, etc.).

Latency data is emitted as **ETW (Event Tracing for Windows)** events, leveraging the existing `TraceLogging` infrastructure in ebpfcore. This provides standard tooling integration (WPA, tracelog, xperf) and easy correlation with other ETW providers in the Windows networking stack.

The design is also forward-looking: the same mechanism can be extended to **eBPF extensions** (e.g., `netebpfext`) to capture end-to-end latency across the entire call chain.

---

## 2. Requirements

| # | Requirement |
|---|---|
| R1 | Latency tracking is **off by default** and enabled on demand via `netsh ebpf`. |
| R2 | Granularity is selectable: **program-invocation only**, or **program-invocation + map helpers**. |
| R3 | Per-event data: process ID, thread ID, start timestamp, end timestamp, delta (end − start). |
| R4 | Data is keyed by **program ID** (and additionally by **helper function ID** for map helpers). |
| R5 | Overhead when disabled must be near-zero (single global flag check). |
| R6 | The mechanism must work at **DISPATCH_LEVEL** (program invoke runs at IRQL ≤ DISPATCH). |
| R7 | Extensible to eBPF extensions to produce end-to-end latency data. |

---

## 3. Design Rationale: ETW Events

| Pros | Cons |
|------|------|
| Standard Windows tracing infrastructure; consumable by WPA, tracelog, xperf, perfview. | `TraceLoggingWrite` adds ~200–500 ns per event at DISPATCH_LEVEL. |
| No memory management needed; OS handles buffering and disk I/O. | At very high call rates (millions of invocations/sec), ETW can **drop events**. |
| Easy correlation with other ETW providers (networking stack, WFP, NDIS, TCPIP, etc.). | A consumer (trace session) must be active at capture time. |
| Structured events with typed fields; automatic decoding by standard tools. | |
| No custom flush/drain mechanism needed. | |
| Two-level gating (global flag + `TraceLoggingProviderEnabled`) eliminates overhead when no session is listening. | |

**Mitigation for event drops at high rates:**
- Use a large ETW buffer size (e.g., 256 MB) and high number of buffers when enabling the trace session.
- Use **real-time** mode with a fast consumer, or log directly to an `.etl` file on a fast disk.
- Provide netsh helper commands to start/stop well-configured trace sessions automatically.

---

## 4. Architecture

```
                                   ┌─────────────────────────┐
                                   │    ETW Consumer          │
                                   │  (WPA / tracelog / CLI)  │
                                   └──────────▲──────────────┘
                                              │ ETW events
┌─────────────┐  netsh ebpf set   ┌───────────┴──────────────┐
│  netsh CLI   │ ──── IOCTL ────▶ │        ebpfcore           │
│  (user mode) │                  │        (kernel)           │
└─────────────┘                  └───────────┬──────────────┘
                                              │
                              ┌───────────────┤
                              ▼               ▼
                    ┌──────────────┐  ┌──────────────────────┐
                    │  ETW Provider │  │  ebpf_program_invoke │
                    │  TraceLogging │◀─│  Map helper wrappers │
                    └──────────────┘  └──────────────────────┘
```

### 4.1 Key Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `ebpf_latency` | `libs/execution_context/ebpf_latency.h/.c` (new) | Global enable/disable state, ETW event emission helpers. |
| Program invoke instrumentation | `ebpf_program.c` — `ebpf_program_invoke()` | Bracket the invocation with timestamp capture and ETW event when tracking is enabled. |
| Map helper instrumentation | `ebpf_core.c` — `_ebpf_core_map_find_element()` etc. | Bracket each map helper with timestamp capture and ETW event when helper-level tracking is enabled. |
| IOCTL handler | `ebpf_core.c` — new operation handlers | Handle enable/disable IOCTLs. |
| Protocol definitions | `ebpf_protocol.h` | New `EBPF_OPERATION_LATENCY_*` IDs and request/reply structs. |
| User-mode API | `ebpf_api.h` / `ebpf_api.cpp` | Thin wrappers around the new IOCTLs. |
| Netsh commands | `tools/netsh/` (new file `latency.c`) | `set latency`, `show latency`, `start latencytrace`, `stop latencytrace` commands. |

---

## 5. Data Structures

### 5.1 ETW Event Payload (Logical Record)

Each ETW event carries the following fields via TraceLogging. There is no fixed C struct stored in memory — the fields are written directly into the ETW event payload by `TraceLoggingWrite`:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `ProgramId` | `uint32_t` | 4 B | `ebpf_core_object_t.id` of the program |
| `HelperFunctionId` | `uint32_t` | 4 B | 0 for program invoke; `BPF_FUNC_xxx` for map helpers |
| `ProcessId` | `uint32_t` | 4 B | Calling process ID |
| `ThreadId` | `uint32_t` | 4 B | Calling thread ID |
| `StartTime` | `uint64_t` | 8 B | `cxplat_query_time_since_boot_precise()`, 100-ns units |
| `EndTime` | `uint64_t` | 8 B | Same units |
| `Duration` | `uint64_t` | 8 B | `EndTime - StartTime` (100-ns units) |
| `CpuId` | `uint8_t` | 1 B | Processor number |
| `Irql` | `uint8_t` | 1 B | IRQL at invocation time |

**User payload per event: 42 bytes** (before ETW header overhead).

ETW adds its own per-event header (~80 bytes, includes timestamp, process/thread ID, provider GUID, activity ID, etc.). The total per-event cost in the ETW buffer is approximately **~128 bytes**.

> **Note:** Since ETW already captures ProcessId, ThreadId, and a system timestamp in its event header, the `ProcessId`, `ThreadId`, and `EndTime` fields are technically redundant. However, including them explicitly simplifies consumer-side parsing and allows the latency record to be self-contained. As an optimization, these fields could be removed to reduce the payload to **26 bytes**, relying on the ETW header instead.

### 5.2 ETW Provider and Keyword

Reuse the existing ebpfcore TraceLogging provider with a new keyword:

```c
// In ebpf_tracelog.h or ebpf_latency.h
#define EBPF_TRACELOG_KEYWORD_LATENCY  0x800   // New keyword for latency events
```

Two event IDs (logically distinguished by the `HelperFunctionId` field):
- **`EbpfProgramLatency`** — emitted per program invocation.
- **`EbpfMapHelperLatency`** — emitted per map helper call.

### 5.3 Global Latency State

```c
typedef struct _ebpf_latency_state {
    volatile long enabled;   // 0 = off, 1 = program only, 2 = program + helpers
} ebpf_latency_state_t;

static ebpf_latency_state_t _ebpf_latency_state = {0};
```

A single `ReadNoFence(&_ebpf_latency_state.enabled)` check in the hot path ensures **zero overhead** when tracking is disabled. No memory allocation is needed — the OS ETW infrastructure handles all buffering.

---

## 6. Hot-Path Instrumentation

### 6.1 Program Invocation (`ebpf_program_invoke`)

```c
_Must_inspect_result_ ebpf_result_t
ebpf_program_invoke(
    _In_ const ebpf_program_t* program,
    _Inout_ void* context,
    _Out_ uint32_t* result,
    _Inout_ ebpf_execution_context_state_t* execution_state)
{
    // --- existing early-exit checks ---

    uint64_t latency_start = 0;
    long latency_mode = ReadNoFence(&_ebpf_latency_state.enabled);
    if (latency_mode > 0) {
        latency_start = cxplat_query_time_since_boot_precise(false);
    }

    // --- existing program invocation + tail call loop ---

    if (latency_mode > 0) {
        uint64_t latency_end = cxplat_query_time_since_boot_precise(false);
        ebpf_latency_emit_program_event(program, latency_start, latency_end);
    }

    return EBPF_SUCCESS;
}
```

**Cost when disabled:** A single `ReadNoFence` of a cache-line-aligned global — effectively **one L1 cache hit** (~1 ns).

### 6.2 Map Helper Functions (`_ebpf_core_map_find_element`, etc.)

Wrap each map helper with a latency measurement only when `latency_mode >= 2`:

```c
static void*
_ebpf_core_map_find_element(ebpf_map_t* map, const uint8_t* key)
{
    uint64_t latency_start = 0;
    long latency_mode = ReadNoFence(&_ebpf_latency_state.enabled);
    if (latency_mode >= 2) {
        latency_start = cxplat_query_time_since_boot_precise(false);
    }

    // --- existing logic ---
    ebpf_result_t retval;
    uint8_t* value;
    retval = ebpf_map_find_entry(map, 0, key, sizeof(&value), (uint8_t*)&value, EBPF_MAP_FLAG_HELPER);

    if (latency_mode >= 2) {
        uint64_t latency_end = cxplat_query_time_since_boot_precise(false);
        ebpf_latency_emit_helper_event(
            map,
            BPF_FUNC_map_lookup_elem,
            latency_start,
            latency_end);
    }

    if (retval != EBPF_SUCCESS) {
        return NULL;
    }
    return value;
}
```

### 6.3 ETW Event Emission

```c
static inline void
ebpf_latency_emit_program_event(
    _In_ const ebpf_program_t* program,
    uint64_t start_time,
    uint64_t end_time)
{
    uint32_t program_id = ((const ebpf_core_object_t*)program)->id;
    uint32_t process_id = (uint32_t)(uintptr_t)PsGetCurrentProcessId();
    uint32_t thread_id  = (uint32_t)(uintptr_t)PsGetCurrentThreadId();
    uint64_t duration   = end_time - start_time;
    uint8_t  cpu_id     = (uint8_t)ebpf_get_current_cpu();
    uint8_t  irql       = (uint8_t)KeGetCurrentIrql();

    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "EbpfProgramLatency",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_LATENCY),
        TraceLoggingUInt32(program_id, "ProgramId"),
        TraceLoggingUInt32(0, "HelperFunctionId"),
        TraceLoggingUInt32(process_id, "ProcessId"),
        TraceLoggingUInt32(thread_id, "ThreadId"),
        TraceLoggingUInt64(start_time, "StartTime"),
        TraceLoggingUInt64(end_time, "EndTime"),
        TraceLoggingUInt64(duration, "Duration"),
        TraceLoggingUInt8(cpu_id, "CpuId"),
        TraceLoggingUInt8(irql, "Irql"));
}

static inline void
ebpf_latency_emit_helper_event(
    _In_ const ebpf_map_t* map,
    uint32_t helper_function_id,
    uint64_t start_time,
    uint64_t end_time)
{
    // Resolve owning program ID from map (or pass program_id directly if available)
    uint32_t program_id = ebpf_map_get_program_id(map);
    uint32_t process_id = (uint32_t)(uintptr_t)PsGetCurrentProcessId();
    uint32_t thread_id  = (uint32_t)(uintptr_t)PsGetCurrentThreadId();
    uint64_t duration   = end_time - start_time;
    uint8_t  cpu_id     = (uint8_t)ebpf_get_current_cpu();
    uint8_t  irql       = (uint8_t)KeGetCurrentIrql();

    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "EbpfMapHelperLatency",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_LATENCY),
        TraceLoggingUInt32(program_id, "ProgramId"),
        TraceLoggingUInt32(helper_function_id, "HelperFunctionId"),
        TraceLoggingUInt32(process_id, "ProcessId"),
        TraceLoggingUInt32(thread_id, "ThreadId"),
        TraceLoggingUInt64(start_time, "StartTime"),
        TraceLoggingUInt64(end_time, "EndTime"),
        TraceLoggingUInt64(duration, "Duration"),
        TraceLoggingUInt8(cpu_id, "CpuId"),
        TraceLoggingUInt8(irql, "Irql"));
}
```

### 6.4 Two-Level Gating for Minimal Overhead

The hot path has two levels of gating:

1. **Level 1 — Global flag (`ReadNoFence`):** Skips everything when latency is disabled. Cost: ~1 ns.
2. **Level 2 — `TraceLoggingProviderEnabled` (implicit in `TraceLoggingWrite`):** Even if the global flag is set, `TraceLoggingWrite` exits early if no ETW session is actively listening with the `EBPF_TRACELOG_KEYWORD_LATENCY` keyword. Cost: ~5–10 ns.

This means:
- **Tracking disabled:** ~1 ns overhead (flag check only).
- **Tracking enabled, no ETW session:** ~10 ns overhead (flag check + provider-enabled check + timestamp).
- **Tracking enabled, ETW session active:** ~200–500 ns overhead (full event emission).

> **Note:** To avoid the ~10 ns overhead when no ETW session is active, the global flag should only be set to non-zero when both the IOCTL enable command is received AND an ETW session is listening. Alternatively, use an `EventEnabled` macro check before acquiring the timestamp.

Optimized pattern:

```c
long latency_mode = ReadNoFence(&_ebpf_latency_state.enabled);
if (latency_mode > 0 &&
    TraceLoggingProviderEnabled(ebpf_tracelog_provider,
                                WINEVENT_LEVEL_VERBOSE,
                                EBPF_TRACELOG_KEYWORD_LATENCY)) {
    latency_start = cxplat_query_time_since_boot_precise(false);
}
```

---

## 7. Control Plane

### 7.1 New IOCTL Operations

Add to `ebpf_protocol.h`:

```c
typedef enum _ebpf_operation_id
{
    // ... existing ...
    EBPF_OPERATION_LATENCY_ENABLE,        // Enable latency tracking
    EBPF_OPERATION_LATENCY_DISABLE,       // Disable latency tracking
} ebpf_operation_id_t;
```

#### Request/Reply Structures

```c
typedef struct _ebpf_operation_latency_enable_request {
    ebpf_operation_header_t header;
    uint32_t mode;            // 1 = program only, 2 = program + helpers
} ebpf_operation_latency_enable_request_t;

typedef struct _ebpf_operation_latency_enable_reply {
    ebpf_operation_header_t header;
} ebpf_operation_latency_enable_reply_t;

typedef struct _ebpf_operation_latency_disable_request {
    ebpf_operation_header_t header;
} ebpf_operation_latency_disable_request_t;

typedef struct _ebpf_operation_latency_disable_reply {
    ebpf_operation_header_t header;
} ebpf_operation_latency_disable_reply_t;
```

No flush IOCTL is needed — ETW handles data delivery to the consumer.

### 7.2 Netsh Commands

New file: `tools/netsh/latency.c`

| Command | Description |
|---------|-------------|
| `netsh ebpf set latency mode=program` | Enable program-invocation-only tracking (sets global flag). |
| `netsh ebpf set latency mode=all` | Enable program + map helper tracking. |
| `netsh ebpf set latency mode=off` | Disable tracking. |
| `netsh ebpf start latencytrace [file=<path>] [buffersize=<MB>]` | Start an ETW trace session pre-configured for latency events. |
| `netsh ebpf stop latencytrace` | Stop the ETW trace session and save to `.etl` file. |
| `netsh ebpf show latencytrace file=<path.etl>` | Parse and display latency records from an `.etl` file. |

The `start latencytrace` command wraps the equivalent of:

```batch
tracelog -start EbpfLatency -guid #<ebpf-provider-guid> -flags 0x800 -level 5 -b 256 -f latency.etl
```

This provides a turnkey experience — users don't need to know ETW details.

### 7.3 User-Mode API

```c
// In ebpf_api.h
ebpf_result_t ebpf_latency_enable(uint32_t mode);
ebpf_result_t ebpf_latency_disable(void);
```

These are thin wrappers around the IOCTLs. No flush/read API is needed since data flows through ETW.

Registration in `dllmain.c`:

```c
CMD_ENTRY_LONG g_EbpfSetCommandTableLong[] = {
    // ... existing ...
    CREATE_CMD_ENTRY_LONG(EBPF_SET_LATENCY, handle_ebpf_set_latency),
};
CMD_ENTRY_LONG g_EbpfStartCommandTableLong[] = {
    // ... existing or new group ...
    CREATE_CMD_ENTRY_LONG(EBPF_START_LATENCYTRACE, handle_ebpf_start_latencytrace),
};
CMD_ENTRY_LONG g_EbpfStopCommandTableLong[] = {
    CREATE_CMD_ENTRY_LONG(EBPF_STOP_LATENCYTRACE, handle_ebpf_stop_latencytrace),
};
CMD_ENTRY_LONG g_EbpfShowCommandTableLong[] = {
    // ... existing ...
    CREATE_CMD_ENTRY_LONG(EBPF_SHOW_LATENCYTRACE, handle_ebpf_show_latencytrace),
};
```

---

## 8. Extension Integration for End-to-End Latency

### 8.1 Problem

For networking scenarios, the overall latency includes:
1. **Extension time** (e.g., `netebpfext` WFP classify → prepare context).
2. **ebpfcore time** (program invocation + map helpers).
3. **Extension time** (post-invocation processing, verdict application).

Currently, the extension calls `invoke_program()` which is opaque — the extension doesn't know the internal ebpfcore latency.

### 8.2 Proposed Extension-Side Instrumentation

Extensions already have well-defined invoke points. For example, in `net_ebpf_ext_hook_provider.c`:

```c
__forceinline static ebpf_result_t
_net_ebpf_extension_hook_invoke_single_program(
    _In_ const net_ebpf_extension_hook_client_t* client,
    _Inout_ void* context,
    _Out_ uint32_t* result)
{
    uint64_t ext_start = 0, ext_end = 0;
    long latency_mode = ReadNoFence(&_net_ebpf_ext_latency_enabled);
    if (latency_mode > 0 &&
        TraceLoggingProviderEnabled(net_ebpf_ext_tracelog_provider,
                                    WINEVENT_LEVEL_VERBOSE,
                                    EBPF_TRACELOG_KEYWORD_LATENCY)) {
        ext_start = cxplat_query_time_since_boot_precise(false);
    }

    ebpf_result_t ret = client->invoke_program(
        client->client_binding_context, context, result);

    if (ext_start != 0) {
        ext_end = cxplat_query_time_since_boot_precise(false);
        net_ebpf_ext_latency_emit_event(client, ext_start, ext_end);
    }
    return ret;
}
```

### 8.3 Extension ETW Event

The extension emits its own ETW event with a structured payload:

```c
TraceLoggingWrite(
    net_ebpf_ext_tracelog_provider,
    "NetEbpfExtInvokeLatency",
    TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
    TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_LATENCY),
    TraceLoggingUInt32(program_id, "ProgramId"),
    TraceLoggingUInt32(hook_type, "HookType"),
    TraceLoggingUInt32(process_id, "ProcessId"),
    TraceLoggingUInt32(thread_id, "ThreadId"),
    TraceLoggingUInt64(ext_start_time, "ExtStartTime"),
    TraceLoggingUInt64(ext_end_time, "ExtEndTime"),
    TraceLoggingUInt64(ext_end_time - ext_start_time, "ExtDuration"),
    TraceLoggingUInt8(cpu_id, "CpuId"));
```

### 8.4 Correlation Strategy

To correlate extension-side and ebpfcore-side events:

1. **By timestamp range + thread ID**: The extension event's `[ext_start, ext_end]` will encompass the ebpfcore event's `[core_start, core_end]` on the same thread. Since ETW captures events in-order per CPU, matching by overlapping time intervals on the same thread gives the decomposition:
   - `ext_pre = core_start - ext_start` (context preparation)
   - `core_time = core_end - core_start` (program execution)
   - `ext_post = ext_end - core_end` (post-processing)

2. **By Activity ID** (recommended enhancement): Use ETW Activity IDs to logically group related events. Before invoking the program, the extension sets an Activity ID that is shared across all events in that invocation:

   ```c
   GUID activity_id;
   EventActivityIdControl(EVENT_ACTIVITY_CTRL_CREATE_ID, &activity_id);
   // Pass activity_id via execution_context_state or TraceLogging activity
   ```

   This allows WPA and other ETW tools to automatically group ebpfcore + extension events.

3. **By correlation ID via `ebpf_execution_context_state_t`** (alternative): Add a 64-bit `invocation_id` to the execution context:
   ```c
   typedef struct _ebpf_execution_context_state {
       // ... existing fields ...
       uint64_t invocation_id; // Monotonically increasing per-CPU counter
   } ebpf_execution_context_state_t;
   ```
   Both the extension and ebpfcore log this ID, enabling exact matching during post-processing.

### 8.5 Merged View via ETW

When using ETW, the merged end-to-end view comes naturally:

1. Start a single ETW trace session that enables **both** the ebpfcore and netebpfext providers with the `LATENCY` keyword.
2. Both providers emit events into the same `.etl` file.
3. Post-processing tools (WPA, custom parser, `netsh ebpf show latencytrace`) can merge events by Activity ID or timestamp/thread correlation.

This is a significant advantage over the ring-buffer approach, which would require separate flush IOCTLs to each driver and manual merge logic.

---

## 9. Timestamp Source

Use `cxplat_query_time_since_boot_precise(false)` which wraps `KeQueryPerformanceCounter` on Windows kernel. This is:
- Monotonic.
- High resolution (~100 ns or better).
- Safe at DISPATCH_LEVEL.
- Already used in the existing `ebpf_program_test_run` code.

The `false` parameter means "include time spent in sleep/hibernate" which is appropriate for latency measurement.

Values are in **100-nanosecond** units (FILETIME). Convert to nanoseconds by multiplying by `EBPF_NS_PER_FILETIME` (= 100) for display.

---

## 10. Memory Management

The ETW approach requires **no kernel memory allocation** for latency tracking:

| Event | Action |
|-------|--------|
| `EBPF_OPERATION_LATENCY_ENABLE` | Set `_ebpf_latency_state.enabled` to the requested mode. |
| `EBPF_OPERATION_LATENCY_DISABLE` | Set `_ebpf_latency_state.enabled` to 0. |
| Driver unload | No cleanup needed (global flag is static). |

All buffering is handled by the OS ETW infrastructure. The ETW session configuration (buffer size, buffer count, flush interval) is controlled by the trace session owner (e.g., the `netsh ebpf start latencytrace` command or `tracelog`).

Recommended ETW session settings for high-throughput latency capture:

| Parameter | Recommended Value | Notes |
|-----------|-------------------|-------|
| Buffer size (`-b`) | 256 KB | Per-buffer size |
| Min buffers (`-min`) | 64 | Minimum buffer pool |
| Max buffers (`-max`) | 256 | Maximum buffer pool |
| Flush timer (`-ft`) | 1 second | How often buffers flush to disk |
| File mode | Sequential | Direct-to-file for sustained throughput |

---

## 11. Thread Safety

- **Enable/Disable**: A single `InterlockedExchange` on the global flag. No locking needed.
- **Event emission**: `TraceLoggingWrite` is thread-safe and IRQL-safe (up to DISPATCH_LEVEL). No additional synchronization required.
- **ETW session**: Managed by the OS; starting/stopping a session is serialized by the ETW infrastructure.

---

## 12. Performance Characteristics

### 12.1 Per-Event Cost

| Path | Cost | Notes |
|------|------|-------|
| Tracking disabled | ~1 ns | `ReadNoFence` on `enabled` flag |
| Tracking enabled, no ETW session | ~10 ns | Flag check + `TraceLoggingProviderEnabled` check |
| Tracking enabled, session active | ~200–500 ns | 2× `cxplat_query_time_since_boot_precise` + `TraceLoggingWrite` |

### 12.2 Throughput Limits

ETW can sustain approximately **1–5 million events/sec** depending on:
- Event payload size (ours is ~42 bytes user payload).
- Number of CPUs.
- Buffer configuration.
- Disk write speed (for file-backed sessions).

For program invocations exceeding ~5M/sec per CPU, expect event drops. The `EventsLost` counter in the trace session statistics indicate drops.

### 12.3 Comparison with Ring Buffer Approach

| Aspect | ETW | In-Memory Ring Buffer |
|--------|-----|----------------------|
| Per-event hot-path cost | ~200–500 ns | ~30–50 ns |
| Memory (kernel) | 0 (OS managed) | 192 KB – 3 MB per CPU |
| Max sustained rate | ~1–5M events/sec | Unlimited (overwrites oldest) |
| Data loss | Possible (drops) | Possible (overwrites) |
| Post-hoc analysis | `.etl` file with standard tools | Custom flush + parse |
| Cross-provider correlation | Native (WPA, xperf) | Manual merge |
| Implementation complexity | Low | Medium |

---

## 13. Implementation Plan

| Phase | Work Items |
|-------|-----------|
| **Phase 1: Core infrastructure** | Create `ebpf_latency.h/.c`. Define `EBPF_TRACELOG_KEYWORD_LATENCY`. Implement global enable/disable state and ETW emission helpers. |
| **Phase 2: Program invocation** | Instrument `ebpf_program_invoke()` in `ebpf_program.c`. Add IOCTL operations and handler in `ebpf_core.c`. |
| **Phase 3: Map helpers** | Instrument `_ebpf_core_map_find_element`, `_ebpf_core_map_update_element`, `_ebpf_core_map_delete_element`, `_ebpf_core_map_find_and_delete_element`, `_ebpf_core_map_push_elem`, `_ebpf_core_map_pop_elem`, `_ebpf_core_map_peek_elem` in `ebpf_core.c`. |
| **Phase 4: User-mode API** | Add `ebpf_latency_enable/disable` functions to `ebpf_api.h/.cpp` with IOCTL wrappers. |
| **Phase 5: Netsh integration** | Add `latency.c` to `tools/netsh/`. Implement `set latency`, `start latencytrace`, `stop latencytrace`, `show latencytrace` commands. |
| **Phase 6: Extension instrumentation** | Add latency tracking to `netebpfext`'s `_net_ebpf_extension_hook_invoke_single_program()` and `net_ebpf_extension_hook_invoke_programs()`. |
| **Phase 7: ETW consumer / parser** | Build a post-processing tool or script to parse `.etl` files and produce merged latency reports (integrated into `netsh ebpf show latencytrace`). |

---

## 14. Example Workflow

### 14.1 Capture Latency Data

```
C:\> netsh ebpf set latency mode=all
Latency tracking enabled (mode=program+helpers).

C:\> netsh ebpf start latencytrace file=c:\traces\ebpf_latency.etl buffersize=256
Started ETW trace session 'EbpfLatencyTrace'.
  Provider: {<ebpf-core-guid>}, Keywords: 0x800, Level: Verbose
  Provider: {<netebpfext-guid>}, Keywords: 0x800, Level: Verbose
  Output:   c:\traces\ebpf_latency.etl
  Buffers:  256 KB x 128

... (run workload) ...

C:\> netsh ebpf stop latencytrace
Stopped ETW trace session 'EbpfLatencyTrace'.
  Events collected: 1,423,891
  Events lost:      0
  File size:        182 MB
  Saved to:         c:\traces\ebpf_latency.etl

C:\> netsh ebpf set latency mode=off
Latency tracking disabled.
```

### 14.2 Analyze Latency Data

```
C:\> netsh ebpf show latencytrace file=c:\traces\ebpf_latency.etl

eBPF Latency Report (c:\traces\ebpf_latency.etl):
  Duration: 30.2 seconds
  Total events: 1,423,891

Program Invocation Summary:
  Program ID  Invocations  Avg (ns)  P50 (ns)  P95 (ns)  P99 (ns)  Max (ns)
  ----------  -----------  --------  --------  --------  --------  --------
  3           847,291      2,340     2,100     3,800     5,200     12,400
  7           112,456      1,890     1,750     2,900     4,100     9,800

Map Helper Summary (Program 3):
  Helper              Calls      Avg (ns)  P50 (ns)  P95 (ns)  P99 (ns)  Max (ns)
  ------------------  ---------  --------  --------  --------  --------  --------
  map_lookup_elem     623,104    680       620       1,100     1,800     4,200
  map_update_elem     89,442     920       850       1,500     2,400     6,100

End-to-End Latency (with netebpfext):
  Program ID  Hook         Ext Pre (ns)  Core (ns)  Ext Post (ns)  Total (ns)
  ----------  ----------   -----------   ---------  -------------  ----------
  3           XDP_HOOK     450           2,340      280            3,070
  7           BIND_HOOK    320           1,890      150            2,360

C:\> netsh ebpf show latencytrace file=c:\traces\ebpf_latency.etl format=csv > latency.csv
Exported 1,423,891 records to CSV.
```

The `.etl` file can also be opened directly in **Windows Performance Analyzer (WPA)** for graphical analysis, timeline views, and correlation with other system events.

---

## 15. Open Questions

1. **Should we remove redundant fields from the ETW payload?** ProcessId and ThreadId are already in the ETW event header. Removing them saves 8 bytes per event but requires consumers to extract them from the header separately. Recommendation: Keep them for simplicity in V1; optimize later if payload size is a concern.

2. **Should we support per-program enable/disable?** The current design enables globally. Per-program filtering could be done at record time (check `program->object.id` against a filter list), but adds a hash lookup to the hot path. Recommendation: Start with global, add per-program filtering as a Phase 2 enhancement.

3. **Activity ID vs. timestamp correlation for cross-provider merge?** Activity IDs provide exact matching but add ~50 ns overhead to set/propagate. Timestamp+thread correlation is free but may have edge cases with preemption. Recommendation: Use timestamp+thread correlation initially; add Activity ID support when needed.

4. **Should the `start/stop latencytrace` commands be in netsh or a separate tool?** Netsh is convenient for eBPF users. However, advanced users may prefer `tracelog`/`wpr` for more control. Recommendation: Provide both — simple netsh commands for common cases, document `tracelog` equivalent for power users.

5. **ETW event versioning.** If the event payload changes in future versions, use TraceLogging's self-describing format (which handles this automatically) and bump the event version field.

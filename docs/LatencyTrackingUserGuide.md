# eBPF Latency Tracking — User Guide

This document describes the two latency tracking backends (ring buffer and ETW),
the commands to operate them, and what happens internally at each step.

ETW and ring buffer are **mutually exclusive** — only one backend can be active
at a time, selected via the `backend=` parameter.

---

## 1. Ring Buffer Backend

Low-overhead, per-CPU ring buffers in kernel non-paged pool.  Records are
compact 24-byte structs with rdtsc timestamps (no strings).  Data is drained
to user mode after tracking stops.

### 1.1 Commands

```
Step 1 — Start:  netsh ebpf set latency mode=all backend=ringbuffer [correlation=yes] [events=500000] [programs=3,7]
Step 2 — (run workload)
Step 3 — Stop:   netsh ebpf set latency mode=off
Step 4 — View:   netsh ebpf show latencytrace [file=latency_data.bin] [format=table|csv]
```

### 1.2 Internals

#### Step 1: `set latency mode=all backend=ringbuffer`

| Layer | What happens |
|-------|-------------|
| **netsh (user mode)** | `handle_ebpf_set_latency` parses `mode`, `backend`, `correlation`, `events`, `programs`. Calls `ebpf_latency_tracking_release()` to clean up any zombie session from a prior run. |
| **ebpfapi.dll** | `ebpf_latency_tracking_enable()` builds an `EBPF_OPERATION_LATENCY_ENABLE` request (including `backend` field) and sends it via IOCTL to the ebpfcore driver. |
| **ebpfcore (kernel)** | `ebpf_latency_enable()` in `ebpf_latency.c`: |
| | 1. Atomically sets `session_active = 1` via `InterlockedCompareExchange` (rejects concurrent sessions). |
| | 2. Queries `ebpf_get_cpu_count()` for the real CPU count. |
| | 3. Allocates `cpu_count` per-CPU ring buffers from non-paged pool. Each buffer holds `events` × 24 bytes (default 100,000 records ≈ 2.3 MB per CPU). |
| | 4. Captures TSC calibration: `__rdtsc()` + QPC timestamp. |
| | 5. Stores the program-ID filter list and correlation flag. |
| | 6. The IOCTL handler stores `backend = EBPF_LATENCY_BACKEND_RINGBUFFER` in kernel state. |
| | 7. Sets `enabled = mode` with release semantics — **recording begins**. |
| **Hot path** | On every eBPF program invocation (`ebpf_program.c`): reads `enabled` flag (~1 ns), if non-zero and program passes filter, raises IRQL to DISPATCH, captures `__rdtsc()`, writes a `PROGRAM_START` record to the current CPU's ring buffer, runs the program, writes a `PROGRAM_END` record. For helpers (`ebpf_core.c`): same pattern with `HELPER_START`/`HELPER_END` records. Buffer is stop-on-full — when full, the `dropped_count` increments. |

#### Step 2: Run workload

Records accumulate in per-CPU ring buffers. No user-mode interaction needed.

#### Step 3: `set latency mode=off`

| Layer | What happens |
|-------|-------------|
| **netsh** | Detects `mode=off`. Calls `ebpf_latency_tracking_query_state()` to ask the kernel for the active backend. Since `backend == RINGBUFFER`, skips ETW teardown. |
| **ebpfapi.dll** | `ebpf_latency_tracking_disable()` sends `EBPF_OPERATION_LATENCY_DISABLE` IOCTL. |
| **ebpfcore** | `ebpf_latency_disable()`: sets `enabled = 0` atomically, issues `MemoryBarrier()` so in-flight writes complete. **Does NOT free buffers** (preserved for drain). **Does NOT reset `session_active`** (intentional — holds the session open). |
| **netsh** | Prints: `Latency tracking disabled. Use 'netsh ebpf show latencytrace' to view collected data.` |

#### Step 4: `show latencytrace [file=latency_data.bin]`

| Layer | What happens |
|-------|-------------|
| **netsh dispatch** | `handle_ebpf_show_latencytrace`: if no `file=` provided, calls `ebpf_latency_tracking_query_state()` IOCTL to check the kernel's `backend` field. Since `backend == RINGBUFFER`, dispatches to `_show_latencytrace_from_ringbuffer(format, output_path)`. |
| **Probe** | Sends `EBPF_OPERATION_LATENCY_DRAIN` IOCTL with `cpu_index=0, record_offset=0`. Kernel verifies `enabled == OFF` and `per_cpu_buffers != NULL`. Returns reply with `cpu_count`, `records_per_cpu`, TSC calibration, and first chunk of CPU 0 records. |
| **Drain loop** | For each CPU 0..N-1, sends repeated drain IOCTLs with incrementing `record_offset` until `records_returned == 0` or `offset >= total_records`. Each IOCTL copies a chunk (up to ~2,700 records per 64 KB reply). |
| **Merge-sort** | All per-CPU records are combined into one vector and sorted by `timestamp` (rdtsc). |
| **Write file** | Writes a binary file: 40-byte header (`magic=EBLT`, version, TSC calibration, cpu_count, total_records) followed by all sorted 24-byte records. |
| **Statistics** | Pairs `PROGRAM_START`/`PROGRAM_END` events per CPU per program to compute durations. Prints summary table: count, avg, P50, P90, P99, max (in TSC ticks). |
| **Release** | Calls `ebpf_latency_tracking_release()` → `EBPF_OPERATION_LATENCY_RELEASE` IOCTL. Kernel frees all ring buffers, resets `session_active = 0`. A new session can now start. |

### 1.3 State Machine

```
                  set mode=all          set mode=off           show latencytrace
  [No session] ─────────────> [Active] ─────────────> [Disabled] ─────────────> [No session]
  session_active=0            session_active=1         session_active=1          session_active=0
  enabled=0                   enabled=1|2              enabled=0                 enabled=0
  buffers=null                buffers=allocated         buffers=preserved         buffers=freed
                                  │                        │
                                  │ writes records         │ drain reads records
                                  ▼                        ▼
                              per-CPU ring             user copies via IOCTL
```

`session_active` stays `1` through disable so buffers survive for drain. Only
`show latencytrace` (or a subsequent `set mode=all`) calls `release()`.

---

## 2. ETW Backend

Uses the Windows Event Tracing for Windows (ETW) infrastructure.  The kernel
emits `EbpfProgramLatency` and `EbpfMapHelperLatency` TraceLogging events with
keyword `0x800`.  Events are captured to an `.etl` file and parsed offline.

### 2.1 Commands

```
Step 1 — Start:  netsh ebpf set latency mode=all backend=etw [file=output.etl] [programs=3,7]
Step 2 — (run workload)
Step 3 — Stop:   netsh ebpf set latency mode=off
Step 4 — View:   netsh ebpf show latencytrace [file=output.etl] [format=table|csv]
```

### 2.2 Internals

#### Step 1: `set latency mode=all backend=etw [file=output.etl]`

| Layer | What happens |
|-------|-------------|
| **netsh (user mode)** | `handle_ebpf_set_latency` parses parameters. Validates that `events` and `correlation` are NOT specified (ETW-only rejects ring-buffer params). Calls `ebpf_latency_tracking_release()` to clean up any zombie session. |
| **ebpfapi.dll** | `ebpf_latency_tracking_enable(mode, flags=0, records_per_cpu=0, backend=ETW, ...)` sends `EBPF_OPERATION_LATENCY_ENABLE` IOCTL with `backend = EBPF_LATENCY_BACKEND_ETW`. |
| **ebpfcore (kernel)** | `ebpf_latency_enable()` runs identically to the ring buffer path — allocates per-CPU buffers (default 100K records) and sets `enabled = mode`. The IOCTL handler then stores `backend = EBPF_LATENCY_BACKEND_ETW` in kernel state, so any process can later query which backend is active. |
| **netsh — ETW setup** | After the IOCTL succeeds, calls `_start_etw_session()`: |
| | 1. Allocates `EVENT_TRACE_PROPERTIES` with session name `"EbpfLatencyTrace"`. |
| | 2. Calls `StartTraceW()` to create a sequential `.etl` file (default: `ebpf_latency.etl`, or user's `file=` path). Buffers: 256 KB × 64–256 buffers, 1-second flush. |
| | 3. Calls `EnableTraceEx2()` on the `EbpfForWindowsProvider` GUID (`{394f321c-...}`) with keyword `0x800` and level `VERBOSE`. |
| | 4. From this point, TraceLogging `EbpfProgramLatency` / `EbpfMapHelperLatency` events flow into the `.etl` file. |
| | If `StartTraceW` fails, the code **rolls back**: disables + releases kernel tracking, returns error. |
| | Records `_active_etw_file` locally for the session (informational only; kernel state is authoritative). |
| **Hot path** | Same kernel instrumentation as ring buffer — `ebpf_latency_write_record()` writes to per-CPU ring buffers. **Additionally**, the kernel's TraceLogging provider emits ETW events (gated by `TraceLoggingProviderEnabled` check). The ETW events contain richer fields: `ProgramName`, `MapName`, `ProcessId`, `ThreadId`, `Irql`, `Duration`, `StartTime`, `EndTime`. |

#### Step 2: Run workload

ETW events stream into the kernel ETW buffers and are flushed to the `.etl`
file every second. Ring buffers also fill (but are not drained for ETW mode).

#### Step 3: `set latency mode=off`

| Layer | What happens |
|-------|-------------|
| **netsh** | Detects `mode=off`. Calls `ebpf_latency_tracking_query_state()` IOCTL — kernel returns `backend = ETW`. |
| **ETW teardown** | Calls `_stop_etw_session()`: sends `ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)` to flush and close the `.etl` file. Prints the saved file path. |
| **ebpfapi.dll** | `ebpf_latency_tracking_disable()` → IOCTL. Kernel sets `enabled = 0`. |
| **Immediate release** | Unlike ring buffer, the ETW path calls `ebpf_latency_tracking_release()` **right away** — the data is in the `.etl` file, so ring buffers are not needed. This frees all kernel memory and resets `session_active = 0`. |
| **netsh** | Prints: `Latency tracking stopped.` |

#### Step 4: `show latencytrace [file=output.etl]`

| Layer | What happens |
|-------|-------------|
| **netsh dispatch** | `handle_ebpf_show_latencytrace`: if no `file=` provided, calls `ebpf_latency_tracking_query_state()` IOCTL. Kernel returns `backend = ETW` → dispatches to `_show_latencytrace_from_etl()` with the default file name (`ebpf_latency.etl`). If the user provides `file=output.etl`, that path is used directly. |
| **Open trace** | Calls `OpenTraceW()` with `PROCESS_TRACE_MODE_EVENT_RECORD` and a callback function. |
| **Parse events** | `ProcessTrace()` replays every event in the `.etl` file. For each event, the callback `_etl_event_record_callback()`: |
| | 1. Filters by provider GUID (`EbpfForWindowsProvider` or `NetEbpfExtProvider`) and keyword `0x800`. |
| | 2. Uses TDH (`TdhGetEventInformation`) to decode the event name: `EbpfProgramLatency`, `EbpfMapHelperLatency`, or `NetEbpfExtInvokeLatency`. |
| | 3. Extracts typed properties (`ProgramId`, `Duration`, `ProgramName`, `HelperFunctionId`, `MapName`, etc.) via `TdhGetProperty`. |
| | 4. In **table** mode: accumulates durations into `program_durations` / `helper_durations` / `ext_durations` maps. In **CSV** mode: prints each event as a CSV row immediately. |
| **Statistics** | After all events are processed, computes per-program and per-helper statistics (count, avg, P50, P95, P99, max) in nanoseconds (100-ns ETW units × 100). Prints formatted tables with dynamic column widths. |
| **No kernel interaction** | Unlike ring buffer, this step is purely user-mode file parsing. No IOCTLs. No session to release. |

### 2.3 State Machine

```
                  set mode=all            set mode=off
  [No session] ─────────────> [Active] ─────────────> [No session]
  session_active=0            session_active=1         session_active=0
  enabled=0                   enabled=1|2              enabled=0
  ETW session=none            ETW session=running      ETW session=stopped
  .etl file=none              .etl file=growing        .etl file=complete
                                  │
                                  │ ETW events flow
                                  ▼
                              .etl file on disk
```

The ETW path has a simpler lifecycle: `mode=off` performs **both** disable and
release in one step (since there is no drain needed — data lives in the `.etl`
file).

---

## 3. Backend Detection Across Processes

Each `netsh` invocation is a separate short-lived process.  The `ebpfnetsh.dll`
is loaded, executes one command, and unloads — so in-process static variables
cannot carry state between commands.

To solve this, the kernel driver stores the `backend` value (ringbuffer or etw)
in the `ebpf_latency_state_t` structure, set at enable time via the
`EBPF_OPERATION_LATENCY_ENABLE` IOCTL.

A new `EBPF_OPERATION_LATENCY_QUERY_STATE` IOCTL allows any process to ask the
kernel:

| Field | Description |
|-------|-------------|
| `mode` | Current tracking mode (0=off, 1=program, 2=all). |
| `backend` | `EBPF_LATENCY_BACKEND_RINGBUFFER` (0) or `EBPF_LATENCY_BACKEND_ETW` (1). |
| `session_active` | Whether a session exists (buffers allocated). |

This is used by:
- **`set latency mode=off`** — queries kernel to decide whether to stop an ETW
  session before disabling.
- **`show latencytrace`** (no `file=` arg) — queries kernel to decide whether
  to drain ring buffers or read the default `.etl` file.
- **`show latency`** — queries kernel to display current status.

---

## 4. Comparison

| Aspect | Ring Buffer | ETW |
|--------|------------|-----|
| **Hot-path overhead** | ~10–30 ns (rdtsc + ring buffer write at DISPATCH) | ~200–500 ns (TraceLogging event emission) |
| **Data format** | Compact 24-byte records, IDs only | Rich events with strings (ProgramName, MapName), process/thread IDs |
| **Storage** | Kernel non-paged pool (bounded by `events` param) | `.etl` file on disk (grows until stopped) |
| **Correlation** | Per-CPU monotonic `correlation_id` (optional) | ProcessId + ThreadId + timestamps |
| **Collection** | Explicit drain via IOCTLs after stop | Automatic — events written to file in real time |
| **Analysis** | `show latencytrace` (built-in summary) or custom tool on `.bin` file | `show latencytrace` (built-in) or WPA / xperf on `.etl` file |
| **Stop → View gap** | `mode=off` preserves buffers; `show latencytrace` drains + releases | `mode=off` closes `.etl`; `show latencytrace` is pure file read |
| **Max events** | Bounded per CPU (stop-on-full, reports drops) | Unbounded (disk space limited, ETW may drop under pressure) |
| **Parameters** | `events=`, `correlation=` | `file=` |
| **Re-enable** | Must drain or re-enable (auto-releases zombie) | Immediate (released at stop) |

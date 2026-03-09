// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_CORE

#include "ebpf_latency.h"
#include "ebpf_platform.h"
#include "ebpf_shared_framework.h"
#include "ebpf_tracelog.h"

#include <intrin.h>

static ebpf_latency_state_t _ebpf_latency_state = {0};

long
ebpf_latency_get_mode()
{
    return ReadNoFence(&_ebpf_latency_state.enabled);
}

BOOLEAN
ebpf_latency_is_correlation_enabled() { return ReadNoFence(&_ebpf_latency_state.correlation_enabled) != 0; }

BOOLEAN
ebpf_latency_should_track_program(uint32_t program_id)
{
    uint32_t count = _ebpf_latency_state.program_id_count;
    if (count == 0) {
        return TRUE; // No filter — track all programs.
    }
    for (uint32_t i = 0; i < count; i++) {
        if (_ebpf_latency_state.program_ids[i] == program_id) {
            return TRUE;
        }
    }
    return FALSE;
}

_Must_inspect_result_ ebpf_result_t
ebpf_latency_enable(
    uint32_t mode,
    uint32_t flags,
    uint32_t records_per_cpu,
    uint32_t program_id_count,
    _In_reads_opt_(program_id_count) const uint32_t* program_ids)
{
    if (mode < EBPF_LATENCY_MODE_PROGRAM || mode > EBPF_LATENCY_MODE_ALL) {
        return EBPF_INVALID_ARGUMENT;
    }
    if (program_id_count > EBPF_LATENCY_MAX_PROGRAM_FILTER) {
        return EBPF_INVALID_ARGUMENT;
    }
    if (program_id_count > 0 && program_ids == NULL) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Validate and default records_per_cpu.
    if (records_per_cpu == 0) {
        records_per_cpu = EBPF_LATENCY_DEFAULT_RECORDS_PER_CPU;
    }
    if (records_per_cpu < EBPF_LATENCY_MIN_RECORDS_PER_CPU || records_per_cpu > EBPF_LATENCY_MAX_RECORDS_PER_CPU) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Atomically claim the session. Only one session at a time.
    long previous = InterlockedCompareExchange(&_ebpf_latency_state.session_active, 1, 0);
    if (previous != 0) {
        return EBPF_INVALID_STATE; // Another session is active.
    }

    // Allocate per-CPU ring buffers from non-paged pool.
    uint32_t cpu_count = ebpf_get_cpu_count();
    _ebpf_latency_state.cpu_count = cpu_count;
    _ebpf_latency_state.records_per_cpu = records_per_cpu;

    _ebpf_latency_state.per_cpu_buffers = (ebpf_latency_ring_buffer_t**)ebpf_allocate_with_tag(
        cpu_count * sizeof(ebpf_latency_ring_buffer_t*), EBPF_POOL_TAG_CORE);
    if (_ebpf_latency_state.per_cpu_buffers == NULL) {
        InterlockedExchange(&_ebpf_latency_state.session_active, 0);
        return EBPF_NO_MEMORY;
    }
    memset(_ebpf_latency_state.per_cpu_buffers, 0, cpu_count * sizeof(ebpf_latency_ring_buffer_t*));

    size_t alloc_size =
        EBPF_OFFSET_OF(ebpf_latency_ring_buffer_t, records) + (size_t)records_per_cpu * sizeof(ebpf_latency_record_t);

    for (uint32_t i = 0; i < cpu_count; i++) {
        _ebpf_latency_state.per_cpu_buffers[i] =
            (ebpf_latency_ring_buffer_t*)ebpf_allocate_with_tag(alloc_size, EBPF_POOL_TAG_CORE);
        if (_ebpf_latency_state.per_cpu_buffers[i] == NULL) {
            // Clean up already-allocated buffers.
            for (uint32_t j = 0; j < i; j++) {
                ebpf_free(_ebpf_latency_state.per_cpu_buffers[j]);
            }
            ebpf_free(_ebpf_latency_state.per_cpu_buffers);
            _ebpf_latency_state.per_cpu_buffers = NULL;
            InterlockedExchange(&_ebpf_latency_state.session_active, 0);
            return EBPF_NO_MEMORY;
        }
        memset(_ebpf_latency_state.per_cpu_buffers[i], 0, alloc_size);
        _ebpf_latency_state.per_cpu_buffers[i]->records_count = records_per_cpu;
    }

    // Populate the program ID filter list.
    _ebpf_latency_state.program_id_count = program_id_count;
    for (uint32_t i = 0; i < program_id_count; i++) {
        _ebpf_latency_state.program_ids[i] = program_ids[i];
    }

    // Capture time calibration.
    _ebpf_latency_state.tsc_at_enable = cxplat_query_time_since_boot_precise(false);
    _ebpf_latency_state.qpc_at_enable = cxplat_query_time_since_boot_precise(false);

    // Timestamps are now in 100-ns (QPC) units; tsc_frequency is not used for conversion.
    _ebpf_latency_state.tsc_frequency = 0;

    // Store correlation flag.
    InterlockedExchange(&_ebpf_latency_state.correlation_enabled, (flags & EBPF_LATENCY_FLAG_CORRELATION_ID) ? 1 : 0);

    // Note: backend field is set by the IOCTL handler after enable succeeds.

    // Enable latency tracking last (write-release semantics).
    InterlockedExchange(&_ebpf_latency_state.enabled, (long)mode);
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_latency_disable()
{
    // Disable tracking first.
    InterlockedExchange(&_ebpf_latency_state.enabled, EBPF_LATENCY_MODE_OFF);

    // Clear correlation flag.
    InterlockedExchange(&_ebpf_latency_state.correlation_enabled, 0);

    // Memory barrier to ensure all in-flight writes see the disabled flag.
    MemoryBarrier();

    // Do NOT free buffers — they must remain for drain IOCTLs.
    // Buffers are freed when ebpf_latency_release() is called.

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_latency_release()
{
    // Ensure tracking is disabled.
    InterlockedExchange(&_ebpf_latency_state.enabled, EBPF_LATENCY_MODE_OFF);

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

    // Clear state.
    _ebpf_latency_state.program_id_count = 0;
    _ebpf_latency_state.cpu_count = 0;
    _ebpf_latency_state.records_per_cpu = 0;
    _ebpf_latency_state.backend = 0;

    // Release the session — allows a new session to start.
    InterlockedExchange(&_ebpf_latency_state.session_active, 0);

    return EBPF_SUCCESS;
}

void
ebpf_latency_write_record(
    uint32_t program_id,
    uint16_t helper_function_id,
    uint16_t map_id,
    uint32_t correlation_id,
    uint64_t timestamp,
    uint8_t event_type)
{
    // Raise to DISPATCH to prevent preemption and CPU migration.
    // This is a no-op if already at DISPATCH_LEVEL.
    uint8_t old_irql = ebpf_raise_irql(DISPATCH_LEVEL);

    uint32_t cpu = ebpf_get_current_cpu();
    if (cpu < _ebpf_latency_state.cpu_count && _ebpf_latency_state.per_cpu_buffers != NULL) {
        ebpf_latency_ring_buffer_t* ring = _ebpf_latency_state.per_cpu_buffers[cpu];
        if (ring != NULL && ring->write_index < ring->records_count) {
            // Stop-on-full: only write if buffer has space.
            ebpf_latency_record_t* rec = &ring->records[ring->write_index];
            rec->timestamp = timestamp;
            rec->correlation_id = correlation_id;
            rec->program_id = program_id;
            rec->helper_function_id = helper_function_id;
            rec->map_id = map_id;
            rec->event_type = event_type;
            rec->cpu_id = (uint8_t)cpu;
            rec->reserved[0] = 0;
            rec->reserved[1] = 0;
            ring->write_index++;
        } else if (ring != NULL) {
            ring->dropped_count++;
        }
    }

    ebpf_lower_irql(old_irql);
}

uint32_t
ebpf_latency_next_correlation_id(uint32_t cpu)
{
    if (cpu < _ebpf_latency_state.cpu_count && _ebpf_latency_state.per_cpu_buffers != NULL) {
        ebpf_latency_ring_buffer_t* ring = _ebpf_latency_state.per_cpu_buffers[cpu];
        if (ring != NULL) {
            uint32_t seq = ++ring->next_correlation_id & 0x00FFFFFF;
            return ((cpu & 0xFF) << 24) | seq;
        }
    }
    return 0;
}

const ebpf_latency_state_t*
ebpf_latency_get_state()
{
    return &_ebpf_latency_state;
}

uint32_t
ebpf_latency_get_backend()
{
    return _ebpf_latency_state.backend;
}

void
ebpf_latency_emit_program_etw_event(
    uint32_t program_id, uint32_t correlation_id, uint64_t start_tsc, uint64_t end_tsc, uint8_t cpu_id)
{
    uint64_t duration = end_tsc - start_tsc;
    uint32_t process_id = (uint32_t)(uintptr_t)PsGetCurrentProcessId();
    uint32_t thread_id = (uint32_t)(uintptr_t)PsGetCurrentThreadId();
    uint32_t irql = (uint32_t)KeGetCurrentIrql();

    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "EbpfProgramLatency",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_LATENCY),
        TraceLoggingUInt32(program_id, "ProgramId"),
        TraceLoggingUInt32(0, "HelperFunctionId"),
        TraceLoggingUInt64((uint64_t)correlation_id, "CorrelationId"),
        TraceLoggingUInt32(process_id, "ProcessId"),
        TraceLoggingUInt32(thread_id, "ThreadId"),
        TraceLoggingUInt64(start_tsc, "StartTime"),
        TraceLoggingUInt64(end_tsc, "EndTime"),
        TraceLoggingUInt64(duration, "Duration"),
        TraceLoggingUInt32((uint32_t)cpu_id, "CpuId"),
        TraceLoggingUInt32(irql, "Irql"));
}

void
ebpf_latency_emit_helper_etw_event(
    uint32_t program_id,
    uint16_t helper_function_id,
    uint16_t map_id,
    uint32_t correlation_id,
    uint64_t start_tsc,
    uint64_t end_tsc,
    uint8_t cpu_id)
{
    UNREFERENCED_PARAMETER(map_id);
    uint64_t duration = end_tsc - start_tsc;
    uint32_t process_id = (uint32_t)(uintptr_t)PsGetCurrentProcessId();
    uint32_t thread_id = (uint32_t)(uintptr_t)PsGetCurrentThreadId();
    uint32_t irql = (uint32_t)KeGetCurrentIrql();

    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "EbpfMapHelperLatency",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_LATENCY),
        TraceLoggingUInt32(program_id, "ProgramId"),
        TraceLoggingUInt32((uint32_t)helper_function_id, "HelperFunctionId"),
        TraceLoggingUInt64((uint64_t)correlation_id, "CorrelationId"),
        TraceLoggingUInt32(process_id, "ProcessId"),
        TraceLoggingUInt32(thread_id, "ThreadId"),
        TraceLoggingUInt64(start_tsc, "StartTime"),
        TraceLoggingUInt64(end_tsc, "EndTime"),
        TraceLoggingUInt64(duration, "Duration"),
        TraceLoggingUInt32((uint32_t)cpu_id, "CpuId"),
        TraceLoggingUInt32(irql, "Irql"));
}

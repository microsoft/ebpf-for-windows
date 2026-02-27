// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_CORE

#include "ebpf_latency.h"
#include "ebpf_platform.h"
#include "ebpf_tracelog.h"

#include <TraceLoggingProvider.h>
#include <winmeta.h>

static ebpf_latency_state_t _ebpf_latency_state = {0};

long
ebpf_latency_get_mode()
{
    return ReadNoFence(&_ebpf_latency_state.enabled);
}

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
    uint32_t mode, uint32_t program_id_count, _In_reads_opt_(program_id_count) const uint32_t* program_ids)
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

    // Atomically claim the session. Only one session at a time.
    long previous = InterlockedCompareExchange(&_ebpf_latency_state.session_active, 1, 0);
    if (previous != 0) {
        return EBPF_INVALID_STATE; // Another session is active.
    }

    // Populate the program ID filter list (under session_active guard).
    _ebpf_latency_state.program_id_count = program_id_count;
    for (uint32_t i = 0; i < program_id_count; i++) {
        _ebpf_latency_state.program_ids[i] = program_ids[i];
    }

    // Enable latency tracking last (write-release semantics).
    InterlockedExchange(&_ebpf_latency_state.enabled, (long)mode);
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_latency_disable()
{
    // Disable tracking first.
    InterlockedExchange(&_ebpf_latency_state.enabled, EBPF_LATENCY_MODE_OFF);

    // Clear filter list.
    _ebpf_latency_state.program_id_count = 0;

    // Release the session.
    InterlockedExchange(&_ebpf_latency_state.session_active, 0);

    return EBPF_SUCCESS;
}

// Maximum name length for ETW event fields (must accommodate BPF_OBJ_NAME_LEN = 64).
#define EBPF_LATENCY_MAX_NAME_LEN 64

// Copy a cxplat_utf8_string_t to a null-terminated stack buffer for TraceLogging.
static void
_ebpf_latency_copy_name(
    _Out_writes_z_(buffer_size) char* buffer, size_t buffer_size, _In_opt_ const cxplat_utf8_string_t* name)
{
    if (name != NULL && name->value != NULL && name->length > 0) {
        size_t len = name->length < (buffer_size - 1) ? name->length : (buffer_size - 1);
        memcpy(buffer, name->value, len);
        buffer[len] = '\0';
    } else {
        buffer[0] = '\0';
    }
}

void
ebpf_latency_emit_program_event(
    uint32_t program_id, _In_opt_ const cxplat_utf8_string_t* program_name, uint64_t start_time, uint64_t end_time)
{
    uint32_t process_id = ebpf_platform_process_id();
    uint32_t thread_id = ebpf_platform_thread_id();
    uint64_t duration = end_time - start_time;
    uint32_t cpu_id = ebpf_get_current_cpu();

    char name_buf[EBPF_LATENCY_MAX_NAME_LEN] = {0};
    _ebpf_latency_copy_name(name_buf, sizeof(name_buf), program_name);

    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "EbpfProgramLatency",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_LATENCY),
        TraceLoggingUInt32(program_id, "ProgramId"),
        TraceLoggingString(name_buf, "ProgramName"),
        TraceLoggingUInt32(0, "HelperFunctionId"),
        TraceLoggingUInt32(process_id, "ProcessId"),
        TraceLoggingUInt32(thread_id, "ThreadId"),
        TraceLoggingUInt64(start_time, "StartTime"),
        TraceLoggingUInt64(end_time, "EndTime"),
        TraceLoggingUInt64(duration, "Duration"),
        TraceLoggingUInt32(cpu_id, "CpuId"));
}

void
ebpf_latency_emit_helper_event(
    uint32_t program_id,
    uint32_t helper_function_id,
    _In_opt_ const cxplat_utf8_string_t* map_name,
    uint64_t start_time,
    uint64_t end_time)
{
    uint32_t process_id = ebpf_platform_process_id();
    uint32_t thread_id = ebpf_platform_thread_id();
    uint64_t duration = end_time - start_time;
    uint32_t cpu_id = ebpf_get_current_cpu();

    char name_buf[EBPF_LATENCY_MAX_NAME_LEN] = {0};
    _ebpf_latency_copy_name(name_buf, sizeof(name_buf), map_name);

    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "EbpfMapHelperLatency",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_LATENCY),
        TraceLoggingUInt32(program_id, "ProgramId"),
        TraceLoggingUInt32(helper_function_id, "HelperFunctionId"),
        TraceLoggingString(name_buf, "MapName"),
        TraceLoggingUInt32(process_id, "ProcessId"),
        TraceLoggingUInt32(thread_id, "ThreadId"),
        TraceLoggingUInt64(start_time, "StartTime"),
        TraceLoggingUInt64(end_time, "EndTime"),
        TraceLoggingUInt64(duration, "Duration"),
        TraceLoggingUInt32(cpu_id, "CpuId"));
}

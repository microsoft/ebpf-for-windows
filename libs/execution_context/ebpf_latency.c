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

_Must_inspect_result_ ebpf_result_t
ebpf_latency_enable(uint32_t mode)
{
    if (mode < EBPF_LATENCY_MODE_PROGRAM || mode > EBPF_LATENCY_MODE_ALL) {
        return EBPF_INVALID_ARGUMENT;
    }
    InterlockedExchange(&_ebpf_latency_state.enabled, (long)mode);
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_latency_disable()
{
    InterlockedExchange(&_ebpf_latency_state.enabled, EBPF_LATENCY_MODE_OFF);
    return EBPF_SUCCESS;
}

void
ebpf_latency_emit_program_event(uint32_t program_id, uint64_t start_time, uint64_t end_time)
{
    uint32_t process_id = ebpf_platform_process_id();
    uint32_t thread_id = ebpf_platform_thread_id();
    uint64_t duration = end_time - start_time;
    uint32_t cpu_id = ebpf_get_current_cpu();

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
        TraceLoggingUInt32(cpu_id, "CpuId"));
}

void
ebpf_latency_emit_helper_event(uint32_t program_id, uint32_t helper_function_id, uint64_t start_time, uint64_t end_time)
{
    uint32_t process_id = ebpf_platform_process_id();
    uint32_t thread_id = ebpf_platform_thread_id();
    uint64_t duration = end_time - start_time;
    uint32_t cpu_id = ebpf_get_current_cpu();

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
        TraceLoggingUInt32(cpu_id, "CpuId"));
}

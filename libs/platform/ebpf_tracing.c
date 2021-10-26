// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include <TraceLoggingProvider.h>
#include <winmeta.h>

TRACELOGGING_DECLARE_PROVIDER(ebpf_tracelog_provider);

void
ebpf_trace_function_entry(_In_z_ const char* function, _In_z_ const char* file, int line)
{
    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "FunctionTrace",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingOpcode(WINEVENT_OPCODE_START),
        TraceLoggingString(function),
        TraceLoggingString(file),
        TraceLoggingLong(line));
}

void
ebpf_trace_function_exit_result(_In_z_ const char* function, _In_z_ const char* file, int line, ebpf_result_t result)
{
    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "FunctionTrace",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingOpcode(WINEVENT_OPCODE_STOP),
        TraceLoggingString(function),
        TraceLoggingString(file),
        TraceLoggingLong(line),
        TraceLoggingLong(result));
}

void
ebpf_trace_function_exit_void(_In_z_ const char* function, _In_z_ const char* file, int line)
{
    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "FunctionTrace",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingOpcode(WINEVENT_OPCODE_STOP),
        TraceLoggingString(function),
        TraceLoggingString(file),
        TraceLoggingLong(line));
}

void
ebpf_trace_function_exit_bool(_In_z_ const char* function, _In_z_ const char* file, int line, bool result)
{
    TraceLoggingWrite(
        ebpf_tracelog_provider,
        "FunctionTrace",
        TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
        TraceLoggingOpcode(WINEVENT_OPCODE_STOP),
        TraceLoggingString(function),
        TraceLoggingString(file),
        TraceLoggingLong(line),
        TraceLoggingBoolean(result));
}

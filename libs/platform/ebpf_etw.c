// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

#include <TraceLoggingProvider.h>
#include <winmeta.h>

TRACELOGGING_DEFINE_PROVIDER(
    ebpf_tracelog_provider,
    "EbpfForWindowsProvider",
    // {394f321c-5cf4-404c-aa34-4df1428a7f9c}
    (0x394f321c, 0x5cf4, 0x404c, 0xaa, 0x34, 0x4d, 0xf1, 0x42, 0x8a, 0x7f, 0x9c));

static bool _ebpf_trace_initiated = false;

_Must_inspect_result_ ebpf_result_t
ebpf_trace_initiate()
{
    if (_ebpf_trace_initiated) {
        return EBPF_SUCCESS;
    }
    TLG_STATUS status = TraceLoggingRegister(ebpf_tracelog_provider);
    if (status != 0) {
        return EBPF_NO_MEMORY;
    } else {
        _ebpf_trace_initiated = true;
        return EBPF_SUCCESS;
    }
}

// Prevent tail call optimization of the call to TraceLoggingUnregister to resolve verifier stop C4/DD
// "An attempt was made to unload a driver without calling EtwUnregister".
#pragma optimize("", off)
void
ebpf_trace_terminate()
{
    if (_ebpf_trace_initiated) {
        TraceLoggingUnregister(ebpf_tracelog_provider);
        _ebpf_trace_initiated = false;
    }
}
#pragma optimize("", on)

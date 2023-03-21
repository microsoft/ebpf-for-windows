// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "net_ebpf_ext.h"

#include <TraceLoggingProvider.h>
#include <winmeta.h>

TRACELOGGING_DEFINE_PROVIDER(
    net_ebpf_ext_tracelog_provider,
    "NetEbpfExtProvider",
    // {f2f2ca01-ad02-4a07-9e90-95a2334f3692}
    (0xf2f2ca01, 0xad02, 0x4a07, 0x9e, 0x90, 0x95, 0xa2, 0x33, 0x4f, 0x36, 0x92));

static bool _net_ebpf_ext_trace_initiated = false;

NTSTATUS
net_ebpf_ext_trace_initiate()
{
    NTSTATUS status = STATUS_SUCCESS;
    if (_net_ebpf_ext_trace_initiated) {
        goto Exit;
    }

    status = TraceLoggingRegister(net_ebpf_ext_tracelog_provider);
    if (status != STATUS_SUCCESS) {
        goto Exit;
    } else {
        _net_ebpf_ext_trace_initiated = true;
    }
Exit:
    return status;
}

// Prevent tail call optimization of the call to TraceLoggingUnregister to resolve verifier stop C4/DD
// "An attempt was made to unload a driver without calling EtwUnregister".
#pragma optimize("", off)
void
net_ebpf_ext_trace_terminate()
{
    if (_net_ebpf_ext_trace_initiated) {
        TraceLoggingUnregister(net_ebpf_ext_tracelog_provider);
        _net_ebpf_ext_trace_initiated = false;
    }
}
#pragma optimize("", on)

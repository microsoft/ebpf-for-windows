// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// This file provides the TraceLogging provider definition for netebpfext.
// All tracelogging function implementations are in ebpf-extension-common.

#include "ebpf_ext_tracelog.h"

#include <TraceLoggingProvider.h>

TRACELOGGING_DEFINE_PROVIDER(
    ebpf_ext_tracelog_provider,
    "NetEbpfExtProvider",
    // {f2f2ca01-ad02-4a07-9e90-95a2334f3692}
    (0xf2f2ca01, 0xad02, 0x4a07, 0x9e, 0x90, 0x95, 0xa2, 0x33, 0x4f, 0x36, 0x92));

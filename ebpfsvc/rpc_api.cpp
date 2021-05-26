// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <mutex>
#include <stdexcept>
#include <stdio.h>
#include <vector>
#include "api_internal.h"
#include "api_service.h"
#include "ebpf_windows.h"
#include "rpc_interface_h.h"
#include "svc_common.h"
#include "Verifier.h"

// Critical section to serialize RPC calls.
// Currently ebpfsvc uses a global context to track verification
// and JIT compilation, hence all RPC calls should be serialized.
static std::mutex _mutex;

ebpf_result_t
ebpf_server_verify_and_jit_program(
    /* [ref][in] */ ebpf_program_load_info* info,
    /* [ref][out] */ uint32_t* logs_size,
    /* [ref][size_is][size_is][out] */ char** logs)
{
    UNREFERENCED_PARAMETER(info);
    UNREFERENCED_PARAMETER(logs_size);
    UNREFERENCED_PARAMETER(logs);

    return EBPF_FAILED;
}

ebpf_result_t
ebpf_server_verify_program(
    /* [ref][in] */ ebpf_program_verify_info* info,
    /* [out] */ uint32_t* logs_size,
    /* [ref][size_is][size_is][out] */ char** logs)
{
    if (info->byte_code_size == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(_mutex);

    // MIDL generates warnings if any [out] param uses 'const',
    // since RPC marshaling will copy the data anyway.  So we
    // can safely cast the 'logs' param below.

    return ebpf_verify_program(
        reinterpret_cast<const GUID*>(&info->program_type),
        info->execution_context,
        info->map_descriptors_count,
        reinterpret_cast<EbpfMapDescriptor*>(info->map_descriptors),
        info->byte_code_size,
        info->byte_code,
        const_cast<const char**>(logs),
        logs_size);
}

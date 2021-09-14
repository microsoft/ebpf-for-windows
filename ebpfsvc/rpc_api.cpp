// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <mutex>
#include <stdexcept>
#include <stdio.h>
#include <vector>
#include "api_service.h"
#include "rpc_interface_h.h"
#include "svc_common.h"

ebpf_result_t
ebpf_server_verify_and_load_program(
    /* [ref][in] */ ebpf_program_load_info* info,
    /* [ref][out] */ uint32_t* logs_size,
    /* [ref][size_is][size_is][out] */ char** logs)
{
    ebpf_result_t result;

    if (info->byte_code_size == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Set the handle of program being verified in thread-local storage.
    set_program_under_verification(reinterpret_cast<ebpf_handle_t>(info->program_handle));

    result = ebpf_verify_and_load_program(
        &info->program_type,
        reinterpret_cast<ebpf_handle_t>(info->program_handle),
        info->execution_context,
        info->execution_type,
        info->map_count,
        info->handle_map,
        info->byte_code_size,
        info->byte_code,
        const_cast<const char**>(logs),
        logs_size);

    ebpf_clear_thread_local_storage();
    return result;
}

ebpf_result_t
ebpf_server_verify_program(
    /* [ref][in] */ ebpf_program_verify_info* info,
    /* [out] */ uint32_t* logs_size,
    /* [ref][size_is][size_is][out] */ char** logs)
{
    ebpf_result_t result;

    if (info->byte_code_size == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    // MIDL generates warnings if any [out] param uses 'const',
    // since RPC marshaling will copy the data anyway.  So we
    // can safely cast the 'logs' param below.

    result = ebpf_verify_program(
        reinterpret_cast<const GUID*>(&info->program_type),
        info->execution_context,
        info->map_descriptors_count,
        reinterpret_cast<EbpfMapDescriptor*>(info->map_descriptors),
        info->byte_code_size,
        info->byte_code,
        const_cast<const char**>(logs),
        logs_size);

    ebpf_clear_thread_local_storage();
    return result;
}

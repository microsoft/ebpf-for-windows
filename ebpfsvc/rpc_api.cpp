// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_service.h"
#include "rpc_interface_h.h"
#include "svc_common.h"

#include <mutex>
#include <stdexcept>
#include <stdio.h>
#include <vector>

bool use_ebpf_store = false;

ebpf_result_t
ebpf_server_verify_and_load_program(
    /* [ref][in] */ ebpf_program_load_info* info,
    /* [ref][out] */ uint32_t* logs_size,
    /* [ref][size_is][size_is][out] */ char** logs)
{
    ebpf_result_t result;

    if (info->instruction_count == 0) {
        return EBPF_INVALID_ARGUMENT;
    }
    *logs = nullptr;
    *logs_size = 0;

    // Set the handle of program being verified in thread-local storage.
    set_program_under_verification(reinterpret_cast<ebpf_handle_t>(info->program_handle));

    const char* ebpf_logs = nullptr;
    uint32_t ebpf_logs_size = 0;
    result = ebpf_verify_and_load_program(
        &info->program_type,
        reinterpret_cast<ebpf_handle_t>(info->program_handle),
        info->execution_context,
        info->execution_type,
        info->map_count,
        info->handle_map,
        info->instruction_count,
        reinterpret_cast<ebpf_inst*>(info->instructions),
        &ebpf_logs,
        &ebpf_logs_size);

    if (ebpf_logs) {
        // The ebpf_logs buffer was allocated by the ebpf allocator whereas we
        // must return a string allocated by the MIDL allocator.
        *logs = (char*)MIDL_user_allocate(ebpf_logs_size);
        if (*logs) {
            memcpy(*logs, ebpf_logs, ebpf_logs_size);
            ebpf_free((void*)ebpf_logs);
            *logs_size = ebpf_logs_size;
        }
    }

    ebpf_clear_thread_local_storage();
    return result;
}

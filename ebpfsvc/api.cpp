/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "svc_common.h"
#include <stdio.h>
#include "rpc_interface_h.h"
#include "ebpf_windows.h"
#include "Verifier.h"
#include "api_internal.h"

// Critical section to serialize RPC calls.
// Currently ebpfsvc uses a global context to track verification
// and JIT compilation, hence all RPC calls should be serialized.
static CRITICAL_SECTION _critical_section;

ebpf_result_t
ebpf_verify_and_jit_program(
    /* [in] */ ebpf_program_load_info* info,
    /* [out] */ uint32_t* logs_size,
    /* [size_is][size_is][out] */ unsigned char** logs)
{
    UNREFERENCED_PARAMETER(info);
    UNREFERENCED_PARAMETER(logs_size);
    UNREFERENCED_PARAMETER(logs);

    return EBPF_FAILED;
}

ebpf_result_t
ebpf_verify_program(
    /* [in] */ ebpf_program_verify_info* info,
    /* [out] */ uint32_t* logs_size,
    /* [size_is][size_is][out] */ unsigned char** logs)
{
    ebpf_result_t result = EBPF_SUCCESS;
    int error = 0;

    if (info->byte_code_size == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    EnterCriticalSection(&_critical_section);

    clear_map_descriptors();
    if (info->map_descriptors_count != 0) {
        try {
            cache_map_file_descriptors(
                reinterpret_cast<EbpfMapDescriptor*>(info->map_descriptors), info->map_descriptors_count);
        } catch (const std::bad_alloc&) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        } catch (...) {
            result = EBPF_FAILED;
            goto Exit;
        }
    }

    // Verify the program
    error = verify_byte_code(
        reinterpret_cast<const GUID*>(&info->program_type),
        info->byte_code,
        info->byte_code_size,
        (const char**)logs,
        logs_size);

    if (error != 0) {
        result = EBPF_VALIDATION_FAILED;
    }

Exit:
    LeaveCriticalSection(&_critical_section);
    return result;
}

void
initialize_api_globals()
{
    InitializeCriticalSection(&_critical_section);
}

void
clean_up_api_globals()
{
    DeleteCriticalSection(&_critical_section);
}

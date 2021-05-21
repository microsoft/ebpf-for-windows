/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <mutex>
#include <stdexcept>
#include <stdio.h>
#include <vector>
#include "api_internal.h"
#include "ebpf_windows.h"
#include "rpc_interface_h.h"
#include "svc_common.h"
#include "Verifier.h"

// Critical section to serialize RPC calls.
// Currently ebpfsvc uses a global context to track verification
// and JIT compilation, hence all RPC calls should be serialized.
static std::mutex _mutex;

ebpf_result_t
ebpf_verify_and_jit_program(
    /* [ref][in] */ ebpf_program_load_info* info,
    /* [ref][out] */ uint32_t* logs_size,
    /* [ref][size_is][size_is][out] */ const char** logs)
{
    UNREFERENCED_PARAMETER(info);
    UNREFERENCED_PARAMETER(logs_size);
    UNREFERENCED_PARAMETER(logs);

    return EBPF_FAILED;
}

ebpf_result_t
ebpf_verify_program(
    /* [ref][in] */ ebpf_program_verify_info* info,
    /* [out] */ uint32_t* logs_size,
    /* [ref][size_is][size_is][out] */ const char** logs)
{
    ebpf_result_t result = EBPF_SUCCESS;
    int error = 0;

    if (info->byte_code_size == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(_mutex);

    clear_map_descriptors();

    try {
        if (info->map_descriptors_count != 0) {
            cache_map_file_descriptors(
                reinterpret_cast<EbpfMapDescriptor*>(info->map_descriptors), info->map_descriptors_count);
        }

        // Verify the program
        error = verify_byte_code(
            reinterpret_cast<const GUID*>(&info->program_type), info->byte_code, info->byte_code_size, logs, logs_size);

        if (error != 0) {
            result = EBPF_VALIDATION_FAILED;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
    } catch (std::runtime_error& err) {
        auto message = err.what();
        *logs = allocate_error_string(message, logs_size);

        result = EBPF_VALIDATION_FAILED;
    } catch (...) {
        result = EBPF_FAILED;
    }

    return result;
}

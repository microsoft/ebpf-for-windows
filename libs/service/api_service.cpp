// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>
#include <stdexcept>
#include "api_common.hpp"
#include "api_internal.h"
#include "api_service.h"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_protocol.h"
#include "map_descriptors.hpp"
#include "platform.h"
extern "C"
{
#include "ubpf.h"
}
#include "Verifier.h"
#include "verifier_service.h"
#include "windows_helpers.hpp"

ebpf_result_t
ebpf_verify_program(
    const GUID* program_type,
    ebpf_execution_context_t execution_context,
    uint32_t map_descriptors_count,
    EbpfMapDescriptor* map_descriptors,
    uint32_t byte_code_size,
    uint8_t* byte_code,
    const char** logs,
    uint32_t* logs_size)
{
    ebpf_result_t result = EBPF_SUCCESS;
    int error = 0;

    // Only kernel execution context supported currently.
    if (execution_context == execution_context_user_mode) {
        return EBPF_INVALID_ARGUMENT;
    }

    clear_map_descriptors();

    try {
        if (map_descriptors_count != 0) {
            cache_map_file_descriptors(map_descriptors, map_descriptors_count);
        }

        // Verify the program
        error = verify_byte_code(program_type, byte_code, byte_code_size, logs, logs_size);

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

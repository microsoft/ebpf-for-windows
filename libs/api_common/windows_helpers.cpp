// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>
#include <stdexcept>
#include <vector>
#include <Windows.h>
#include "device_helper.hpp"
#include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_xdp_program_data.h"
#include "platform.h"
#undef VOID
#include "platform.hpp"

struct guid_compare
{
    bool
    operator()(const GUID& a, const GUID& b) const
    {
        return (memcmp(&a, &b, sizeof(GUID)) < 0);
    }
};

static thread_local std::map<GUID, ebpf_helper::ebpf_memory_ptr, guid_compare> _program_information_cache;

void
clear_program_information_cache()
{
    _program_information_cache.clear();
}

uint32_t
get_program_information_data(ebpf_program_type_t program_type, ebpf_extension_data_t** program_information_data)
{
    ebpf_protocol_buffer_t reply_buffer(1024);
    ebpf_operation_get_program_information_request_t request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_INFORMATION, program_type};

    auto reply = reinterpret_cast<ebpf_operation_get_program_information_reply_t*>(reply_buffer.data());
    uint32_t retval = invoke_ioctl(device_handle, request, reply_buffer);
    if (retval != ERROR_SUCCESS) {
        return retval;
    }

    if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_INFORMATION) {
        return ERROR_INVALID_PARAMETER;
    }

    size_t allocation_size =
        reply->header.length - EBPF_OFFSET_OF(ebpf_operation_get_program_information_reply_t, version);

    *program_information_data = (ebpf_extension_data_t*)malloc(allocation_size);
    if (!*program_information_data)
        return ERROR_OUTOFMEMORY;

    memcpy(
        *program_information_data,
        reply_buffer.data() + EBPF_OFFSET_OF(ebpf_operation_get_program_information_reply_t, version),
        allocation_size);

    return retval;
}

ebpf_result_t
get_program_type_info(const ebpf_program_information_t** info)
{
    const GUID* program_type = reinterpret_cast<const GUID*>(global_program_info.type.platform_specific_data);
    ebpf_result_t result;
    ebpf_program_information_t* program_information;
    const uint8_t* encoded_data = nullptr;
    size_t encoded_data_size = 0;

    // See if we already have the program information cached.
    auto it = _program_information_cache.find(*program_type);
    if (it == _program_information_cache.end()) {
        // Try to query the information from the execution context.
        ebpf_extension_data_t* program_information_data;
        uint32_t error = get_program_information_data(*program_type, &program_information_data);
        if (error == ERROR_SUCCESS) {
            encoded_data = program_information_data->data;
            encoded_data_size = program_information_data->size;
        } else {
            // Fall back to using static data so that verification can be tried
            // (e.g., from a netsh command) even if the execution context isn't running.
            // TODO: remove this in the future.
            if (memcmp(program_type, &EBPF_PROGRAM_TYPE_XDP, sizeof(*program_type)) == 0) {
                encoded_data = _ebpf_encoded_xdp_program_information_data;
                encoded_data_size = sizeof(_ebpf_encoded_xdp_program_information_data);
            } else if (memcmp(program_type, &EBPF_PROGRAM_TYPE_BIND, sizeof(*program_type)) == 0) {
                encoded_data = _ebpf_encoded_bind_program_information_data;
                encoded_data_size = sizeof(_ebpf_encoded_bind_program_information_data);
            }
        }
        if (encoded_data == nullptr) {
            return EBPF_INVALID_ARGUMENT;
        }

        result = ebpf_program_information_decode(&program_information, encoded_data, (unsigned long)encoded_data_size);
        if (result != EBPF_SUCCESS) {
            return result;
        }

        _program_information_cache[*program_type] = ebpf_helper::ebpf_memory_ptr(program_information);
    }

    *info = (const ebpf_program_information_t*)_program_information_cache[*program_type].get();

    return EBPF_SUCCESS;
}

static ebpf_helper_function_prototype_t*
_get_helper_function_prototype(const ebpf_program_information_t* info, unsigned int n)
{
    for (uint32_t i = 0; i < info->count_of_helpers; i++) {
        if (n == info->helper_prototype[i].helper_id) {
            return &info->helper_prototype[i];
        }
    }
    return nullptr;
}

// Check whether a given integer is a valid helper ID.
bool
is_helper_usable_windows(unsigned int n)
{
    const ebpf_program_information_t* info;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("helper not usable: ") + std::to_string(n));
    }
    return _get_helper_function_prototype(info, n) != nullptr;
}

// Get the prototype for the helper with a given ID.
EbpfHelperPrototype
get_helper_prototype_windows(unsigned int n)
{
    const ebpf_program_information_t* info;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("program type information not found."));
    }
    EbpfHelperPrototype verifier_prototype = {0};

    // TODO (issue #153): remove duplicate struct for ebpf_context_descriptor_t so no cast is needed.
    verifier_prototype.context_descriptor = (EbpfContextDescriptor*)info->program_type_descriptor.context_descriptor;

    ebpf_helper_function_prototype_t* raw_prototype = _get_helper_function_prototype(info, n);
    if (raw_prototype == nullptr) {
        throw std::runtime_error(std::string("helper prototype not found: ") + std::to_string(n));
    }
    verifier_prototype.name = raw_prototype->name;

    // TODO (issue #153): remove duplicate enum for ebpf_helper_return_type_t so no cast is needed.
    // Today one is a C++ enum class and the other is a C enum, but the values match.
    verifier_prototype.return_type = (EbpfHelperReturnType)raw_prototype->return_type;

    for (int i = 0; i < 5; i++) {
        // TODO (issue #153): remove duplicate enum for ebpf_helper_argument_type_t so no cast is needed.
        // Today one is a C++ enum class and the other is a C enum, but the values match.
        verifier_prototype.argument_type[i] = (EbpfHelperArgumentType)raw_prototype->arguments[i];
    }

    return verifier_prototype;
}

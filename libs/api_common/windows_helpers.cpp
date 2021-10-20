// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>
#include <stdexcept>
#include <vector>
#include <Windows.h>
#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_serialize.h"
#include "ebpf_xdp_program_data.h"
#include "platform.h"
#include "platform.hpp"

struct guid_compare
{
    bool
    operator()(const GUID& a, const GUID& b) const
    {
        return (memcmp(&a, &b, sizeof(GUID)) < 0);
    }
};

struct _ebpf_program_info_deleter
{
    void
    operator()(_In_ _Post_invalid_ ebpf_program_info_t* program_info)
    {
        ebpf_program_info_free(program_info);
    }
};

typedef std::unique_ptr<ebpf_program_info_t, _ebpf_program_info_deleter> ebpf_program_info_ptr_t;
static thread_local std::map<GUID, ebpf_program_info_ptr_t, guid_compare> _program_info_cache;

static thread_local std::map<GUID, ebpf_helper::ebpf_memory_ptr, guid_compare> _static_program_info_cache;

static thread_local ebpf_handle_t _program_under_verification = ebpf_handle_invalid;

void
set_program_under_verification(ebpf_handle_t program)
{
    _program_under_verification = program;
}

void
clear_program_info_cache()
{
    _program_info_cache.clear();
}

#define GET_PROGRAM_INFO_REPLY_BUFFER_SIZE 2048

ebpf_result_t
get_program_info_data(ebpf_program_type_t program_type, _Outptr_ ebpf_program_info_t** program_info)
{
    ebpf_protocol_buffer_t reply_buffer(GET_PROGRAM_INFO_REPLY_BUFFER_SIZE);
    size_t required_buffer_length;
    ebpf_operation_get_program_info_request_t request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_INFO,
        program_type,
        _program_under_verification};

    *program_info = nullptr;

    auto reply = reinterpret_cast<ebpf_operation_get_program_info_reply_t*>(reply_buffer.data());
    ebpf_result_t result = win32_error_code_to_ebpf_result(invoke_ioctl(request, reply_buffer));
    if ((result != EBPF_SUCCESS) && (result != EBPF_INSUFFICIENT_BUFFER))
        goto Exit;

    if (result == EBPF_INSUFFICIENT_BUFFER) {
        required_buffer_length = reply->header.length;
        reply_buffer.resize(required_buffer_length);
        reply = reinterpret_cast<ebpf_operation_get_program_info_reply_t*>(reply_buffer.data());
        result = win32_error_code_to_ebpf_result(invoke_ioctl(request, reply_buffer));
        if (result != EBPF_SUCCESS)
            goto Exit;
    }

    if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_INFO) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Deserialize the reply data into program info.
    result = ebpf_deserialize_program_info(reply->size, reply->data, program_info);

Exit:
    return result;
}

ebpf_result_t
get_program_type_info(const ebpf_program_info_t** info)
{
    const GUID* program_type = reinterpret_cast<const GUID*>(global_program_info.type.platform_specific_data);
    ebpf_result_t result;
    ebpf_program_info_t* program_info;
    const uint8_t* encoded_data = nullptr;
    size_t encoded_data_size = 0;
    bool fall_back = false;

    // See if we already have the program info cached.
    auto it = _program_info_cache.find(*program_type);
    if (it == _program_info_cache.end()) {
        // Try to query the info from the execution context.
        result = get_program_info_data(*program_type, &program_info);
        if (result != EBPF_SUCCESS) {
            fall_back = true;
        } else {
            _program_info_cache[*program_type] = ebpf_program_info_ptr_t(program_info);
        }
    }

    if (fall_back) {
        // Fall back to using static data so that verification can be tried
        // (e.g., from a netsh command) even if the execution context isn't running.
        // TODO: remove this in the future.
        auto iter = _static_program_info_cache.find(*program_type);
        if (iter == _static_program_info_cache.end()) {
            if (memcmp(program_type, &EBPF_PROGRAM_TYPE_XDP, sizeof(*program_type)) == 0) {
                encoded_data = _ebpf_encoded_xdp_program_info_data;
                encoded_data_size = sizeof(_ebpf_encoded_xdp_program_info_data);
            } else if (memcmp(program_type, &EBPF_PROGRAM_TYPE_BIND, sizeof(*program_type)) == 0) {
                encoded_data = _ebpf_encoded_bind_program_info_data;
                encoded_data_size = sizeof(_ebpf_encoded_bind_program_info_data);
            }
            ebpf_assert(encoded_data != nullptr);

            result = ebpf_program_info_decode(&program_info, encoded_data, (unsigned long)encoded_data_size);
            if (result != EBPF_SUCCESS) {
                return result;
            }

            _static_program_info_cache[*program_type] = ebpf_helper::ebpf_memory_ptr(program_info);
        }
    }

    if (!fall_back) {
        *info = (const ebpf_program_info_t*)_program_info_cache[*program_type].get();
    } else {
        *info = (const ebpf_program_info_t*)_static_program_info_cache[*program_type].get();
    }

    return EBPF_SUCCESS;
}

static ebpf_helper_function_prototype_t*
_get_helper_function_prototype(const ebpf_program_info_t* info, unsigned int n)
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
is_helper_usable_windows(int32_t n)
{
    const ebpf_program_info_t* info;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("helper not usable: ") + std::to_string(n));
    }
    return _get_helper_function_prototype(info, n) != nullptr;
}

// Get the prototype for the helper with a given ID.
EbpfHelperPrototype
get_helper_prototype_windows(int32_t n)
{
    const ebpf_program_info_t* info;
    ebpf_result_t result = get_program_type_info(&info);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("program type info not found."));
    }
    EbpfHelperPrototype verifier_prototype = {0};

    verifier_prototype.context_descriptor = info->program_type_descriptor.context_descriptor;

    ebpf_helper_function_prototype_t* raw_prototype = _get_helper_function_prototype(info, n);
    if (raw_prototype == nullptr) {
        throw std::runtime_error(std::string("helper prototype not found: ") + std::to_string(n));
    }
    verifier_prototype.name = raw_prototype->name;

    verifier_prototype.return_type = raw_prototype->return_type;

    for (int i = 0; i < 5; i++) {
        verifier_prototype.argument_type[i] = raw_prototype->arguments[i];
    }

    return verifier_prototype;
}

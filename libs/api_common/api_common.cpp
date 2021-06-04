// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdint.h>
#include <string>
#include <vector>
#include <Windows.h>
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)

const char*
allocate_error_string(const std::string& str, uint32_t* length = nullptr)
{
    char* error_message;
    size_t error_message_length = str.size() + 1;
    error_message = (char*)malloc(error_message_length);
    if (error_message != nullptr) {
        strcpy_s(error_message, error_message_length, str.c_str());
        if (length != nullptr) {
            *length = (uint32_t)error_message_length;
        }
    }
    return error_message; // Error;
}

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions)
{
    return {reinterpret_cast<const uint8_t*>(instructions.data()),
            reinterpret_cast<const uint8_t*>(instructions.data()) + instructions.size() * sizeof(ebpf_inst)};
}

int
get_file_size(const char* filename, size_t* byte_code_size)
{
    int result = 0;
    *byte_code_size = NULL;
    struct stat st = {0};
    result = stat(filename, &st);
    if (!result) {
        std::cout << "file size " << st.st_size << std::endl;
        *byte_code_size = st.st_size;
    }

    return result;
}

ebpf_result_t
windows_error_to_ebpf_result(uint32_t error)
{
    switch (error) {
    case ERROR_SUCCESS:
        return EBPF_SUCCESS;

    case ERROR_INVALID_HANDLE:
        return EBPF_ERROR_INVALID_HANDLE;

    case ERROR_FILE_NOT_FOUND:
        return EBPF_FILE_NOT_FOUND;

    case ERROR_NOT_ENOUGH_MEMORY:
        return EBPF_NO_MEMORY;
    }

    return EBPF_FAILED;
}

ebpf_result_t
query_map_definition(
    ebpf_handle_t handle,
    uint32_t* size,
    uint32_t* type,
    uint32_t* key_size,
    uint32_t* value_size,
    uint32_t* max_entries)
{
    _ebpf_operation_query_map_definition_request request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_QUERY_MAP_DEFINITION, reinterpret_cast<uint64_t>(handle)};

    _ebpf_operation_query_map_definition_reply reply;

    uint32_t result = invoke_ioctl(request, reply);
    if (result == ERROR_SUCCESS) {
        *size = reply.map_definition.size;
        *type = reply.map_definition.type;
        *key_size = reply.map_definition.key_size;
        *value_size = reply.map_definition.value_size;
        *max_entries = reply.map_definition.max_entries;
    }

    return windows_error_to_ebpf_result(result);
}

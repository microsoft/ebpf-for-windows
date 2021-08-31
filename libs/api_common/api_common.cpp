// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdint.h>
#include <string>
#include <vector>
#include <Windows.h>

#include "api_common.hpp"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "device_helper.hpp"

#include "ebpf_verifier_wrapper.hpp"

#include "map_descriptors.hpp"

thread_local static const ebpf_program_type_t* _global_program_type = nullptr;
thread_local static const ebpf_attach_type_t* _global_attach_type = nullptr;

const char*
allocate_string(const std::string& string, uint32_t* length) noexcept
{
    char* new_string;
    size_t string_length = string.size() + 1;
    new_string = (char*)malloc(string_length);
    if (new_string != nullptr) {
        strcpy_s(new_string, string_length, string.c_str());
        if (length != nullptr) {
            *length = (uint32_t)string_length;
        }
    }
    return new_string;
}

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions)
{
    return {
        reinterpret_cast<const uint8_t*>(instructions.data()),
        reinterpret_cast<const uint8_t*>(instructions.data()) + instructions.size() * sizeof(ebpf_inst)};
}

int
get_file_size(const char* filename, size_t* byte_code_size) noexcept
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
query_map_definition(
    ebpf_handle_t handle,
    _Out_ uint32_t* size,
    _Out_ uint32_t* type,
    _Out_ uint32_t* key_size,
    _Out_ uint32_t* value_size,
    _Out_ uint32_t* max_entries,
    _Out_ uint32_t* inner_map_id) noexcept
{
    _ebpf_operation_query_map_definition_request request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_QUERY_MAP_DEFINITION, reinterpret_cast<uint64_t>(handle)};

    _ebpf_operation_query_map_definition_reply reply;

    uint32_t error = invoke_ioctl(request, reply);
    ebpf_result_t result = windows_error_to_ebpf_result(error);
    if (result == EBPF_SUCCESS) {
        *size = reply.map_definition.size;
        *type = reply.map_definition.type;
        *key_size = reply.map_definition.key_size;
        *value_size = reply.map_definition.value_size;
        *max_entries = reply.map_definition.max_entries;
        *inner_map_id = reply.map_definition.inner_map_id;
    }
    return result;
}

void
set_global_program_and_attach_type(const ebpf_program_type_t* program_type, const ebpf_attach_type_t* attach_type)
{
    _global_program_type = program_type;
    _global_attach_type = attach_type;
}

const ebpf_program_type_t*
get_global_program_type()
{
    return _global_program_type;
}

const ebpf_attach_type_t*
get_global_attach_type()
{
    return _global_attach_type;
}

void
ebpf_clear_thread_local_storage() noexcept
{
    clear_map_descriptors();
    clear_program_info_cache();
    set_program_under_verification(ebpf_handle_invalid);
}
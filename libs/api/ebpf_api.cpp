// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "pch.h"

#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_protocol.h"
#include "map_descriptors.hpp"
#include "rpc_client.h"
extern "C"
{
#include "ubpf.h"
}
#include "Verifier.h"

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

uint32_t
ebpf_api_initiate()
{
    uint32_t result;

    result = initialize_device_handle();
    if (result != ERROR_SUCCESS) {
        goto Exit;
    }

    result = initialize_rpc_binding();

Exit:
    if (result != ERROR_SUCCESS) {
        clean_up_device_handle();
        clean_up_rpc_binding();
    }
    return result;
}

void
ebpf_api_terminate()
{
    clean_up_device_handle();
    clean_up_rpc_binding();
}

int
create_map_function(
    uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t)
{
    _ebpf_operation_create_map_request request{
        sizeof(_ebpf_operation_create_map_request),
        ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP,
        {sizeof(struct _ebpf_map_definition), type, key_size, value_size, max_entries}};

    _ebpf_operation_create_map_reply reply{};

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
    if (retval != ERROR_SUCCESS) {
        throw std::runtime_error(std::string("Error ") + std::to_string(retval) + " trying to create map");
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP) {
        throw std::runtime_error(std::string("reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP"));
    }

    return cache_map_handle(reply.handle, type, key_size, value_size);
}

static uint32_t
_create_program(
    ebpf_program_type_t program_type,
    const std::string& file_name,
    const std::string& section_name,
    ebpf_handle_t* program_handle)
{
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_create_program_request_t* request;
    ebpf_operation_create_program_reply_t reply;

    request_buffer.resize(
        offsetof(ebpf_operation_create_program_request_t, data) + file_name.size() + section_name.size());

    request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request_buffer.data());
    request->header.id = EBPF_OPERATION_CREATE_PROGRAM;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_type = program_type;
    request->section_name_offset =
        static_cast<uint16_t>(offsetof(ebpf_operation_create_program_request_t, data) + file_name.size());
    std::copy(
        file_name.begin(),
        file_name.end(),
        request_buffer.begin() + offsetof(ebpf_operation_create_program_request_t, data));

    std::copy(section_name.begin(), section_name.end(), request_buffer.begin() + request->section_name_offset);

    uint32_t retval = invoke_ioctl(device_handle, request_buffer, reply);
    if (retval != ERROR_SUCCESS) {
        return retval;
    }
    *program_handle = reinterpret_cast<ebpf_handle_t>(reply.program_handle);
    return retval;
}

uint32_t
ebpf_get_program_byte_code(
    const char* file_name,
    const char* section_name,
    ebpf_program_type_t* program_type,
    bool mock_map_fd,
    uint8_t** instructions,
    uint32_t* instructions_size,
    EbpfMapDescriptor** map_descriptors,
    int* map_descriptors_count,
    const char** error_message)
{
    ebpf_code_buffer_t byte_code(MAX_CODE_SIZE);
    size_t byte_code_size = byte_code.size();
    uint32_t result = ERROR_SUCCESS;

    clear_map_descriptors();
    *instructions = nullptr;
    *map_descriptors = nullptr;

    ebpf_verifier_options_t verifier_options{false, false, false, false, mock_map_fd};
    if (load_byte_code(
            file_name,
            section_name,
            &verifier_options,
            byte_code.data(),
            &byte_code_size,
            program_type,
            error_message) != 0) {
        result = ERROR_INVALID_PARAMETER;
        goto Done;
    }

    // Copy instructions to output buffer.
    *instructions_size = (uint32_t)byte_code_size;
    if (*instructions_size > 0) {
        *instructions = new uint8_t[byte_code_size];
        if (*instructions == nullptr) {
            result = ERROR_NOT_ENOUGH_MEMORY;
            goto Done;
        }
        memcpy(*instructions, byte_code.data(), byte_code_size);
    }

    // Copy map file descriptors (if any) to output buffer.
    *map_descriptors_count = (int)get_map_descriptor_size();
    if (*map_descriptors_count > 0) {
        *map_descriptors = new EbpfMapDescriptor[*map_descriptors_count];
        if (*map_descriptors == nullptr) {
            result = ERROR_NOT_ENOUGH_MEMORY;
            goto Done;
        }
        for (int i = 0; i < *map_descriptors_count; i++) {
            *(*map_descriptors + i) = get_map_descriptor_at_index(i);
        }
    }

Done:
    clear_map_descriptors();
    return result;
}

uint32_t
ebpf_api_load_program(
    const char* file_name,
    const char* section_name,
    ebpf_execution_type_t execution_type,
    ebpf_handle_t* handle,
    uint32_t* count_of_map_handles,
    ebpf_handle_t* map_handles,
    const char** error_message)
{
    ebpf_handle_t program_handle = INVALID_HANDLE_VALUE;
    ebpf_program_type_t program_type;
    ebpf_code_buffer_t byte_code(MAX_CODE_SIZE);
    size_t byte_code_size = byte_code.size();
    ebpf_protocol_buffer_t request_buffer;
    uint32_t error_message_size = 0;
    std::vector<uintptr_t> handles;
    uint32_t result;
    ebpf_program_load_info load_info = {0};

    *handle = 0;
    *error_message = nullptr;

    clear_map_descriptors();

    ebpf_verifier_options_t verifier_options{false, false, false, false, false};
    if (load_byte_code(
            file_name,
            section_name,
            &verifier_options,
            byte_code.data(),
            &byte_code_size,
            &program_type,
            error_message) != 0) {
        result = ERROR_INVALID_PARAMETER;
        goto Done;
    }

    byte_code.resize(byte_code_size);

    // TODO: (issue #169): Should switch this to more idiomatic C++
    // Note: This leaks the program handle on some errors.
    result = _create_program(program_type, file_name, section_name, &program_handle);
    if (result != ERROR_SUCCESS) {
        goto Done;
    }

    if (get_map_descriptor_size() > *count_of_map_handles) {
        result = ERROR_INSUFFICIENT_BUFFER;
        goto Done;
    }

    // populate load_info.
    load_info.file_name = const_cast<char*>(file_name);
    load_info.section_name = const_cast<char*>(section_name);
    load_info.program_name = nullptr;
    load_info.program_type = program_type;
    load_info.program_handle = program_handle;
    load_info.execution_type = execution_type;
    load_info.byte_code = byte_code.data();
    load_info.byte_code_size = (uint32_t)byte_code_size;
    load_info.execution_context = execution_context_kernel_mode;
    load_info.map_count = (uint32_t)get_map_descriptor_size();

    if (load_info.map_count > 0) {
        load_info.handle_map = (fd_handle_map*)calloc(load_info.map_count, sizeof(fd_handle_map));
        if (load_info.handle_map == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }

        auto descriptors = get_all_map_descriptors();
        auto index = 0;
        for (const auto& descriptor : descriptors) {
            load_info.handle_map[index].file_descriptor = descriptor.ebpf_map_descriptor.original_fd;
            load_info.handle_map[index].handle = reinterpret_cast<file_handle_t>(descriptor.handle);
            index++;
        }
    }

    result = ebpf_rpc_load_program(&load_info, error_message, &error_message_size);
    if (result != ERROR_SUCCESS) {
        goto Done;
    }

    // Program is verified and loaded.
    *count_of_map_handles = 0;
    handles = get_all_map_handles();
    for (const auto& map_handle : handles) {
        map_handles[*count_of_map_handles] = reinterpret_cast<HANDLE>(map_handle);
        (*count_of_map_handles)++;
    }

    *handle = program_handle;
    program_handle = INVALID_HANDLE_VALUE;

Done:
    if (result != ERROR_SUCCESS) {
        handles = get_all_map_handles();
        for (const auto& map_handle : handles) {
            ebpf_api_close_handle((ebpf_handle_t)map_handle);
        }
    }
    clear_map_descriptors();

    if (program_handle != INVALID_HANDLE_VALUE) {
        ebpf_api_close_handle(program_handle);
    }

    return result;
}

void
ebpf_api_free_string(const char* error_message)
{
    return free(const_cast<char*>(error_message));
}

uint32_t
ebpf_api_pin_object(ebpf_handle_t handle, const uint8_t* name, uint32_t name_length)
{
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, name) + name_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = reinterpret_cast<uint64_t>(handle);
    std::copy(name, name + name_length, request->name);
    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t
ebpf_api_unpin_object(const uint8_t* name, uint32_t name_length)
{
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, name) + name_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = UINT64_MAX;
    std::copy(name, name + name_length, request->name);
    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t
ebpf_api_get_pinned_map(const uint8_t* name, uint32_t name_length, ebpf_handle_t* handle)
{
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_get_pinning_request_t, name) + name_length);
    auto request = reinterpret_cast<ebpf_operation_get_pinning_request_t*>(request_buffer.data());
    ebpf_operation_get_map_pinning_reply_t reply;

    request->header.id = EBPF_OPERATION_GET_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    std::copy(name, name + name_length, request->name);
    auto result = invoke_ioctl(device_handle, request_buffer, reply);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_PINNING) {
        return ERROR_INVALID_PARAMETER;
    }

    *handle = reinterpret_cast<ebpf_handle_t>(reply.handle);

    return result;
}

uint32_t
ebpf_api_map_find_element(
    ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, uint8_t* value)
{
    ebpf_protocol_buffer_t request_buffer(sizeof(_ebpf_operation_map_find_element_request) + key_size - 1);
    ebpf_protocol_buffer_t reply_buffer(sizeof(_ebpf_operation_map_find_element_reply) + value_size - 1);
    auto request = reinterpret_cast<_ebpf_operation_map_find_element_request*>(request_buffer.data());
    auto reply = reinterpret_cast<_ebpf_operation_map_find_element_reply*>(reply_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_FIND_ELEMENT;
    request->handle = reinterpret_cast<uint64_t>(handle);
    std::copy(key, key + key_size, request->key);

    auto retval = invoke_ioctl(device_handle, request_buffer, reply_buffer);

    if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_MAP_FIND_ELEMENT) {
        return ERROR_INVALID_PARAMETER;
    }

    if (retval == ERROR_SUCCESS) {
        std::copy(reply->value, reply->value + value_size, value);
    }
    return retval;
}

uint32_t
ebpf_api_map_update_element(
    ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, const uint8_t* value)
{
    ebpf_protocol_buffer_t request_buffer(
        sizeof(_ebpf_operation_map_update_element_request) - 1 + key_size + value_size);
    auto request = reinterpret_cast<_ebpf_operation_map_update_element_request*>(request_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
    request->handle = (uint64_t)handle;
    std::copy(key, key + key_size, request->data);
    std::copy(value, value + value_size, request->data + key_size);

    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t
ebpf_api_map_delete_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key)
{
    ebpf_protocol_buffer_t request_buffer(sizeof(_ebpf_operation_map_delete_element_request) - 1 + key_size);
    auto request = reinterpret_cast<_ebpf_operation_map_delete_element_request*>(request_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_DELETE_ELEMENT;
    request->handle = (uint64_t)handle;
    std::copy(key, key + key_size, request->key);

    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t
ebpf_api_get_next_map_key(ebpf_handle_t handle, uint32_t key_size, const uint8_t* previous_key, uint8_t* next_key)
{
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_map_get_next_key_request_t, previous_key) + key_size);
    ebpf_protocol_buffer_t reply_buffer(offsetof(ebpf_operation_map_get_next_key_reply_t, next_key) + key_size);
    auto request = reinterpret_cast<ebpf_operation_map_get_next_key_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_map_get_next_key_reply_t*>(reply_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_GET_NEXT_KEY;
    request->handle = reinterpret_cast<uint64_t>(handle);
    if (previous_key) {
        std::copy(previous_key, previous_key + key_size, request->previous_key);
    } else {
        request->header.length = offsetof(ebpf_operation_map_get_next_key_request_t, previous_key);
    }

    auto retval = invoke_ioctl(device_handle, request_buffer, reply_buffer);

    if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_MAP_GET_NEXT_KEY) {
        return ERROR_INVALID_PARAMETER;
    }

    if (retval == ERROR_SUCCESS) {
        std::copy(reply->next_key, reply->next_key + key_size, next_key);
    }
    return retval;
}

uint32_t
ebpf_api_get_next_map(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle)
{
    _ebpf_operation_get_next_map_request request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_MAP, reinterpret_cast<uint64_t>(previous_handle)};

    _ebpf_operation_get_next_map_reply reply;

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
    if (retval == ERROR_SUCCESS) {
        *next_handle = reinterpret_cast<ebpf_handle_t>(reply.next_handle);
    }
    return retval;
}

uint32_t
ebpf_api_get_next_program(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle)
{
    _ebpf_operation_get_next_program_request request{sizeof(request),
                                                     ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PROGRAM,
                                                     reinterpret_cast<uint64_t>(previous_handle)};

    _ebpf_operation_get_next_program_reply reply;

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
    if (retval == ERROR_SUCCESS) {
        *next_handle = reinterpret_cast<ebpf_handle_t>(reply.next_handle);
    }
    return retval;
}

uint32_t
ebpf_api_map_query_definition(
    ebpf_handle_t handle,
    uint32_t* size,
    uint32_t* type,
    uint32_t* key_size,
    uint32_t* value_size,
    uint32_t* max_entries)
{
    return query_map_definition(handle, size, type, key_size, value_size, max_entries);
}

uint32_t
ebpf_api_program_query_information(
    ebpf_handle_t handle, ebpf_execution_type_t* execution_type, const char** file_name, const char** section_name)
{
    ebpf_protocol_buffer_t reply_buffer(1024);
    _ebpf_operation_query_program_information_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_QUERY_PROGRAM_INFORMATION,
        reinterpret_cast<uint64_t>(handle)};

    auto reply = reinterpret_cast<_ebpf_operation_query_program_information_reply*>(reply_buffer.data());

    uint32_t retval = invoke_ioctl(device_handle, request, reply_buffer);
    if (retval != ERROR_SUCCESS) {
        return retval;
    }

    size_t file_name_length = reply->section_name_offset - reply->file_name_offset;
    size_t section_name_length = reply->header.length - reply->section_name_offset;
    char* local_file_name = reinterpret_cast<char*>(calloc(file_name_length + 1, sizeof(char)));
    char* local_section_name = reinterpret_cast<char*>(calloc(section_name_length + 1, sizeof(char)));

    if (!local_file_name || !local_section_name) {
        free(local_file_name);
        free(local_section_name);
        return ERROR_OUTOFMEMORY;
    }

    memcpy(local_file_name, reply_buffer.data() + reply->file_name_offset, file_name_length);
    memcpy(local_section_name, reply_buffer.data() + reply->section_name_offset, section_name_length);

    local_file_name[file_name_length] = '\0';
    local_section_name[section_name_length] = '\0';

    *execution_type = reply->code_type == EBPF_CODE_NATIVE ? EBPF_EXECUTION_JIT : EBPF_EXECUTION_INTERPRET;
    *file_name = local_file_name;
    *section_name = local_section_name;

    return retval;
}

uint32_t
ebpf_api_link_program(ebpf_handle_t program_handle, ebpf_attach_type_t attach_type, ebpf_handle_t* link_handle)
{
    ebpf_operation_link_program_request_t request = {
        sizeof(request), EBPF_OPERATION_LINK_PROGRAM, reinterpret_cast<uint64_t>(program_handle), attach_type};
    ebpf_operation_link_program_reply_t reply;

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
    if (retval != ERROR_SUCCESS) {
        return retval;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_LINK_PROGRAM) {
        return ERROR_INVALID_PARAMETER;
    }

    *link_handle = reinterpret_cast<ebpf_handle_t>(reply.link_handle);
    return retval;
}

uint32_t
ebpf_api_close_handle(ebpf_handle_t handle)
{
    ebpf_operation_close_handle_request_t request = {
        sizeof(request), EBPF_OPERATION_CLOSE_HANDLE, reinterpret_cast<uint64_t>(handle)};

    return invoke_ioctl(device_handle, request);
}

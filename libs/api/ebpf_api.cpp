// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "pch.h"

#include <io.h>
#include "api_common.hpp"
#include "api_internal.h"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_protocol.h"
#include "ebpf_serialize.h"
#include "map_descriptors.hpp"
#include "rpc_client.h"
extern "C"
{
#include "ubpf.h"
}
#include "Verifier.h"

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

static uint64_t _ebpf_file_descriptor_counter = 0;
static std::map<fd_t, ebpf_program_t*> _ebpf_programs;
static std::map<fd_t, ebpf_map_t*> _ebpf_maps;
static std::vector<ebpf_object_t*> _ebpf_objects;

static void
_clean_up_ebpf_objects();

uint32_t
ebpf_api_initiate()
{
    uint32_t result;

    // This is best effort. If device handle does not initialize,
    // it will be re-attempted before an IOCTL call is made.
    initialize_device_handle();

    result = initialize_rpc_binding();

    if (result != ERROR_SUCCESS) {
        clean_up_device_handle();
        clean_up_rpc_binding();
    }
    return result;
}

void
ebpf_api_terminate()
{
    _clean_up_ebpf_objects();
    clean_up_device_handle();
    clean_up_rpc_binding();
}

ebpf_result_t
ebpf_api_create_map(
    ebpf_map_type_t type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t map_flags,
    _Out_ handle_t* handle)
{
    UNREFERENCED_PARAMETER(map_flags);

    _ebpf_operation_create_map_request request{
        sizeof(_ebpf_operation_create_map_request),
        ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP,
        {sizeof(struct _ebpf_map_definition), type, key_size, value_size, max_entries}};

    _ebpf_operation_create_map_reply reply{};

    uint32_t return_value = EBPF_SUCCESS;

    if (handle == nullptr) {
        return_value = ERROR_INVALID_PARAMETER;
        goto Exit;
    }
    *handle = INVALID_HANDLE_VALUE;

    return_value = invoke_ioctl(request, reply);

    if (return_value != ERROR_SUCCESS)
        goto Exit;

    ebpf_assert(reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP);

    *handle = reinterpret_cast<ebpf_handle_t>(reply.handle);

Exit:
    return windows_error_to_ebpf_result(return_value);
}

int
create_map_internal(
    uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t)
{
    handle_t map_handle = INVALID_HANDLE_VALUE;

    ebpf_result_t result =
        ebpf_api_create_map(static_cast<ebpf_map_type_t>(type), key_size, value_size, max_entries, 0, &map_handle);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("Error ") + std::to_string(result) + " trying to create map");
    }

    return cache_map_handle(reinterpret_cast<uint64_t>(map_handle), type, key_size, value_size, max_entries);
}

static ebpf_result_t
_create_program(
    ebpf_program_type_t program_type,
    _In_ const std::string& file_name,
    _In_ const std::string& section_name,
    _In_ const std::string& program_name,
    _Out_ ebpf_handle_t* program_handle)
{
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_create_program_request_t* request;
    ebpf_operation_create_program_reply_t reply;
    *program_handle = ebpf_handle_invalid;

    request_buffer.resize(
        offsetof(ebpf_operation_create_program_request_t, data) + file_name.size() + section_name.size() +
        program_name.size());

    request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request_buffer.data());
    request->header.id = EBPF_OPERATION_CREATE_PROGRAM;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_type = program_type;
    request->section_name_offset =
        static_cast<uint16_t>(offsetof(ebpf_operation_create_program_request_t, data) + file_name.size());
    request->program_name_offset = static_cast<uint16_t>(request->section_name_offset + section_name.size());
    std::copy(
        file_name.begin(),
        file_name.end(),
        request_buffer.begin() + offsetof(ebpf_operation_create_program_request_t, data));

    std::copy(section_name.begin(), section_name.end(), request_buffer.begin() + request->section_name_offset);
    std::copy(program_name.begin(), program_name.end(), request_buffer.begin() + request->program_name_offset);

    uint32_t error = invoke_ioctl(request_buffer, reply);
    if (error != ERROR_SUCCESS) {
        goto Exit;
    }
    *program_handle = reinterpret_cast<ebpf_handle_t>(reply.program_handle);

Exit:
    return windows_error_to_ebpf_result(error);
}

ebpf_result_t
ebpf_get_program_byte_code(
    _In_z_ const char* file_name,
    _In_z_ const char* section_name,
    bool mock_map_fd,
    std::vector<ebpf_program_t*>& programs,
    _Outptr_result_maybenull_ EbpfMapDescriptor** map_descriptors,
    _Out_ int* map_descriptors_count,
    _Outptr_result_maybenull_ const char** error_message)
{
    ebpf_result_t result = EBPF_SUCCESS;

    clear_map_descriptors();
    *map_descriptors = nullptr;

    ebpf_verifier_options_t verifier_options{false, false, false, false, mock_map_fd};
    result = load_byte_code(file_name, section_name, &verifier_options, programs, error_message);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    if (programs.size() != 1) {
        result = EBPF_FAILED;
        goto Done;
    }

    // Copy map file descriptors (if any) to output buffer.
    *map_descriptors_count = (int)get_map_descriptor_size();
    if (*map_descriptors_count > 0) {
        *map_descriptors = new EbpfMapDescriptor[*map_descriptors_count];
        if (*map_descriptors == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
        for (int i = 0; i < *map_descriptors_count; i++) {
            *(*map_descriptors + i) = get_map_descriptor_at_index(i);
        }
    }

Done:
    if (result != EBPF_SUCCESS) {
        clean_up_ebpf_programs(programs);
    }
    clear_map_descriptors();
    return result;
}

ebpf_result_t
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
    ebpf_protocol_buffer_t request_buffer;
    uint32_t error_message_size = 0;
    std::vector<uintptr_t> handles;
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_load_info load_info = {0};
    std::vector<fd_handle_map> handle_map;
    std::vector<ebpf_program_t*> programs;
    ebpf_program_t* program = nullptr;

    *handle = 0;
    *error_message = nullptr;

    clear_map_descriptors();

    try {
        ebpf_verifier_options_t verifier_options{false, false, false, false, false};
        result = load_byte_code(file_name, section_name, &verifier_options, programs, error_message);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        if (programs.size() != 1) {
            result = EBPF_ELF_PARSING_FAILED;
            goto Done;
        }
        program = programs[0];

        // TODO: (issue #169): Should switch this to more idiomatic C++
        // Note: This leaks the program handle on some errors.
        result = _create_program(program->program_type, file_name, section_name, std::string(), &program_handle);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        if (get_map_descriptor_size() > *count_of_map_handles) {
            result = EBPF_INSUFFICIENT_BUFFER;
            goto Done;
        }

        // populate load_info.
        load_info.file_name = const_cast<char*>(file_name);
        load_info.section_name = const_cast<char*>(section_name);
        load_info.program_name = nullptr;
        load_info.program_type = program->program_type;
        load_info.program_handle = program_handle;
        load_info.execution_type = execution_type;
        load_info.byte_code = program->byte_code;
        load_info.byte_code_size = program->byte_code_size;
        load_info.execution_context = execution_context_kernel_mode;
        load_info.map_count = (uint32_t)get_map_descriptor_size();

        if (load_info.map_count > 0) {
            auto descriptors = get_all_map_descriptors();
            for (const auto& descriptor : descriptors) {
                handle_map.emplace_back(
                    descriptor.ebpf_map_descriptor.original_fd, reinterpret_cast<file_handle_t>(descriptor.handle));
            }

            load_info.handle_map = handle_map.data();
        }

        result = ebpf_rpc_load_program(&load_info, error_message, &error_message_size);
        if (result != EBPF_SUCCESS) {
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
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Done;
    } catch (...) {
        result = EBPF_FAILED;
        goto Done;
    }

Done:
    if (result != EBPF_SUCCESS) {
        handles = get_all_map_handles();
        for (const auto& map_handle : handles) {
            ebpf_api_close_handle((ebpf_handle_t)map_handle);
        }

        clean_up_ebpf_programs(programs);
    }
    clear_map_descriptors();

    if (program_handle != INVALID_HANDLE_VALUE) {
        ebpf_api_close_handle(program_handle);
    }

    return result;
}

void
ebpf_free_string(_In_opt_ _Post_invalid_ const char* error_message)
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
    return invoke_ioctl(request_buffer);
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
    return invoke_ioctl(request_buffer);
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
    auto result = invoke_ioctl(request_buffer, reply);
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

    auto retval = invoke_ioctl(request_buffer, reply_buffer);

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

    return invoke_ioctl(request_buffer);
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

    return invoke_ioctl(request_buffer);
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

    auto retval = invoke_ioctl(request_buffer, reply_buffer);

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

    uint32_t retval = invoke_ioctl(request, reply);
    if (retval == ERROR_SUCCESS) {
        *next_handle = reinterpret_cast<ebpf_handle_t>(reply.next_handle);
    }
    return retval;
}

uint32_t
ebpf_api_get_next_program(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle)
{
    _ebpf_operation_get_next_program_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PROGRAM,
        reinterpret_cast<uint64_t>(previous_handle)};

    _ebpf_operation_get_next_program_reply reply;

    uint32_t retval = invoke_ioctl(request, reply);
    if (retval == ERROR_SUCCESS) {
        *next_handle = reinterpret_cast<ebpf_handle_t>(reply.next_handle);
    }
    return retval;
}

ebpf_result_t
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

    uint32_t retval = invoke_ioctl(request, reply_buffer);
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

    uint32_t retval = invoke_ioctl(request, reply);
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

    return invoke_ioctl(request);
}

ebpf_result_t
ebpf_api_get_pinned_map_info(
    _Out_ uint16_t* map_count, _Outptr_result_buffer_maybenull_(*map_count) ebpf_map_information_t** map_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_operation_get_map_information_request_t request = {
        sizeof(request), EBPF_OPERATION_GET_MAP_INFORMATION, reinterpret_cast<uint64_t>(INVALID_HANDLE_VALUE)};
    ebpf_protocol_buffer_t reply_buffer;
    ebpf_operation_get_map_information_reply_t* reply = nullptr;
    size_t min_expected_buffer_length = 0;
    size_t serialized_buffer_length = 0;
    uint16_t local_map_count = 0;
    ebpf_map_information_t* local_map_info = nullptr;
    size_t output_buffer_length = 4 * 1024;
    uint8_t attempt_count = 0;

    if ((map_count == nullptr) || (map_info == nullptr)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    while (attempt_count < IOCTL_MAX_ATTEMPTS) {
        size_t reply_length;
        result = ebpf_safe_size_t_add(
            EBPF_OFFSET_OF(ebpf_operation_get_map_information_reply_t, data), output_buffer_length, &reply_length);
        if (result != EBPF_SUCCESS)
            goto Exit;

        try {
            reply_buffer.resize(reply_length);
        } catch (const std::bad_alloc&) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        } catch (...) {
            result = EBPF_FAILED;
            goto Exit;
        }

        // Invoke IOCTL.
        result = windows_error_to_ebpf_result(invoke_ioctl(request, reply_buffer));

        if ((result != EBPF_SUCCESS) && (result != EBPF_INSUFFICIENT_BUFFER))
            goto Exit;

        reply = reinterpret_cast<ebpf_operation_get_map_information_reply_t*>(reply_buffer.data());

        if (result == EBPF_INSUFFICIENT_BUFFER) {
            output_buffer_length = reply->size;
            attempt_count++;
            continue;
        } else
            // Success.
            break;
    }

    if (attempt_count == IOCTL_MAX_ATTEMPTS)
        goto Exit;

    local_map_count = reply->map_count;
    serialized_buffer_length = reply->size;

    if (local_map_count == 0)
        // No pinned maps present.
        goto Exit;

    // Check if the data buffer in IOCTL reply is at least as long as the
    // minimum expected length needed to hold the array of ebpf map information objects.
    result = ebpf_safe_size_t_multiply(
        EBPF_OFFSET_OF(ebpf_serialized_map_information_t, pin_path),
        (size_t)local_map_count,
        &min_expected_buffer_length);
    if (result != EBPF_SUCCESS)
        goto Exit;

    ebpf_assert(serialized_buffer_length >= min_expected_buffer_length);
    if (serialized_buffer_length < min_expected_buffer_length) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Deserialize reply buffer.
    result =
        ebpf_deserialize_map_information_array(serialized_buffer_length, reply->data, local_map_count, &local_map_info);
    if (result != EBPF_SUCCESS)
        goto Exit;

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_api_map_info_free(local_map_count, local_map_info);
        local_map_count = 0;
        local_map_info = nullptr;
    }

    *map_count = local_map_count;
    *map_info = local_map_info;

    return result;
}

void
ebpf_api_map_info_free(const uint16_t map_count, _In_opt_count_(map_count) const ebpf_map_information_t* map_info)
{
    ebpf_map_information_array_free(map_count, const_cast<ebpf_map_information_t*>(map_info));
}

void
clean_up_ebpf_program(_In_ _Post_invalid_ ebpf_program_t* program)
{
    if (program == nullptr) {
        return;
    }
    if (program->fd != 0) {
        _ebpf_programs.erase(program->fd);
    }
    if (program->handle != ebpf_handle_invalid) {
        CloseHandle(program->handle);
    }
    free(program->byte_code);
    free(program->program_name);
    free(program->section_name);

    free(program);
}

void
clean_up_ebpf_programs(_Inout_ std::vector<ebpf_program_t*>& programs)
{
    for (auto& program : programs) {
        clean_up_ebpf_program(program);
    }
    programs.resize(0);
}

void
clean_up_ebpf_map(_In_ _Post_invalid_ ebpf_map_t* map)
{
    if (map->map_fd != 0) {
        _ebpf_maps.erase(map->map_fd);
    }
    if (map->map_handle != ebpf_handle_invalid) {
        CloseHandle(map->map_handle);
    }

    free(map);
}

void
clean_up_ebpf_maps(_Inout_ std::vector<ebpf_map_t*>& maps)
{
    for (auto& map : maps) {
        clean_up_ebpf_map(map);
    }
    maps.resize(0);
}

static void
_clean_up_ebpf_object(_In_opt_ _Post_invalid_ ebpf_object_t* object)
{
    if (object != nullptr) {
        clean_up_ebpf_programs(object->programs);
        clean_up_ebpf_maps(object->maps);

        delete object;
    }
}

static void
_remove_ebpf_object_from_globals(_In_ const ebpf_object_t* object)
{
    for (int i = 0; i < _ebpf_objects.size(); i++) {
        if (_ebpf_objects[i] == object) {
            _ebpf_objects[i] = nullptr;
            break;
        }
    }
}

static void
_clean_up_ebpf_objects()
{
    for (auto& object : _ebpf_objects) {
        _clean_up_ebpf_object(object);
    }

    _ebpf_objects.resize(0);

    assert(_ebpf_programs.size() == 0);
    assert(_ebpf_maps.size() == 0);
}

static void
_initialize_map(_Out_ ebpf_map_t* map, _In_ const ebpf_object_t* object, _In_ const map_cache_t& map_cache)
{
    map->object = object;
    map->map_handle = (ebpf_handle_t)map_cache.handle;
    map->map_fd = map_cache.ebpf_map_descriptor.original_fd;
    map->map_defintion.type = (ebpf_map_type_t)map_cache.ebpf_map_descriptor.type;
    map->map_defintion.key_size = map_cache.ebpf_map_descriptor.key_size;
    map->map_defintion.value_size = map_cache.ebpf_map_descriptor.value_size;
    map->map_defintion.max_entries = map_cache.ebpf_map_descriptor.max_entries;
    map->pinned = false;
    map->pin_path = nullptr;
}

static ebpf_result_t
_initialize_ebpf_object_from_elf(
    _In_z_ const char* file_name,
    _In_opt_ const ebpf_program_type_t* expected_program_type,
    _In_opt_ const ebpf_attach_type_t* expected_attach_type,
    _Out_ ebpf_object_t& object,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    set_global_program_and_attach_type(expected_program_type, expected_attach_type);

    ebpf_verifier_options_t verifier_options{false, false, false, false, false};
    result = load_byte_code(file_name, nullptr, &verifier_options, object.programs, error_message);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    object.file_name = _strdup(file_name);
    if (object.file_name == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    try {
        auto map_descriptors = get_all_map_descriptors();
        for (const auto& descriptor : map_descriptors) {
            ebpf_map_t* map = (ebpf_map_t*)calloc(1, sizeof(ebpf_map_t));
            if (map == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            _initialize_map(map, &object, descriptor);
            object.maps.emplace_back(map);
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        clean_up_ebpf_programs(object.programs);
    }
    return result;
}

ebpf_result_t
ebpf_program_load(
    _In_z_ const char* file_name,
    _In_opt_ const ebpf_program_type_t* program_type,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_ ebpf_execution_type_t execution_type,
    _Outptr_ struct _ebpf_object** object,
    _Out_ fd_t* program_fd,
    _Outptr_result_maybenull_z_ const char** log_buffer)
{
    ebpf_object_t* new_object = nullptr;
    ebpf_protocol_buffer_t request_buffer;
    uint32_t error_message_size = 0;
    std::vector<uintptr_t> handles;
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_load_info load_info = {0};
    std::vector<fd_handle_map> handle_map;

    if (file_name == nullptr || object == nullptr || program_fd == nullptr || log_buffer == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // If custom attach type is provided, then custom program type should also
    // be provided.
    if (program_type == nullptr && attach_type != nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    clear_map_descriptors();
    *log_buffer = nullptr;
    *object = nullptr;

    try {
        new_object = new ebpf_object_t();
        if (new_object == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }

        result = _initialize_ebpf_object_from_elf(file_name, program_type, attach_type, *new_object, log_buffer);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        for (auto& program : new_object->programs) {
            result = _create_program(
                program->program_type, file_name, program->section_name, program->program_name, &program->handle);
            if (result != EBPF_SUCCESS) {
                goto Done;
            }

            // TODO: (Issue #287) _open_osfhandle() fails for the program handle.
            // Workaround: for now increment a global counter and use that as
            // file descriptor.
            program->fd = static_cast<fd_t>(InterlockedIncrement(&_ebpf_file_descriptor_counter));

            // populate load_info.
            load_info.file_name = const_cast<char*>(file_name);
            load_info.section_name = const_cast<char*>(program->section_name);
            load_info.program_name = const_cast<char*>(program->program_name);
            load_info.program_type = program->program_type;
            load_info.program_handle = program->handle;
            load_info.execution_type = execution_type;
            load_info.byte_code = program->byte_code;
            load_info.byte_code_size = program->byte_code_size;
            load_info.execution_context = execution_context_kernel_mode;
            load_info.map_count = (uint32_t)get_map_descriptor_size();

            if (load_info.map_count > 0) {
                auto descriptors = get_all_map_descriptors();
                for (const auto& descriptor : descriptors) {
                    handle_map.emplace_back(
                        descriptor.ebpf_map_descriptor.original_fd, reinterpret_cast<file_handle_t>(descriptor.handle));
                }

                load_info.handle_map = handle_map.data();
            }

            result = ebpf_rpc_load_program(&load_info, log_buffer, &error_message_size);
            if (result != EBPF_SUCCESS) {
                goto Done;
            }
        }

        for (auto& program : new_object->programs) {
            _ebpf_programs.insert(std::pair<fd_t, ebpf_program_t*>(program->fd, program));
        }
        for (auto& map : new_object->maps) {
            _ebpf_maps.insert(std::pair<fd_t, ebpf_map_t*>(map->map_fd, map));
        }

        *object = new_object;
        _ebpf_objects.emplace_back(*object);
        *program_fd = new_object->programs[0]->fd;
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Done;
    } catch (...) {
        result = EBPF_FAILED;
        goto Done;
    }

Done:
    if (result != EBPF_SUCCESS) {
        _clean_up_ebpf_object(new_object);
    }
    clear_map_descriptors();
    return result;
}

_Ret_maybenull_ struct _ebpf_program*
ebpf_program_next(_In_opt_ const struct _ebpf_program* previous, _In_ const struct _ebpf_object* object)
{
    ebpf_program_t* program = nullptr;
    if (object == nullptr) {
        goto Exit;
    }
    if (previous != nullptr && previous->object != object) {
        goto Exit;
    }
    if (previous == nullptr) {
        program = object->programs[0];
    } else {
        size_t programs_count = object->programs.size();
        for (size_t i = 0; i < programs_count; i++) {
            if (object->programs[i] == previous && i < programs_count - 1) {
                program = object->programs[i + 1];
                break;
            }
        }
    }

Exit:
    return program;
}

_Ret_maybenull_ struct _ebpf_program*
ebpf_program_previous(_In_opt_ const struct _ebpf_program* next, _In_ const struct _ebpf_object* object)
{
    ebpf_program_t* program = nullptr;
    if (object == nullptr) {
        goto Exit;
    }
    if (next != nullptr && next->object != object) {
        goto Exit;
    }
    if (next == nullptr) {
        program = object->programs[object->programs.size() - 1];
    } else {
        size_t programs_count = object->programs.size();
        for (auto i = programs_count - 1; i > 0; i--) {
            if (object->programs[i] == next) {
                program = object->programs[i - 1];
                break;
            }
        }
    }

Exit:
    return program;
}

_Ret_maybenull_ struct _ebpf_map*
ebpf_map_next(_In_opt_ const struct _ebpf_map* previous, _In_ const struct _ebpf_object* object)
{
    ebpf_map_t* map = nullptr;
    if (object == nullptr) {
        goto Exit;
    }
    if (previous != nullptr && previous->object != object) {
        goto Exit;
    }
    if (previous == nullptr) {
        map = object->maps[0];
    } else {
        size_t maps_count = object->maps.size();
        for (size_t i = 0; i < maps_count; i++) {
            if (object->maps[i] == previous && i < maps_count - 1) {
                map = object->maps[i + 1];
                break;
            }
        }
    }

Exit:
    return map;
}

_Ret_maybenull_ struct _ebpf_map*
ebpf_map_previous(_In_opt_ const struct _ebpf_map* next, _In_ const struct _ebpf_object* object)
{
    ebpf_map_t* map = nullptr;
    if (object == nullptr) {
        goto Exit;
    }
    if (next != nullptr && next->object != object) {
        goto Exit;
    }
    if (next == nullptr) {
        map = object->maps[object->maps.size() - 1];
    } else {
        size_t maps_count = object->maps.size();
        for (auto i = maps_count - 1; i > 0; i--) {
            if (object->maps[i] == next) {
                map = object->maps[i - 1];
                break;
            }
        }
    }

Exit:
    return map;
}

fd_t
ebpf_program_get_fd(_In_ const struct _ebpf_program* program)
{
    if (program == nullptr) {
        return ebpf_fd_invalid;
    }
    return program->fd;
}

fd_t
ebpf_map_get_fd(_In_ const struct _ebpf_map* map)
{
    if (map == nullptr) {
        return ebpf_fd_invalid;
    }
    return map->map_fd;
}

void
ebpf_object_close(_In_ _Post_invalid_ struct _ebpf_object* object)
{
    if (object == nullptr) {
        return;
    }

    _remove_ebpf_object_from_globals(object);
    _clean_up_ebpf_object(object);
}

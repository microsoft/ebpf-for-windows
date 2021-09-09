// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "pch.h"

#include <fcntl.h>
#include <io.h>
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

#ifndef GUID_NULL
const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

static uint64_t _ebpf_file_descriptor_counter = 0;
static std::map<fd_t, ebpf_handle_t> _fd_to_handle_map;
static std::map<ebpf_handle_t, ebpf_program_t*> _ebpf_programs;
static std::map<ebpf_handle_t, ebpf_map_t*> _ebpf_maps;
static std::vector<ebpf_object_t*> _ebpf_objects;

static void
_clean_up_ebpf_objects();

static fd_t
_get_next_file_descriptor(ebpf_handle_t handle) noexcept
{
    try {
        fd_t fd = static_cast<fd_t>(InterlockedIncrement(&_ebpf_file_descriptor_counter));
        _fd_to_handle_map.insert(std::pair<fd_t, ebpf_handle_t>(fd, handle));
        return fd;
    } catch (...) {
        return ebpf_fd_invalid;
    }
}

inline static ebpf_handle_t
_get_handle_from_fd(fd_t fd)
{
    std::map<fd_t, ebpf_handle_t>::iterator it = _fd_to_handle_map.find(fd);
    if (it != _fd_to_handle_map.end()) {
        return it->second;
    }

    return ebpf_handle_invalid;
}

inline static ebpf_map_t*
_get_ebpf_map_from_handle(ebpf_handle_t map_handle)
{
    if (map_handle == ebpf_handle_invalid) {
        return nullptr;
    }
    ebpf_map_t* map = nullptr;
    std::map<ebpf_handle_t, ebpf_map_t*>::iterator it = _ebpf_maps.find(map_handle);
    if (it != _ebpf_maps.end()) {
        map = it->second;
    }

    return map;
}

inline static ebpf_program_t*
_get_ebpf_program_from_handle(ebpf_handle_t program_handle)
{
    if (program_handle == ebpf_handle_invalid) {
        return nullptr;
    }
    ebpf_program_t* program = nullptr;
    std::map<ebpf_handle_t, ebpf_program_t*>::iterator it = _ebpf_programs.find(program_handle);
    if (it != _ebpf_programs.end()) {
        program = it->second;
    }

    return program;
}

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
        EBPF_OFFSET_OF(ebpf_operation_create_map_request_t, data),
        ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP,
        {sizeof(ebpf_map_definition_in_memory_t), type, key_size, value_size, max_entries},
        (uint64_t)ebpf_handle_invalid};

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

static ebpf_result_t
_create_map(
    _In_opt_z_ const char* name,
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Out_ ebpf_handle_t* map_handle)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t return_value = ERROR_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    _ebpf_operation_create_map_request* request;
    ebpf_operation_create_map_reply_t reply;
    std::string map_name;
    size_t map_name_size;

    if (name != nullptr) {
        map_name = std::string(name);
    }
    *map_handle = ebpf_handle_invalid;
    map_name_size = map_name.size();

    size_t buffer_size = offsetof(ebpf_operation_create_map_request_t, data) + map_name_size;
    request_buffer.resize(buffer_size);

    request = reinterpret_cast<ebpf_operation_create_map_request_t*>(request_buffer.data());
    request->header.id = EBPF_OPERATION_CREATE_MAP;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->ebpf_map_definition = *map_definition;
    request->inner_map_handle = (uint64_t)inner_map_handle;
    std::copy(
        map_name.begin(), map_name.end(), request_buffer.begin() + offsetof(ebpf_operation_create_map_request_t, data));

    return_value = invoke_ioctl(request_buffer, reply);
    if (return_value != ERROR_SUCCESS) {
        result = windows_error_to_ebpf_result(return_value);
        goto Exit;
    }
    ebpf_assert(reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP);
    *map_handle = reinterpret_cast<ebpf_handle_t>(reply.handle);

Exit:
    return result;
}

ebpf_result_t
ebpf_create_map_name(
    ebpf_map_type_t type,
    _In_opt_z_ const char* name,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t map_flags,
    _Out_ fd_t* map_fd)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle = ebpf_handle_invalid;
    ebpf_map_definition_in_memory_t map_definition = {0};

    if (map_flags != 0 || map_fd == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    *map_fd = ebpf_fd_invalid;

    try {
        map_definition.size = sizeof(map_definition);
        map_definition.type = type;
        map_definition.key_size = key_size;
        map_definition.value_size = value_size;
        map_definition.max_entries = max_entries;

        result = _create_map(name, &map_definition, ebpf_handle_invalid, &map_handle);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
        *map_fd = _get_next_file_descriptor(map_handle);
        if (*map_fd == ebpf_fd_invalid) {
            result = EBPF_NO_MEMORY;
            goto Exit;
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
        if (map_handle != ebpf_handle_invalid) {
            Platform::CloseHandle(map_handle);
        }
    }
    return result;
}

ebpf_result_t
ebpf_create_map(
    ebpf_map_type_t type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t map_flags,
    _Out_ fd_t* map_fd)
{
    return ebpf_create_map_name(type, nullptr, key_size, value_size, max_entries, map_flags, map_fd);
}

static ebpf_result_t
_map_lookup_element(
    ebpf_handle_t handle,
    uint32_t key_size,
    _In_ const uint8_t* key,
    uint32_t value_size,
    _Out_ uint8_t* value) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    try {
        ebpf_protocol_buffer_t request_buffer(
            EBPF_OFFSET_OF(ebpf_operation_map_find_element_request_t, key) + key_size);
        ebpf_protocol_buffer_t reply_buffer(
            EBPF_OFFSET_OF(ebpf_operation_map_find_element_reply_t, value) + value_size);
        auto request = reinterpret_cast<ebpf_operation_map_find_element_request_t*>(request_buffer.data());
        auto reply = reinterpret_cast<ebpf_operation_map_find_element_reply_t*>(reply_buffer.data());

        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_FIND_ELEMENT;
        request->handle = reinterpret_cast<uint64_t>(handle);
        std::copy(key, key + key_size, request->key);

        result = windows_error_to_ebpf_result(invoke_ioctl(request_buffer, reply_buffer));

        if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_MAP_FIND_ELEMENT) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if (result == EBPF_SUCCESS) {
            std::copy(reply->value, reply->value + value_size, value);
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    return result;
}

static inline ebpf_result_t
_get_map_descriptor_properties(
    ebpf_handle_t handle, _Out_ uint32_t* type, _Out_ uint32_t* key_size, _Out_ uint32_t* value_size)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_map_t* map;

    *type = BPF_MAP_TYPE_UNSPECIFIED;
    *key_size = 0;
    *value_size = 0;

    // First check if the map is present in the cache.
    map = _get_ebpf_map_from_handle(handle);
    if (map == nullptr) {
        // Map is not present in the local cache. Query map descriptor from EC.
        uint32_t size;
        uint32_t max_entries;
        ebpf_id_t inner_map_id;
        result = query_map_definition(handle, &size, type, key_size, value_size, &max_entries, &inner_map_id);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    } else {
        *type = map->map_definition.type;
        *key_size = map->map_definition.key_size;
        *value_size = map->map_definition.value_size;
    }

Exit:
    return result;
}

ebpf_result_t
ebpf_map_lookup_element(fd_t map_fd, _In_ const void* key, _Out_ void* value)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t type;

    if (map_fd <= 0 || key == nullptr || value == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    *((uint8_t*)value) = 0;

    map_handle = _get_handle_from_fd(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_FD;
        goto Exit;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    assert(key_size != 0);
    assert(value_size != 0);

    result = _map_lookup_element(map_handle, key_size, (uint8_t*)key, value_size, (uint8_t*)value);

Exit:
    return result;
}

static ebpf_result_t
_update_map_element(
    ebpf_handle_t map_handle,
    _In_ const void* key,
    uint32_t key_size,
    _In_ const void* value,
    uint32_t value_size,
    uint64_t flags) noexcept
{
    ebpf_result_t result;
    ebpf_protocol_buffer_t request_buffer;
    epf_operation_map_update_element_request_t* request;

    try {
        request_buffer.resize(EBPF_OFFSET_OF(epf_operation_map_update_element_request_t, data) + key_size + value_size);
        request = reinterpret_cast<_ebpf_operation_map_update_element_request*>(request_buffer.data());

        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
        request->handle = (uint64_t)map_handle;
        request->option = static_cast<ebpf_map_option_t>(flags);
        std::copy((uint8_t*)key, (uint8_t*)key + key_size, request->data);
        std::copy((uint8_t*)value, (uint8_t*)value + value_size, request->data + key_size);

        result = windows_error_to_ebpf_result(invoke_ioctl(request_buffer));
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    return result;
}

static ebpf_result_t
_update_map_element_with_handle(
    ebpf_handle_t map_handle,
    uint32_t key_size,
    _In_ const uint8_t* key,
    ebpf_handle_t value_handle,
    uint64_t flags) noexcept
{
    ebpf_protocol_buffer_t request_buffer(
        EBPF_OFFSET_OF(ebpf_operation_map_update_element_with_handle_request_t, key) + key_size);
    auto request = reinterpret_cast<ebpf_operation_map_update_element_with_handle_request_t*>(request_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE;
    request->map_handle = (uintptr_t)map_handle;
    request->value_handle = (uintptr_t)value_handle;
    request->option = static_cast<ebpf_map_option_t>(flags);
    std::copy(key, key + key_size, request->key);

    return windows_error_to_ebpf_result(invoke_ioctl(request_buffer));
}

ebpf_result_t
ebpf_map_update_element(fd_t map_fd, _In_ const void* key, _In_ const void* value, uint64_t flags)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t type;

    if (map_fd <= 0 || key == nullptr || value == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    switch (flags) {
    case EBPF_ANY:
    case EBPF_NOEXIST:
    case EBPF_EXIST:
        break;
    default:
        return EBPF_INVALID_ARGUMENT;
    }

    map_handle = _get_handle_from_fd(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    assert(key_size != 0);
    assert(value_size != 0);
    assert(type != 0);

    if ((type == BPF_MAP_TYPE_PROG_ARRAY) || (type == BPF_MAP_TYPE_HASH_OF_MAPS) ||
        (type == BPF_MAP_TYPE_ARRAY_OF_MAPS)) {
        fd_t fd = *(fd_t*)value;
        ebpf_handle_t handle = _get_handle_from_fd(fd);
        if (handle == ebpf_handle_invalid) {
            return EBPF_INVALID_FD;
        }

        return _update_map_element_with_handle(map_handle, key_size, (const uint8_t*)key, handle, flags);
    } else {
        return _update_map_element(map_handle, key, key_size, value, value_size, flags);
    }
}

ebpf_result_t
ebpf_map_delete_element(fd_t map_fd, _In_ const void* key)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t type;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_map_delete_element_request_t* request;

    if (map_fd <= 0 || key == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    map_handle = _get_handle_from_fd(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_FD;
        goto Exit;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    assert(key_size != 0);
    assert(value_size != 0);

    try {
        request_buffer.resize(EBPF_OFFSET_OF(ebpf_operation_map_delete_element_request_t, key) + key_size);
        request = reinterpret_cast<ebpf_operation_map_delete_element_request_t*>(request_buffer.data());

        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_DELETE_ELEMENT;
        request->handle = (uint64_t)map_handle;
        std::copy((uint8_t*)key, (uint8_t*)key + key_size, request->key);

        result = windows_error_to_ebpf_result(invoke_ioctl(request_buffer));
        if (result == EBPF_INVALID_OBJECT) {
            result = EBPF_INVALID_FD;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    return result;
}

ebpf_result_t
ebpf_map_get_next_key(fd_t map_fd, _In_opt_ const void* previous_key, _Out_ void* next_key)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_protocol_buffer_t reply_buffer;
    ebpf_operation_map_get_next_key_request_t* request;
    ebpf_operation_map_get_next_key_reply_t* reply;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t type;
    ebpf_handle_t map_handle = ebpf_handle_invalid;

    if (map_fd <= 0 || next_key == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    map_handle = _get_handle_from_fd(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_FD;
        goto Exit;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    assert(key_size != 0);
    assert(value_size != 0);

    try {
        request_buffer.resize((offsetof(ebpf_operation_map_get_next_key_request_t, previous_key) + key_size));
        reply_buffer.resize((offsetof(ebpf_operation_map_get_next_key_reply_t, next_key) + key_size));
        request = reinterpret_cast<ebpf_operation_map_get_next_key_request_t*>(request_buffer.data());
        reply = reinterpret_cast<ebpf_operation_map_get_next_key_reply_t*>(reply_buffer.data());

        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_GET_NEXT_KEY;
        request->handle = reinterpret_cast<uint64_t>(map_handle);
        if (previous_key) {
            uint8_t* end = (uint8_t*)previous_key + key_size;
            std::copy((uint8_t*)previous_key, end, request->previous_key);
        } else {
            request->header.length = offsetof(ebpf_operation_map_get_next_key_request_t, previous_key);
        }

        result = windows_error_to_ebpf_result(invoke_ioctl(request_buffer, reply_buffer));

        if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_MAP_GET_NEXT_KEY) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if (result == EBPF_SUCCESS) {
            std::copy(reply->next_key, reply->next_key + key_size, (uint8_t*)next_key);
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    return result;
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
    std::vector<ebpf_map_t*> maps;

    clear_map_descriptors();
    *map_descriptors = nullptr;

    ebpf_verifier_options_t verifier_options{false, false, false, false, mock_map_fd};
    result = load_byte_code(file_name, section_name, &verifier_options, programs, maps, error_message);
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
    clean_up_ebpf_maps(maps);
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
    std::vector<ebpf_handle_t> handles;
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_load_info load_info = {0};
    std::vector<original_fd_handle_map_t> handle_map;
    std::vector<ebpf_program_t*> programs;
    std::vector<ebpf_map_t*> maps;
    ebpf_program_t* program = nullptr;

    *handle = 0;
    *error_message = nullptr;

    clear_map_descriptors();

    try {
        ebpf_verifier_options_t verifier_options{false, false, false, false, false};
        result = load_byte_code(file_name, section_name, &verifier_options, programs, maps, error_message);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        if (programs.size() != 1) {
            result = EBPF_ELF_PARSING_FAILED;
            goto Done;
        }
        program = programs[0];

        // Create all the maps.
        for (auto& map : maps) {
            ebpf_handle_t inner_map_handle = (map->inner_map) ? map->inner_map->map_handle : ebpf_handle_invalid;
            result = _create_map(map->name, &map->map_definition, inner_map_handle, &map->map_handle);
            if (result != EBPF_SUCCESS) {
                goto Done;
            }
            map->map_fd = _get_next_file_descriptor(map->map_handle);
            if (map->map_fd == ebpf_fd_invalid) {
                result = EBPF_FAILED;
                goto Done;
            }
        }

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
            for (auto& map : maps) {
                fd_t inner_map_original_fd = (map->inner_map) ? map->inner_map->original_fd : ebpf_fd_invalid;
                handle_map.emplace_back(
                    map->original_fd, inner_map_original_fd, reinterpret_cast<file_handle_t>(map->map_handle));
            }

            load_info.handle_map = handle_map.data();
        }

        result = ebpf_rpc_load_program(&load_info, error_message, &error_message_size);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        // Program is verified and loaded.
        *count_of_map_handles = 0;
        for (auto& map : maps) {
            map_handles[*count_of_map_handles] = reinterpret_cast<HANDLE>(map->map_handle);
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
    } else {
        // Clean up ebpf_program_t structures without closing the handle.
        for (auto& program_it : programs) {
            program_it->handle = ebpf_handle_invalid;
            clean_up_ebpf_program(program_it);
        }
    }
    clear_map_descriptors();

    // Clean up ebpf_map_t structures without closing the handle.
    for (auto& map : maps) {
        map->map_handle = ebpf_handle_invalid;
        clean_up_ebpf_map(map);
    }

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

ebpf_result_t
ebpf_object_pin(fd_t fd, _In_z_ const char* path)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t handle;
    if (fd <= 0 || path == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    // This is a workaround till we start using _open_osfhandle() to generate
    // fds for the handles (issue tracked by TODO: Issue# 287). Once this is
    // fixed, _get_osfhandle() can be directly used to fetch the corresponding
    // handle.
    handle = _get_handle_from_fd(fd);
    if (handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    auto path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, name) + path_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = reinterpret_cast<uint64_t>(handle);
    std::copy(path, path + path_length, request->name);
    result = windows_error_to_ebpf_result(invoke_ioctl(request_buffer));

    return result;
}

ebpf_result_t
ebpf_object_unpin(_In_z_ const char* path)
{
    if (path == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    auto path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, name) + path_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = UINT64_MAX;
    std::copy(path, path + path_length, request->name);
    return windows_error_to_ebpf_result(invoke_ioctl(request_buffer));
}

ebpf_result_t
ebpf_map_pin(_In_ struct bpf_map* map, _In_opt_z_ const char* path)
{
    if (map == nullptr || (map->pin_path == nullptr && path == nullptr)) {
        return EBPF_INVALID_ARGUMENT;
    }
    if (map->pinned) {
        return (map->pin_path != nullptr && path != nullptr && strcmp(path, map->pin_path) == 0)
                   ? EBPF_OBJECT_ALREADY_EXISTS
                   : EBPF_ALREADY_PINNED;
    }
    if (path != nullptr) {
        // If pin path is already set, the pin path provided now should be same
        // as the one previously set.
        if (map->pin_path != nullptr && strcmp(path, map->pin_path) != 0) {
            return EBPF_INVALID_ARGUMENT;
        }
        free(map->pin_path);
        map->pin_path = _strdup(path);
        if (map->pin_path == nullptr) {
            return EBPF_NO_MEMORY;
        }
    }
    assert(map->map_handle != ebpf_handle_invalid);
    assert(map->map_fd > 0);
    ebpf_result_t result = ebpf_object_pin(map->map_fd, map->pin_path);
    if (result == EBPF_SUCCESS) {
        map->pinned = true;
    }

    return result;
}

ebpf_result_t
ebpf_map_set_pin_path(_In_ struct bpf_map* map, _In_ const char* path)
{
    if (map == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    char* old_path = map->pin_path;
    if (path != nullptr) {
        path = _strdup(path);
        if (path == nullptr) {
            return EBPF_NO_MEMORY;
        }
    }
    map->pin_path = const_cast<char*>(path);
    free(old_path);

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_map_unpin(_In_ struct bpf_map* map, _In_opt_z_ const char* path)
{
    if (map == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (map->pin_path != nullptr) {
        // If pin path is already set, the pin path provided now should be same
        // as the one previously set.
        if (path != nullptr && strcmp(path, map->pin_path) != 0) {
            return EBPF_INVALID_ARGUMENT;
        }
        path = map->pin_path;
    } else if (path == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    assert(map->map_handle != ebpf_handle_invalid);
    assert(map->map_fd > 0);

    ebpf_result_t result = ebpf_object_unpin(path);
    if (result == EBPF_SUCCESS) {
        map->pinned = false;
    }

    return result;
}

fd_t
ebpf_object_get(_In_z_ const char* path)
{
    size_t path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_get_pinning_request_t, name) + path_length);
    auto request = reinterpret_cast<ebpf_operation_get_pinning_request_t*>(request_buffer.data());
    ebpf_operation_get_map_pinning_reply_t reply;

    request->header.id = EBPF_OPERATION_GET_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    std::copy(path, path + path_length, request->name);
    auto result = invoke_ioctl(request_buffer, reply);
    if (result != ERROR_SUCCESS) {
        return ebpf_fd_invalid;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_PINNING) {
        return ebpf_fd_invalid;
    }

    ebpf_handle_t handle = reinterpret_cast<ebpf_handle_t>(reply.handle);
    fd_t fd = _get_next_file_descriptor(handle);
    if (fd == ebpf_fd_invalid) {
        Platform::CloseHandle(handle);
    }
    return fd;
}

ebpf_result_t
ebpf_get_next_map(fd_t previous_fd, _Out_ fd_t* next_fd)
{
    if (next_fd == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    fd_t local_fd = previous_fd;
    *next_fd = ebpf_fd_invalid;

    ebpf_handle_t previous_handle = _get_handle_from_fd(local_fd);
    ebpf_operation_get_next_map_request_t request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_MAP, reinterpret_cast<uint64_t>(previous_handle)};

    ebpf_operation_get_next_map_reply_t reply;

    uint32_t retval = invoke_ioctl(request, reply);
    if (retval == ERROR_SUCCESS) {
        ebpf_handle_t next_handle = reinterpret_cast<ebpf_handle_t>(reply.next_handle);
        if (next_handle != ebpf_handle_invalid) {
            fd_t fd = _get_next_file_descriptor(next_handle);
            if (fd == ebpf_fd_invalid) {
                // Some error getting fd for the handle.
                Platform::CloseHandle(next_handle);
                retval = ERROR_OUTOFMEMORY;
            } else {
                *next_fd = fd;
            }
        } else {
            *next_fd = ebpf_fd_invalid;
        }
    }
    return windows_error_to_ebpf_result(retval);
}

ebpf_result_t
ebpf_get_next_program(fd_t previous_fd, _Out_ fd_t* next_fd)
{
    if (next_fd == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    fd_t local_fd = previous_fd;
    *next_fd = ebpf_fd_invalid;

    ebpf_handle_t previous_handle = _get_handle_from_fd(local_fd);
    ebpf_operation_get_next_program_request_t request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PROGRAM,
        reinterpret_cast<uint64_t>(previous_handle)};

    ebpf_operation_get_next_program_reply_t reply;

    uint32_t retval = invoke_ioctl(request, reply);
    if (retval == ERROR_SUCCESS) {
        ebpf_handle_t next_handle = reinterpret_cast<ebpf_handle_t>(reply.next_handle);
        if (next_handle != ebpf_handle_invalid) {
            fd_t fd = _get_next_file_descriptor(next_handle);
            if (fd == ebpf_fd_invalid) {
                // Some error getting fd for the handle.
                Platform::CloseHandle(next_handle);
                retval = ERROR_OUTOFMEMORY;
            } else {
                *next_fd = fd;
            }
        } else {
            *next_fd = ebpf_fd_invalid;
        }
    }
    return windows_error_to_ebpf_result(retval);
}

ebpf_result_t
ebpf_map_query_definition(
    fd_t fd,
    _Out_ uint32_t* size,
    _Out_ uint32_t* type,
    _Out_ uint32_t* key_size,
    _Out_ uint32_t* value_size,
    _Out_ uint32_t* max_entries,
    _Out_ ebpf_id_t* inner_map_id)
{
    ebpf_handle_t map_handle = _get_handle_from_fd(fd);
    if (map_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }
    return query_map_definition(map_handle, size, type, key_size, value_size, max_entries, inner_map_id);
}

ebpf_result_t
ebpf_program_query_info(
    fd_t fd,
    _Out_ ebpf_execution_type_t* execution_type,
    _Outptr_result_z_ const char** file_name,
    _Outptr_result_z_ const char** section_name)
{
    ebpf_result_t result;
    ebpf_handle_t handle = _get_handle_from_fd(fd);
    if (handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    if (execution_type == nullptr || file_name == nullptr || section_name == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_protocol_buffer_t reply_buffer(1024);
    ebpf_operation_query_program_info_request_t request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_QUERY_PROGRAM_INFO, reinterpret_cast<uint64_t>(handle)};

    auto reply = reinterpret_cast<ebpf_operation_query_program_info_reply_t*>(reply_buffer.data());

    uint32_t retval = invoke_ioctl(request, reply_buffer);
    if (retval != ERROR_SUCCESS) {
        result = windows_error_to_ebpf_result(retval);
        __analysis_assume(result != EBPF_SUCCESS);
        return result;
    }

    size_t file_name_length = reply->section_name_offset - reply->file_name_offset;
    size_t section_name_length = reply->header.length - reply->section_name_offset;
    char* local_file_name = reinterpret_cast<char*>(calloc(file_name_length + 1, sizeof(char)));
    char* local_section_name = reinterpret_cast<char*>(calloc(section_name_length + 1, sizeof(char)));

    if (!local_file_name || !local_section_name) {
        free(local_file_name);
        free(local_section_name);
        return EBPF_NO_MEMORY;
    }

    memcpy(local_file_name, reply_buffer.data() + reply->file_name_offset, file_name_length);
    memcpy(local_section_name, reply_buffer.data() + reply->section_name_offset, section_name_length);

    local_file_name[file_name_length] = '\0';
    local_section_name[section_name_length] = '\0';

    *execution_type = reply->code_type == EBPF_CODE_NATIVE ? EBPF_EXECUTION_JIT : EBPF_EXECUTION_INTERPRET;
    *file_name = local_file_name;
    *section_name = local_section_name;

    return windows_error_to_ebpf_result(retval);
}

uint32_t
ebpf_api_link_program(ebpf_handle_t program_handle, ebpf_attach_type_t attach_type, ebpf_handle_t* link_handle)
{
    ebpf_operation_link_program_request_t request = {
        EBPF_OFFSET_OF(ebpf_operation_link_program_request_t, data),
        EBPF_OPERATION_LINK_PROGRAM,
        reinterpret_cast<uint64_t>(program_handle),
        attach_type};
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

static ebpf_result_t
_link_ebpf_program(
    ebpf_handle_t program_handle,
    _In_ const ebpf_attach_type_t* attach_type,
    _Out_ ebpf_handle_t* link_handle,
    _In_reads_bytes_opt_(attach_parameter_size) uint8_t* attach_parameter,
    size_t attach_parameter_size) noexcept
{
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_link_program_request_t* request;
    ebpf_operation_link_program_reply_t reply;
    ebpf_result_t result = EBPF_SUCCESS;
    *link_handle = ebpf_handle_invalid;

    try {
        size_t buffer_size = offsetof(ebpf_operation_link_program_request_t, data) + attach_parameter_size;
        request_buffer.resize(buffer_size);
        request = reinterpret_cast<ebpf_operation_link_program_request_t*>(request_buffer.data());
        request->header.id = EBPF_OPERATION_LINK_PROGRAM;
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->program_handle = reinterpret_cast<uint64_t>(program_handle);
        request->attach_type = *attach_type;

        if (attach_parameter_size > 0) {
            memcpy_s(request->data, attach_parameter_size, attach_parameter, attach_parameter_size);
        }

        result = windows_error_to_ebpf_result(invoke_ioctl(request_buffer, reply));
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_LINK_PROGRAM) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        *link_handle = reinterpret_cast<ebpf_handle_t>(reply.link_handle);
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    return result;
}

static void
_clean_up_ebpf_link(_In_opt_ _Post_invalid_ ebpf_link_t* link)
{
    if (link == nullptr) {
        return;
    }
    if (link->handle != ebpf_handle_invalid) {
        ebpf_api_close_handle(link->handle);
    }
    free(link->pin_path);

    free(link);
}

static ebpf_result_t
_detach_link_by_handle(ebpf_handle_t link_handle)
{
    ebpf_operation_unlink_program_request_t request = {
        sizeof(request), EBPF_OPERATION_UNLINK_PROGRAM, reinterpret_cast<uint64_t>(link_handle)};

    return windows_error_to_ebpf_result(invoke_ioctl(request));
}

ebpf_result_t
ebpf_detach_link_by_fd(fd_t fd)
{
    ebpf_handle_t link_handle = _get_handle_from_fd(fd);
    if (link_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    return _detach_link_by_handle(link_handle);
}

ebpf_result_t
ebpf_program_attach(
    _In_ struct bpf_program* program,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_opt_(attach_params_size) void* attach_parameters,
    _In_ size_t attach_params_size,
    _Outptr_ struct bpf_link** link)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_attach_type_t* program_attach_type;
    ebpf_link_t* new_link = nullptr;

    if (program == nullptr || link == nullptr || (attach_params_size != 0 && attach_parameters == nullptr) ||
        (attach_parameters != nullptr && attach_params_size == 0)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    if (IsEqualGUID(program->attach_type, GUID_NULL)) {
        if (attach_type == nullptr) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        } else {
            program_attach_type = attach_type;
        }
    } else {
        program_attach_type = &program->attach_type;
    }
    assert(program->handle != ebpf_handle_invalid);

    *link = nullptr;
    new_link = (ebpf_link_t*)calloc(1, sizeof(ebpf_link_t));
    if (new_link == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    result = _link_ebpf_program(
        program->handle, program_attach_type, &new_link->handle, (uint8_t*)attach_parameters, attach_params_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    new_link->fd = _get_next_file_descriptor(new_link->handle);
    if (new_link->fd == ebpf_fd_invalid) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    *link = new_link;

Exit:
    if (result != EBPF_SUCCESS) {
        if (new_link != nullptr && new_link->handle != ebpf_handle_invalid) {
            ebpf_link_detach(new_link);
        }
        _clean_up_ebpf_link(new_link);
    }
    return result;
}

ebpf_result_t
ebpf_program_attach_by_fd(
    fd_t program_fd,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_opt_(attach_params_size) void* attach_parameters,
    _In_ size_t attach_params_size,
    _Outptr_ struct bpf_link** link)
{
    ebpf_program_t* program = _get_ebpf_program_from_handle(_get_handle_from_fd(program_fd));
    if (program == nullptr || link == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    *link = nullptr;

    return ebpf_program_attach(program, attach_type, attach_parameters, attach_params_size, link);
}

uint32_t
ebpf_api_unlink_program(ebpf_handle_t link_handle)
{
    ebpf_operation_unlink_program_request_t request = {
        sizeof(request), EBPF_OPERATION_UNLINK_PROGRAM, reinterpret_cast<uint64_t>(link_handle)};

    return invoke_ioctl(request);
}

ebpf_result_t
ebpf_link_detach(_In_ struct bpf_link* link)
{
    if (link == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    return _detach_link_by_handle(link->handle);
}

ebpf_result_t
ebpf_link_close(_In_ struct bpf_link* link)
{
    if (link == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    _clean_up_ebpf_link(link);

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_api_close_handle(ebpf_handle_t handle)
{
    ebpf_operation_close_handle_request_t request = {
        sizeof(request), EBPF_OPERATION_CLOSE_HANDLE, reinterpret_cast<uint64_t>(handle)};

    return windows_error_to_ebpf_result(invoke_ioctl(request));
}

ebpf_result_t
ebpf_close_fd(fd_t fd)
{
    ebpf_handle_t handle = _get_handle_from_fd(fd);
    if (handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }
    _fd_to_handle_map.erase(fd);
    ebpf_api_close_handle(handle);

    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_api_get_pinned_map_info(
    _Out_ uint16_t* map_count, _Outptr_result_buffer_maybenull_(*map_count) ebpf_map_info_t** map_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_operation_get_map_info_request_t request = {
        sizeof(request), EBPF_OPERATION_GET_MAP_INFO, reinterpret_cast<uint64_t>(INVALID_HANDLE_VALUE)};
    ebpf_protocol_buffer_t reply_buffer;
    ebpf_operation_get_map_info_reply_t* reply = nullptr;
    size_t min_expected_buffer_length = 0;
    size_t serialized_buffer_length = 0;
    uint16_t local_map_count = 0;
    ebpf_map_info_t* local_map_info = nullptr;
    size_t output_buffer_length = 4 * 1024;
    uint8_t attempt_count = 0;

    if ((map_count == nullptr) || (map_info == nullptr)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    while (attempt_count < IOCTL_MAX_ATTEMPTS) {
        size_t reply_length;
        result = ebpf_safe_size_t_add(
            EBPF_OFFSET_OF(ebpf_operation_get_map_info_reply_t, data), output_buffer_length, &reply_length);
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

        reply = reinterpret_cast<ebpf_operation_get_map_info_reply_t*>(reply_buffer.data());

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
    // minimum expected length needed to hold the array of ebpf map info objects.
    result = ebpf_safe_size_t_multiply(
        EBPF_OFFSET_OF(ebpf_serialized_map_info_t, pin_path), (size_t)local_map_count, &min_expected_buffer_length);
    if (result != EBPF_SUCCESS)
        goto Exit;

    ebpf_assert(serialized_buffer_length >= min_expected_buffer_length);
    if (serialized_buffer_length < min_expected_buffer_length) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Deserialize reply buffer.
    result = ebpf_deserialize_map_info_array(serialized_buffer_length, reply->data, local_map_count, &local_map_info);
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
ebpf_api_map_info_free(
    const uint16_t map_count, _In_opt_count_(map_count) _Post_ptr_invalid_ const ebpf_map_info_t* map_info)
{
    ebpf_map_info_array_free(map_count, const_cast<ebpf_map_info_t*>(map_info));
}

void
clean_up_ebpf_program(_In_ _Post_invalid_ ebpf_program_t* program)
{
    if (program == nullptr) {
        return;
    }
    if (program->fd != 0) {
        _fd_to_handle_map.erase(program->fd);
    }
    if (program->handle != ebpf_handle_invalid) {
        _ebpf_programs.erase(program->handle);
        ebpf_api_close_handle(program->handle);
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
    if (map == nullptr) {
        return;
    }
    if (map->map_fd != 0) {
        _fd_to_handle_map.erase(map->map_fd);
    }
    if (map->map_handle != ebpf_handle_invalid) {
        _ebpf_maps.erase(map->map_handle);
        ebpf_api_close_handle(map->map_handle);
    }
    free(map->name);

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

void
initialize_map(_Out_ ebpf_map_t* map, _In_ const map_cache_t& map_cache)
{
    // Initialize handle to ebpf_handle_invalid.
    map->map_handle = ebpf_handle_invalid;
    map->original_fd = map_cache.verifier_map_descriptor.original_fd;
    map->map_definition.size = sizeof(map->map_definition);
    map->map_definition.type = (ebpf_map_type_t)map_cache.verifier_map_descriptor.type;
    map->map_definition.key_size = map_cache.verifier_map_descriptor.key_size;
    map->map_definition.value_size = map_cache.verifier_map_descriptor.value_size;
    map->map_definition.max_entries = map_cache.verifier_map_descriptor.max_entries;

    // TODO(issue #396): fill in inner map id, if any.
    map->map_definition.inner_map_id = (uint32_t)-1;

    map->inner_map_original_fd = map_cache.verifier_map_descriptor.inner_map_fd;

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
    result = load_byte_code(file_name, nullptr, &verifier_options, object.programs, object.maps, error_message);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    object.file_name = _strdup(file_name);
    if (object.file_name == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (auto& program : object.programs) {
        program->object = &object;
    }
    for (auto& map : object.maps) {
        map->object = &object;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        clean_up_ebpf_programs(object.programs);
        clean_up_ebpf_maps(object.maps);
    }
    return result;
}

// Find a map that needs to be created and doesn't depend on
// creating another map first.  That is, we want to create an
// inner map template before creating an outer map that depends
// on the inner map template.
static ebpf_map_t*
_get_next_map_to_create(std::vector<ebpf_map_t*>& maps)
{
    for (auto& map : maps) {
        if (map->map_handle != ebpf_handle_invalid) {
            // Already created.
            continue;
        }
        if (map->map_definition.type != BPF_MAP_TYPE_ARRAY_OF_MAPS &&
            map->map_definition.type != BPF_MAP_TYPE_HASH_OF_MAPS) {
            return map;
        }
        if (map->inner_map == nullptr) {
            // This map requires an inner map template, look up which one.
            for (auto& inner_map : maps) {
                if (inner_map->original_fd == map->inner_map_original_fd) {
                    map->inner_map = inner_map;
                    break;
                }
            }
            if (map->inner_map == nullptr) {
                // We can't create this map because there is no inner template.
                continue;
            }
        }
        if (map->inner_map->map_handle == ebpf_handle_invalid) {
            // We need to create the inner map template first.
            continue;
        }

        // The inner map has been created so we can now
        // go ahead and create this outer map with the real
        // inner_map_id instead of the mock one.
        map->map_definition.inner_map_id = map->inner_map->map_id;
        return map;
    }

    // There are no maps left that we can create.
    return nullptr;
}

ebpf_result_t
ebpf_program_load(
    _In_z_ const char* file_name,
    _In_opt_ const ebpf_program_type_t* program_type,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_ ebpf_execution_type_t execution_type,
    _Outptr_ struct bpf_object** object,
    _Out_ fd_t* program_fd,
    _Outptr_result_maybenull_z_ const char** log_buffer)
{
    ebpf_object_t* new_object = nullptr;
    ebpf_protocol_buffer_t request_buffer;
    uint32_t error_message_size = 0;
    std::vector<uintptr_t> handles;
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_load_info load_info = {0};
    std::vector<original_fd_handle_map_t> handle_map;

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

        // Create all maps.
        // TODO: update ebpf_map_definition_t structure so that it contains flag and pinning information.
        for (int count = 0; count < new_object->maps.size(); count++) {
            ebpf_map_t* map = _get_next_map_to_create(new_object->maps);
            if (map == nullptr) {
                // Any remaining maps cannot be created.
                result = EBPF_INVALID_OBJECT;
                goto Done;
            }

            ebpf_handle_t inner_map_handle = (map->inner_map) ? map->inner_map->map_handle : ebpf_handle_invalid;
            result = _create_map(map->name, &map->map_definition, inner_map_handle, &map->map_handle);
            if (result != EBPF_SUCCESS) {
                goto Done;
            }
            map->map_fd = _get_next_file_descriptor(map->map_handle);
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
            program->fd = _get_next_file_descriptor(program->handle);

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
            load_info.map_count = (uint32_t)new_object->maps.size();

            if (load_info.map_count > 0) {
                for (auto& map : new_object->maps) {
                    fd_t inner_map_original_fd = (map->inner_map) ? map->inner_map->original_fd : ebpf_fd_invalid;
                    handle_map.emplace_back(
                        map->original_fd, inner_map_original_fd, reinterpret_cast<file_handle_t>(map->map_handle));
                }

                load_info.handle_map = handle_map.data();
            }

            result = ebpf_rpc_load_program(&load_info, log_buffer, &error_message_size);
            if (result != EBPF_SUCCESS) {
                goto Done;
            }
        }

        for (auto& program : new_object->programs) {
            _ebpf_programs.insert(std::pair<ebpf_handle_t, ebpf_program_t*>(program->handle, program));
        }
        for (auto& map : new_object->maps) {
            _ebpf_maps.insert(std::pair<ebpf_handle_t, ebpf_map_t*>(map->map_handle, map));
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

_Ret_maybenull_ struct bpf_program*
ebpf_program_next(_In_opt_ const struct bpf_program* previous, _In_ const struct bpf_object* object)
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

_Ret_maybenull_ struct bpf_program*
ebpf_program_previous(_In_opt_ const struct bpf_program* next, _In_ const struct bpf_object* object)
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

_Ret_maybenull_ struct bpf_map*
ebpf_map_next(_In_opt_ const struct bpf_map* previous, _In_ const struct bpf_object* object)
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

_Ret_maybenull_ struct bpf_map*
ebpf_map_previous(_In_opt_ const struct bpf_map* next, _In_ const struct bpf_object* object)
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
ebpf_program_get_fd(_In_ const struct bpf_program* program)
{
    if (program == nullptr) {
        return ebpf_fd_invalid;
    }
    return program->fd;
}

fd_t
ebpf_map_get_fd(_In_ const struct bpf_map* map)
{
    if (map == nullptr) {
        return ebpf_fd_invalid;
    }
    return map->map_fd;
}

void
ebpf_object_close(_In_ _Post_invalid_ struct bpf_object* object)
{
    if (object == nullptr) {
        return;
    }

    _remove_ebpf_object_from_globals(object);
    _clean_up_ebpf_object(object);
}

static ebpf_result_t
_get_fd_by_id(ebpf_operation_id_t operation, ebpf_id_t id, _Out_ int* fd) noexcept
{
    _ebpf_operation_get_handle_by_id_request request{sizeof(request), operation, id};
    _ebpf_operation_get_handle_by_id_reply reply;

    uint32_t error = invoke_ioctl(request, reply);
    ebpf_result_t result = windows_error_to_ebpf_result(error);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    *fd = _get_next_file_descriptor((ebpf_handle_t)reply.handle);
    return (*fd == ebpf_fd_invalid) ? EBPF_NO_MEMORY : EBPF_SUCCESS;
}

ebpf_result_t
ebpf_get_map_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept
{
    return _get_fd_by_id(ebpf_operation_id_t::EBPF_OPERATION_GET_MAP_HANDLE_BY_ID, id, fd);
}

ebpf_result_t
ebpf_get_program_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept
{
    return _get_fd_by_id(ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID, id, fd);
}

ebpf_result_t
ebpf_get_link_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept
{
    return _get_fd_by_id(ebpf_operation_id_t::EBPF_OPERATION_GET_LINK_HANDLE_BY_ID, id, fd);
}

static ebpf_result_t
_get_next_id(ebpf_operation_id_t operation, ebpf_id_t start_id, _Out_ ebpf_id_t* next_id)
{
    _ebpf_operation_get_next_id_request request{sizeof(request), operation, start_id};
    _ebpf_operation_get_next_id_reply reply;

    uint32_t error = invoke_ioctl(request, reply);
    ebpf_result_t result = windows_error_to_ebpf_result(error);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    *next_id = reply.next_id;
    return EBPF_SUCCESS;
}

ebpf_result_t
ebpf_get_next_link_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id) noexcept
{
    return _get_next_id(ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_LINK_ID, start_id, next_id);
}

ebpf_result_t
ebpf_get_next_map_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id) noexcept
{
    return _get_next_id(ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_MAP_ID, start_id, next_id);
}

ebpf_result_t
ebpf_get_next_program_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id) noexcept
{
    return _get_next_id(ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PROGRAM_ID, start_id, next_id);
}

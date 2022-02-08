// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "pch.h"

#include <fcntl.h>
#include <io.h>
#include <mutex>

#include "api_internal.h"
#include "bpf.h"
#include "device_helper.hpp"
#include "ebpf_api.h"
#include "ebpf_platform.h"
#include "ebpf_protocol.h"
#include "ebpf_ring_buffer.h"
#include "ebpf_serialize.h"
#pragma warning(push)
#pragma warning(disable : 4200) // Zero-sized array in struct/union
#include "libbpf.h"
#pragma warning(pop)
#include "map_descriptors.hpp"
#include "rpc_client.h"
extern "C"
{
#include "ubpf.h"
}
#include "Verifier.h"
#include "windows_platform_common.hpp"

using namespace Platform;

#ifndef GUID_NULL
const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

static std::map<ebpf_handle_t, ebpf_program_t*> _ebpf_programs;
static std::map<ebpf_handle_t, ebpf_map_t*> _ebpf_maps;
static std::vector<ebpf_object_t*> _ebpf_objects;

#define DEFAULT_PIN_ROOT_PATH "/ebpf/global"

static void
_clean_up_ebpf_objects();

static fd_t
_create_file_descriptor_for_handle(ebpf_handle_t handle) noexcept
{
    return Platform::_open_osfhandle(handle, 0);
}

inline static ebpf_handle_t
_get_handle_from_file_descriptor(fd_t fd)
{
    return Platform::_get_osfhandle(fd);
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
        result = win32_error_code_to_ebpf_result(return_value);
        goto Exit;
    }
    ebpf_assert(reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP);
    *map_handle = reply.handle;

Exit:
    return result;
}

ebpf_result_t
ebpf_map_create(
    enum bpf_map_type map_type,
    _In_opt_z_ const char* map_name,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _In_opt_ const struct bpf_map_create_opts* opts,
    _Out_ fd_t* map_fd)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle = ebpf_handle_invalid;
    ebpf_handle_t inner_map_handle = ebpf_handle_invalid;
    ebpf_map_definition_in_memory_t map_definition = {0};

    if ((opts && opts->map_flags != 0) || map_fd == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    *map_fd = ebpf_fd_invalid;

    try {
        map_definition.size = sizeof(map_definition);
        map_definition.type = map_type;
        map_definition.key_size = key_size;
        map_definition.value_size = value_size;
        map_definition.max_entries = max_entries;

        inner_map_handle = (opts) ? _get_handle_from_file_descriptor(opts->inner_map_fd) : ebpf_handle_invalid;

        result = _create_map(map_name, &map_definition, inner_map_handle, &map_handle);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
        *map_fd = _create_file_descriptor_for_handle(map_handle);
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

static ebpf_result_t
_map_lookup_element(
    ebpf_handle_t handle,
    bool find_and_delete,
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
        request->find_and_delete = find_and_delete;
        request->handle = handle;
        std::copy(key, key + key_size, request->key);

        result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer, reply_buffer));

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
    ebpf_handle_t handle,
    _Out_ uint32_t* type,
    _Out_ uint32_t* key_size,
    _Out_ uint32_t* value_size,
    _Out_ uint32_t* max_entries)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_map_t* map;

    *type = BPF_MAP_TYPE_UNSPEC;
    *key_size = 0;
    *value_size = 0;
    *max_entries = 0;

    // First check if the map is present in the cache.
    map = _get_ebpf_map_from_handle(handle);
    if (map == nullptr) {
        // Map is not present in the local cache. Query map descriptor from EC.
        ebpf_id_t inner_map_id;
        result = query_map_definition(handle, type, key_size, value_size, max_entries, &inner_map_id);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    } else {
        *type = map->map_definition.type;
        *key_size = map->map_definition.key_size;
        *value_size = map->map_definition.value_size;
        *max_entries = map->map_definition.max_entries;
    }

Exit:
    return result;
}

static ebpf_result_t
_ebpf_map_lookup_element_helper(fd_t map_fd, bool find_and_delete, _In_ const void* key, _Out_ void* value)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t max_entries = 0;
    uint32_t type;

    if (map_fd <= 0 || key == nullptr || value == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    *((uint8_t*)value) = 0;

    map_handle = _get_handle_from_file_descriptor(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_FD;
        goto Exit;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size, &max_entries);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    assert(key_size != 0);
    assert(value_size != 0);

    result = _map_lookup_element(map_handle, find_and_delete, key_size, (uint8_t*)key, value_size, (uint8_t*)value);

Exit:
    return result;
}

ebpf_result_t
ebpf_map_lookup_element(fd_t map_fd, _In_ const void* key, _Out_ void* value)
{
    return _ebpf_map_lookup_element_helper(map_fd, false, key, value);
}

ebpf_result_t
ebpf_map_lookup_and_delete_element(fd_t map_fd, _In_ const void* key, _Out_ void* value)
{
    return _ebpf_map_lookup_element_helper(map_fd, true, key, value);
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

        result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer));
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

    return win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer));
}

ebpf_result_t
ebpf_map_update_element(fd_t map_fd, _In_ const void* key, _In_ const void* value, uint64_t flags)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t max_entries = 0;
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

    map_handle = _get_handle_from_file_descriptor(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size, &max_entries);
    if (result != EBPF_SUCCESS) {
        return result;
    }
    assert(key_size != 0);
    assert(value_size != 0);
    assert(type != 0);

    if ((type == BPF_MAP_TYPE_PROG_ARRAY) || (type == BPF_MAP_TYPE_HASH_OF_MAPS) ||
        (type == BPF_MAP_TYPE_ARRAY_OF_MAPS)) {
        fd_t fd = *(fd_t*)value;
        ebpf_handle_t handle = ebpf_handle_invalid;
        // If the fd is valid, resolve it to a handle, else pass ebpf_handle_invalid to the IOCTL.
        if (fd != ebpf_fd_invalid) {
            handle = _get_handle_from_file_descriptor(fd);
            if (handle == ebpf_handle_invalid) {
                return EBPF_INVALID_FD;
            }
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
    uint32_t max_entries = 0;
    uint32_t type;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_map_delete_element_request_t* request;

    if (map_fd <= 0 || key == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    map_handle = _get_handle_from_file_descriptor(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_FD;
        goto Exit;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size, &max_entries);
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

        result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer));
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
    uint32_t max_entries = 0;
    uint32_t type;
    ebpf_handle_t map_handle = ebpf_handle_invalid;

    if (map_fd <= 0 || next_key == nullptr) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    map_handle = _get_handle_from_file_descriptor(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_FD;
        goto Exit;
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size, &max_entries);
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
        request->handle = map_handle;
        if (previous_key) {
            uint8_t* end = (uint8_t*)previous_key + key_size;
            std::copy((uint8_t*)previous_key, end, request->previous_key);
        } else {
            request->header.length = offsetof(ebpf_operation_map_get_next_key_request_t, previous_key);
        }

        result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer, reply_buffer));

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
    *program_handle = reply.program_handle;

Exit:
    return win32_error_code_to_ebpf_result(error);
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
    result = load_byte_code(
        file_name, section_name, &verifier_options, DEFAULT_PIN_ROOT_PATH, programs, maps, error_message);
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

void
ebpf_free_string(_In_opt_ _Post_invalid_ const char* error_message)
{
    return free(const_cast<char*>(error_message));
}

ebpf_result_t
ebpf_object_pin(fd_t fd, _In_z_ const char* path)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t handle;
    if (fd <= 0 || path == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    handle = _get_handle_from_file_descriptor(fd);
    if (handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    auto path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, path) + path_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = handle;
    std::copy(path, path + path_length, request->path);
    result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer));

    return result;
}

ebpf_result_t
ebpf_object_unpin(_In_z_ const char* path)
{
    if (path == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    auto path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, path) + path_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = UINT64_MAX;
    std::copy(path, path + path_length, request->path);
    return win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer));
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
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_get_pinning_request_t, path) + path_length);
    auto request = reinterpret_cast<ebpf_operation_get_pinning_request_t*>(request_buffer.data());
    ebpf_operation_get_map_pinning_reply_t reply;

    request->header.id = EBPF_OPERATION_GET_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    std::copy(path, path + path_length, request->path);
    auto result = invoke_ioctl(request_buffer, reply);
    if (result != ERROR_SUCCESS) {
        return ebpf_fd_invalid;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_PINNING) {
        return ebpf_fd_invalid;
    }

    ebpf_handle_t handle = reply.handle;
    fd_t fd = _create_file_descriptor_for_handle(handle);
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

    ebpf_handle_t previous_handle = _get_handle_from_file_descriptor(local_fd);
    ebpf_operation_get_next_map_request_t request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_MAP, previous_handle};

    ebpf_operation_get_next_map_reply_t reply;

    uint32_t retval = invoke_ioctl(request, reply);
    if (retval == ERROR_SUCCESS) {
        ebpf_handle_t next_handle = reply.next_handle;
        if (next_handle != ebpf_handle_invalid) {
            fd_t fd = _create_file_descriptor_for_handle(next_handle);
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
    return win32_error_code_to_ebpf_result(retval);
}

ebpf_result_t
ebpf_get_next_program(fd_t previous_fd, _Out_ fd_t* next_fd)
{
    if (next_fd == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    fd_t local_fd = previous_fd;
    *next_fd = ebpf_fd_invalid;

    ebpf_handle_t previous_handle = _get_handle_from_file_descriptor(local_fd);
    ebpf_operation_get_next_program_request_t request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PROGRAM, previous_handle};

    ebpf_operation_get_next_program_reply_t reply;

    uint32_t retval = invoke_ioctl(request, reply);
    if (retval == ERROR_SUCCESS) {
        ebpf_handle_t next_handle = reply.next_handle;
        if (next_handle != ebpf_handle_invalid) {
            fd_t fd = _create_file_descriptor_for_handle(next_handle);
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
    return win32_error_code_to_ebpf_result(retval);
}

ebpf_result_t
ebpf_program_query_info(
    fd_t fd,
    _Out_ ebpf_execution_type_t* execution_type,
    _Outptr_result_z_ const char** file_name,
    _Outptr_result_z_ const char** section_name)
{
    ebpf_result_t result;
    ebpf_handle_t handle = _get_handle_from_file_descriptor(fd);
    if (handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    if (execution_type == nullptr || file_name == nullptr || section_name == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_protocol_buffer_t reply_buffer(1024);
    ebpf_operation_query_program_info_request_t request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_QUERY_PROGRAM_INFO, handle};

    auto reply = reinterpret_cast<ebpf_operation_query_program_info_reply_t*>(reply_buffer.data());

    uint32_t retval = invoke_ioctl(request, reply_buffer);
    if (retval != ERROR_SUCCESS) {
        result = win32_error_code_to_ebpf_result(retval);
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

    return win32_error_code_to_ebpf_result(retval);
}

uint32_t
ebpf_api_link_program(ebpf_handle_t program_handle, ebpf_attach_type_t attach_type, ebpf_handle_t* link_handle)
{
    ebpf_operation_link_program_request_t request = {
        EBPF_OFFSET_OF(ebpf_operation_link_program_request_t, data),
        EBPF_OPERATION_LINK_PROGRAM,
        program_handle,
        attach_type};
    ebpf_operation_link_program_reply_t reply;

    uint32_t retval = invoke_ioctl(request, reply);
    if (retval != ERROR_SUCCESS) {
        return retval;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_LINK_PROGRAM) {
        return ERROR_INVALID_PARAMETER;
    }

    *link_handle = reply.link_handle;
    return retval;
}

static ebpf_result_t
_link_ebpf_program(
    ebpf_handle_t program_handle,
    _In_ const ebpf_attach_type_t* attach_type,
    _Out_ ebpf_link_t** link,
    _In_reads_bytes_opt_(attach_parameter_size) uint8_t* attach_parameter,
    size_t attach_parameter_size) noexcept
{
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_link_program_request_t* request;
    ebpf_operation_link_program_reply_t reply;
    ebpf_result_t result = EBPF_SUCCESS;

    *link = nullptr;
    ebpf_link_t* new_link = (ebpf_link_t*)calloc(1, sizeof(ebpf_link_t));
    if (new_link == nullptr) {
        return EBPF_NO_MEMORY;
    }
    new_link->handle = ebpf_handle_invalid;

    try {
        size_t buffer_size = offsetof(ebpf_operation_link_program_request_t, data) + attach_parameter_size;
        request_buffer.resize(buffer_size);
        request = reinterpret_cast<ebpf_operation_link_program_request_t*>(request_buffer.data());
        request->header.id = EBPF_OPERATION_LINK_PROGRAM;
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->program_handle = program_handle;
        request->attach_type = *attach_type;

        if (attach_parameter_size > 0) {
            memcpy_s(request->data, attach_parameter_size, attach_parameter, attach_parameter_size);
        }

        result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer, reply));
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_LINK_PROGRAM) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        new_link->handle = reply.link_handle;
        new_link->fd = _create_file_descriptor_for_handle(new_link->handle);
        if (new_link->fd == ebpf_fd_invalid) {
            result = EBPF_NO_MEMORY;
        } else {
            *link = new_link;
            new_link = nullptr;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    } catch (...) {
        result = EBPF_FAILED;
        goto Exit;
    }

Exit:
    if (new_link != nullptr) {
        ebpf_link_detach(new_link);
        ebpf_link_close(new_link);
    }
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
    ebpf_operation_unlink_program_request_t request = {sizeof(request), EBPF_OPERATION_UNLINK_PROGRAM, link_handle};

    return win32_error_code_to_ebpf_result(invoke_ioctl(request));
}

ebpf_result_t
ebpf_detach_link_by_fd(fd_t fd)
{
    ebpf_handle_t link_handle = _get_handle_from_file_descriptor(fd);
    if (link_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    return _detach_link_by_handle(link_handle);
}

ebpf_result_t
ebpf_program_attach(
    _In_ const struct bpf_program* program,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_opt_(attach_params_size) void* attach_parameters,
    _In_ size_t attach_params_size,
    _Outptr_ struct bpf_link** link)
{
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_attach_type_t* program_attach_type;

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
    if (program->handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    result =
        _link_ebpf_program(program->handle, program_attach_type, link, (uint8_t*)attach_parameters, attach_params_size);

Exit:
    return result;
}

ebpf_result_t
ebpf_program_attach_by_fd(
    fd_t program_fd,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
    _In_ size_t attach_parameters_size,
    _Outptr_ struct bpf_link** link)
{
    if (link == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }
    *link = nullptr;

    ebpf_handle_t program_handle = _get_handle_from_file_descriptor(program_fd);
    if (program_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    if (attach_type == nullptr) {
        // We can only use an unspecified attach_type if we can find an ebpf_program_t.
        ebpf_program_t* program = _get_ebpf_program_from_handle(program_handle);
        if (program == nullptr) {
            return EBPF_INVALID_ARGUMENT;
        }

        return ebpf_program_attach(program, attach_type, attach_parameters, attach_parameters_size, link);
    }

    return _link_ebpf_program(program_handle, attach_type, link, (uint8_t*)attach_parameters, attach_parameters_size);
}

uint32_t
ebpf_api_unlink_program(ebpf_handle_t link_handle)
{
    ebpf_operation_unlink_program_request_t request = {sizeof(request), EBPF_OPERATION_UNLINK_PROGRAM, link_handle};

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
    ebpf_operation_close_handle_request_t request = {sizeof(request), EBPF_OPERATION_CLOSE_HANDLE, handle};

    return win32_error_code_to_ebpf_result(invoke_ioctl(request));
}

ebpf_result_t
ebpf_api_get_pinned_map_info(
    _Out_ uint16_t* map_count, _Outptr_result_buffer_maybenull_(*map_count) ebpf_map_info_t** map_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_operation_get_map_info_request_t request = {sizeof(request), EBPF_OPERATION_GET_MAP_INFO, ebpf_handle_invalid};
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
        result = win32_error_code_to_ebpf_result(invoke_ioctl(request, reply_buffer));

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
    ebpf_program_unload(program);

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
    if (map->map_fd > 0) {
        Platform::_close(map->map_fd);
    }
    if (map->map_handle != ebpf_handle_invalid) {
        _ebpf_maps.erase(map->map_handle);
    }
    free(map->name);
    free(map->pin_path);

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
    map->map_definition.pinning = map_cache.pinning;

    // Set the inner map ID if we have a real inner map fd.
    map->map_definition.inner_map_id = EBPF_ID_NONE;
    if (map_cache.verifier_map_descriptor.inner_map_fd != ebpf_fd_invalid) {
        struct bpf_map_info info;
        uint32_t info_size = (uint32_t)sizeof(info);
        if (ebpf_object_get_info_by_fd(map_cache.verifier_map_descriptor.inner_map_fd, &info, &info_size) ==
            EBPF_SUCCESS) {
            map->map_definition.inner_map_id = info.id;
        }
    }

    map->inner_map_original_fd = map_cache.verifier_map_descriptor.inner_map_fd;

    map->pinned = false;
    map->reused = false;
    map->pin_path = nullptr;
}

static ebpf_result_t
_initialize_ebpf_object_from_elf(
    _In_z_ const char* file_name,
    _In_opt_z_ const char* object_name,
    _In_opt_z_ const char* pin_root_path,
    _In_opt_ const ebpf_program_type_t* expected_program_type,
    _In_opt_ const ebpf_attach_type_t* expected_attach_type,
    _Out_ ebpf_object_t& object,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    set_global_program_and_attach_type(expected_program_type, expected_attach_type);

    ebpf_verifier_options_t verifier_options{false, false, false, false, false};
    result = load_byte_code(
        file_name,
        nullptr,
        &verifier_options,
        pin_root_path ? pin_root_path : DEFAULT_PIN_ROOT_PATH,
        object.programs,
        object.maps,
        error_message);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    object.object_name = _strdup(object_name ? object_name : file_name);
    if (object.object_name == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    for (auto& program : object.programs) {
        program->fd = ebpf_fd_invalid;
        program->object = &object;
    }
    for (auto& map : object.maps) {
        map->map_fd = ebpf_fd_invalid;
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
                if (!inner_map) {
                    continue;
                }
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
ebpf_object_open(
    _In_z_ const char* path,
    _In_opt_z_ const char* object_name,
    _In_opt_z_ const char* pin_root_path,
    _In_opt_ const ebpf_program_type_t* program_type,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _Outptr_ struct bpf_object** object,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    *error_message = nullptr;

    ebpf_object_t* new_object = new (std::nothrow) ebpf_object_t();
    if (new_object == nullptr) {
        return EBPF_NO_MEMORY;
    }

    ebpf_result_t result = _initialize_ebpf_object_from_elf(
        path, object_name, pin_root_path, program_type, attach_type, *new_object, error_message);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    *object = new_object;
    _ebpf_objects.emplace_back(*object);

Done:
    clear_map_descriptors();
    if (result != EBPF_SUCCESS) {
        _clean_up_ebpf_object(new_object);
    }
    return result;
}

static inline bool
_ebpf_is_map_in_map(ebpf_map_t* map)
{
    if (map->map_definition.type == BPF_MAP_TYPE_HASH_OF_MAPS ||
        map->map_definition.type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        return true;
    }

    return false;
}

static ebpf_result_t
_ebpf_validate_map(_In_ ebpf_map_t* map, fd_t original_map_fd)
{
    // Validate that the existing map definition matches with this new map.
    struct bpf_map_info info;
    fd_t inner_map_info_fd = ebpf_fd_invalid;
    uint32_t info_size = (uint32_t)sizeof(info);
    ebpf_result_t result = ebpf_object_get_info_by_fd(original_map_fd, &info, &info_size);
    if (result != EBPF_SUCCESS) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (info.type != map->map_definition.type || info.key_size != map->map_definition.key_size ||
        info.value_size != map->map_definition.value_size || info.max_entries != map->map_definition.max_entries) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Extra checks for map-in-map.
    if (_ebpf_is_map_in_map(map)) {
        ebpf_map_t* inner_map = map->inner_map;
        ebpf_assert(inner_map != nullptr);

        if (info.inner_map_id == EBPF_ID_NONE) {
            // The original map is pinned but its template is not initialized yet.
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // For map-in-map, validate the inner map template also.
        result = ebpf_get_map_fd_by_id(info.inner_map_id, &inner_map_info_fd);
        if (result != EBPF_SUCCESS) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        result = _ebpf_validate_map(inner_map, inner_map_info_fd);
    }

Exit:
    Platform::_close(inner_map_info_fd);
    return result;
}

static ebpf_result_t
_ebpf_object_reuse_map(_In_ ebpf_map_t* map)
{
    ebpf_result_t result = EBPF_SUCCESS;

    // Check if a map is already present with this pin path.
    fd_t map_fd = ebpf_object_get(map->pin_path);
    if (map_fd == ebpf_fd_invalid) {
        return EBPF_SUCCESS;
    }

    // Recursively validate that the map definition matches with the existing
    // map.
    result = _ebpf_validate_map(map, map_fd);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // The map can be reused. Populate map handle and fd.
    map->map_fd = map_fd;
    map->map_handle = _get_handle_from_file_descriptor(map_fd);
    map->reused = true;
    map->pinned = true;

Exit:
    if (result != EBPF_SUCCESS) {
        Platform::_close(map_fd);
    }
    return result;
}

static ebpf_result_t
_ebpf_object_create_maps(_Inout_ ebpf_object_t* object)
{
    ebpf_result_t result = EBPF_SUCCESS;

    clear_map_descriptors();

    // TODO: update ebpf_map_definition_t structure so that it contains flag and pinning information.
    for (int count = 0; count < object->maps.size(); count++) {
        ebpf_map_t* map = _get_next_map_to_create(object->maps);
        if (map == nullptr) {
            // Any remaining maps cannot be created.
            result = EBPF_INVALID_OBJECT;
            break;
        }

        if (map->map_definition.pinning == PIN_GLOBAL_NS) {
            result = _ebpf_object_reuse_map(map);
            if (result != EBPF_SUCCESS) {
                break;
            }
            if (map->reused) {
                continue;
            }
        }

        ebpf_handle_t inner_map_handle = (map->inner_map) ? map->inner_map->map_handle : ebpf_handle_invalid;
        result = _create_map(map->name, &map->map_definition, inner_map_handle, &map->map_handle);
        if (result != EBPF_SUCCESS) {
            break;
        }
        map->map_fd = _create_file_descriptor_for_handle(map->map_handle);

        // If pin_path is set and the map is not yet pinned, pin it now.
        if (map->pin_path && !map->pinned) {
            result = ebpf_map_pin(map, nullptr);
            if (result != EBPF_SUCCESS) {
                break;
            }
        }
    }

    try {
        if (result == EBPF_SUCCESS) {
            for (auto& map : object->maps) {
                _ebpf_maps.insert(std::pair<ebpf_handle_t, ebpf_map_t*>(map->map_handle, map));
            }
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
    } catch (...) {
        result = EBPF_FAILED;
    }

    if (result != EBPF_SUCCESS) {
        // Unpin all the maps which have been auto-pinned above.
        for (auto& map : object->maps) {
            if (map->pin_path && map->pinned && !map->reused) {
                ebpf_map_unpin(map, nullptr);
            }
        }
        clean_up_ebpf_maps(object->maps);
    }

    clear_map_descriptors();
    return result;
}

ebpf_result_t
ebpf_program_load_bytes(
    _In_ const ebpf_program_type_t* program_type,
    ebpf_execution_type_t execution_type,
    _In_reads_(byte_code_size) const uint8_t* byte_code,
    uint32_t byte_code_size,
    _Out_writes_opt_(log_buffer_size) char* log_buffer,
    size_t log_buffer_size,
    _Out_ fd_t* program_fd)
{
    if ((log_buffer != nullptr) != (log_buffer_size > 0)) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Create a unique object/section/program name.
    srand(static_cast<unsigned int>(time(nullptr)));
    char unique_name[80];
    sprintf_s(unique_name, sizeof(unique_name), "raw#%u", rand());

    ebpf_handle_t program_handle;
    ebpf_result_t result = _create_program(*program_type, unique_name, unique_name, unique_name, &program_handle);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    // Populate load_info.
    ebpf_program_load_info load_info = {0};
    load_info.object_name = const_cast<char*>(unique_name);
    load_info.section_name = const_cast<char*>(unique_name);
    load_info.program_name = const_cast<char*>(unique_name);
    load_info.program_type = *program_type;
    load_info.program_handle = reinterpret_cast<file_handle_t>(program_handle);
    load_info.execution_type = execution_type;
    load_info.byte_code = const_cast<uint8_t*>(byte_code);
    load_info.byte_code_size = byte_code_size;
    load_info.execution_context = execution_context_kernel_mode;

    // Resolve map handles in byte code.
    std::vector<original_fd_handle_map_t> handle_map;
    const ebpf_inst* instructions = reinterpret_cast<const ebpf_inst*>(byte_code);
    const ebpf_inst* instruction_end = reinterpret_cast<const ebpf_inst*>(byte_code + byte_code_size);
    for (size_t index = 0; index < byte_code_size / sizeof(ebpf_inst); index++) {
        const ebpf_inst& first_instruction = instructions[index];
        if (first_instruction.opcode != INST_OP_LDDW_IMM) {
            continue;
        }
        if (&instructions[index + 1] >= instruction_end) {
            result = EBPF_INVALID_ARGUMENT;
            break;
        }
        index++;

        // Check for LD_MAP flag.
        if (first_instruction.src != 1) {
            continue;
        }

        // Get the real map_fd value and handle.
        int map_fd = static_cast<int>(first_instruction.imm);
        ebpf_handle_t handle = Platform::_get_osfhandle(map_fd);

        // Look up inner map id.
        uint32_t type;
        uint32_t key_size;
        uint32_t value_size;
        uint32_t max_entries;
        ebpf_id_t inner_map_id;
        result = query_map_definition(handle, &type, &key_size, &value_size, &max_entries, &inner_map_id);
        if (result != EBPF_SUCCESS) {
            break;
        }

        // Get a file descriptor for the inner map, if any.
        int inner_map_fd = ebpf_fd_invalid;
        if (inner_map_id != EBPF_ID_NONE) {
            result = ebpf_get_map_fd_by_id(inner_map_id, &inner_map_fd);
            if (result != EBPF_SUCCESS) {
                break;
            }
        }

        handle_map.emplace_back((uint32_t)map_fd, (uint32_t)inner_map_fd, (file_handle_t)handle);
    }

    const char* log_buffer_output = nullptr;
    if (result == EBPF_SUCCESS) {
        load_info.map_count = (uint32_t)handle_map.size();
        load_info.handle_map = handle_map.data();

        uint32_t error_message_size = 0;
        result = ebpf_rpc_load_program(&load_info, &log_buffer_output, &error_message_size);
    }

    // Close any inner map fds.
    for (original_fd_handle_map_t& entry : handle_map) {
        if (entry.inner_map_original_fd != ebpf_fd_invalid) {
            Platform::_close(entry.inner_map_original_fd);
        }
    }

    if (log_buffer_size > 0) {
        log_buffer[0] = 0;
        if (log_buffer_output) {
            strcpy_s(log_buffer, log_buffer_size, log_buffer_output);
        }
    }
    ebpf_free_string(log_buffer_output);

    *program_fd = (result == EBPF_SUCCESS) ? _create_file_descriptor_for_handle(program_handle) : ebpf_fd_invalid;
    if (*program_fd == ebpf_fd_invalid) {
        CloseHandle(program_handle);
    }

    return result;
}

static ebpf_result_t
_ebpf_object_load_programs(
    _Inout_ struct bpf_object* object,
    ebpf_execution_type_t execution_type,
    _Outptr_result_maybenull_z_ const char** log_buffer)
{
    ebpf_result_t result = EBPF_SUCCESS;
    std::vector<original_fd_handle_map_t> handle_map;
    uint32_t error_message_size = 0;

    *log_buffer = nullptr;

    for (auto& program : object->programs) {
        result = _create_program(
            program->program_type, object->object_name, program->section_name, program->program_name, &program->handle);
        if (result != EBPF_SUCCESS) {
            break;
        }

        program->fd = _create_file_descriptor_for_handle(program->handle);

        // Populate load_info.
        ebpf_program_load_info load_info = {0};
        load_info.object_name = const_cast<char*>(object->object_name);
        load_info.section_name = const_cast<char*>(program->section_name);
        load_info.program_name = const_cast<char*>(program->program_name);
        load_info.program_type = program->program_type;
        load_info.program_handle = reinterpret_cast<file_handle_t>(program->handle);
        load_info.execution_type = execution_type;
        load_info.byte_code = program->byte_code;
        load_info.byte_code_size = program->byte_code_size;
        load_info.execution_context = execution_context_kernel_mode;
        load_info.map_count = (uint32_t)object->maps.size();

        if (load_info.map_count > 0) {
            for (auto& map : object->maps) {
                fd_t inner_map_original_fd = (map->inner_map) ? map->inner_map->original_fd : ebpf_fd_invalid;
                handle_map.emplace_back(
                    map->original_fd, inner_map_original_fd, reinterpret_cast<file_handle_t>(map->map_handle));
            }

            load_info.handle_map = handle_map.data();
        }

        result = ebpf_rpc_load_program(&load_info, log_buffer, &error_message_size);
        if (result != EBPF_SUCCESS) {
            break;
        }
    }

    if (result == EBPF_SUCCESS) {
        for (auto& program : object->programs) {
            _ebpf_programs.insert(std::pair<ebpf_handle_t, ebpf_program_t*>(program->handle, program));
        }
    }
    return result;
}

// This logic is intended to be similar to libbpf's bpf_object__load_xattr().
ebpf_result_t
ebpf_object_load(
    _Inout_ struct bpf_object* object,
    ebpf_execution_type_t execution_type,
    _Outptr_result_maybenull_z_ const char** log_buffer)
{
    if (!object)
        return EBPF_INVALID_ARGUMENT;

    if (object->loaded) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_result_t result = EBPF_SUCCESS;
    try {
        result = _ebpf_object_create_maps(object);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        result = _ebpf_object_load_programs(object, execution_type, log_buffer);
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Done;
    } catch (...) {
        result = EBPF_FAILED;
        goto Done;
    }

    object->loaded = true; /* doesn't matter if successfully loaded or not */

Done:
    if (result != EBPF_SUCCESS) {
        ebpf_object_unload(object);
    }
    return result;
}

// This function is intended to work like libbpf's bpf_object__unload().
ebpf_result_t
ebpf_object_unload(_In_ struct bpf_object* object)
{
    if (!object)
        return EBPF_INVALID_ARGUMENT;

    for (auto& map : object->maps) {
        if (map->map_fd > 0) {
            Platform::_close(map->map_fd);
            map->map_fd = ebpf_fd_invalid;
        }
        if (map->map_handle != ebpf_handle_invalid) {
            _ebpf_maps.erase(map->map_handle);
            map->map_handle = ebpf_handle_invalid;
        }
    }

    for (auto& program : object->programs) {
        ebpf_program_unload(program);
    }

    return EBPF_SUCCESS;
}

// This function is intended to work like libbpf's bpf_program__unload().
ebpf_result_t
ebpf_program_unload(_In_ struct bpf_program* program)
{
    if (!program)
        return EBPF_INVALID_ARGUMENT;

    if (program->fd != ebpf_fd_invalid) {
        Platform::_close(program->fd);
        program->fd = ebpf_fd_invalid;
    }
    if (program->handle != ebpf_handle_invalid) {
        _ebpf_programs.erase(program->handle);
        program->handle = ebpf_handle_invalid;
    }
    return EBPF_SUCCESS;
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
    std::vector<uintptr_t> handles;
    ebpf_result_t result = EBPF_SUCCESS;

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

    try {
        result = ebpf_object_open(file_name, nullptr, nullptr, program_type, attach_type, &new_object, log_buffer);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        result = ebpf_object_load(new_object, execution_type, log_buffer);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        *object = new_object;
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
        ebpf_object_close(new_object);
    }
    clear_map_descriptors();
    return result;
}

_Ret_maybenull_ struct bpf_object*
ebpf_object_next(_In_opt_ const struct bpf_object* previous)
{
    if (previous == nullptr) {
        // Return first object.
        return (!_ebpf_objects.empty()) ? _ebpf_objects[0] : nullptr;
    }
    auto it = std::find(_ebpf_objects.begin(), _ebpf_objects.end(), previous);
    if (it == _ebpf_objects.end()) {
        // Previous object not found.
        return nullptr;
    }
    it++;
    if (it == _ebpf_objects.end()) {
        // No more objects.
        return nullptr;
    }
    return *it;
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
ebpf_object_close(_In_opt_ _Post_invalid_ struct bpf_object* object)
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
    ebpf_result_t result = win32_error_code_to_ebpf_result(error);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    *fd = _create_file_descriptor_for_handle((ebpf_handle_t)reply.handle);
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

ebpf_result_t
ebpf_get_next_pinned_program_path(
    _In_z_ const char* start_path, _Out_writes_z_(EBPF_MAX_PIN_PATH_LENGTH) char* next_path)
{
    if (start_path == nullptr || next_path == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    size_t start_path_length = strlen(start_path);

    ebpf_protocol_buffer_t request_buffer(
        EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_path_request_t, start_path) + start_path_length);
    ebpf_protocol_buffer_t reply_buffer(
        EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_path_reply_t, next_path) + EBPF_MAX_PIN_PATH_LENGTH - 1);
    ebpf_operation_get_next_pinned_path_request_t* request =
        reinterpret_cast<ebpf_operation_get_next_pinned_path_request_t*>(request_buffer.data());
    ebpf_operation_get_next_pinned_path_reply_t* reply =
        reinterpret_cast<ebpf_operation_get_next_pinned_path_reply_t*>(reply_buffer.data());

    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    reply->header.length = static_cast<uint16_t>(reply_buffer.size());

    memcpy(request->start_path, start_path, start_path_length);

    uint32_t error = invoke_ioctl(request_buffer, reply_buffer);
    ebpf_result_t result = win32_error_code_to_ebpf_result(error);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    size_t next_path_length =
        reply->header.length - EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_path_reply_t, next_path);
    memcpy(next_path, reply->next_path, next_path_length);

    next_path[next_path_length] = '\0';

    return EBPF_SUCCESS;
}

static ebpf_result_t
_get_next_id(ebpf_operation_id_t operation, ebpf_id_t start_id, _Out_ ebpf_id_t* next_id)
{
    _ebpf_operation_get_next_id_request request{sizeof(request), operation, start_id};
    _ebpf_operation_get_next_id_reply reply;

    uint32_t error = invoke_ioctl(request, reply);
    ebpf_result_t result = win32_error_code_to_ebpf_result(error);
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

ebpf_result_t
ebpf_object_get_info_by_fd(
    fd_t bpf_fd, _Out_writes_bytes_to_(*info_size, *info_size) void* info, _Inout_ uint32_t* info_size)
{
    ebpf_handle_t handle = _get_handle_from_file_descriptor(bpf_fd);
    if (handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    return ebpf_object_get_info(handle, info, info_size);
}

ebpf_result_t
ebpf_get_program_type_by_name(
    _In_z_ const char* name, _Out_ ebpf_program_type_t* program_type, _Out_ ebpf_attach_type_t* expected_attach_type)
{
    if (name == nullptr || program_type == nullptr || expected_attach_type == nullptr) {
        return EBPF_INVALID_ARGUMENT;
    }

    EbpfProgramType type = get_program_type_windows(name, name);
    ebpf_windows_program_type_data_t* data = (ebpf_windows_program_type_data_t*)type.platform_specific_data;

    *program_type = data->program_type_uuid;
    *expected_attach_type = data->attach_type_uuid;

    return EBPF_SUCCESS;
}

_Ret_maybenull_z_ const char*
ebpf_get_program_type_name(_In_ const ebpf_program_type_t* program_type)
{
    if (program_type == nullptr) {
        return nullptr;
    }
    const EbpfProgramType& type = get_program_type_windows(*program_type);
    return type.name.c_str();
}

_Ret_maybenull_z_ const char*
ebpf_get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type)
{
    return get_attach_type_name(attach_type);
}

ebpf_result_t
ebpf_program_bind_map(fd_t program_fd, fd_t map_fd)
{
    ebpf_handle_t program_handle = _get_handle_from_file_descriptor(program_fd);
    if (program_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    ebpf_handle_t map_handle = _get_handle_from_file_descriptor(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    ebpf_operation_bind_map_request_t request;
    request.header.id = EBPF_OPERATION_BIND_MAP;
    request.header.length = sizeof(request);
    request.program_handle = program_handle;
    request.map_handle = map_handle;

    return win32_error_code_to_ebpf_result(invoke_ioctl(request));
}

typedef struct _ebpf_ring_buffer_subscription
{
    _ebpf_ring_buffer_subscription()
        : unsubscribed(false), ring_buffer_map_handle(ebpf_handle_invalid), sample_callback_context(nullptr),
          sample_callback(nullptr), buffer(nullptr), reply({}), async_ioctl_completion(nullptr),
          async_ioctl_failed(false)
    {}
    ~_ebpf_ring_buffer_subscription()
    {
        EBPF_LOG_ENTRY();
        if (async_ioctl_completion != nullptr)
            clean_up_async_ioctl_completion(async_ioctl_completion);
        if (ring_buffer_map_handle != ebpf_handle_invalid)
            Platform::CloseHandle(ring_buffer_map_handle);
    }
    std::mutex lock;
    _Write_guarded_by_(lock) boolean unsubscribed;
    ebpf_handle_t ring_buffer_map_handle;
    void* sample_callback_context;
    ring_buffer_sample_fn sample_callback;
    uint8_t* buffer;
    ebpf_operation_ring_buffer_map_async_query_reply_t reply;
    _Write_guarded_by_(lock) async_ioctl_completion_t* async_ioctl_completion;
    _Write_guarded_by_(lock) bool async_ioctl_failed;
} ebpf_ring_buffer_subscription_t;

typedef std::unique_ptr<ebpf_ring_buffer_subscription_t> ebpf_ring_buffer_subscription_ptr;

static ebpf_result_t
_ebpf_ring_buffer_map_async_query_completion(_Inout_opt_ void* completion_context)
{
    EBPF_LOG_ENTRY();
    if (completion_context == nullptr)
        return EBPF_INVALID_ARGUMENT;

    ebpf_ring_buffer_subscription_t* subscription =
        reinterpret_cast<ebpf_ring_buffer_subscription_t*>(completion_context);

    size_t consumer = 0;
    size_t producer = 0;

    ebpf_result_t result = EBPF_SUCCESS;
    // Check the result of the completed async IOCTL call.
    result = get_async_ioctl_result(subscription->async_ioctl_completion);

    if (result != EBPF_SUCCESS) {
        if (result != EBPF_CANCELED) {
            // The async IOCTL was not canceled, but completed with a failure status. Mark the subscription object as
            // such, so that it gets freed when the user eventually unsubscribes.
            std::scoped_lock lock{subscription->lock};
            subscription->async_ioctl_failed = true;
            EBPF_RETURN_RESULT(result);
        } else {
            // User has canceled subscription. Invoke user specified callback for the final time with NULL record. This
            // will let the user app clean up its state.
            subscription->sample_callback(subscription->sample_callback_context, nullptr, 0);
        }
    } else {
        // Async IOCTL operation returned with success status. Read the ring buffer records and indicate it to the
        // subscriber.

        size_t ring_buffer_size;
        uint32_t dummy;

        result = _get_map_descriptor_properties(
            subscription->ring_buffer_map_handle,
            &dummy,
            &dummy,
            &dummy,
            reinterpret_cast<uint32_t*>(&ring_buffer_size));
        if (result != EBPF_SUCCESS)
            EBPF_RETURN_RESULT(result);

        ebpf_operation_ring_buffer_map_async_query_reply_t* reply = &subscription->reply;
        ebpf_ring_buffer_map_async_query_result_t* async_query_result = &reply->async_query_result;
        consumer = async_query_result->consumer;
        producer = async_query_result->producer;
        for (;;) {
            auto record = ebpf_ring_buffer_next_record(subscription->buffer, ring_buffer_size, consumer, producer);

            if (record == nullptr)
                // No more records.
                break;

            int callback_result = subscription->sample_callback(
                subscription->sample_callback_context,
                const_cast<void*>(reinterpret_cast<const void*>(record->data)),
                record->header.length - EBPF_OFFSET_OF(ebpf_ring_buffer_record_t, data));
            if (callback_result != 0)
                break;

            consumer += record->header.length;
        }
    }

    bool free_subscription = false;
    {
        std::scoped_lock lock{subscription->lock};

        if (subscription->unsubscribed) {
            //  If the user has unsubscribed, this is the final callback. Mark the
            //  subscription context for deletion.
            result = EBPF_CANCELED;
            free_subscription = true;
        } else {
            // If still subscribed, post the next async IOCTL call while holding the lock. It is safe to do so as the
            // async call is not blocking.

            // First, register wait for the new async IOCTL operation completion.
            result = register_wait_async_ioctl_operation(subscription->async_ioctl_completion);
            if (result != EBPF_SUCCESS)
                EBPF_RETURN_RESULT(result);

            // Then, post the async IOCTL.
            ebpf_operation_ring_buffer_map_async_query_request_t async_query_request{
                sizeof(async_query_request),
                EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY,
                subscription->ring_buffer_map_handle,
                consumer};
            memset(&subscription->reply, 0, sizeof(ebpf_operation_ring_buffer_map_async_query_reply_t));
            result = win32_error_code_to_ebpf_result(invoke_ioctl(
                async_query_request,
                subscription->reply,
                get_async_ioctl_operation_overlapped(subscription->async_ioctl_completion)));
            if (result == EBPF_PENDING)
                result = EBPF_SUCCESS;
        }
    }
    if (free_subscription)
        delete subscription;

    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_ring_buffer_map_subscribe(
    fd_t ring_buffer_map_fd,
    _In_opt_ void* sample_callback_context,
    ring_buffer_sample_fn sample_callback,
    _Outptr_ ring_buffer_subscription_t** subscription)
{
    EBPF_LOG_ENTRY();

    ebpf_result_t result = EBPF_SUCCESS;

    *subscription = nullptr;

    ebpf_ring_buffer_subscription_ptr local_subscription = std::make_unique<ebpf_ring_buffer_subscription_t>();

    local_subscription->ring_buffer_map_handle = ebpf_handle_invalid;

    // Get the handle to ring buffer map.
    ebpf_handle_t ring_buffer_map_handle = _get_handle_from_file_descriptor(ring_buffer_map_fd);
    if (ring_buffer_map_handle == ebpf_handle_invalid) {
        result = EBPF_INVALID_FD;
        EBPF_RETURN_RESULT(result);
    }

    if (!Platform::DuplicateHandle(
            reinterpret_cast<ebpf_handle_t>(GetCurrentProcess()),
            ring_buffer_map_handle,
            reinterpret_cast<ebpf_handle_t>(GetCurrentProcess()),
            &local_subscription->ring_buffer_map_handle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS)) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        _Analysis_assume_(result != EBPF_SUCCESS);
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, DuplicateHandle);
        return result;
    }

    // Get user-mode address to ring buffer shared data.
    ebpf_operation_ring_buffer_map_query_buffer_request_t query_buffer_request{
        sizeof(query_buffer_request),
        EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER,
        local_subscription->ring_buffer_map_handle};
    ebpf_operation_ring_buffer_map_query_buffer_reply_t query_buffer_reply{};
    result = win32_error_code_to_ebpf_result(invoke_ioctl(query_buffer_request, query_buffer_reply));
    if (result != EBPF_SUCCESS)
        EBPF_RETURN_RESULT(result);
    local_subscription->buffer = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(query_buffer_reply.buffer_address));

    // Initialize the async IOCTL operation.
    local_subscription->sample_callback_context = sample_callback_context;
    local_subscription->sample_callback = sample_callback;
    memset(&local_subscription->reply, 0, sizeof(ebpf_operation_ring_buffer_map_async_query_reply_t));
    result = initialize_async_ioctl_operation(
        local_subscription.get(),
        _ebpf_ring_buffer_map_async_query_completion,
        &local_subscription->async_ioctl_completion);
    if (result != EBPF_SUCCESS)
        EBPF_RETURN_RESULT(result);

    // Issue the async query IOCTL.
    ebpf_operation_ring_buffer_map_async_query_request_t async_query_request{
        sizeof(async_query_request),
        EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY,
        local_subscription->ring_buffer_map_handle};
    result = win32_error_code_to_ebpf_result(invoke_ioctl(
        async_query_request,
        local_subscription->reply,
        get_async_ioctl_operation_overlapped(local_subscription->async_ioctl_completion)));
    if (result == EBPF_PENDING)
        result = EBPF_SUCCESS;

    *subscription = local_subscription.release();

    EBPF_RETURN_RESULT(result);
}

bool
ebpf_ring_buffer_map_unsubscribe(_Inout_ _Post_invalid_ ring_buffer_subscription_t* subscription)
{
    EBPF_LOG_ENTRY();
    boolean cancel_result = true;
    boolean free_subscription = false;
    {
        std::scoped_lock lock{subscription->lock};
        // Set the unsubscribed flag, so that if a completion callback is ongoing, it does not issue another async
        // IOCTL.
        subscription->unsubscribed = true;
        // Check if an earlier async opeeration has failed. In that case a new async operation will not be queued. This
        // is the only case in which the subscription object can be freed in this function.
        if (subscription->async_ioctl_failed)
            free_subscription = true;
        else {
            // Attempt to cancel an ongoing async IOCTL.
            cancel_result =
                cancel_async_ioctl(get_async_ioctl_operation_overlapped(subscription->async_ioctl_completion));
            // If the async operation could be canceled, a final completion callback would be invoked with EBPF_CANCELED
            // status. If the async operation could not be canceled, that would mean a callback is ongoing which would
            // eventually find out the subscription is canceled and will not post another async operation. In either
            // case the final callback would free the subscription object.
        }
    }

    if (free_subscription)
        delete subscription;

    EBPF_RETURN_BOOL(cancel_result);
}

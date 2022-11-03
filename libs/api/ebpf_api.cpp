// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include "pch.h"

#include <codecvt>
#include <fcntl.h>
#include <io.h>
#include <mutex>

#include "api_internal.h"
#include "bpf.h"
#include "bpf2c.h"
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
#define _PEPARSE_WINDOWS_CONFLICTS
#include "pe-parse/parse.h"

#include "rpc_client.h"
extern "C"
{
#include "ubpf.h"
}
#include "utilities.hpp"
#include "Verifier.h"
#include "windows_platform_common.hpp"

using namespace peparse;
using namespace Platform;

#ifndef GUID_NULL
const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

static std::map<ebpf_handle_t, ebpf_program_t*> _ebpf_programs;
static std::map<ebpf_handle_t, ebpf_map_t*> _ebpf_maps;
static std::vector<ebpf_object_t*> _ebpf_objects;

#define DEFAULT_PIN_ROOT_PATH "/ebpf/global"

#define SERVICE_PATH_PREFIX L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define PARAMETERS_PATH_PREFIX L"System\\CurrentControlSet\\Services\\"
#define SERVICE_PARAMETERS L"Parameters"
#define NPI_MODULE_ID L"NpiModuleId"

static void
_clean_up_ebpf_objects() noexcept;

static ebpf_result_t
_ebpf_program_load_native(
    _In_z_ const char* file_name,
    _In_opt_ const ebpf_program_type_t* program_type,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    ebpf_execution_type_t execution_type,
    _Inout_ struct bpf_object* object,
    _Out_ fd_t* program_fd) noexcept;

static _Ret_z_ const char*
_ebpf_get_section_string(
    _In_ const struct _ebpf_pe_context* pe_context,
    uintptr_t address,
    _In_ const image_section_header& section_header,
    _In_ const bounded_buffer* buffer) noexcept;

static fd_t
_create_file_descriptor_for_handle(ebpf_handle_t handle) noexcept
{
    return Platform::_open_osfhandle(handle, 0);
}

inline static ebpf_handle_t
_get_handle_from_file_descriptor(fd_t fd) noexcept
{
    return Platform::_get_osfhandle(fd);
}

inline static int
_ebpf_create_registry_key(HKEY root_key, _In_z_ const wchar_t* path) noexcept
{
    return Platform::_create_registry_key(root_key, path);
}

inline static int
_ebpf_update_registry_value(
    HKEY root_key,
    _In_z_ const wchar_t* sub_key,
    DWORD type,
    _In_z_ const wchar_t* value_name,
    _In_reads_bytes_(value_size) const void* value,
    uint32_t value_size) noexcept
{
    return Platform::_update_registry_value(root_key, sub_key, type, value_name, value, value_size);
}

static std::wstring
_get_wstring_from_string(std::string& text) noexcept(false)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wide = converter.from_bytes(text);

    return wide;
}

inline static ebpf_map_t*
_get_ebpf_map_from_handle(ebpf_handle_t map_handle) noexcept
{
    EBPF_LOG_ENTRY();

    ebpf_assert(map_handle != ebpf_handle_invalid);

    ebpf_map_t* map = nullptr;
    std::map<ebpf_handle_t, ebpf_map_t*>::iterator it = _ebpf_maps.find(map_handle);
    if (it != _ebpf_maps.end()) {
        map = it->second;
    }

    EBPF_RETURN_POINTER(ebpf_map_t*, map);
}

inline static ebpf_program_t*
_get_ebpf_program_from_handle(ebpf_handle_t program_handle) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(program_handle != ebpf_handle_invalid);

    ebpf_program_t* program = nullptr;
    std::map<ebpf_handle_t, ebpf_program_t*>::iterator it = _ebpf_programs.find(program_handle);
    if (it != _ebpf_programs.end()) {
        program = it->second;
    }

    EBPF_RETURN_POINTER(ebpf_program_t*, program);
}

uint32_t
ebpf_api_initiate() noexcept
{
    EBPF_LOG_ENTRY();

    ebpf_trace_initiate();

    // This is best effort. If device handle does not initialize,
    // it will be re-attempted before an IOCTL call is made.
    initialize_device_handle();

    RPC_STATUS status = initialize_rpc_binding();

    if (status != RPC_S_OK) {
        clean_up_device_handle();
        clean_up_rpc_binding();
        EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(status));
    }

    // Load provider data from ebpf store. This is best effort
    // as there may be no data present in the store.
    load_ebpf_provider_data();

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

void
ebpf_api_terminate() noexcept
{
    clear_ebpf_provider_data();
    _clean_up_ebpf_objects();
    clean_up_device_handle();
    clean_up_rpc_binding();
    ebpf_trace_terminate();
}

static ebpf_result_t
_create_map(
    _In_opt_z_ const char* name,
    _In_ const ebpf_map_definition_in_memory_t* map_definition,
    ebpf_handle_t inner_map_handle,
    _Out_ ebpf_handle_t* map_handle) noexcept(false)
{
    EBPF_LOG_ENTRY();

    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t return_value = ERROR_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    _ebpf_operation_create_map_request* request;
    ebpf_operation_create_map_reply_t reply;
    std::string map_name;
    size_t map_name_size;

    ebpf_assert(map_definition);
    ebpf_assert(map_handle);

    if (name != nullptr) {
        map_name = std::string(name);
    }
    *map_handle = ebpf_handle_invalid;
    map_name_size = map_name.size();

    size_t buffer_size = offsetof(ebpf_operation_create_map_request_t, data) + map_name_size;
    request_buffer.resize(buffer_size);

    request = reinterpret_cast<ebpf_operation_create_map_request_t*>(request_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP;
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
    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_map_create(
    enum bpf_map_type map_type,
    _In_opt_z_ const char* map_name,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _In_opt_ const struct bpf_map_create_opts* opts,
    _Out_ fd_t* map_fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle = ebpf_handle_invalid;
    ebpf_handle_t inner_map_handle = ebpf_handle_invalid;
    ebpf_map_definition_in_memory_t map_definition = {};

    ebpf_assert(map_fd);

    if (opts && opts->map_flags != 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    *map_fd = ebpf_fd_invalid;

    try {
        map_definition.type = map_type;
        map_definition.key_size = key_size;
        map_definition.value_size = value_size;
        map_definition.max_entries = max_entries;

        // bpf_map_create_opts has inner_map_fd defined as __u32, so it cannot be set to
        // ebpf_fd_invalid (-1). Hence treat inner_map_fd = 0 as ebpf_fd_invalid.
        inner_map_handle = (opts && opts->inner_map_fd != 0) ? _get_handle_from_file_descriptor(opts->inner_map_fd)
                                                             : ebpf_handle_invalid;

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
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_map_lookup_element(
    ebpf_handle_t handle,
    bool find_and_delete,
    uint32_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    uint32_t value_size,
    _Out_ uint8_t* value) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_assert(value);
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
        if (key_size > 0) {
            std::copy(key, key + key_size, request->key);
        }

        result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer, reply_buffer));
        if (result == EBPF_SUCCESS) {
            ebpf_assert(reply->header.id == ebpf_operation_id_t::EBPF_OPERATION_MAP_FIND_ELEMENT);
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
    EBPF_RETURN_RESULT(result);
}

static inline ebpf_result_t
_get_map_descriptor_properties(
    ebpf_handle_t handle,
    _Out_ uint32_t* type,
    _Out_ uint32_t* key_size,
    _Out_ uint32_t* value_size,
    _Out_ uint32_t* max_entries) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_map_t* map;

    ebpf_assert(type);
    ebpf_assert(key_size);
    ebpf_assert(value_size);
    ebpf_assert(max_entries);

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
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
    } else {
        *type = map->map_definition.type;
        *key_size = map->map_definition.key_size;
        *value_size = map->map_definition.value_size;
        *max_entries = map->map_definition.max_entries;
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_map_lookup_element_helper(fd_t map_fd, bool find_and_delete, _In_opt_ const void* key, _Out_ void* value) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t max_entries = 0;
    uint32_t type;

    ebpf_assert(value);
    if (map_fd <= 0) {
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
    if ((key == nullptr) != (key_size == 0)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    assert(value_size != 0);
    if (BPF_MAP_TYPE_PER_CPU(type)) {
        value_size = EBPF_PAD_8(value_size) * libbpf_num_possible_cpus();
    }

    result = _map_lookup_element(map_handle, find_and_delete, key_size, (uint8_t*)key, value_size, (uint8_t*)value);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_map_lookup_element(fd_t map_fd, _In_opt_ const void* key, _Out_ void* value) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(value);
    auto result = _ebpf_map_lookup_element_helper(map_fd, false, key, value);
    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_map_lookup_and_delete_element(fd_t map_fd, _In_opt_ const void* key, _Out_ void* value) noexcept
{
    EBPF_LOG_ENTRY();
    auto result = _ebpf_map_lookup_element_helper(map_fd, true, key, value);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_update_map_element(
    ebpf_handle_t map_handle,
    _In_opt_ const void* key,
    uint32_t key_size,
    _In_ const void* value,
    uint32_t value_size,
    uint64_t flags) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_map_update_element_request_t* request;
    ebpf_assert(value);
    ebpf_assert(key || !key_size);

    try {
        request_buffer.resize(
            EBPF_OFFSET_OF(ebpf_operation_map_update_element_request_t, data) + key_size + value_size);
        request = reinterpret_cast<_ebpf_operation_map_update_element_request*>(request_buffer.data());

        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
        request->handle = (uint64_t)map_handle;
        request->option = static_cast<ebpf_map_option_t>(flags);
        if (key_size > 0) {
            std::copy((uint8_t*)key, (uint8_t*)key + key_size, request->data);
        }
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
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_update_map_element_with_handle(
    ebpf_handle_t map_handle,
    uint32_t key_size,
    _In_ const uint8_t* key,
    ebpf_handle_t value_handle,
    uint64_t flags) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(key);
    ebpf_protocol_buffer_t request_buffer(
        EBPF_OFFSET_OF(ebpf_operation_map_update_element_with_handle_request_t, key) + key_size);
    auto request = reinterpret_cast<ebpf_operation_map_update_element_with_handle_request_t*>(request_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE;
    request->map_handle = (uintptr_t)map_handle;
    request->value_handle = (uintptr_t)value_handle;
    request->option = static_cast<ebpf_map_option_t>(flags);
    std::copy(key, key + key_size, request->key);

    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer)));
}

ebpf_result_t
ebpf_map_update_element(fd_t map_fd, _In_opt_ const void* key, _In_ const void* value, uint64_t flags) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t max_entries = 0;
    uint32_t type;

    ebpf_assert(value);
    if (map_fd <= 0) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    switch (flags) {
    case EBPF_ANY:
    case EBPF_NOEXIST:
    case EBPF_EXIST:
        break;
    default:
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    map_handle = _get_handle_from_file_descriptor(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    // Get map properties, either from local cache or from EC.
    result = _get_map_descriptor_properties(map_handle, &type, &key_size, &value_size, &max_entries);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }
    if ((key == nullptr) != (key_size == 0)) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }
    assert(value_size != 0);
    assert(type != 0);

    if (BPF_MAP_TYPE_PER_CPU(type)) {
        value_size = EBPF_PAD_8(value_size) * libbpf_num_possible_cpus();
    }

    if ((type == BPF_MAP_TYPE_PROG_ARRAY) || (type == BPF_MAP_TYPE_HASH_OF_MAPS) ||
        (type == BPF_MAP_TYPE_ARRAY_OF_MAPS)) {
        fd_t fd = *(fd_t*)value;
        ebpf_handle_t handle = ebpf_handle_invalid;
        // If the fd is valid, resolve it to a handle, else pass ebpf_handle_invalid to the IOCTL.
        if (fd != ebpf_fd_invalid) {
            handle = _get_handle_from_file_descriptor(fd);
            if (handle == ebpf_handle_invalid) {
                EBPF_RETURN_RESULT(EBPF_INVALID_FD);
            }
        }

        assert(key_size != 0);
        __analysis_assume(key_size != 0);
        EBPF_RETURN_RESULT(_update_map_element_with_handle(map_handle, key_size, (const uint8_t*)key, handle, flags));
    } else {
        EBPF_RETURN_RESULT(_update_map_element(map_handle, key, key_size, value, value_size, flags));
    }
}

ebpf_result_t
ebpf_map_delete_element(fd_t map_fd, _In_ const void* key) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t map_handle;
    uint32_t key_size = 0;
    uint32_t value_size = 0;
    uint32_t max_entries = 0;
    uint32_t type;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_map_delete_element_request_t* request;

    ebpf_assert(key);
    if (map_fd <= 0) {
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
    if (key_size == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
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
    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_map_get_next_key(fd_t map_fd, _In_opt_ const void* previous_key, _Out_ void* next_key) noexcept
{
    EBPF_LOG_ENTRY();
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

    ebpf_assert(next_key);

    if (map_fd <= 0) {
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
    if (key_size == 0) {
        result = EBPF_OPERATION_NOT_SUPPORTED;
        goto Exit;
    }
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

        if (result == EBPF_SUCCESS) {
            ebpf_assert(reply->header.id == ebpf_operation_id_t::EBPF_OPERATION_MAP_GET_NEXT_KEY);
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
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_create_program(
    ebpf_program_type_t program_type,
    _In_ const std::string& file_name,
    _In_ const std::string& section_name,
    _In_ const std::string& program_name,
    _Out_ ebpf_handle_t* program_handle) noexcept(false)
{
    EBPF_LOG_ENTRY();
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_create_program_request_t* request;
    ebpf_operation_create_program_reply_t reply;
    ebpf_assert(program_handle);
    *program_handle = ebpf_handle_invalid;

    request_buffer.resize(
        offsetof(ebpf_operation_create_program_request_t, data) + file_name.size() + section_name.size() +
        program_name.size());

    request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_CREATE_PROGRAM;
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
    ebpf_assert(reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_CREATE_PROGRAM);
    *program_handle = reply.program_handle;

Exit:
    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(error));
}

void
ebpf_free_string(_In_opt_ _Post_invalid_ const char* error_message)
{
    EBPF_LOG_ENTRY();
    free(const_cast<char*>(error_message));
    EBPF_LOG_EXIT();
}

ebpf_result_t
ebpf_object_pin(fd_t fd, _In_z_ const char* path) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t handle;

    ebpf_assert(path);
    if (fd <= 0) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    handle = _get_handle_from_file_descriptor(fd);
    if (handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    auto path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, path) + path_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = handle;
    std::copy(path, path + path_length, request->path);
    result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer));

    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_object_unpin(_In_z_ const char* path)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(path);
    auto path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_update_pinning_request_t, path) + path_length);
    auto request = reinterpret_cast<ebpf_operation_update_pinning_request_t*>(request_buffer.data());

    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_UPDATE_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = UINT64_MAX;
    std::copy(path, path + path_length, request->path);
    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer)));
}

ebpf_result_t
ebpf_map_pin(_In_ struct bpf_map* map, _In_opt_z_ const char* path) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map);
    if (map->pin_path == nullptr && path == nullptr) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }
    if (map->pinned) {
        EBPF_RETURN_RESULT(
            (map->pin_path != nullptr && path != nullptr && strcmp(path, map->pin_path) == 0)
                ? EBPF_OBJECT_ALREADY_EXISTS
                : EBPF_ALREADY_PINNED);
    }
    if (path != nullptr) {
        // If pin path is already set, the pin path provided now should be same
        // as the one previously set.
        if (map->pin_path != nullptr && strcmp(path, map->pin_path) != 0) {
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }
        free(map->pin_path);
        map->pin_path = _strdup(path);
        if (map->pin_path == nullptr) {
            EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
        }
    }
    assert(map->map_handle != ebpf_handle_invalid);
    assert(map->map_fd > 0);
    ebpf_result_t result = ebpf_object_pin(map->map_fd, map->pin_path);
    if (result == EBPF_SUCCESS) {
        map->pinned = true;
    }

    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_map_set_pin_path(_In_ struct bpf_map* map, _In_opt_z_ const char* path) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map);
    char* old_path = map->pin_path;
    if (path != nullptr) {
        path = _strdup(path);
        if (path == nullptr) {
            EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
        }
    }
    map->pin_path = const_cast<char*>(path);
    free(old_path);

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

ebpf_result_t
ebpf_map_unpin(_In_ struct bpf_map* map, _In_opt_z_ const char* path) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map);
    if (map->pin_path != nullptr) {
        // If pin path is already set, the pin path provided now should be same
        // as the one previously set.
        if (path != nullptr && strcmp(path, map->pin_path) != 0) {
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }
        path = map->pin_path;
    } else if (path == nullptr) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }
    assert(map->map_handle != ebpf_handle_invalid);
    assert(map->map_fd > 0);

    ebpf_result_t result = ebpf_object_unpin(path);
    if (result == EBPF_SUCCESS) {
        map->pinned = false;
    }

    EBPF_RETURN_RESULT(result);
}

fd_t
ebpf_object_get(_In_z_ const char* path) noexcept
{
    EBPF_LOG_ENTRY();
    size_t path_length = strlen(path);
    ebpf_protocol_buffer_t request_buffer(offsetof(ebpf_operation_get_pinned_object_request_t, path) + path_length);
    auto request = reinterpret_cast<ebpf_operation_get_pinned_object_request_t*>(request_buffer.data());
    ebpf_operation_get_pinned_object_reply_t reply;
    ebpf_assert(path);

    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_GET_PINNED_OBJECT;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    std::copy(path, path + path_length, request->path);
    auto result = invoke_ioctl(request_buffer, reply);
    if (result != ERROR_SUCCESS) {
        EBPF_RETURN_FD(ebpf_fd_invalid);
    }

    ebpf_assert(reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_GET_PINNED_OBJECT);

    ebpf_handle_t handle = reply.handle;
    fd_t fd = _create_file_descriptor_for_handle(handle);
    if (fd == ebpf_fd_invalid) {
        Platform::CloseHandle(handle);
    }
    EBPF_RETURN_FD(fd);
}

ebpf_result_t
ebpf_program_query_info(
    fd_t fd,
    _Out_ ebpf_execution_type_t* execution_type,
    _Outptr_result_z_ const char** file_name,
    _Outptr_result_z_ const char** section_name)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_handle_t handle = _get_handle_from_file_descriptor(fd);
    if (handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    ebpf_assert(execution_type);
    ebpf_assert(file_name);
    ebpf_assert(section_name);

    ebpf_protocol_buffer_t reply_buffer(1024);
    ebpf_operation_query_program_info_request_t request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_QUERY_PROGRAM_INFO, handle};

    auto reply = reinterpret_cast<ebpf_operation_query_program_info_reply_t*>(reply_buffer.data());

    uint32_t retval = invoke_ioctl(request, reply_buffer);
    if (retval != ERROR_SUCCESS) {
        result = win32_error_code_to_ebpf_result(retval);
        __analysis_assume(result != EBPF_SUCCESS);
        EBPF_RETURN_RESULT(result);
    }
    ebpf_assert(reply->header.id == ebpf_operation_id_t::EBPF_OPERATION_QUERY_PROGRAM_INFO);

    size_t file_name_length = reply->section_name_offset - reply->file_name_offset;
    size_t section_name_length = reply->header.length - reply->section_name_offset;
    char* local_file_name = reinterpret_cast<char*>(calloc(file_name_length + 1, sizeof(char)));
    char* local_section_name = reinterpret_cast<char*>(calloc(section_name_length + 1, sizeof(char)));

    if (!local_file_name || !local_section_name) {
        free(local_file_name);
        free(local_section_name);
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    memcpy(local_file_name, reply_buffer.data() + reply->file_name_offset, file_name_length);
    memcpy(local_section_name, reply_buffer.data() + reply->section_name_offset, section_name_length);

    local_file_name[file_name_length] = '\0';
    local_section_name[section_name_length] = '\0';

    *execution_type = (ebpf_execution_type_t)reply->code_type;
    *file_name = local_file_name;
    *section_name = local_section_name;

    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(retval));
}

static ebpf_result_t
_link_ebpf_program(
    ebpf_handle_t program_handle,
    _In_ const ebpf_attach_type_t* attach_type,
    _Out_ ebpf_link_t** link,
    _In_reads_bytes_opt_(attach_parameter_size) uint8_t* attach_parameter,
    size_t attach_parameter_size) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_link_program_request_t* request;
    ebpf_operation_link_program_reply_t reply;
    ebpf_result_t result = EBPF_SUCCESS;
    bool attached = false;

    ebpf_assert(attach_type);
    ebpf_assert(link);
    ebpf_assert(attach_parameter || !attach_parameter_size);

    *link = nullptr;
    ebpf_link_t* new_link = (ebpf_link_t*)calloc(1, sizeof(ebpf_link_t));
    if (new_link == nullptr) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }
    new_link->handle = ebpf_handle_invalid;

    try {
        size_t buffer_size = offsetof(ebpf_operation_link_program_request_t, data) + attach_parameter_size;
        request_buffer.resize(buffer_size);
        request = reinterpret_cast<ebpf_operation_link_program_request_t*>(request_buffer.data());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LINK_PROGRAM;
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
        ebpf_assert(reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_LINK_PROGRAM);
        attached = true;

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
        if (attached)
            ebpf_link_detach(new_link);
        ebpf_link_close(new_link);
    }
    EBPF_RETURN_RESULT(result);
}

static void
_clean_up_ebpf_link(_In_opt_ _Post_invalid_ ebpf_link_t* link) noexcept
{
    EBPF_LOG_ENTRY();
    if (link == nullptr) {
        EBPF_RETURN_VOID();
    }
    if (link->handle != ebpf_handle_invalid) {
        ebpf_api_close_handle(link->handle);
    }
    free(link->pin_path);

    free(link);
    EBPF_RETURN_VOID();
}

static ebpf_result_t
_detach_link_by_handle(ebpf_handle_t link_handle) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_operation_unlink_program_request_t request = {0};
    request.header.length = sizeof(request);
    request.header.id = ebpf_operation_id_t::EBPF_OPERATION_UNLINK_PROGRAM;
    request.link_handle = link_handle;

    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(invoke_ioctl(request)));
}

ebpf_result_t
ebpf_detach_link_by_fd(fd_t fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_handle_t link_handle = _get_handle_from_file_descriptor(fd);
    if (link_handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    EBPF_RETURN_RESULT(_detach_link_by_handle(link_handle));
}

ebpf_result_t
ebpf_program_attach(
    _In_ const struct bpf_program* program,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_opt_(attach_params_size) void* attach_parameters,
    _In_ size_t attach_params_size,
    _Outptr_ struct bpf_link** link)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    const ebpf_attach_type_t* program_attach_type;

    ebpf_assert(program);
    ebpf_assert(link);
    ebpf_assert(attach_parameters || !attach_params_size);
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
    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_program_attach_by_fd(
    fd_t program_fd,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
    _In_ size_t attach_parameters_size,
    _Outptr_ struct bpf_link** link)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(attach_parameters || !attach_parameters_size);
    ebpf_assert(link);
    *link = nullptr;

    ebpf_handle_t program_handle = _get_handle_from_file_descriptor(program_fd);
    if (program_handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    if (attach_type == nullptr) {
        // Unspecified attach_type is allowed only if we can find an ebpf_program_t.
        ebpf_program_t* program = _get_ebpf_program_from_handle(program_handle);
        if (program == nullptr) {
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }

        EBPF_RETURN_RESULT(ebpf_program_attach(program, attach_type, attach_parameters, attach_parameters_size, link));
    }

    EBPF_RETURN_RESULT(
        _link_ebpf_program(program_handle, attach_type, link, (uint8_t*)attach_parameters, attach_parameters_size));
}

ebpf_result_t
ebpf_api_unlink_program(ebpf_handle_t link_handle)
{
    EBPF_LOG_ENTRY();
    ebpf_operation_unlink_program_request_t request = {0};
    request.header.length = sizeof(request);
    request.header.id = ebpf_operation_id_t::EBPF_OPERATION_UNLINK_PROGRAM;
    request.link_handle = link_handle;

    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(invoke_ioctl(request)));
}

ebpf_result_t
ebpf_link_detach(_In_ struct bpf_link* link)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(link);
    EBPF_RETURN_RESULT(_detach_link_by_handle(link->handle));
}

ebpf_result_t
ebpf_program_detach(
    fd_t program_fd,
    _In_ const ebpf_attach_type_t* attach_type,
    _In_reads_bytes_(attach_parameter_size) void* attach_parameter,
    size_t attach_parameter_size) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_unlink_program_request_t* request;
    size_t buffer_size = offsetof(ebpf_operation_unlink_program_request_t, data) + attach_parameter_size;

    EBPF_LOG_ENTRY();

    try {
        request_buffer.resize(buffer_size);
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    request = reinterpret_cast<ebpf_operation_unlink_program_request_t*>(request_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_UNLINK_PROGRAM;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->link_handle = ebpf_handle_invalid;
    request->program_handle =
        (program_fd != ebpf_fd_invalid) ? _get_handle_from_file_descriptor(program_fd) : ebpf_handle_invalid;
    request->attach_type = *attach_type;

    if (attach_parameter_size > 0) {
        request->attach_data_present = true;
        memcpy_s(request->data, attach_parameter_size, attach_parameter, attach_parameter_size);
    }

    result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer));
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_link_close(_In_ _Post_invalid_ struct bpf_link* link)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(link);
    _clean_up_ebpf_link(link);

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

ebpf_result_t
ebpf_api_close_handle(ebpf_handle_t handle)
{
    EBPF_LOG_ENTRY();
    ebpf_operation_close_handle_request_t request = {
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_CLOSE_HANDLE, handle};

    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(invoke_ioctl(request)));
}

ebpf_result_t
ebpf_api_get_pinned_map_info(
    _Out_ uint16_t* map_count, _Outptr_result_buffer_maybenull_(*map_count) ebpf_map_info_t** map_info)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_operation_get_pinned_map_info_request_t request = {
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_GET_PINNED_MAP_INFO};
    ebpf_protocol_buffer_t reply_buffer;
    ebpf_operation_get_pinned_map_info_reply_t* reply = nullptr;
    size_t min_expected_buffer_length = 0;
    size_t serialized_buffer_length = 0;
    uint16_t local_map_count = 0;
    ebpf_map_info_t* local_map_info = nullptr;
    size_t output_buffer_length = 4 * 1024;
    uint8_t attempt_count = 0;

    ebpf_assert(map_count);
    ebpf_assert(map_info);

    while (attempt_count < IOCTL_MAX_ATTEMPTS) {
        size_t reply_length;
        result = ebpf_safe_size_t_add(
            EBPF_OFFSET_OF(ebpf_operation_get_pinned_map_info_reply_t, data), output_buffer_length, &reply_length);
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

        reply = reinterpret_cast<ebpf_operation_get_pinned_map_info_reply_t*>(reply_buffer.data());
        ebpf_assert(reply->header.id == ebpf_operation_id_t::EBPF_OPERATION_GET_PINNED_MAP_INFO);

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

    EBPF_RETURN_RESULT(result);
}

void
ebpf_api_map_info_free(
    const uint16_t map_count, _In_opt_count_(map_count) _Post_ptr_invalid_ const ebpf_map_info_t* map_info)
{
    EBPF_LOG_ENTRY();
    ebpf_map_info_array_free(map_count, const_cast<ebpf_map_info_t*>(map_info));
}

void
clean_up_ebpf_program(_In_ _Post_invalid_ ebpf_program_t* program) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(program);
    ebpf_program_unload(program);

    free(program->instructions);
    free(program->program_name);
    free(program->section_name);
    free((void*)program->log_buffer);

    free(program);
}

void
clean_up_ebpf_programs(_Inout_ std::vector<ebpf_program_t*>& programs) noexcept
{
    EBPF_LOG_ENTRY();
    for (auto& program : programs) {
        clean_up_ebpf_program(program);
    }
    programs.resize(0);
}

void
clean_up_ebpf_map(_In_ _Post_invalid_ ebpf_map_t* map) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map);
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
clean_up_ebpf_maps(_Inout_ std::vector<ebpf_map_t*>& maps) noexcept
{
    EBPF_LOG_ENTRY();
    for (auto& map : maps) {
        clean_up_ebpf_map(map);
    }
    maps.resize(0);
}

static void
_clean_up_ebpf_object(_In_opt_ ebpf_object_t* object) noexcept
{
    EBPF_LOG_ENTRY();
    if (object != nullptr) {
        clean_up_ebpf_programs(object->programs);
        clean_up_ebpf_maps(object->maps);

        free(object->object_name);
        free(object->file_name);
    }
}

static void
_delete_ebpf_object(_In_opt_ _Post_invalid_ ebpf_object_t* object) noexcept
{
    EBPF_LOG_ENTRY();
    if (object != nullptr) {
        _clean_up_ebpf_object(object);

        delete object;
    }
}

static void
_remove_ebpf_object_from_globals(_In_ const ebpf_object_t* object) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(object);
    auto it = std::find(_ebpf_objects.begin(), _ebpf_objects.end(), object);
    ebpf_assert(it != _ebpf_objects.end());
    _ebpf_objects.erase(it);
}

static void
_clean_up_ebpf_objects() noexcept
{
    EBPF_LOG_ENTRY();
    for (auto& object : _ebpf_objects) {
        _delete_ebpf_object(object);
    }

    _ebpf_objects.resize(0);

    ebpf_assert(_ebpf_programs.size() == 0);
    ebpf_assert(_ebpf_maps.size() == 0);
}

void
initialize_map(_Out_ ebpf_map_t* map, _In_ const map_cache_t& map_cache) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map);

    // Initialize handle to ebpf_handle_invalid.
    map->map_handle = ebpf_handle_invalid;
    map->original_fd = map_cache.verifier_map_descriptor.original_fd;
    map->map_definition.type = (ebpf_map_type_t)map_cache.verifier_map_descriptor.type;
    map->map_definition.key_size = map_cache.verifier_map_descriptor.key_size;
    map->map_definition.value_size = map_cache.verifier_map_descriptor.value_size;
    map->map_definition.max_entries = map_cache.verifier_map_descriptor.max_entries;
    map->map_definition.pinning = map_cache.pinning;

    // Set the inner map ID if we have a real inner map fd.
    map->map_definition.inner_map_id = EBPF_ID_NONE;
    if (map_cache.verifier_map_descriptor.inner_map_fd != ebpf_fd_invalid) {
        struct bpf_map_info info = {0};
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
_initialize_ebpf_maps_native(
    size_t count_of_maps,
    _In_reads_(count_of_maps) ebpf_handle_t* map_handles,
    _Inout_ std::vector<ebpf_map_t*>& maps) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map_handles);
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_map_t* map = nullptr;

    for (int i = 0; i < count_of_maps; i++) {
        if (map_handles[i] == ebpf_handle_invalid) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        struct bpf_map_info info = {0};
        uint32_t info_size = (uint32_t)sizeof(info);
        result = ebpf_object_get_info(map_handles[i], &info, &info_size);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        map = maps[i];

        // Note that the map name need not match, if the map was reused
        // based on a pin path.  Other fields ought to match however.
        ebpf_assert(map->map_definition.type == info.type);
        ebpf_assert(map->map_definition.key_size == info.key_size);
        ebpf_assert(map->map_definition.value_size == info.value_size);
        ebpf_assert(map->map_definition.max_entries == info.max_entries);

        map->map_definition.inner_map_id = info.inner_map_id;
        map->map_fd = _create_file_descriptor_for_handle(map_handles[i]);
        if (map->map_fd == ebpf_fd_invalid) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        map->map_handle = map_handles[i];
        map_handles[i] = ebpf_handle_invalid;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        if (map != nullptr) {
            clean_up_ebpf_map(map);
            map = nullptr;
        }

        clean_up_ebpf_maps(maps);
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_initialize_ebpf_programs_native(
    size_t count_of_programs,
    _In_reads_(count_of_programs) ebpf_handle_t* program_handles,
    _Inout_ std::vector<ebpf_program_t*>& programs) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(program_handles);
    ebpf_result_t result = EBPF_SUCCESS;

    for (int i = 0; i < count_of_programs; i++) {
        if (program_handles[i] == ebpf_handle_invalid) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        struct bpf_prog_info info = {};
        uint32_t info_size = (uint32_t)sizeof(info);
        result = ebpf_object_get_info(program_handles[i], &info, &info_size);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        ebpf_program_t* program = programs[i];
        program->fd = _create_file_descriptor_for_handle(program_handles[i]);
        if (program->fd == ebpf_fd_invalid) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        program->handle = program_handles[i];
        program_handles[i] = ebpf_handle_invalid;
        program->program_type = info.type_uuid;
        program->attach_type = info.attach_type_uuid;
    }

Exit:
    if (result != EBPF_SUCCESS) {
        clean_up_ebpf_programs(programs);
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_initialize_ebpf_object_native(
    size_t count_of_maps,
    _In_reads_(count_of_maps) ebpf_handle_t* map_handles,
    size_t count_of_programs,
    _In_reads_(count_of_programs) ebpf_handle_t* program_handles,
    _Out_ ebpf_object_t& object) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_assert(map_handles);
    ebpf_assert(program_handles);

    result = _initialize_ebpf_programs_native(count_of_programs, program_handles, object.programs);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = _initialize_ebpf_maps_native(count_of_maps, map_handles, object.maps);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // The following should have already been populated by
    // _ebpf_enumerate_native_sections when opening the object.
    ebpf_assert(object.file_name != nullptr);
    ebpf_assert(object.object_name != nullptr);

    for (auto& map : object.maps) {
        map->object = &object;
    }
    object.loaded = true;

Exit:
    if (result != EBPF_SUCCESS) {
        _clean_up_ebpf_object(&object);
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_enumerate_native_sections(
    _In_z_ const char* file,
    _Inout_opt_ ebpf_object_t* object,
    _In_opt_z_ const char* pin_root_path,
    _Outptr_result_maybenull_ ebpf_section_info_t** infos,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept;

static ebpf_result_t
_initialize_ebpf_object_from_native_file(
    _In_z_ const char* file_name,
    _In_opt_z_ const char* pin_root_path,
    _Inout_ ebpf_object_t& object,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_program_t* program = nullptr;

    EBPF_LOG_ENTRY();
    ebpf_assert(file_name);
    ebpf_assert(error_message);

    ebpf_section_info_t* infos = nullptr;
    ebpf_result_t result = _ebpf_enumerate_native_sections(file_name, &object, pin_root_path, &infos, error_message);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    object.execution_type = EBPF_EXECUTION_NATIVE;

    for (ebpf_section_info_t* info = infos; info; info = info->next) {
        program = (ebpf_program_t*)calloc(1, sizeof(ebpf_program_t));
        if (program == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        program->handle = ebpf_handle_invalid;
        program->program_type = info->program_type;
        program->attach_type = info->expected_attach_type;

        program->section_name = _strdup(info->section_name);
        if (program->section_name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        program->program_name = _strdup(info->program_name);
        if (program->program_name == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }

        // Update attach type for the program.
        if (get_global_program_type() != nullptr) {
            const ebpf_attach_type_t* attach_type = get_global_attach_type();
            if (attach_type != nullptr) {
                program->attach_type = *attach_type;
            }
        }

        object.programs.emplace_back(program);
        program = nullptr;
    }

Exit:
    free(program);
    if (result != EBPF_SUCCESS) {
        clean_up_ebpf_programs(object.programs);
        clean_up_ebpf_maps(object.maps);
    }
    ebpf_free_sections(infos);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_initialize_ebpf_object_from_elf(
    _In_z_ const char* file_name,
    _In_opt_z_ const char* pin_root_path,
    _Inout_ ebpf_object_t& object,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(file_name);
    ebpf_assert(error_message);

    ebpf_result_t result = EBPF_SUCCESS;

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

Exit:
    if (result != EBPF_SUCCESS) {
        clean_up_ebpf_programs(object.programs);
        clean_up_ebpf_maps(object.maps);
    }
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_initialize_ebpf_object_from_file(
    _In_z_ const char* path,
    _In_opt_z_ const char* object_name,
    _In_opt_z_ const char* pin_root_path,
    _Out_ ebpf_object_t* new_object,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;

    new_object->file_name = _strdup(path);
    if (new_object->file_name == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    new_object->object_name = _strdup(object_name ? object_name : path);
    if (new_object->object_name == nullptr) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    if (Platform::_is_native_program(path)) {
        result = _initialize_ebpf_object_from_native_file(path, pin_root_path, *new_object, error_message);
    } else {
        result = _initialize_ebpf_object_from_elf(path, pin_root_path, *new_object, error_message);
    }
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    for (auto& program : new_object->programs) {
        program->fd = ebpf_fd_invalid;
        program->object = new_object;
    }
    for (auto& map : new_object->maps) {
        map->map_fd = ebpf_fd_invalid;
        map->object = new_object;
    }
Done:
    return result;
}

// Find a map that needs to be created and doesn't depend on
// creating another map first.  That is, we want to create an
// inner map template before creating an outer map that depends
// on the inner map template.
static ebpf_map_t*
_get_next_map_to_create(std::vector<ebpf_map_t*>& maps) noexcept
{
    EBPF_LOG_ENTRY();
    for (auto& map : maps) {
        if (map->map_handle != ebpf_handle_invalid) {
            // Already created.
            continue;
        }
        if (map->map_definition.type != BPF_MAP_TYPE_ARRAY_OF_MAPS &&
            map->map_definition.type != BPF_MAP_TYPE_HASH_OF_MAPS) {
            EBPF_RETURN_POINTER(ebpf_map_t*, map);
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
        EBPF_RETURN_POINTER(ebpf_map_t*, map);
    }

    // There are no maps left that we can create.
    EBPF_RETURN_POINTER(ebpf_map_t*, nullptr);
}

static void
_ebpf_free_section_info(_In_ _Frees_ptr_ ebpf_section_info_t* info) noexcept
{
    EBPF_LOG_ENTRY();
    while (info->stats != nullptr) {
        ebpf_stat_t* stat = info->stats;
#pragma warning(push)
#pragma warning(disable : 6001)
        // MSVC incorrectly reports this as using uninitialized memory.
        info->stats = stat->next;
        free((void*)stat->key);
#pragma warning(pop)
        free(stat);
    }
    free((void*)info->program_name);
    free((void*)info->section_name);
    free((void*)info->program_type_name);
    free(info->raw_data);
    free(info);
    EBPF_LOG_EXIT();
}

void
ebpf_free_sections(_In_opt_ ebpf_section_info_t* infos)
{
    EBPF_LOG_ENTRY();
    while (infos != nullptr) {
        ebpf_section_info_t* info = infos;
        infos = info->next;
        _ebpf_free_section_info(info);
    }
    EBPF_LOG_EXIT();
}

typedef struct _ebpf_pe_context
{
    ebpf_result_t result;
    ebpf_object_t* object;
    const char* pin_root_path;
    uintptr_t image_base;
    ebpf_section_info_t* infos;
    std::map<std::string, std::string> section_names;
    std::map<std::string, std::string> program_names;
    std::map<std::string, GUID> section_program_types;
    std::map<std::string, GUID> section_attach_types;
    uintptr_t rdata_base;
    size_t rdata_size;
    const bounded_buffer* rdata_buffer;
    uintptr_t data_base;
    size_t data_size;
    const bounded_buffer* data_buffer;
} ebpf_pe_context_t;

static int // Returns 0 on success, 1 on error.
_ebpf_pe_get_map_definitions(
    _Inout_ void* context,
    _In_ const VA& va,
    _In_ const std::string& section_name,
    _In_ const image_section_header& section_header,
    _In_ const bounded_buffer* buffer) noexcept
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(va);
    UNREFERENCED_PARAMETER(buffer);

    ebpf_map_t* map = nullptr;
    ebpf_pe_context_t* pe_context = (ebpf_pe_context_t*)context;
    if (section_name == "maps") {
        // bpf2c generates a section that has map names shorter than sizeof(map_entry_t)
        // at the start of the section.  Skip over them looking for the map_entry_t
        // which starts with an 8-byte-aligned NULL pointer where the previous
        // byte (if any) is also 00, and the following 8 bytes are non-NULL.
        uint32_t map_offset = 0;
        uint64_t zero = 0;
        while (map_offset + 16 < section_header.Misc.VirtualSize &&
               (memcmp(buffer->buf + map_offset, &zero, sizeof(zero)) != 0 ||
                (map_offset > 0 && buffer->buf[map_offset - 1] != 0) ||
                memcmp(buffer->buf + map_offset + 8, &zero, sizeof(zero)) == 0)) {
            map_offset += 8;
        }
        if (pe_context->object != nullptr) {
            for (int map_index = 0; map_offset + sizeof(map_entry_t) <= section_header.Misc.VirtualSize;
                 map_offset += sizeof(map_entry_t), map_index++) {
                map_entry_t* entry = (map_entry_t*)(buffer->buf + map_offset);
                if (entry->address != nullptr) {
                    // bpf2c generates a section that has map names longer than sizeof(map_entry_t)
                    // at the end of the section.  This entry seems to be a map name string, so we've
                    // reached the end of the maps.
                    break;
                }

                map = (ebpf_map_t*)calloc(1, sizeof(ebpf_map_t));
                if (map == nullptr) {
                    goto Error;
                }

                map->map_handle = ebpf_handle_invalid;
                map->original_fd = (fd_t)map_index;
                map->map_definition.type = entry->definition.type;
                map->map_definition.key_size = entry->definition.key_size;
                map->map_definition.value_size = entry->definition.value_size;
                map->map_definition.max_entries = entry->definition.max_entries;
                map->map_definition.pinning = entry->definition.pinning;
                map->map_definition.inner_map_id = entry->definition.inner_id;
                map->inner_map_original_fd = entry->definition.inner_map_idx;
                map->pinned = false;
                map->reused = false;
                map->pin_path = nullptr;

                const char* map_name =
                    _ebpf_get_section_string(pe_context, (uintptr_t)entry->name, section_header, buffer);
                map->name = _strdup(map_name);
                if (map->name == nullptr) {
                    pe_context->result = EBPF_NO_MEMORY;
                    goto Error;
                }
                if (map->map_definition.pinning == PIN_GLOBAL_NS) {
                    char pin_path_buffer[EBPF_MAX_PIN_PATH_LENGTH];
                    int len = snprintf(
                        pin_path_buffer,
                        EBPF_MAX_PIN_PATH_LENGTH,
                        "%s/%s",
                        pe_context->pin_root_path ? pe_context->pin_root_path : DEFAULT_PIN_ROOT_PATH,
                        map->name);
                    if (len < 0 || len >= EBPF_MAX_PIN_PATH_LENGTH) {
                        pe_context->result = EBPF_INVALID_ARGUMENT;
                        goto Error;
                    }
                    map->pin_path = _strdup(pin_path_buffer);
                    if (map->pin_path == nullptr) {
                        pe_context->result = EBPF_NO_MEMORY;
                        goto Error;
                    }
                }
                pe_context->object->maps.emplace_back(map);
                map = nullptr;
            }
        }
    } else if (section_name == ".rdata") {
        pe_context->rdata_base = pe_context->image_base + section_header.VirtualAddress;
        pe_context->rdata_size = section_header.Misc.VirtualSize;
        pe_context->rdata_buffer = buffer;
    } else if (section_name == ".data") {
        pe_context->data_base = pe_context->image_base + section_header.VirtualAddress;
        pe_context->data_size = section_header.Misc.VirtualSize;
        pe_context->data_buffer = buffer;
    }

    EBPF_LOG_FUNCTION_SUCCESS();
    return 0;

Error:
    if (map) {
        clean_up_ebpf_map(map);
    }
    EBPF_LOG_FUNCTION_ERROR(pe_context->result);
    return 1;
}

static _Ret_z_ const char*
_ebpf_get_section_string(
    _In_ const ebpf_pe_context_t* pe_context,
    uintptr_t address,
    _In_ const image_section_header& section_header,
    _In_ const bounded_buffer* buffer) noexcept
{
    EBPF_LOG_ENTRY();
    if (address >= pe_context->rdata_base && address < pe_context->rdata_base + pe_context->rdata_size) {
        // String is in rdata section (.sys files do this).
        uintptr_t offset = address - pe_context->rdata_base;
        EBPF_RETURN_POINTER(const char*, (const char*)(pe_context->rdata_buffer->buf + offset));
    } else {
        // String is in programs section (.dll files do this).
        uintptr_t base = pe_context->image_base + section_header.VirtualAddress;
        ebpf_assert(address >= base && address < base + section_header.Misc.VirtualSize);
        uintptr_t offset = address - base;
        EBPF_RETURN_POINTER(const char*, (const char*)(buffer->buf + offset));
    }
}

static int
_ebpf_pe_get_section_names(
    _Inout_ void* context,
    _In_ const VA& va,
    _In_ const std::string& section_name,
    _In_ const image_section_header& section_header,
    _In_ const bounded_buffer* buffer) noexcept
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(va);

    ebpf_pe_context_t* pe_context = (ebpf_pe_context_t*)context;
    if (section_name == "programs") {
        // bpf2c generates a section that has ELF section names as strings at the
        // start of the section.  Skip over them looking for the program_entry_t
        // which starts with a 16-byte-aligned NULL pointer where the previous
        // byte (if any) is also 00.
        uint32_t program_offset = 0;
        uint64_t zero = 0;
        while (program_offset + sizeof(zero) <= section_header.Misc.VirtualSize &&
               (memcmp(buffer->buf + program_offset, &zero, sizeof(zero)) != 0 ||
                (program_offset > 0 && buffer->buf[program_offset - 1] != 0))) {
            program_offset += 16;
        }
        int program_count = (section_header.Misc.VirtualSize - program_offset) / sizeof(program_entry_t);
        for (int i = 0; i < program_count; i++) {
            program_entry_t* program = (program_entry_t*)(buffer->buf + program_offset + i * sizeof(program_entry_t));
            const char* pe_section_name =
                _ebpf_get_section_string(pe_context, (uintptr_t)program->pe_section_name, section_header, buffer);
            const char* elf_section_name =
                _ebpf_get_section_string(pe_context, (uintptr_t)program->section_name, section_header, buffer);
            pe_context->section_names[pe_section_name] = elf_section_name;

            const char* program_name =
                _ebpf_get_section_string(pe_context, (uintptr_t)program->program_name, section_header, buffer);
            pe_context->program_names[pe_section_name] = program_name;

            uintptr_t program_type_guid_address = (uintptr_t)program->program_type;
            ebpf_assert(
                program_type_guid_address >= pe_context->data_base &&
                program_type_guid_address < pe_context->data_base + pe_context->data_size);
            uintptr_t offset = program_type_guid_address - pe_context->data_base;
            pe_context->section_program_types[pe_section_name] = *(GUID*)(pe_context->data_buffer->buf + offset);

            uintptr_t attach_type_guid_address = (uintptr_t)program->expected_attach_type;
            ebpf_assert(
                attach_type_guid_address >= pe_context->data_base &&
                attach_type_guid_address < pe_context->data_base + pe_context->data_size);
            offset = attach_type_guid_address - pe_context->data_base;
            pe_context->section_attach_types[pe_section_name] = *(GUID*)(pe_context->data_buffer->buf + offset);
        }
    }

    EBPF_LOG_EXIT();
    return 0;
}

static int
_ebpf_pe_add_section(
    void* context,
    const VA& va,
    const std::string& pe_section_name,
    const image_section_header& section_header,
    const bounded_buffer* buffer) noexcept
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(va);
    UNREFERENCED_PARAMETER(buffer);

    if (!(section_header.Characteristics & IMAGE_SCN_CNT_CODE)) {
        // Not a code section.
        return 0;
    }
    ebpf_pe_context_t* pe_context = (ebpf_pe_context_t*)context;

    // Get ELF section name.
    if (!pe_context->section_names.contains(pe_section_name)) {
        // Not an eBPF program section.
        EBPF_LOG_EXIT();
        return 0;
    }
    std::string elf_section_name = pe_context->section_names[pe_section_name];
    std::string program_name = pe_context->program_names[pe_section_name];

    ebpf_section_info_t* info = (ebpf_section_info_t*)malloc(sizeof(*info));
    if (info == nullptr) {
        EBPF_LOG_EXIT();
        return 1;
    }

    memset(info, 0, sizeof(*info));
    info->section_name = _strdup(elf_section_name.c_str());
    info->program_name = _strdup(program_name.c_str());
    info->program_type = pe_context->section_program_types[pe_section_name];
    info->expected_attach_type = pe_context->section_attach_types[pe_section_name];
    info->program_type_name = ebpf_get_program_type_name(&pe_context->section_program_types[pe_section_name]);
    if (info->program_type_name == nullptr) {
        EBPF_LOG_EXIT();
        return 1;
    }
    info->program_type_name = _strdup(info->program_type_name);
    info->raw_data_size = section_header.Misc.VirtualSize;
    info->raw_data = (char*)malloc(section_header.Misc.VirtualSize);
    if (info->raw_data == nullptr || info->program_type_name == nullptr || info->section_name == nullptr) {
        _ebpf_free_section_info(info);
        EBPF_LOG_EXIT();
        return 1;
    }
    memcpy(info->raw_data, buffer->buf, section_header.Misc.VirtualSize);

    // Append to existing list.
    ebpf_section_info_t** pnext = &pe_context->infos;
    while (*pnext) {
        pnext = &(*pnext)->next;
    }
    *pnext = info;

    EBPF_LOG_EXIT();
    return 0;
}

static ebpf_result_t
_ebpf_enumerate_native_sections(
    _In_z_ const char* file,
    _Inout_opt_ ebpf_object_t* object,
    _In_opt_z_ const char* pin_root_path,
    _Outptr_result_maybenull_ ebpf_section_info_t** infos,
    _Outptr_result_maybenull_z_ const char** error_message) noexcept
{
    EBPF_LOG_ENTRY();
    *infos = nullptr;
    *error_message = nullptr;

    parsed_pe* pe = ParsePEFromFile(file);
    if (pe == nullptr) {
        EBPF_RETURN_RESULT(EBPF_FILE_NOT_FOUND);
    }

    ebpf_pe_context_t context = {
        .result = EBPF_SUCCESS,
        .object = object,
        .pin_root_path = pin_root_path,
        .image_base = pe->peHeader.nt.OptionalHeader64.ImageBase};
    IterSec(pe, _ebpf_pe_get_map_definitions, &context);
    IterSec(pe, _ebpf_pe_get_section_names, &context);
    IterSec(pe, _ebpf_pe_add_section, &context);

    DestructParsedPE(pe);

    *infos = context.infos;
    EBPF_RETURN_RESULT(context.result);
}

ebpf_result_t
ebpf_enumerate_sections(
    _In_z_ const char* file,
    bool verbose,
    _Outptr_result_maybenull_ ebpf_section_info_t** infos,
    _Outptr_result_maybenull_z_ const char** error_message)
{
    EBPF_LOG_ENTRY();
    std::string file_name_string(file);
    std::string file_extension = file_name_string.substr(file_name_string.find_last_of(".") + 1);
    if (file_extension == "dll" || file_extension == "sys") {
        // Verbose is currently unused.
        EBPF_RETURN_RESULT(_ebpf_enumerate_native_sections(file, nullptr, nullptr, infos, error_message));
    } else {
        EBPF_RETURN_RESULT(
            ebpf_api_elf_enumerate_sections(file, nullptr, verbose, infos, error_message) ? EBPF_FAILED : EBPF_SUCCESS);
    }
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
    EBPF_LOG_ENTRY();
    ebpf_assert(path);
    ebpf_assert(object);
    ebpf_assert(error_message);
    *error_message = nullptr;

    ebpf_object_t* new_object = new (std::nothrow) ebpf_object_t();
    if (new_object == nullptr) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    set_global_program_and_attach_type(program_type, attach_type);

    ebpf_result_t result =
        _initialize_ebpf_object_from_file(path, object_name, pin_root_path, new_object, error_message);
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
    EBPF_RETURN_RESULT(result);
}

static inline bool
_ebpf_is_map_in_map(ebpf_map_t* map) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map);
    if (map->map_definition.type == BPF_MAP_TYPE_HASH_OF_MAPS ||
        map->map_definition.type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        EBPF_RETURN_BOOL(true);
    }

    EBPF_RETURN_BOOL(false);
}

ebpf_result_t
ebpf_object_set_execution_type(_In_ struct bpf_object* object, ebpf_execution_type_t execution_type)
{
    if (Platform::_is_native_program(object->file_name)) {
        if (execution_type == EBPF_EXECUTION_INTERPRET || execution_type == EBPF_EXECUTION_JIT) {
            return EBPF_INVALID_ARGUMENT;
        }

        object->execution_type = EBPF_EXECUTION_NATIVE;
    } else {
        if (execution_type == EBPF_EXECUTION_NATIVE) {
            return EBPF_INVALID_ARGUMENT;
        }

        // Set the default execution type to JIT if execution_type is EBPF_EXECUTION_ANY.
        // This will eventually be decided by a system-wide policy.
        // TODO(Issue #288): Configure system-wide execution type.
        object->execution_type = (execution_type == EBPF_EXECUTION_ANY) ? EBPF_EXECUTION_JIT : execution_type;
    }
    return EBPF_SUCCESS;
}

ebpf_execution_type_t
ebpf_object_get_execution_type(_In_ struct bpf_object* object)
{
    return object->execution_type;
}

static ebpf_result_t
_ebpf_validate_map(_In_ ebpf_map_t* map, fd_t original_map_fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(map);
    // Validate that the existing map definition matches with this new map.
    struct bpf_map_info info = {0};
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
        ebpf_assert(inner_map);

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
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_object_reuse_map(_In_ ebpf_map_t* map) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;

    ebpf_assert(map);

    // Check if a map is already present with this pin path.
    fd_t map_fd = ebpf_object_get(map->pin_path);
    if (map_fd == ebpf_fd_invalid) {
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
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
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_object_create_maps(_Inout_ ebpf_object_t* object) noexcept(false)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(object);

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
    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_program_load_bytes(
    _In_ const ebpf_program_type_t* program_type,
    _In_opt_z_ const char* program_name,
    ebpf_execution_type_t execution_type,
    _In_reads_(instruction_count) const ebpf_inst* instructions,
    uint32_t instruction_count,
    _Out_writes_opt_(log_buffer_size) char* log_buffer,
    size_t log_buffer_size,
    _Out_ fd_t* program_fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(program_type);
    ebpf_assert(instructions);
    ebpf_assert(program_fd);
    ebpf_assert(log_buffer || !log_buffer_size);

    if ((log_buffer != nullptr) != (log_buffer_size > 0)) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    char unique_name[80];
    if (program_name == nullptr) {
        // Create a unique object/section/program name.
        srand(static_cast<unsigned int>(time(nullptr)));
        sprintf_s(unique_name, sizeof(unique_name), "raw#%u", rand());
        program_name = unique_name;
    }

    ebpf_handle_t program_handle;
    ebpf_result_t result = _create_program(*program_type, program_name, program_name, program_name, &program_handle);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }

    // Populate load_info.
    ebpf_program_load_info load_info = {0};
    load_info.object_name = const_cast<char*>(program_name);
    load_info.section_name = const_cast<char*>(program_name);
    load_info.program_name = const_cast<char*>(program_name);
    load_info.program_type = *program_type;
    load_info.program_handle = reinterpret_cast<file_handle_t>(program_handle);
    load_info.execution_type = execution_type;
    load_info.instructions = (ebpf_instruction_t*)instructions;
    load_info.instruction_count = instruction_count;
    load_info.execution_context = execution_context_kernel_mode;

    // Resolve map handles in byte code.
    std::vector<original_fd_handle_map_t> handle_map;
    for (size_t index = 0; index < instruction_count; index++) {
        const ebpf_inst& first_instruction = instructions[index];
        if (first_instruction.opcode != INST_OP_LDDW_IMM) {
            continue;
        }
        if (index + 1 >= instruction_count) {
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

    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_object_load_programs(_Inout_ struct bpf_object* object) noexcept(false)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(object);
    ebpf_result_t result = EBPF_SUCCESS;
    std::vector<original_fd_handle_map_t> handle_map;

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
        load_info.execution_type = object->execution_type;
        load_info.instructions = reinterpret_cast<ebpf_instruction_t*>(program->instructions);
        load_info.instruction_count = program->instruction_count;
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

        result = ebpf_rpc_load_program(&load_info, &program->log_buffer, &program->log_buffer_size);
        if (result != EBPF_SUCCESS) {
            break;
        }
    }

    if (result == EBPF_SUCCESS) {
        for (auto& program : object->programs) {
            _ebpf_programs.insert(std::pair<ebpf_handle_t, ebpf_program_t*>(program->handle, program));
        }
    }
    EBPF_RETURN_RESULT(result);
}

// This logic is intended to be similar to libbpf's bpf_object__load_xattr().
ebpf_result_t
ebpf_object_load(_Inout_ struct bpf_object* object) noexcept
{
    ebpf_result_t result;
    EBPF_LOG_ENTRY();
    ebpf_assert(object);
    if (object->loaded) {
        EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
    }

    if (Platform::_is_native_program(object->file_name)) {
        struct bpf_program* program = bpf_object__next_program(object, nullptr);
        if (program == nullptr) {
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }
        fd_t program_fd;
        return _ebpf_program_load_native(
            object->file_name,
            &program->program_type,
            &program->attach_type,
            object->execution_type,
            object,
            &program_fd);
    }

    try {
        result = _ebpf_object_create_maps(object);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        result = _ebpf_object_load_programs(object);
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
    EBPF_RETURN_RESULT(result);
}

// This function is intended to work like libbpf's bpf_object__unload().
ebpf_result_t
ebpf_object_unload(_In_ struct bpf_object* object) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(object);

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

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

// This function is intended to work like libbpf's bpf_program__unload().
ebpf_result_t
ebpf_program_unload(_In_ struct bpf_program* program) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(program);

    if (program->fd != ebpf_fd_invalid) {
        Platform::_close(program->fd);
        program->fd = ebpf_fd_invalid;
    }
    if (program->handle != ebpf_handle_invalid) {
        _ebpf_programs.erase(program->handle);
        program->handle = ebpf_handle_invalid;
    }
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

/**
 * @brief Load native module for the specified driver service.
 *
 * @param[in] service_path Path to the driver service.
 * @param[in] module_id Module ID corresponding to the native module.
 * @param[out] count_of_maps Count of maps present in the native module.
 * @param[out] count_of_programs Count of programs present in the native module.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 *  operation.
 * @retval EBPF_OBJECT_NOT_FOUND Native module for that module ID not found.
 * @retval EBPF_OBJECT_ALREADY_EXISTS Native module for this module ID is already
 *  initialized.
 */
static ebpf_result_t
_load_native_module(
    _In_ const std::wstring& service_path,
    _In_ const GUID* module_id,
    _Out_ size_t* count_of_maps,
    _Out_ size_t* count_of_programs) noexcept(false)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(module_id);
    ebpf_assert(count_of_maps);
    ebpf_assert(count_of_programs);

    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t error = ERROR_SUCCESS;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_load_native_module_request_t* request;
    ebpf_operation_load_native_module_reply_t reply;
    size_t service_path_size = service_path.size() * 2;

    *count_of_maps = 0;
    *count_of_programs = 0;

    size_t buffer_size = offsetof(ebpf_operation_load_native_module_request_t, data) + service_path_size;
    request_buffer.resize(buffer_size);

    request = reinterpret_cast<ebpf_operation_load_native_module_request_t*>(request_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_NATIVE_MODULE;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->module_id = *module_id;
    memcpy(
        request_buffer.data() + offsetof(ebpf_operation_load_native_module_request_t, data),
        (char*)service_path.c_str(),
        service_path_size);

    error = invoke_ioctl(request_buffer, reply);
    if (error != ERROR_SUCCESS) {
        result = win32_error_code_to_ebpf_result(error);
        EBPF_LOG_WIN32_WSTRING_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, service_path.c_str(), invoke_ioctl);
        goto Done;
    }

    ebpf_assert(reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_LOAD_NATIVE_MODULE);
    *count_of_maps = reply.count_of_maps;
    *count_of_programs = reply.count_of_programs;

Done:
    EBPF_RETURN_RESULT(result);
}

/**
 * @brief Create maps and load programs from a loaded native module.
 *
 * @param[in] module_id Module ID corresponding to the native module.
 * @param[in] program_type Optionally, the program type to use when loading
 *  the eBPF program. If program type is not supplied, it is derived from
 *  the section prefix in the ELF file.
 * @param[in] count_of_maps Count of maps present in the native module.
 * @param[out] map_handles Array of size count_of_maps which contains the map handles.
 * @param[in] count_of_programs Count of programs present in the native module.
 * @param[out] program_handles Array of size count_of_programs which contains the program handles.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate resources for this
 *  operation.
 * @retval EBPF_OBJECT_NOT_FOUND No native module exists with that module ID.
 * @retval EBPF_OBJECT_ALREADY_EXISTS Native module for this module ID is already
 *  loaded.
 * @retval EBPF_ARITHMETIC_OVERFLOW An arithmetic overflow has occurred.
 */
static ebpf_result_t
_load_native_programs(
    _In_ const GUID* module_id,
    _In_opt_ const ebpf_program_type_t* program_type,
    size_t count_of_maps,
    _Out_writes_(count_of_maps) ebpf_handle_t* map_handles,
    size_t count_of_programs,
    _Out_writes_(count_of_programs) ebpf_handle_t* program_handles) noexcept(false)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(module_id);
    ebpf_assert(map_handles);
    ebpf_assert(program_handles);

    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t error = ERROR_SUCCESS;
    ebpf_protocol_buffer_t reply_buffer;
    ebpf_operation_load_native_programs_request_t request;
    ebpf_operation_load_native_programs_reply_t* reply;
    size_t map_handles_size = count_of_maps * sizeof(ebpf_handle_t);
    size_t program_handles_size = count_of_programs * sizeof(ebpf_handle_t);
    size_t handles_size = map_handles_size + program_handles_size;

    size_t buffer_size = offsetof(ebpf_operation_load_native_programs_reply_t, data) + handles_size;
    reply_buffer.resize(buffer_size);

    reply = reinterpret_cast<ebpf_operation_load_native_programs_reply_t*>(reply_buffer.data());
    request.header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_NATIVE_PROGRAMS;
    request.header.length = sizeof(ebpf_operation_load_native_programs_request_t);
    request.module_id = *module_id;
    request.program_type = program_type ? *program_type : GUID_NULL;

    error = invoke_ioctl(request, reply_buffer);
    if (error != ERROR_SUCCESS) {
        result = win32_error_code_to_ebpf_result(error);
        EBPF_LOG_WIN32_GUID_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, *module_id, invoke_ioctl);
        goto Done;
    }

    ebpf_assert(reply->header.id == ebpf_operation_id_t::EBPF_OPERATION_LOAD_NATIVE_PROGRAMS);
    if (reply->map_handle_count != count_of_maps || reply->program_handle_count != count_of_programs) {
        result = EBPF_FAILED;
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_API,
            "_load_native_programs: Program or map count does not match the expected count");
        goto Done;
    }

    memcpy(map_handles, reply->data, map_handles_size);
    memcpy(program_handles, reply->data + map_handles_size, program_handles_size);

Done:
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_program_load_native(
    _In_z_ const char* file_name,
    _In_opt_ const ebpf_program_type_t* program_type,
    _In_opt_ const ebpf_attach_type_t* attach_type,
    ebpf_execution_type_t execution_type,
    _Inout_ struct bpf_object* object,
    _Out_ fd_t* program_fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(file_name);
    ebpf_assert(object);
    ebpf_assert(program_fd);

    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t error;
    GUID service_name_guid;
    GUID provider_module_id;
    std::wstring service_name;
    std::string file_name_string(file_name);
    SC_HANDLE service_handle = nullptr;
    SERVICE_STATUS status = {0};
    std::wstring service_path(SERVICE_PATH_PREFIX);
    std::wstring paramaters_path(PARAMETERS_PATH_PREFIX);
    ebpf_protocol_buffer_t request_buffer;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    ebpf_handle_t* map_handles = nullptr;
    ebpf_handle_t* program_handles = nullptr;

    UNREFERENCED_PARAMETER(attach_type);
    UNREFERENCED_PARAMETER(execution_type);

    if (UuidCreate(&service_name_guid) != RPC_S_OK) {
        EBPF_RETURN_RESULT(EBPF_OPERATION_NOT_SUPPORTED);
    }
    if (UuidCreate(&provider_module_id) != RPC_S_OK) {
        EBPF_RETURN_RESULT(EBPF_OPERATION_NOT_SUPPORTED);
    }

    EBPF_LOG_MESSAGE_GUID_GUID_STRING(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_API,
        "_ebpf_program_load_native",
        file_name,
        service_name_guid,
        provider_module_id);

    try {
        // Create a driver service with a random name.
        service_name = guid_to_wide_string(&service_name_guid);

        error = Platform::_create_service(
            service_name.c_str(), _get_wstring_from_string(file_name_string).c_str(), &service_handle);
        if (error != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(error);
            EBPF_LOG_WIN32_STRING_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, file_name, _create_service);
            goto Done;
        }

        // Create registry path and update module ID in the service path.
        paramaters_path = paramaters_path + service_name.c_str() + L"\\" + SERVICE_PARAMETERS;
        error = _ebpf_create_registry_key(HKEY_LOCAL_MACHINE, paramaters_path.c_str());
        if (error != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(error);
            EBPF_LOG_WIN32_STRING_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, file_name, _ebpf_create_registry_key);
            goto Done;
        }
        error = _ebpf_update_registry_value(
            HKEY_LOCAL_MACHINE, paramaters_path.c_str(), REG_BINARY, NPI_MODULE_ID, &provider_module_id, sizeof(GUID));
        if (error != ERROR_SUCCESS) {
            result = win32_error_code_to_ebpf_result(error);
            EBPF_LOG_WIN32_STRING_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, file_name, _ebpf_update_registry_value);
            goto Done;
        }

        service_path = service_path + service_name.c_str();
        result = _load_native_module(service_path, &provider_module_id, &count_of_maps, &count_of_programs);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        if (count_of_programs == 0) {
            result = EBPF_INVALID_OBJECT;
            EBPF_LOG_MESSAGE_STRING(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_API,
                "_ebpf_program_load_native: O programs found",
                file_name);
            goto Done;
        }

        // Allocate buffer for program and map handles.
        program_handles = (ebpf_handle_t*)calloc(count_of_programs, sizeof(ebpf_handle_t));
        if (program_handles == nullptr) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }

        if (count_of_maps > 0) {
            map_handles = (ebpf_handle_t*)calloc(count_of_maps, sizeof(ebpf_handle_t));
            if (map_handles == nullptr) {
                result = EBPF_NO_MEMORY;
                goto Done;
            }
        }

        result = _load_native_programs(
            &provider_module_id, program_type, count_of_maps, map_handles, count_of_programs, program_handles);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        result =
            _initialize_ebpf_object_native(count_of_maps, map_handles, count_of_programs, program_handles, *object);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        *program_fd = object->programs[0]->fd;
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Done;
    } catch (...) {
        result = EBPF_FAILED;
        goto Done;
    }

Done:
    if (result != EBPF_SUCCESS) {
        if (map_handles != nullptr) {
            for (int i = 0; i < count_of_maps; i++) {
                if (map_handles[i] != ebpf_handle_invalid && map_handles[i] != 0) {
                    Platform::CloseHandle(map_handles[i]);
                }
            }
        }

#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory '*program_handles'
        if (program_handles != nullptr) {
            for (int i = 0; i < count_of_programs; i++) {
                if (program_handles[i] != ebpf_handle_invalid && program_handles[i] != 0) {
                    Platform::CloseHandle(program_handles[i]);
                }
            }
        }
#pragma warning(pop)

        Platform::_stop_service(service_handle);
    }
    free(map_handles);
    free(program_handles);

    // Workaround: Querying service status hydrates service reference count in SCM.
    // This ensures that when _delete_service() is called, the service is marked
    // pending for delete, and a later call to ZwUnloadDriver() by ebpfcore does not
    // fail. One side effect of this approach still is that the stale service entries
    // in the registry will not be cleaned up till the next reboot.
    Platform::_query_service_status(service_handle, &status);
    EBPF_LOG_MESSAGE_WSTRING(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_API,
        "_ebpf_program_load_native: Deleting service",
        service_name.c_str());
    Platform::_delete_service(service_handle);
    EBPF_RETURN_RESULT(result);
}

_Ret_maybenull_ struct bpf_object*
ebpf_object_next(_In_opt_ const struct bpf_object* previous) noexcept
{
    EBPF_LOG_ENTRY();
    if (previous == nullptr) {
        // Return first object.
        EBPF_RETURN_POINTER(struct bpf_object*, (!_ebpf_objects.empty()) ? _ebpf_objects[0] : nullptr);
    }
    auto it = std::find(_ebpf_objects.begin(), _ebpf_objects.end(), previous);
    if (it == _ebpf_objects.end()) {
        // Previous object not found.
        EBPF_RETURN_POINTER(struct bpf_object*, nullptr);
    }
    it++;
    if (it == _ebpf_objects.end()) {
        // No more objects.
        EBPF_RETURN_POINTER(struct bpf_object*, nullptr);
    }
    EBPF_RETURN_POINTER(struct bpf_object*, *it);
}

_Ret_maybenull_ struct bpf_program*
ebpf_program_next(_In_opt_ const struct bpf_program* previous, _In_ const struct bpf_object* object) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_program_t* program = nullptr;
    ebpf_assert(object);
    if (previous != nullptr && previous->object != object) {
        goto Exit;
    }
    if (previous == nullptr) {
        program = (object->programs.size() > 0) ? object->programs[0] : nullptr;
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
    EBPF_RETURN_POINTER(bpf_program*, program);
}

_Ret_maybenull_ struct bpf_program*
ebpf_program_previous(_In_opt_ const struct bpf_program* next, _In_ const struct bpf_object* object) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_program_t* program = nullptr;
    ebpf_assert(object);
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
    EBPF_RETURN_POINTER(bpf_program*, program);
}

_Ret_maybenull_ struct bpf_map*
ebpf_map_next(_In_opt_ const struct bpf_map* previous, _In_ const struct bpf_object* object) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_map_t* map = nullptr;
    ebpf_assert(object);
    if (previous != nullptr && previous->object != object) {
        goto Exit;
    }
    if (previous == nullptr) {
        map = (object->maps.size() > 0) ? object->maps[0] : nullptr;
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
    EBPF_RETURN_POINTER(bpf_map*, map);
}

_Ret_maybenull_ struct bpf_map*
ebpf_map_previous(_In_opt_ const struct bpf_map* next, _In_ const struct bpf_object* object) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_map_t* map = nullptr;
    ebpf_assert(object);
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
    EBPF_RETURN_POINTER(bpf_map*, map);
}

fd_t
ebpf_program_get_fd(_In_ const struct bpf_program* program) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(program);
    EBPF_RETURN_FD(program->fd);
}

void
ebpf_object_close(_In_opt_ _Post_invalid_ struct bpf_object* object) noexcept
{
    EBPF_LOG_ENTRY();
    if (object == nullptr) {
        EBPF_RETURN_VOID();
    }

    _remove_ebpf_object_from_globals(object);
    _delete_ebpf_object(object);
    EBPF_RETURN_VOID();
}

static ebpf_result_t
_get_fd_by_id(ebpf_operation_id_t operation, ebpf_id_t id, _Out_ int* fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(fd);
    _ebpf_operation_get_handle_by_id_request request{sizeof(request), operation, id};
    _ebpf_operation_get_handle_by_id_reply reply;

    uint32_t error = invoke_ioctl(request, reply);
    ebpf_result_t result = win32_error_code_to_ebpf_result(error);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }
    ebpf_assert(reply.header.id == operation);

    *fd = _create_file_descriptor_for_handle((ebpf_handle_t)reply.handle);
    EBPF_RETURN_RESULT((*fd == ebpf_fd_invalid) ? EBPF_NO_MEMORY : EBPF_SUCCESS);
}

ebpf_result_t
ebpf_get_map_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(fd);
    EBPF_RETURN_RESULT(_get_fd_by_id(ebpf_operation_id_t::EBPF_OPERATION_GET_MAP_HANDLE_BY_ID, id, fd));
}

ebpf_result_t
ebpf_get_program_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(fd);
    EBPF_RETURN_RESULT(_get_fd_by_id(ebpf_operation_id_t::EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID, id, fd));
}

ebpf_result_t
ebpf_get_link_fd_by_id(ebpf_id_t id, _Out_ int* fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(fd);
    EBPF_RETURN_RESULT(_get_fd_by_id(ebpf_operation_id_t::EBPF_OPERATION_GET_LINK_HANDLE_BY_ID, id, fd));
}

ebpf_result_t
ebpf_get_next_pinned_program_path(
    _In_z_ const char* start_path, _Out_writes_z_(EBPF_MAX_PIN_PATH_LENGTH) char* next_path)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(start_path);
    ebpf_assert(next_path);

    size_t start_path_length = strlen(start_path);

    ebpf_protocol_buffer_t request_buffer(
        EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_program_path_request_t, start_path) + start_path_length);
    ebpf_protocol_buffer_t reply_buffer(
        EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_program_path_reply_t, next_path) + EBPF_MAX_PIN_PATH_LENGTH - 1);
    ebpf_operation_get_next_pinned_program_path_request_t* request =
        reinterpret_cast<ebpf_operation_get_next_pinned_program_path_request_t*>(request_buffer.data());
    ebpf_operation_get_next_pinned_program_path_reply_t* reply =
        reinterpret_cast<ebpf_operation_get_next_pinned_program_path_reply_t*>(reply_buffer.data());

    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    reply->header.length = static_cast<uint16_t>(reply_buffer.size());

    memcpy(request->start_path, start_path, start_path_length);

    uint32_t error = invoke_ioctl(request_buffer, reply_buffer);
    ebpf_result_t result = win32_error_code_to_ebpf_result(error);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }
    ebpf_assert(reply->header.id == ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH);
    size_t next_path_length =
        reply->header.length - EBPF_OFFSET_OF(ebpf_operation_get_next_pinned_program_path_reply_t, next_path);
    memcpy(next_path, reply->next_path, next_path_length);

    next_path[next_path_length] = '\0';

    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

static ebpf_result_t
_get_next_id(ebpf_operation_id_t operation, ebpf_id_t start_id, _Out_ ebpf_id_t* next_id) noexcept
{
    EBPF_LOG_ENTRY();
    _ebpf_operation_get_next_id_request request{sizeof(request), operation, start_id};
    _ebpf_operation_get_next_id_reply reply;

    ebpf_assert(next_id);

    uint32_t error = invoke_ioctl(request, reply);
    ebpf_result_t result = win32_error_code_to_ebpf_result(error);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }
    ebpf_assert(reply.header.id == operation);
    *next_id = reply.next_id;
    EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

ebpf_result_t
ebpf_get_next_link_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(next_id);
    EBPF_RETURN_RESULT(_get_next_id(ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_LINK_ID, start_id, next_id));
}

ebpf_result_t
ebpf_get_next_map_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(next_id);
    EBPF_RETURN_RESULT(_get_next_id(ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_MAP_ID, start_id, next_id));
}

ebpf_result_t
ebpf_get_next_program_id(ebpf_id_t start_id, _Out_ ebpf_id_t* next_id) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(next_id);
    EBPF_RETURN_RESULT(_get_next_id(ebpf_operation_id_t::EBPF_OPERATION_GET_NEXT_PROGRAM_ID, start_id, next_id));
}

ebpf_result_t
ebpf_object_get_info_by_fd(
    fd_t bpf_fd, _Inout_updates_bytes_to_(*info_size, *info_size) void* info, _Inout_ uint32_t* info_size) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(info);
    ebpf_assert(info_size);

    ebpf_handle_t handle = _get_handle_from_file_descriptor(bpf_fd);
    if (handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    EBPF_RETURN_RESULT(ebpf_object_get_info(handle, info, info_size));
}

ebpf_result_t
ebpf_get_program_type_by_name(
    _In_z_ const char* name, _Out_ ebpf_program_type_t* program_type, _Out_ ebpf_attach_type_t* expected_attach_type)
{
    ebpf_result_t result = EBPF_SUCCESS;
    EBPF_LOG_ENTRY();
    ebpf_assert(name);
    ebpf_assert(program_type);
    ebpf_assert(expected_attach_type);

    result = get_program_and_attach_type(name, program_type, expected_attach_type);

    EBPF_RETURN_RESULT(result);
}

ebpf_result_t
ebpf_get_program_info_from_verifier(_Outptr_ const ebpf_program_info_t** program_info)
{
    ebpf_result_t result = EBPF_SUCCESS;
    EBPF_LOG_ENTRY();

    result = get_program_type_info(program_info);

    EBPF_RETURN_RESULT(result);
}

_Ret_maybenull_ const ebpf_program_type_t*
ebpf_get_ebpf_program_type(bpf_prog_type_t bpf_program_type) noexcept
{
    if (bpf_program_type == BPF_PROG_TYPE_UNSPEC) {
        return &EBPF_PROGRAM_TYPE_UNSPECIFIED;
    }

    return get_ebpf_program_type(bpf_program_type);
}

_Ret_maybenull_z_ const char*
ebpf_get_program_type_name(_In_ const ebpf_program_type_t* program_type)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(program_type);

    try {
        const EbpfProgramType& type = get_program_type_windows(*program_type);
        EBPF_RETURN_POINTER(const char*, type.name.c_str());
    } catch (...) {
        return nullptr;
    }
}

_Ret_maybenull_z_ const char*
ebpf_get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type)
{
    EBPF_LOG_ENTRY();
    ebpf_assert(attach_type);
    EBPF_RETURN_POINTER(const char*, get_attach_type_name(attach_type));
}

ebpf_result_t
ebpf_program_bind_map(fd_t program_fd, fd_t map_fd) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_handle_t program_handle = _get_handle_from_file_descriptor(program_fd);
    if (program_handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    ebpf_handle_t map_handle = _get_handle_from_file_descriptor(map_fd);
    if (map_handle == ebpf_handle_invalid) {
        EBPF_RETURN_RESULT(EBPF_INVALID_FD);
    }

    ebpf_operation_bind_map_request_t request;
    request.header.id = ebpf_operation_id_t::EBPF_OPERATION_BIND_MAP;
    request.header.length = sizeof(request);
    request.program_handle = program_handle;
    request.map_handle = map_handle;

    EBPF_RETURN_RESULT(win32_error_code_to_ebpf_result(invoke_ioctl(request)));
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
_ebpf_ring_buffer_map_async_query_completion(_Inout_ void* completion_context) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(completion_context);

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
            TraceLoggingWrite(
                ebpf_tracelog_provider,
                EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,
                TraceLoggingLevel(WINEVENT_LEVEL_INFO),
                TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_API),
                TraceLoggingString(__FUNCTION__, "ring_buffer map async query completion invoked with EBPF_CANCELED."));

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
                ebpf_operation_id_t::EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY,
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
    _Outptr_ ring_buffer_subscription_t** subscription) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(sample_callback);
    ebpf_assert(subscription);
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
        EBPF_RETURN_RESULT(result);
    }

    // Get user-mode address to ring buffer shared data.
    ebpf_operation_ring_buffer_map_query_buffer_request_t query_buffer_request{
        sizeof(query_buffer_request),
        ebpf_operation_id_t::EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER,
        local_subscription->ring_buffer_map_handle};
    ebpf_operation_ring_buffer_map_query_buffer_reply_t query_buffer_reply{};
    result = win32_error_code_to_ebpf_result(invoke_ioctl(query_buffer_request, query_buffer_reply));
    if (result != EBPF_SUCCESS)
        EBPF_RETURN_RESULT(result);
    ebpf_assert(query_buffer_reply.header.id == ebpf_operation_id_t::EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER);
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
        ebpf_operation_id_t::EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY,
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
ebpf_ring_buffer_map_unsubscribe(_Inout_ _Post_invalid_ ring_buffer_subscription_t* subscription) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_assert(subscription);
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

            TraceLoggingWrite(
                ebpf_tracelog_provider,
                EBPF_TRACELOG_EVENT_GENERIC_MESSAGE,
                TraceLoggingLevel(WINEVENT_LEVEL_INFO),
                TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_API),
                TraceLoggingString(__FUNCTION__, "Attempt to cancel async query on ring_buffer map."));

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

/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include "pch.h"
#include "platform.h"
#define EBPF_API
extern "C"
{
#include "api.h"
#include "ubpf.h"
}

#include "protocol.h"
#include "unwind_helper.h"
#include "Verifier.h"

#include <stdexcept>

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

// Device type 
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPFCTL_METHOD_BUFFERED \
    CTL_CODE( EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )

static HANDLE device_handle = INVALID_HANDLE_VALUE;

template <typename request_t, typename reply_t>
static DWORD invoke_ioctl(HANDLE handle, request_t request, reply_t reply)
{
    DWORD actual_reply_size;
    DWORD request_size;
    void* request_ptr;
    DWORD reply_size;
    void* reply_ptr;

    if constexpr (std::is_same<request_t, nullptr_t>::value) {
        request_size = 0;
        request_ptr = nullptr;
    }
    else if constexpr (std::is_same< request_t, std::vector<uint8_t>>::value)
    {
        request_size = static_cast<DWORD>(request.size());
        request_ptr = request.data();
    }
    else
    {
        request_size = sizeof(*request);
        request_ptr = request;
    }

    if constexpr (std::is_same<reply_t, nullptr_t>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    }
    else if constexpr (std::is_same< reply_t, std::vector<uint8_t>>::value)
    {
        reply_size = reply.size();
        reply_ptr = reply.data();
    }
    else
    {
        reply_size = sizeof(*reply);
        reply_ptr = reply;
    }

    auto result = Platform::DeviceIoControl(
        handle,
        (DWORD)IOCTL_EBPFCTL_METHOD_BUFFERED,
        request_ptr,
        request_size,
        reply_ptr,
        reply_size,
        &actual_reply_size,
        nullptr);

    if (!result) 
    {
        return GetLastError();
    }

    if (actual_reply_size != reply_size)
    {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

DLL DWORD ebpf_api_initiate()
{
    LPCWSTR ebpfDeviceName = L"\\\\.\\EbpfIoDevice";

    if (device_handle != INVALID_HANDLE_VALUE)
    {
        return ERROR_ALREADY_INITIALIZED;
    }

    device_handle = Platform::CreateFile(ebpfDeviceName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (device_handle == INVALID_HANDLE_VALUE)
    {
        return GetLastError();
    }

    return 0;
}

DLL void ebpf_api_terminate()
{
    if (device_handle != INVALID_HANDLE_VALUE)
    {
        Platform::CloseHandle(device_handle);
        device_handle = INVALID_HANDLE_VALUE;
    }
}

typedef struct _map_cache {
    uintptr_t handle;
    EbpfMapDescriptor ebpf_map_descriptor;
} map_cache_t;

// TODO: this duplicates global_program_info.map_descriptors in ebpfverifier.lib
// https://github.com/vbpf/ebpf-verifier/issues/113 tracks getting rid of global
// state in that lib, but won't notice this global state which has the same problem.
std::vector<map_cache_t> _map_file_descriptors;

int create_map_function(uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options)
{
    _ebpf_operation_create_map_request request{
        sizeof(_ebpf_operation_create_map_request),
        ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP,
        {
            sizeof(struct _ebpf_map_definition),
            type,
            key_size,
            value_size,
            max_entries
        }
    };

    _ebpf_operation_create_map_reply reply{};

    DWORD retval = invoke_ioctl(device_handle, &request, &reply);
    if (retval != ERROR_SUCCESS)
    {
        throw std::runtime_error(std::string("Error ") + std::to_string(retval) + " trying to create map");
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP)
    {
        throw std::runtime_error(std::string("reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP"));
    }

    // TODO: Replace this with the CRT helper to create FD from handle once we have real handles.
    int fd = static_cast<int>(_map_file_descriptors.size() + 1);
    _map_file_descriptors.push_back({ reply.handle, {fd, type, key_size, value_size, 0} });
    return static_cast<int>(_map_file_descriptors.size());
}

static map_cache_t& get_map_cache_entry(uint64_t map_fd)
{
    return _map_file_descriptors[map_fd - 1];
}

EbpfMapDescriptor& get_map_descriptor_internal(int map_fd)
{
    return get_map_cache_entry(map_fd).ebpf_map_descriptor;
}

static uint64_t map_resolver(void* context, uint64_t fd)
{
    _ebpf_operation_resolve_map_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP,
        get_map_cache_entry(fd).handle };

    _ebpf_operation_resolve_map_reply reply;

    invoke_ioctl(context, &request, &reply);

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP)
    {
        return 0;
    }

    return reply.address[0];
}

static uint64_t helper_resolver(void* context, uint32_t helper)
{
        _ebpf_operation_resolve_helper_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER,
        helper };

    _ebpf_operation_resolve_map_reply reply;

    invoke_ioctl(context, &request, &reply);

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER)
    {
        return 0;
    }

    return reply.address[0];
}

DLL DWORD ebpf_api_load_program(const char* file_name, const char* section_name, HANDLE* handle, char** error_message)
{
    std::vector<uint8_t> byte_code(MAX_CODE_SIZE);
    size_t byte_code_size = byte_code.size();
    std::vector<uint8_t> machine_code(MAX_CODE_SIZE);
    size_t machine_code_size = machine_code.size();
    std::vector<uint8_t> request_buffer;
    _ebpf_operation_load_code_reply reply;
    struct ubpf_vm* vm = nullptr;
    _unwind_helper unwind([&]
        {
            if (vm)
            {
                ubpf_destroy(vm);
            }
        });

    DWORD result;

    try
    {
        _map_file_descriptors.resize(0);
        // Verify code.
        if (verify(file_name, section_name, byte_code.data(), &byte_code_size, error_message) != 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
    }
    catch (std::runtime_error & err)
    {
        auto message = err.what();
        auto message_length = strlen(message) + 1;
        *error_message = reinterpret_cast<char*>(calloc(message_length + 1, sizeof(char)));
        if (*error_message)
        {
            strcpy_s(*error_message, message_length, message);
        }
        return ERROR_INVALID_PARAMETER;
    }

    // JIT code.
    vm = ubpf_create();
    if (vm == nullptr)
    {
        return ERROR_OUTOFMEMORY;
    }
    byte_code.resize(byte_code_size);

    if (ubpf_register_map_resolver(vm, device_handle, map_resolver) < 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (ubpf_register_helper_resolver(vm, device_handle, helper_resolver) < 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (ubpf_load(vm, byte_code.data(), static_cast<uint32_t>(byte_code.size()), error_message) < 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (ubpf_translate(vm, machine_code.data(), &machine_code_size, error_message))
    {
        return ERROR_INVALID_PARAMETER;
    }
    machine_code.resize(machine_code_size);

    request_buffer.resize(machine_code.size() + sizeof(_ebpf_operation_header));
    auto header = reinterpret_cast<_ebpf_operation_header*>(request_buffer.data());
    header->id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
    header->length = static_cast<uint16_t>(request_buffer.size());
    std::copy(machine_code.begin(), machine_code.end(), request_buffer.begin() + sizeof(_ebpf_operation_header));

    result = invoke_ioctl(device_handle, request_buffer, &reply);

    if (result != ERROR_SUCCESS)
    {
        return result;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *handle = reinterpret_cast<HANDLE>(reply.handle);

    return result;
}

DLL void ebpf_api_free_error_message(char* error_message)
{
    return free(error_message);
}

DLL void ebpf_api_unload_program(HANDLE handle)
{
    CloseHandle(handle);
    return;
}

DLL DWORD ebpf_api_attach_program(HANDLE handle, ebpf_program_type_t hook_point)
{
    _ebpf_operation_attach_detach_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_ATTACH_CODE,
        reinterpret_cast<uint64_t>(handle),
        hook_point };

    return invoke_ioctl(device_handle, &request, nullptr);
}

DLL DWORD ebpf_api_detach_program(HANDLE handle, ebpf_program_type_t hook_point)
{
    _ebpf_operation_attach_detach_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_DETACH_CODE,
        reinterpret_cast<uint64_t>(handle),
        hook_point };

    return invoke_ioctl(device_handle, &request, nullptr);
}

DLL DWORD ebpf_api_map_lookup_element(HANDLE handle, DWORD key_size, unsigned char* key, DWORD value_size, unsigned char* value)
{
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_lookup_element_request) + key_size - 1);
    std::vector<uint8_t> reply_buffer(sizeof(_ebpf_operation_map_lookup_element_reply) + value_size - 1);
    auto request = reinterpret_cast<_ebpf_operation_map_lookup_element_request*>(request_buffer.data());
    auto reply = reinterpret_cast<_ebpf_operation_map_lookup_element_reply*>(reply_buffer.data());

    request->header.length = request_buffer.size();
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_LOOKUP_ELEMENT;
    std::copy(key, key + key_size, request->key);

    auto retval = invoke_ioctl(device_handle, request_buffer, reply_buffer);

    if (reply->header.id != ebpf_operation_id_t::EBPF_OPERATION_MAP_LOOKUP_ELEMENT)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (retval == ERROR_SUCCESS)
    {
        std::copy(reply->value, reply->value + value_size, value);
    }
    return retval;

}

DLL DWORD ebpf_api_map_update_element(HANDLE handle, DWORD key_size, unsigned char* key, DWORD value_size, unsigned char* value)
{
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_update_element_request) - 1 + key_size + value_size);
    auto request = reinterpret_cast<_ebpf_operation_map_update_element_request*>(request_buffer.data());

    request->header.length = request_buffer.size();
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_LOOKUP_ELEMENT;
    std::copy(key, key + key_size, request->data);
    std::copy(value, value + value_size, request->data + key_size);

    return invoke_ioctl(device_handle, request_buffer, nullptr);
}

DLL DWORD ebpf_api_map_delete_element(HANDLE handle, DWORD key_size, unsigned char* key)
{
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_delete_element_request) - 1 + key_size);
    auto request = reinterpret_cast<_ebpf_operation_map_delete_element_request*>(request_buffer.data());

    request->header.length = request_buffer.size();
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_DELETE_ELEMENT;
    std::copy(key, key + key_size, request->key);

    return invoke_ioctl(device_handle, request_buffer, nullptr);
}

DLL DWORD ebpf_api_map_enumerate(HANDLE previous_handle, HANDLE* next_handle)
{
    _ebpf_operation_enumerate_maps_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_ENUMERATE_MAPS,
        reinterpret_cast<uint64_t>(previous_handle) };

    _ebpf_operation_enumerate_maps_reply reply;

    DWORD retval = invoke_ioctl(device_handle, &request, &reply);
    if (retval == ERROR_SUCCESS)
    {
        *next_handle = reinterpret_cast<HANDLE>(reply.next_handle);
    }
    return retval;
}

DLL DWORD ebpf_api_map_query_definition(HANDLE handle, DWORD* size, DWORD* type, DWORD* key_size, DWORD* value_size, DWORD* max_entries)
{
    _ebpf_operation_query_map_definition_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_QUERY_MAP_DEFINITION,
        reinterpret_cast<uint64_t>(handle) };

    _ebpf_operation_query_map_definition_reply reply;

    DWORD retval = invoke_ioctl(device_handle, &request, &reply);
    if (retval == ERROR_SUCCESS)
    {
        *size = reply.map_definition.size;
        *type = reply.map_definition.type;
        *key_size = reply.map_definition.key_size;
        *value_size = reply.map_definition.value_size;
        *max_entries = reply.map_definition.max_entries;
    }
    return retval;
}

DLL void ebpf_api_delete_map(HANDLE handle)
{
    CloseHandle(handle);
}

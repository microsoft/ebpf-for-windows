/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include "pch.h"
#include "tlv.h"

extern "C"
{
#include "api.h"
#include "ubpf.h"
}
#include "platform.h"

#include "ebpf_protocol.h"
#include "unwind_helper.h"
#include "Verifier.h"

#include <stdexcept>

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

// Device type 
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPFCTL_METHOD_BUFFERED \
    CTL_CODE( EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )

static ebpf_handle_t device_handle = INVALID_HANDLE_VALUE;

struct empty_reply {} _empty_reply;

template <typename request_t, typename reply_t = empty_reply>
static uint32_t invoke_ioctl(ebpf_handle_t handle, request_t & request, reply_t & reply = _empty_reply)
{
    uint32_t actual_reply_size;
    uint32_t request_size;
    void* request_ptr;
    uint32_t reply_size;
    void* reply_ptr;

    if constexpr (std::is_same<request_t, nullptr_t>::value) {
        request_size = 0;
        request_ptr = nullptr;
    }
    else if constexpr (std::is_same< request_t, std::vector<uint8_t>>::value)
    {
        request_size = static_cast<uint32_t>(request.size());
        request_ptr = request.data();
    }
    else
    {
        request_size = sizeof(request);
        request_ptr = &request;
    }

    if constexpr (std::is_same<reply_t, nullptr_t>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    }
    else if constexpr (std::is_same< reply_t, std::vector<uint8_t>>::value)
    {
        reply_size = static_cast<uint32_t>(reply.size());
        reply_ptr = reply.data();
    }
    else if constexpr (std::is_same< reply_t, empty_reply >::value)
    {
        reply_size = 0;
        reply_ptr = nullptr;
    }
    else
    {
        reply_size = static_cast < uint32_t>(sizeof(reply));
        reply_ptr = &reply;
    }

    auto result = Platform::DeviceIoControl(
        handle,
        IOCTL_EBPFCTL_METHOD_BUFFERED,
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

uint32_t ebpf_api_initiate()
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

void ebpf_api_terminate()
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

int create_map_function(uint32_t type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t)
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

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
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

    invoke_ioctl(context, request, reply);

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

    invoke_ioctl(context, request, reply);

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER)
    {
        return 0;
    }

    return reply.address[0];
}

static uint32_t resolve_maps_in_byte_code(std::vector<uint8_t>& byte_code)
{
    ebpf_inst* instructions = reinterpret_cast<ebpf_inst*>(byte_code.data());
    ebpf_inst* instruction_end = reinterpret_cast<ebpf_inst*>(byte_code.data() + byte_code.size());
    for (size_t index = 0; index < byte_code.size() / sizeof(ebpf_inst); index++)
    {
        ebpf_inst& first_instruction = instructions[index];
        ebpf_inst& second_instruction = instructions[index + 1];
        if (first_instruction.opcode != INST_OP_LDDW_IMM)
        {
            continue;
        }
        if (&instructions[index + 1] >= instruction_end)
        {
            return ERROR_INVALID_PARAMETER;
        }
        index++;

        // Check for LD_MAP flag
        if (first_instruction.src != 1)
        {
            continue;
        }

        // Clear LD_MAP flag
        first_instruction.src = 0;

        // Resolve FD -> map address.
        uint64_t imm = static_cast<uint64_t>(first_instruction.imm) | (static_cast<uint64_t>(second_instruction.imm) << 32);
        uint64_t new_imm = map_resolver(device_handle, imm);
        if (new_imm == 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        first_instruction.imm = static_cast<uint32_t>(new_imm);
        second_instruction.imm = static_cast<uint32_t>(new_imm >> 32);
    }
    return ERROR_SUCCESS;
}

uint32_t ebpf_api_load_program(const char* file_name, const char* section_name, ebpf_execution_type_t execution_type, ebpf_handle_t* handle, const char** error_message)
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

    uint32_t result;

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
        char * error = reinterpret_cast<char*>(calloc(message_length + 1, sizeof(char)));
        if (error)
        {
            strcpy_s(error, message_length, message);
        }
        *error_message = error;
        return ERROR_INVALID_PARAMETER;
    }

    byte_code.resize(byte_code_size);
    result = resolve_maps_in_byte_code(byte_code);
    if (result != ERROR_SUCCESS)
    {
        return result;
    }

    if (execution_type == EBPF_EXECUTION_JIT)
    {
        // JIT code.
        vm = ubpf_create();
        if (vm == nullptr)
        {
            return ERROR_OUTOFMEMORY;
        }

        if (ubpf_register_helper_resolver(vm, device_handle, helper_resolver) < 0)
        {
            return ERROR_INVALID_PARAMETER;
        }

        if (ubpf_load(vm, byte_code.data(), static_cast<uint32_t>(byte_code.size()), const_cast<char**>(error_message)) < 0)
        {
            return ERROR_INVALID_PARAMETER;
        }

        if (ubpf_translate(vm, machine_code.data(), &machine_code_size, const_cast<char**>(error_message)))
        {
            return ERROR_INVALID_PARAMETER;
        }
        machine_code.resize(machine_code_size);

        request_buffer.resize(machine_code.size() + offsetof(ebpf_operation_load_code_request_t, code));
        auto request = reinterpret_cast<ebpf_operation_load_code_request_t*>(request_buffer.data());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->code_type = EBPF_CODE_NATIVE;
        std::copy(machine_code.begin(), machine_code.end(), request_buffer.begin() + offsetof(ebpf_operation_load_code_request_t, code));
    }
    else
    {
        request_buffer.resize(byte_code.size() + offsetof(ebpf_operation_load_code_request_t, code));
        auto request = reinterpret_cast<ebpf_operation_load_code_request_t*>(request_buffer.data());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->code_type = EBPF_CODE_EBPF;
        std::copy(byte_code.begin(), byte_code.end(), request_buffer.begin() + offsetof(ebpf_operation_load_code_request_t, code));
    }

    result = invoke_ioctl(device_handle, request_buffer, reply);

    if (result != ERROR_SUCCESS)
    {
        return result;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *handle = reinterpret_cast<ebpf_handle_t>(reply.handle);

    return result;
}

void ebpf_api_free_error_message(const char* error_message)
{
    return free(const_cast<char*>(error_message));
}

void ebpf_api_unload_program(ebpf_handle_t handle)
{
    CloseHandle(handle);
    return;
}

uint32_t ebpf_api_attach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point)
{
    _ebpf_operation_attach_detach_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_ATTACH_CODE,
        reinterpret_cast<uint64_t>(handle),
        hook_point };

    return invoke_ioctl(device_handle, request);
}

uint32_t ebpf_api_detach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point)
{
    _ebpf_operation_attach_detach_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_DETACH_CODE,
        reinterpret_cast<uint64_t>(handle),
        hook_point };

    return invoke_ioctl(device_handle, request);
}

uint32_t ebpf_api_map_lookup_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, uint8_t* value)
{
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_lookup_element_request) + key_size - 1);
    std::vector<uint8_t> reply_buffer(sizeof(_ebpf_operation_map_lookup_element_reply) + value_size - 1);
    auto request = reinterpret_cast<_ebpf_operation_map_lookup_element_request*>(request_buffer.data());
    auto reply = reinterpret_cast<_ebpf_operation_map_lookup_element_reply*>(reply_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_LOOKUP_ELEMENT;
    request->handle = reinterpret_cast<uint64_t>(handle);
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

uint32_t ebpf_api_map_update_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, const uint8_t* value)
{
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_update_element_request) - 1 + key_size + value_size);
    auto request = reinterpret_cast<_ebpf_operation_map_update_element_request*>(request_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
    request->handle = (uint64_t)handle;
    std::copy(key, key + key_size, request->data);
    std::copy(value, value + value_size, request->data + key_size);

    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t ebpf_api_map_delete_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key)
{
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_delete_element_request) - 1 + key_size);
    auto request = reinterpret_cast<_ebpf_operation_map_delete_element_request*>(request_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_DELETE_ELEMENT;
    request->handle = (uint64_t)handle;
    std::copy(key, key + key_size, request->key);

    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t ebpf_api_map_enumerate(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle)
{
    _ebpf_operation_enumerate_maps_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_ENUMERATE_MAPS,
        reinterpret_cast<uint64_t>(previous_handle) };

    _ebpf_operation_enumerate_maps_reply reply;

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
    if (retval == ERROR_SUCCESS)
    {
        *next_handle = reinterpret_cast<ebpf_handle_t>(reply.next_handle);
    }
    return retval;
}

uint32_t ebpf_api_map_query_definition(ebpf_handle_t handle, uint32_t* size, uint32_t* type, uint32_t* key_size, uint32_t* value_size, uint32_t* max_entries)
{
    _ebpf_operation_query_map_definition_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_QUERY_MAP_DEFINITION,
        reinterpret_cast<uint64_t>(handle) };

    _ebpf_operation_query_map_definition_reply reply;

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
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

void ebpf_api_delete_map(ebpf_handle_t handle)
{
    CloseHandle(handle);
}

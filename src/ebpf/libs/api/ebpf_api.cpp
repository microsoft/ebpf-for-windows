/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include "pch.h"
#include "ebpf_api.h"

#include <map>
#include <stdexcept>

#include "ebpf_protocol.h"
#include "platform.h"
#include "tlv.h"
extern "C"
{
#include "ubpf.h"
}
#include "unwind_helper.h"
#include "Verifier.h"

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

// Device type
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPFCTL_METHOD_BUFFERED CTL_CODE(EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

static ebpf_handle_t device_handle = INVALID_HANDLE_VALUE;

struct empty_reply
{
} _empty_reply;

template <typename request_t, typename reply_t = empty_reply>
static uint32_t
invoke_ioctl(ebpf_handle_t handle, request_t& request, reply_t& reply = _empty_reply)
{
    uint32_t actual_reply_size;
    uint32_t request_size;
    void* request_ptr;
    uint32_t reply_size;
    void* reply_ptr;
    bool variable_reply_size = false;

    if constexpr (std::is_same<request_t, nullptr_t>::value) {
        request_size = 0;
        request_ptr = nullptr;
    } else if constexpr (std::is_same<request_t, std::vector<uint8_t>>::value) {
        request_size = static_cast<uint32_t>(request.size());
        request_ptr = request.data();
    } else {
        request_size = sizeof(request);
        request_ptr = &request;
    }

    if constexpr (std::is_same<reply_t, nullptr_t>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else if constexpr (std::is_same<reply_t, std::vector<uint8_t>>::value) {
        reply_size = static_cast<uint32_t>(reply.size());
        reply_ptr = reply.data();
        variable_reply_size = true;
    } else if constexpr (std::is_same<reply_t, empty_reply>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else {
        reply_size = static_cast<uint32_t>(sizeof(reply));
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

    if (!result) {
        return GetLastError();
    }

    if (actual_reply_size != reply_size && !variable_reply_size) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

uint32_t
ebpf_api_initiate()
{
    LPCWSTR ebpfDeviceName = L"\\\\.\\EbpfIoDevice";

    if (device_handle != INVALID_HANDLE_VALUE) {
        return ERROR_ALREADY_INITIALIZED;
    }

    device_handle = Platform::CreateFile(
        ebpfDeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (device_handle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    return 0;
}

void
ebpf_api_terminate()
{
    if (device_handle != INVALID_HANDLE_VALUE) {
        Platform::CloseHandle(device_handle);
        device_handle = INVALID_HANDLE_VALUE;
    }
}

typedef struct _map_cache
{
    uintptr_t handle;
    EbpfMapDescriptor ebpf_map_descriptor;
} map_cache_t;

// TODO: this duplicates global_program_info.map_descriptors in ebpfverifier.lib
// https://github.com/vbpf/ebpf-verifier/issues/113 tracks getting rid of global
// state in that lib, but won't notice this global state which has the same
// problem.
std::vector<map_cache_t> _map_file_descriptors;

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

    // TODO: Replace this with the CRT helper to create FD from handle once we
    // have real handles.
    int fd = static_cast<int>(_map_file_descriptors.size() + 1);
    _map_file_descriptors.push_back({reply.handle, {fd, type, key_size, value_size, 0}});
    return static_cast<int>(_map_file_descriptors.size());
}

static map_cache_t&
get_map_cache_entry(uint64_t map_fd)
{
    return _map_file_descriptors[map_fd - 1];
}

EbpfMapDescriptor&
get_map_descriptor_internal(int map_fd)
{
    return get_map_cache_entry(map_fd).ebpf_map_descriptor;
}

static uint32_t
resolve_maps_in_byte_code(std::vector<uint8_t>& byte_code)
{
    std::vector<size_t> instruction_offsets;
    std::vector<uint64_t> map_handles;

    ebpf_inst* instructions = reinterpret_cast<ebpf_inst*>(byte_code.data());
    ebpf_inst* instruction_end = reinterpret_cast<ebpf_inst*>(byte_code.data() + byte_code.size());
    for (size_t index = 0; index < byte_code.size() / sizeof(ebpf_inst); index++) {
        ebpf_inst& first_instruction = instructions[index];
        ebpf_inst& second_instruction = instructions[index + 1];
        if (first_instruction.opcode != INST_OP_LDDW_IMM) {
            continue;
        }
        if (&instructions[index + 1] >= instruction_end) {
            return ERROR_INVALID_PARAMETER;
        }
        index++;

        // Check for LD_MAP flag
        if (first_instruction.src != 1) {
            continue;
        }

        uint64_t imm =
            static_cast<uint64_t>(first_instruction.imm) | (static_cast<uint64_t>(second_instruction.imm) << 32);
        instruction_offsets.push_back(index - 1);
        map_handles.push_back(imm);
    }

    std::vector<uint8_t> request_buffer(
        offsetof(ebpf_operation_resolve_map_request_t, map_handle) + sizeof(uint64_t) * map_handles.size());

    std::vector<uint8_t> reply_buffer(
        offsetof(ebpf_operation_resolve_map_reply_t, address) + sizeof(uint64_t) * map_handles.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_map_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP;
    request->header.length = static_cast<uint16_t>(request_buffer.size());

    for (size_t index = 0; index < map_handles.size(); index++) {
        request->map_handle[index] = map_handles[index];
    }

    uint32_t result = invoke_ioctl(device_handle, request_buffer, reply_buffer);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    for (size_t index = 0; index < map_handles.size(); index++) {
        ebpf_inst& first_instruction = instructions[instruction_offsets[index]];
        ebpf_inst& second_instruction = instructions[instruction_offsets[index] + 1];

        // Clear LD_MAP flag
        first_instruction.src = 0;

        // Replace handle with address
        uint64_t new_imm = reply->address[index];
        first_instruction.imm = static_cast<uint32_t>(new_imm);
        second_instruction.imm = static_cast<uint32_t>(new_imm >> 32);
    }

    return ERROR_SUCCESS;
}

static uint32_t
build_helper_id_to_address_map(std::vector<uint8_t>& byte_code, std::map<uint32_t, uint64_t>& helper_id_to_adddress)
{
    ebpf_inst* instructions = reinterpret_cast<ebpf_inst*>(byte_code.data());
    for (size_t index = 0; index < byte_code.size() / sizeof(ebpf_inst); index++) {
        ebpf_inst& instruction = instructions[index];
        if (instruction.opcode != INST_OP_CALL) {
            continue;
        }
        helper_id_to_adddress[instruction.imm] = 0;
    }

    std::vector<uint8_t> request_buffer(
        offsetof(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t) * helper_id_to_adddress.size());

    std::vector<uint8_t> reply_buffer(
        offsetof(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uint64_t) * helper_id_to_adddress.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_helper_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER;
    request->header.length = static_cast<uint16_t>(request_buffer.size());

    size_t index = 0;
    for (const auto& helper : helper_id_to_adddress) {
        request->helper_id[index++] = helper.first;
    }

    uint32_t result = invoke_ioctl(device_handle, request_buffer, reply_buffer);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    index = 0;
    for (auto& helper : helper_id_to_adddress) {
        helper.second = reply->address[index++];
    }

    return EBPF_ERROR_SUCCESS;
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
    std::vector<uint8_t> byte_code(MAX_CODE_SIZE);
    size_t byte_code_size = byte_code.size();
    std::vector<uint8_t> request_buffer;
    _ebpf_operation_load_code_reply reply;
    struct ubpf_vm* vm = nullptr;
    _unwind_helper unwind([&] {
        if (vm) {
            ubpf_destroy(vm);
        }
        for (auto& map : _map_file_descriptors) {
            ebpf_api_delete_map(reinterpret_cast<ebpf_handle_t>(map.handle));
        }
    });

    uint32_t result;

    try {
        _map_file_descriptors.resize(0);
        // Verify code.
        if (verify(file_name, section_name, byte_code.data(), &byte_code_size, error_message) != 0) {
            return ERROR_INVALID_PARAMETER;
        }
    } catch (std::runtime_error& err) {
        auto message = err.what();
        auto message_length = strlen(message) + 1;
        char* error = reinterpret_cast<char*>(calloc(message_length + 1, sizeof(char)));
        if (error) {
            strcpy_s(error, message_length, message);
        }
        *error_message = error;
        return ERROR_INVALID_PARAMETER;
    }

    if (_map_file_descriptors.size() > *count_of_map_handles) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *count_of_map_handles = 0;
    for (const auto& map : _map_file_descriptors) {
        map_handles[*count_of_map_handles] = reinterpret_cast<HANDLE>(map.handle);
        (*count_of_map_handles)++;
    }

    byte_code.resize(byte_code_size);
    result = resolve_maps_in_byte_code(byte_code);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    std::vector<uint8_t> file_name_bytes(strlen(file_name));
    std::vector<uint8_t> section_name_bytes(strlen(section_name));
    std::copy(file_name, file_name + file_name_bytes.size(), file_name_bytes.begin());
    std::copy(section_name, section_name + section_name_bytes.size(), section_name_bytes.begin());

    if (execution_type == EBPF_EXECUTION_JIT) {
        std::map<uint32_t, uint64_t> helper_id_to_adddress;
        result = build_helper_id_to_address_map(byte_code, helper_id_to_adddress);
        if (result != ERROR_SUCCESS) {
            return result;
        }

        std::vector<uint8_t> machine_code(MAX_CODE_SIZE);
        size_t machine_code_size = machine_code.size();

        // JIT code.
        vm = ubpf_create();
        if (vm == nullptr) {
            return ERROR_OUTOFMEMORY;
        }

        for (const auto& helper : helper_id_to_adddress) {
            if (ubpf_register(vm, helper.first, nullptr, reinterpret_cast<void*>(helper.second)) < 0) {
                return ERROR_INVALID_PARAMETER;
            }
        }

        if (ubpf_load(
                vm, byte_code.data(), static_cast<uint32_t>(byte_code.size()), const_cast<char**>(error_message)) < 0) {
            return ERROR_INVALID_PARAMETER;
        }

        if (ubpf_translate(vm, machine_code.data(), &machine_code_size, const_cast<char**>(error_message))) {
            return ERROR_INVALID_PARAMETER;
        }
        machine_code.resize(machine_code_size);
        byte_code = machine_code;
    }

    request_buffer.resize(
        offsetof(ebpf_operation_load_code_request_t, data) + file_name_bytes.size() + section_name_bytes.size() +
        byte_code.size());
    auto request = reinterpret_cast<ebpf_operation_load_code_request_t*>(request_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->code_type = execution_type == EBPF_EXECUTION_JIT ? EBPF_CODE_NATIVE : EBPF_CODE_EBPF;
    request->file_name_offset = offsetof(ebpf_operation_load_code_request_t, data);
    request->section_name_offset = request->file_name_offset + static_cast<uint16_t>(file_name_bytes.size());
    request->code_offset = request->section_name_offset + static_cast<uint16_t>(section_name_bytes.size());
    std::copy(file_name_bytes.begin(), file_name_bytes.end(), request_buffer.begin() + request->file_name_offset);
    std::copy(
        section_name_bytes.begin(), section_name_bytes.end(), request_buffer.begin() + request->section_name_offset);

    std::copy(byte_code.begin(), byte_code.end(), request_buffer.begin() + request->code_offset);

    result = invoke_ioctl(device_handle, request_buffer, reply);

    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE) {
        return ERROR_INVALID_PARAMETER;
    }

    *handle = reinterpret_cast<ebpf_handle_t>(reply.handle);

    if (result == ERROR_SUCCESS) {
        _map_file_descriptors.clear();
    }
    return result;
}

void
ebpf_api_free_string(const char* error_message)
{
    return free(const_cast<char*>(error_message));
}

uint32_t
ebpf_api_pin_map(ebpf_handle_t handle, const uint8_t* name, uint32_t name_length)
{
    std::vector<uint8_t> request_buffer(offsetof(ebpf_operation_update_map_pinning_request_t, name) + name_length);
    auto request = reinterpret_cast<ebpf_operation_update_map_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_MAP_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = reinterpret_cast<uint64_t>(handle);
    std::copy(name, name + name_length, request->name);
    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t
ebpf_api_unpin_map(const uint8_t* name, uint32_t name_length)
{
    std::vector<uint8_t> request_buffer(offsetof(ebpf_operation_update_map_pinning_request_t, name) + name_length);
    auto request = reinterpret_cast<ebpf_operation_update_map_pinning_request_t*>(request_buffer.data());

    request->header.id = EBPF_OPERATION_UPDATE_MAP_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->handle = UINT64_MAX;
    std::copy(name, name + name_length, request->name);
    return invoke_ioctl(device_handle, request_buffer);
}

uint32_t
ebpf_api_get_pinned_map(const uint8_t* name, uint32_t name_length, ebpf_handle_t* handle)
{
    std::vector<uint8_t> request_buffer(offsetof(ebpf_operation_get_map_pinning_request_t, name) + name_length);
    auto request = reinterpret_cast<ebpf_operation_get_map_pinning_request_t*>(request_buffer.data());
    ebpf_operation_get_map_pinning_reply_t reply;

    request->header.id = EBPF_OPERATION_GET_MAP_PINNING;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    std::copy(name, name + name_length, request->name);
    auto result = invoke_ioctl(device_handle, request_buffer, reply);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_MAP_PINNING) {
        return ERROR_INVALID_PARAMETER;
    }

    *handle = reinterpret_cast<ebpf_handle_t>(reply.handle);

    return result;
}

void
ebpf_api_unload_program(ebpf_handle_t handle)
{
    _ebpf_operation_unload_code_request request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_UNLOAD_CODE, reinterpret_cast<uint64_t>(handle)};

    invoke_ioctl(device_handle, request);

    return;
}

uint32_t
ebpf_api_attach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point)
{
    _ebpf_operation_attach_detach_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_ATTACH_CODE,
        reinterpret_cast<uint64_t>(handle),
        hook_point};

    return invoke_ioctl(device_handle, request);
}

uint32_t
ebpf_api_detach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point)
{
    _ebpf_operation_attach_detach_request request{
        sizeof(request),
        ebpf_operation_id_t::EBPF_OPERATION_DETACH_CODE,
        reinterpret_cast<uint64_t>(handle),
        hook_point};

    return invoke_ioctl(device_handle, request);
}

uint32_t
ebpf_api_map_find_element(
    ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, uint8_t* value)
{
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_find_element_request) + key_size - 1);
    std::vector<uint8_t> reply_buffer(sizeof(_ebpf_operation_map_find_element_reply) + value_size - 1);
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
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_update_element_request) - 1 + key_size + value_size);
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
    std::vector<uint8_t> request_buffer(sizeof(_ebpf_operation_map_delete_element_request) - 1 + key_size);
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
    std::vector<uint8_t> request_buffer(offsetof(ebpf_operation_map_get_next_key_request_t, previous_key) + key_size);
    std::vector<uint8_t> reply_buffer(offsetof(ebpf_operation_map_get_next_key_reply_t, next_key) + key_size);
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
    _ebpf_operation_get_next_program_request request{
        sizeof(request),
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
    _ebpf_operation_query_map_definition_request request{
        sizeof(request), ebpf_operation_id_t::EBPF_OPERATION_QUERY_MAP_DEFINITION, reinterpret_cast<uint64_t>(handle)};

    _ebpf_operation_query_map_definition_reply reply;

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
    if (retval == ERROR_SUCCESS) {
        *size = reply.map_definition.size;
        *type = reply.map_definition.type;
        *key_size = reply.map_definition.key_size;
        *value_size = reply.map_definition.value_size;
        *max_entries = reply.map_definition.max_entries;
    }
    return retval;
}

uint32_t
ebpf_api_program_query_information(
    ebpf_handle_t handle, ebpf_execution_type_t* program_type, const char** file_name, const char** section_name)
{
    std::vector<uint8_t> reply_buffer(1024);
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

    *program_type = reply->code_type == EBPF_CODE_NATIVE ? EBPF_EXECUTION_JIT : EBPF_EXECUTION_INTERPRET;
    *file_name = local_file_name;
    *section_name = local_section_name;

    return retval;
}

void
ebpf_api_delete_map(ebpf_handle_t handle)
{
    UNREFERENCED_PARAMETER(handle);
    // TODO: Call close handle once the switch to using OB handles
}

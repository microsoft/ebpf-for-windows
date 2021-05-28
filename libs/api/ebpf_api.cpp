// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "pch.h"
#include "ebpf_api.h"

#include <map>
#include <stdexcept>
#include "api_common.hpp"
#include "ebpf_protocol.h"
#include "ebpf_platform.h"
#include "map_descriptors.hpp"
#include "platform.h"
extern "C"
{
#include "ubpf.h"
}
#include "Verifier.h"
#include "verifier_service.h"
#include "windows_helpers.hpp"

#define MAX_CODE_SIZE (32 * 1024) // 32 KB

// ebpf_handle_t device_handle = INVALID_HANDLE_VALUE;

uint32_t
ebpf_api_initiate()
{
    if (device_handle != INVALID_HANDLE_VALUE) {
        return ERROR_ALREADY_INITIALIZED;
    }

    device_handle = Platform::CreateFile(
        EBPF_DEVICE_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

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
resolve_maps_in_byte_code(ebpf_handle_t program_handle, ebpf_code_buffer_t& byte_code)
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

    if (map_handles.size() == 0) {
        return ERROR_SUCCESS;
    }

    ebpf_protocol_buffer_t request_buffer(
        offsetof(ebpf_operation_resolve_map_request_t, map_handle) + sizeof(uint64_t) * map_handles.size());

    ebpf_protocol_buffer_t reply_buffer(
        offsetof(ebpf_operation_resolve_map_reply_t, address) + sizeof(uint64_t) * map_handles.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_map_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_handle = reinterpret_cast<uint64_t>(program_handle);

    for (size_t index = 0; index < map_handles.size(); index++) {
        if (map_handles[index] > get_map_descriptor_size()) {
            return ERROR_INVALID_PARAMETER;
        }
        request->map_handle[index] = get_map_handle_at_index((int)map_handles[index] - 1);
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
build_helper_id_to_address_map(
    ebpf_handle_t program_handle, ebpf_code_buffer_t& byte_code, std::map<uint32_t, uint64_t>& helper_id_to_adddress)
{
    ebpf_inst* instructions = reinterpret_cast<ebpf_inst*>(byte_code.data());
    for (size_t index = 0; index < byte_code.size() / sizeof(ebpf_inst); index++) {
        ebpf_inst& instruction = instructions[index];
        if (instruction.opcode != INST_OP_CALL) {
            continue;
        }
        helper_id_to_adddress[instruction.imm] = 0;
    }

    if (helper_id_to_adddress.size() == 0)
        return ERROR_SUCCESS;

    ebpf_protocol_buffer_t request_buffer(
        offsetof(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t) * helper_id_to_adddress.size());

    ebpf_protocol_buffer_t reply_buffer(
        offsetof(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uint64_t) * helper_id_to_adddress.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_helper_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_handle = reinterpret_cast<uint64_t>(program_handle);

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

    return EBPF_SUCCESS;
}

static uint32_t
resolve_ec_function(ebpf_ec_function_t function, uint64_t* address)
{
    ebpf_operation_get_ec_function_request_t request = {sizeof(request), EBPF_OPERATION_GET_EC_FUNCTION, function};
    ebpf_operation_get_ec_function_reply_t reply;

    uint32_t retval = invoke_ioctl(device_handle, request, reply);
    if (retval != ERROR_SUCCESS) {
        return retval;
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_EC_FUNCTION) {
        return ERROR_INVALID_PARAMETER;
    }

    *address = reply.address;

    return retval;
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
    struct ubpf_vm* vm = nullptr;
    uint64_t log_function_address;
    ebpf_operation_load_code_request_t* request = nullptr;
    uint32_t error_message_size = 0;
    std::vector<uintptr_t> handles;
    uint32_t result;

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

    // TODO: (issue #169): Should switch this to more idiomatic C++
    // Note: This leaks the program handle on some errors.
    result = _create_program(program_type, file_name, section_name, &program_handle);
    if (result != ERROR_SUCCESS)
        goto Done;

    // Verify code.
    if (verify_byte_code(&program_type, byte_code.data(), byte_code_size, error_message, &error_message_size) != 0) {
        result = ERROR_INVALID_PARAMETER;
        goto Done;
    }

    if (get_map_descriptor_size() > *count_of_map_handles) {
        result = ERROR_INSUFFICIENT_BUFFER;
        goto Done;
    }

    *count_of_map_handles = 0;
    handles = get_all_map_handles();
    for (const auto& map_handle : handles) {
        map_handles[*count_of_map_handles] = reinterpret_cast<HANDLE>(map_handle);
        (*count_of_map_handles)++;
    }

    byte_code.resize(byte_code_size);
    result = resolve_maps_in_byte_code(program_handle, byte_code);
    if (result != ERROR_SUCCESS) {
        goto Done;
    }

    result = resolve_ec_function(EBPF_EC_FUNCTION_LOG, &log_function_address);
    if (result != ERROR_SUCCESS)
        goto Done;

    if (execution_type == EBPF_EXECUTION_JIT) {
        std::map<uint32_t, uint64_t> helper_id_to_adddress;
        result = build_helper_id_to_address_map(program_handle, byte_code, helper_id_to_adddress);
        if (result != ERROR_SUCCESS)
            goto Done;

        ebpf_code_buffer_t machine_code(MAX_CODE_SIZE);
        size_t machine_code_size = machine_code.size();

        // JIT code.
        vm = ubpf_create();
        if (vm == nullptr)
            goto Done;

        for (const auto& helper : helper_id_to_adddress) {
            if (ubpf_register(vm, helper.first, nullptr, reinterpret_cast<void*>(helper.second)) < 0)
                goto Done;
        }

        ubpf_set_error_print(
            vm, reinterpret_cast<int (*)(FILE * stream, const char* format, ...)>(log_function_address));

        if (ubpf_load(
                vm, byte_code.data(), static_cast<uint32_t>(byte_code.size()), const_cast<char**>(error_message)) < 0) {
            result = ERROR_INVALID_PARAMETER;
            goto Done;
        }

        if (ubpf_translate(vm, machine_code.data(), &machine_code_size, const_cast<char**>(error_message))) {
            result = ERROR_INVALID_PARAMETER;
            goto Done;
        }
        machine_code.resize(machine_code_size);
        byte_code = machine_code;
    }

    request_buffer.resize(offsetof(ebpf_operation_load_code_request_t, code) + byte_code.size());
    request = reinterpret_cast<ebpf_operation_load_code_request_t*>(request_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_handle = reinterpret_cast<uint64_t>(program_handle);
    request->code_type = execution_type == EBPF_EXECUTION_JIT ? EBPF_CODE_NATIVE : EBPF_CODE_EBPF;

    std::copy(
        byte_code.begin(),
        byte_code.end(),
        request_buffer.begin() + offsetof(ebpf_operation_load_code_request_t, code));

    result = invoke_ioctl(device_handle, request_buffer);

    if (result != ERROR_SUCCESS)
        goto Done;

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

    if (vm)
        ubpf_destroy(vm);

    if (program_handle != INVALID_HANDLE_VALUE)
        ebpf_api_close_handle(program_handle);

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

    *program_type = reply->code_type == EBPF_CODE_NATIVE ? EBPF_EXECUTION_JIT : EBPF_EXECUTION_INTERPRET;
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

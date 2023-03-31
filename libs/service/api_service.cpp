// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "api_service.h"
#include "device_helper.hpp"
#include "ebpf_platform.h"
#include "ebpf_protocol.h"
#include "map_descriptors.hpp"
#include "platform.h"
extern "C"
{
#include "ubpf.h"
}
#include "Verifier.h"
#include "verifier_service.h"
#include "windows_platform.hpp"

#include <map>
#include <stdexcept>

// Maximum size of JIT'ed native code.
#define MAX_NATIVE_CODE_SIZE_IN_BYTES (32 * 1024) // 32 KB

static ebpf_result_t
_build_helper_id_to_address_map(
    ebpf_handle_t program_handle,
    _In_reads_(instruction_count) ebpf_inst* instructions,
    uint32_t instruction_count,
    std::vector<uint64_t>& helper_addresses,
    uint32_t& unwind_index)
{
    // Note:
    // eBPF supports helper IDs in the range [1, MAXUINT32]
    // uBPF jitter only supports helper IDs in the range [0,63]
    // Build a table to map [1, MAXUINT32] -> [0,63]
    std::map<uint32_t, uint32_t> helper_id_mapping;
    unwind_index = MAXUINT32;

    for (size_t index = 0; index < instruction_count; index++) {
        ebpf_inst& instruction = instructions[index];
        if (instruction.opcode != INST_OP_CALL) {
            continue;
        }
        helper_id_mapping[instruction.imm] = 0;
    }

    if (helper_id_mapping.size() == 0) {
        return EBPF_SUCCESS;
    }

    // uBPF jitter supports a maximum of 64 helper functions
    if (helper_id_mapping.size() > 64) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    ebpf_protocol_buffer_t request_buffer(
        offsetof(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t) * helper_id_mapping.size());

    ebpf_protocol_buffer_t reply_buffer(
        offsetof(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uint64_t) * helper_id_mapping.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_helper_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_handle = program_handle;

    // Build list of helper_ids to resolve and assign new helper id.
    // New helper ids are in the range [0,63]
    uint32_t index = 0;
    for (auto& [old_helper_id, new_helper_id] : helper_id_mapping) {
        request->helper_id[index] = old_helper_id;
        new_helper_id = index;
        index++;
    }

    uint32_t result = invoke_ioctl(request_buffer, reply_buffer);
    if (result != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(result);
    }

    helper_addresses.resize(helper_id_mapping.size());

    index = 0;
    for (auto& address : helper_addresses) {
        address = reply->address[index++];
    }

    // Replace old helper_ids in range [1, MAXUINT32] with new helper ids in range [0,63]
    for (index = 0; index < instruction_count; index++) {
        ebpf_inst& instruction = instructions[index];
        if (instruction.opcode != INST_OP_CALL) {
            continue;
        }
        instruction.imm = helper_id_mapping[instruction.imm];
    }
    for (auto& [old_helper_id, new_helper_id] : helper_id_mapping) {
        if (get_helper_prototype_windows(old_helper_id).return_type !=
            EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED) {
            continue;
        }
        unwind_index = new_helper_id;
        break;
    }

    return EBPF_SUCCESS;
}

static ebpf_result_t
_resolve_ec_function(ebpf_ec_function_t function, uint64_t* address)
{
    ebpf_operation_get_ec_function_request_t request = {sizeof(request), EBPF_OPERATION_GET_EC_FUNCTION, function};
    ebpf_operation_get_ec_function_reply_t reply;

    uint32_t result = invoke_ioctl(request, reply);
    if (result != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(result);
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_EC_FUNCTION) {
        return EBPF_INVALID_ARGUMENT;
    }

    *address = reply.address;

    return EBPF_SUCCESS;
}

// Replace map fds with map addresses.
static ebpf_result_t
_resolve_maps_in_byte_code(
    ebpf_handle_t program_handle, _In_reads_(instruction_count) ebpf_inst* instructions, uint32_t instruction_count)
{
    // Create parallel vectors indexed by # of occurrence in the instructions.
    std::vector<size_t> instruction_offsets; // 0-based instruction number.
    std::vector<fd_t> map_fds;               // map_fd used in the bytecode.

    for (size_t index = 0; index < instruction_count; index++) {
        ebpf_inst& first_instruction = instructions[index];
        if (first_instruction.opcode != INST_OP_LDDW_IMM) {
            continue;
        }
        if (index + 1 >= instruction_count) {
            return EBPF_INVALID_ARGUMENT;
        }
        index++;

        // Check for LD_MAP flag
        if (first_instruction.src != 1) {
            continue;
        }

        fd_t map_fd = static_cast<fd_t>(first_instruction.imm);
        instruction_offsets.push_back(index - 1);
        map_fds.push_back(map_fd);
    }

    if (map_fds.empty()) {
        return EBPF_SUCCESS;
    }

    ebpf_protocol_buffer_t request_buffer(
        offsetof(ebpf_operation_resolve_map_request_t, map_handle) + sizeof(uint64_t) * map_fds.size());

    ebpf_protocol_buffer_t reply_buffer(
        offsetof(ebpf_operation_resolve_map_reply_t, address) + sizeof(uint64_t) * map_fds.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_map_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_handle = program_handle;

    for (size_t index = 0; index < map_fds.size(); index++) {
        request->map_handle[index] = get_map_handle(map_fds[index]);
    }

    uint32_t result = invoke_ioctl(request_buffer, reply_buffer);
    if (result != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(result);
    }

    for (size_t index = 0; index < map_fds.size(); index++) {
        ebpf_inst& first_instruction = instructions[instruction_offsets[index]];
        ebpf_inst& second_instruction = instructions[instruction_offsets[index] + 1];

        // Clear LD_MAP flag
        first_instruction.src = 0;

        // Replace handle with address
        uint64_t new_imm = reply->address[index];
        first_instruction.imm = static_cast<uint32_t>(new_imm);
        second_instruction.imm = static_cast<uint32_t>(new_imm >> 32);
    }

    return EBPF_SUCCESS;
}

static ebpf_result_t
_query_and_cache_map_descriptors(
    _In_reads_(handle_map_count) original_fd_handle_map_t* handle_map, uint32_t handle_map_count)
{
    ebpf_result_t result;
    EbpfMapDescriptor descriptor;

    if (handle_map_count > 0) {
        for (uint32_t i = 0; i < handle_map_count; i++) {
            descriptor = {0};
            ebpf_id_t inner_map_id;
            result = query_map_definition(
                reinterpret_cast<ebpf_handle_t>(handle_map[i].handle),
                &descriptor.type,
                &descriptor.key_size,
                &descriptor.value_size,
                &descriptor.max_entries,
                &inner_map_id);
            if (result != EBPF_SUCCESS) {
                return result;
            }

            cache_map_original_file_descriptor_with_handle(
                handle_map[i].original_fd,
                descriptor.type,
                descriptor.key_size,
                descriptor.value_size,
                descriptor.max_entries,
                handle_map[i].inner_map_original_fd,
                reinterpret_cast<ebpf_handle_t>(handle_map[i].handle),
                0);
        }
    }

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_verify_and_load_program(
    _In_ const GUID* program_type,
    ebpf_handle_t program_handle,
    ebpf_execution_context_t execution_context,
    ebpf_execution_type_t execution_type,
    uint32_t handle_map_count,
    _In_reads_(handle_map_count) original_fd_handle_map_t* handle_map,
    uint32_t instruction_count,
    _In_reads_(instruction_count) ebpf_inst* instructions,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_ uint32_t* error_message_size) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    int error = 0;
    uint64_t log_function_address;
    struct ubpf_vm* vm = nullptr;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_load_code_request_t* request = nullptr;

    // Only kernel execution context supported currently.
    if (execution_context == execution_context_user_mode) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Set the default execution type to JIT. This will eventually
    // be decided by a system-wide policy. TODO(Issue #288): Configure
    // system-wide execution type.
    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }

    *error_message = nullptr;
    *error_message_size = 0;

    clear_map_descriptors();

    // Query map descriptors from execution context.
    try {
        result = _query_and_cache_map_descriptors(handle_map, handle_map_count);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Verify the program.
        set_verification_in_progress(true);
        result = verify_byte_code(program_type, instructions, instruction_count, error_message, error_message_size);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = _resolve_maps_in_byte_code(program_handle, instructions, instruction_count);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = _resolve_ec_function(EBPF_EC_FUNCTION_LOG, &log_function_address);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        std::vector<uint64_t> helper_id_address;
        uint32_t unwind_index;
        result = _build_helper_id_to_address_map(
            program_handle, instructions, instruction_count, helper_id_address, unwind_index);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        ebpf_code_buffer_t machine_code(MAX_NATIVE_CODE_SIZE_IN_BYTES);
        uint8_t* byte_code_data = (uint8_t*)instructions;
        size_t byte_code_size = instruction_count * sizeof(*instructions);

        if (execution_type == EBPF_EXECUTION_JIT) {
            size_t machine_code_size = machine_code.size();

            // JIT code.
            vm = ubpf_create();
            if (vm == nullptr) {
                result = EBPF_JIT_COMPILATION_FAILED;
                goto Exit;
            }

            for (uint32_t helper_id = 0; (size_t)helper_id < helper_id_address.size(); helper_id++) {
                if (ubpf_register(vm, helper_id, nullptr, reinterpret_cast<void*>(helper_id_address[helper_id])) < 0) {
                    result = EBPF_JIT_COMPILATION_FAILED;
                    goto Exit;
                }
            }

            if (unwind_index != MAXUINT32) {
                ubpf_set_unwind_function_index(vm, unwind_index);
            }

            ubpf_set_error_print(
                vm, reinterpret_cast<int (*)(FILE * stream, const char* format, ...)>(log_function_address));

            if (ubpf_load(
                    vm, byte_code_data, static_cast<uint32_t>(byte_code_size), const_cast<char**>(error_message)) < 0) {
                result = EBPF_JIT_COMPILATION_FAILED;
                goto Exit;
            }

            if (ubpf_translate(vm, machine_code.data(), &machine_code_size, const_cast<char**>(error_message))) {
                result = EBPF_JIT_COMPILATION_FAILED;
                goto Exit;
            }
            machine_code.resize(machine_code_size);
            byte_code_data = machine_code.data();
            byte_code_size = machine_code.size();

            if (*error_message != nullptr) {
                *error_message_size = (uint32_t)strlen(*error_message);
            }
        }

        request_buffer.resize(offsetof(ebpf_operation_load_code_request_t, code) + byte_code_size);
        request = reinterpret_cast<ebpf_operation_load_code_request_t*>(request_buffer.data());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->program_handle = program_handle;
        request->code_type = execution_type == EBPF_EXECUTION_JIT ? EBPF_CODE_JIT : EBPF_CODE_EBPF;

        memcpy(request->code, byte_code_data, byte_code_size);

        error = invoke_ioctl(request_buffer);

        if (error != ERROR_SUCCESS) {
            result = EBPF_PROGRAM_LOAD_FAILED;
            goto Exit;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
    } catch (std::runtime_error& err) {
        auto message = err.what();
        *error_message = allocate_string(message, error_message_size);

        result = EBPF_VERIFICATION_FAILED;
    } catch (...) {
        result = EBPF_FAILED;
    }

Exit:
    if (vm) {
        ubpf_destroy(vm);
    }

    return result;
}

uint32_t
ebpf_service_initialize() noexcept
{
    // This is best effort. If device handle does not initialize,
    // it will be re-attempted before an IOCTL call is made.
    // This is needed to ensure the service can successfully start
    // even if the driver is not installed.
    (void)initialize_device_handle();

    return ERROR_SUCCESS;
}

void
ebpf_service_cleanup() noexcept
{
    clean_up_device_handle();
}

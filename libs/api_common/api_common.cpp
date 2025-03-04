// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_shared_framework.h"
#include "ebpf_verifier_wrapper.hpp"
#include "map_descriptors.hpp"

#include <stdint.h>
#include <string>
#include <vector>

thread_local static const ebpf_program_type_t* _global_program_type = nullptr;
thread_local static const ebpf_attach_type_t* _global_attach_type = nullptr;

const char*
allocate_string(const std::string& string, uint32_t* length) noexcept
{
    char* new_string;
    size_t string_length = string.size() + 1;
    new_string = (char*)ebpf_allocate(string_length);
    if (new_string != nullptr) {
        strcpy_s(new_string, string_length, string.c_str());
        if (length != nullptr) {
            *length = (uint32_t)string_length;
        }
    }
    return new_string;
}

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions)
{
    return {
        reinterpret_cast<const uint8_t*>(instructions.data()),
        reinterpret_cast<const uint8_t*>(instructions.data()) + instructions.size() * sizeof(ebpf_inst)};
}

int
get_file_size(const char* filename, size_t* byte_code_size) noexcept
{
    int result = 0;
    *byte_code_size = NULL;
    struct stat st = {0};
    result = stat(filename, &st);
    if (!result) {
        std::cout << "file size " << st.st_size << std::endl;
        *byte_code_size = st.st_size;
    }

    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_get_info(
    ebpf_handle_t handle,
    _Inout_updates_bytes_to_opt_(*info_size, *info_size) void* info,
    _Inout_opt_ uint32_t* info_size,
    _Out_opt_ ebpf_object_type_t* type) noexcept
{
    EBPF_LOG_ENTRY();

    if (info != nullptr && (info_size == nullptr || *info_size == 0)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (handle == ebpf_handle_invalid) {
        return EBPF_INVALID_FD;
    }

    uint32_t request_info_size = 0;
    if (info_size != nullptr) {
        request_info_size = *info_size;
    }

    ebpf_protocol_buffer_t request_buffer(
        EBPF_OFFSET_OF(ebpf_operation_get_object_info_request_t, info) + request_info_size);
    ebpf_protocol_buffer_t reply_buffer(
        EBPF_OFFSET_OF(ebpf_operation_get_object_info_reply_t, info) + request_info_size);
    auto request = reinterpret_cast<ebpf_operation_get_object_info_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_get_object_info_reply_t*>(reply_buffer.data());

    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_GET_OBJECT_INFO;
    request->handle = handle;
    if (info != nullptr) {
        memcpy(request->info, info, *info_size);
    }

    ebpf_result_t result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer, reply_buffer));
    if (result == EBPF_SUCCESS) {
        if (type != nullptr) {
            *type = reply->type;
        }
        if (info != nullptr) {
            *info_size = reply->header.length - EBPF_OFFSET_OF(ebpf_operation_get_object_info_reply_t, info);
            memcpy(info, reply->info, *info_size);
        }
    }

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
query_map_definition(
    ebpf_handle_t handle,
    _Out_ uint32_t* id,
    _Out_ uint32_t* type,
    _Out_ uint32_t* key_size,
    _Out_ uint32_t* value_size,
    _Out_ uint32_t* max_entries,
    _Out_ ebpf_id_t* inner_map_id) noexcept
{
    bpf_map_info info = {0};
    uint32_t info_size = sizeof(info);
    ebpf_result_t result = ebpf_object_get_info(handle, &info, &info_size, NULL);
    if (result == EBPF_SUCCESS) {
        *id = info.id;
        *type = info.type;
        *key_size = info.key_size;
        *value_size = info.value_size;
        *max_entries = info.max_entries;
        *inner_map_id = info.inner_map_id;
    }
    return result;
}

void
set_global_program_and_attach_type(
    _In_opt_ const ebpf_program_type_t* program_type, _In_opt_ const ebpf_attach_type_t* attach_type)
{
    _global_program_type = program_type;
    _global_attach_type = attach_type;
}

_Ret_maybenull_ const ebpf_program_type_t*
get_global_program_type()
{
    return _global_program_type;
}

_Ret_maybenull_ const ebpf_attach_type_t*
get_global_attach_type()
{
    return _global_attach_type;
}

void
ebpf_clear_thread_local_storage() noexcept
{
    set_global_program_and_attach_type(nullptr, nullptr);
    clear_map_descriptors();
    clear_program_info_cache();
    set_program_under_verification(ebpf_handle_invalid);
    clean_up_sync_device_handle();
}

// Returned value is true if the program passes verification.
bool
ebpf_verify_program(
    std::ostream& os,
    _In_ const InstructionSeq& instruction_sequence,
    _In_ const program_info& info,
    _In_ const ebpf_verifier_options_t& options,
    _Out_ ebpf_api_verifier_stats_t* stats)
{
    stats->total_unreachable = 0;
    stats->total_warnings = 0;
    stats->max_loop_count = 0;

    // Convert the instruction sequence to a control-flow graph.
    try {
        if (info.type.platform_specific_data == (uintptr_t)&EBPF_PROGRAM_TYPE_UNSPECIFIED) {
            throw std::runtime_error("Unspecified program type.");
        }
        const auto program = Program::from_sequence(instruction_sequence, info, options.cfg_opts);
        auto invariants = analyze(program);
        if (options.verbosity_opts.print_invariants) {
            print_invariants(os, program, options.verbosity_opts.simplify, invariants);
        }
        bool pass;
        if (options.verbosity_opts.print_failures) {
            auto report = invariants.check_assertions(program);
            thread_local_options.verbosity_opts.print_line_info = true;
            print_warnings(os, report);
            pass = report.verified();
            stats->total_warnings = (int)report.warning_set().size();
            stats->total_unreachable = (int)report.reachability_set().size();
        } else {
            pass = invariants.verified(program);
        }
        stats->max_loop_count = invariants.max_loop_count();
        return pass;
    } catch (UnmarshalError& e) {
        os << "error: " << e.what() << std::endl;
        return false;
    }
}

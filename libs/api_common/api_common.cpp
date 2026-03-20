// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "ebpf_result.h"
#include "ebpf_shared_framework.h"
#include "ebpf_verifier_wrapper.hpp"
#include "map_descriptors.hpp"
#include "windows_platform_common.hpp"

#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

thread_local static const ebpf_program_type_t* _global_program_type = nullptr;
thread_local static const ebpf_attach_type_t* _global_attach_type = nullptr;

// Per-instruction map annotations from the most recent verification.
// Strings in _map_annotation_names are owned by this vector; the ebpf_verifier_map_info_t
// entries in _map_annotations point into them.
thread_local static std::vector<std::string> _map_annotation_names;
thread_local static std::vector<ebpf_verifier_map_info_t> _map_annotations;

const char*
allocate_string(const std::string& string, uint32_t* length) noexcept
{
    char* new_string;
    size_t string_length = 0;
    if (ebpf_safe_size_t_add(string.size(), 1, &string_length) != EBPF_SUCCESS) {
        return nullptr;
    }
    if ((length != nullptr) && (string_length > UINT32_MAX)) {
        return nullptr;
    }
    new_string = (char*)ebpf_allocate_with_tag(string_length, EBPF_POOL_TAG_DEFAULT);
    if (new_string != nullptr) {
        strcpy_s(new_string, string_length, string.c_str());
        if (length != nullptr) {
            *length = (uint32_t)string_length;
        }
    }
    return new_string;
}

ebpf_result_t
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions, std::vector<uint8_t>& byte_code)
{
    size_t byte_count = 0;
    ebpf_result_t result = ebpf_safe_size_t_multiply(instructions.size(), sizeof(ebpf_inst), &byte_count);
    if (result != EBPF_SUCCESS) {
        return result;
    }

    byte_code = {
        reinterpret_cast<const uint8_t*>(instructions.data()),
        reinterpret_cast<const uint8_t*>(instructions.data()) + byte_count};
    return EBPF_SUCCESS;
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
    ebpf_result_t result = EBPF_SUCCESS;
    size_t request_buffer_length = 0;
    size_t reply_buffer_length = 0;
    size_t returned_info_size = 0;

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

    result = ebpf_safe_size_t_add(
        EBPF_OFFSET_OF(ebpf_operation_get_object_info_request_t, info), request_info_size, &request_buffer_length);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }

    result = ebpf_safe_size_t_add(
        EBPF_OFFSET_OF(ebpf_operation_get_object_info_reply_t, info), request_info_size, &reply_buffer_length);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }

    ebpf_protocol_buffer_t request_buffer(request_buffer_length);
    ebpf_protocol_buffer_t reply_buffer(reply_buffer_length);
    auto request = reinterpret_cast<ebpf_operation_get_object_info_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_get_object_info_reply_t*>(reply_buffer.data());

    result = ebpf_safe_size_t_to_uint16(request_buffer.size(), &request->header.length);
    if (result != EBPF_SUCCESS) {
        EBPF_RETURN_RESULT(result);
    }
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_GET_OBJECT_INFO;
    request->handle = handle;
    if (info != nullptr) {
        memcpy(request->info, info, *info_size);
    }

    result = win32_error_code_to_ebpf_result(invoke_ioctl(request_buffer, reply_buffer));
    if (result == EBPF_SUCCESS) {
        if (type != nullptr) {
            *type = reply->type;
        }
        if (info != nullptr) {
            result = ebpf_safe_size_t_subtract(
                static_cast<size_t>(reply->header.length),
                EBPF_OFFSET_OF(ebpf_operation_get_object_info_reply_t, info),
                &returned_info_size);
            if (result != EBPF_SUCCESS) {
                EBPF_RETURN_RESULT(result);
            }
            *info_size = static_cast<uint32_t>(returned_info_size);
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
    ebpf_object_type_t object_type = EBPF_OBJECT_UNKNOWN;
    ebpf_result_t result = ebpf_object_get_info(handle, &info, &info_size, &object_type);
    if (result == EBPF_SUCCESS) {
        if (object_type != EBPF_OBJECT_MAP) {
            result = EBPF_INVALID_ARGUMENT;
        } else {
            *id = info.id;
            *type = info.type;
            *key_size = info.key_size;
            *value_size = info.value_size;
            *max_entries = info.max_entries;
            *inner_map_id = info.inner_map_id;
        }
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
    set_verification_program_type(nullptr);
    clean_up_sync_device_handle();
    _map_annotations.clear();
    _map_annotation_names.clear();
}

// Returned value is true if the program passes verification.
bool
ebpf_verify_program(
    std::ostream& os,
    _In_ const prevail::InstructionSeq& instruction_sequence,
    _In_ const prevail::ProgramInfo& info,
    _In_ const prevail::VerifierOptions& options,
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
        set_verification_program_type(&info.type);
        auto program = prevail::Program::from_sequence(instruction_sequence, info, options);
        prevail::AnalysisContext context{std::move(program), options};
        auto analysis_result = prevail::analyze(context);

        // Extract per-instruction map annotations using the verifier's abstract domain.
        // For each map helper call, query the pre-state to determine which map r1 holds.
        _map_annotations.clear();
        _map_annotation_names.clear();
        if (!analysis_result.failed) {
            for (const auto& [label, inv_pair] : analysis_result.invariants) {
                if (label.isjump() || !label.stack_frame_prefix.empty() || !label.special_label.empty()) {
                    continue;
                }
                const auto& inst = program.instruction_at(label);
                const auto* call = std::get_if<prevail::Call>(&inst);
                if (!call || !call->is_map_lookup) {
                    continue;
                }

                // Use the verifier's abstract domain to query r1's map identity.
                const prevail::EbpfDomain& pre = inv_pair.pre;
                int32_t start_fd = 0, end_fd = 0;
                if (!pre.get_map_fd_range(prevail::Reg{1}, &start_fd, &end_fd) || start_fd != end_fd) {
                    continue; // Ambiguous map — skip annotation.
                }

                auto map_type = pre.get_map_type(prevail::Reg{1});
                if (!map_type.has_value()) {
                    continue; // Ambiguous type — skip annotation.
                }

                // Look up the map descriptor to get name, value_size, max_entries.
                // Find the descriptor by original_fd.
                const std::string* map_name = nullptr;
                uint32_t value_size = 0;
                uint32_t max_entries = 0;
                for (const auto& desc : info.map_descriptors) {
                    if (desc.original_fd == start_fd) {
                        if (!desc.name.empty()) {
                            _map_annotation_names.push_back(desc.name);
                            map_name = &_map_annotation_names.back();
                        }
                        value_size = desc.value_size;
                        max_entries = desc.max_entries;
                        break;
                    }
                }

                if (map_name == nullptr) {
                    continue; // No name — can't match to bpf2c's map_definitions.
                }

                ebpf_verifier_map_info_t ann = {};
                ann.instruction_offset = (uint32_t)label.from;
                ann.helper_id = call->func;
                ann.map_name = map_name->c_str();
                ann.map_type = *map_type;
                ann.value_size = value_size;
                ann.max_entries = max_entries;
                _map_annotations.push_back(ann);
            }
        }

        if (options.verbosity_opts.print_invariants) {
            print_invariants(os, context.program, analysis_result, options.verbosity_opts);
        }
        bool pass = !analysis_result.failed;
        if (options.verbosity_opts.print_failures) {
            if (auto verification_error = analysis_result.find_first_error()) {
                print_error(os, *verification_error, context.program, options.verbosity_opts);
            }
        }
        // Count unreachable labels reported by the analysis result.
        stats->total_unreachable = (int)analysis_result.find_unreachable(context.program).size();
        // Handle failure slice output when collect_instruction_deps is enabled.
        if (options.verbosity_opts.collect_instruction_deps && analysis_result.failed) {
            // Limit to 1 slice to keep diagnostic output concise for the API consumer.
            prevail::AnalysisResult::SliceParams slice_params{.max_slices = 1};
            auto slices = analysis_result.compute_failure_slices(slice_params, context);
            print_failure_slices(os, context.program, analysis_result, slices, options.verbosity_opts);
        }
        // Get the warning count by counting invariants with errors.
        stats->total_warnings = 0;
        for (const auto& invariant : analysis_result.invariants) {
            if (invariant.second.error.has_value()) {
                stats->total_warnings++;
            }
        }
        stats->max_loop_count = analysis_result.max_loop_count;
        return pass;
    } catch (prevail::UnmarshalError& e) {
        os << "error: " << e.what() << std::endl;
        return false;
    }
}

prevail::VerifierOptions
ebpf_get_default_verifier_options(ebpf_verification_verbosity_t verbosity)
{
    prevail::VerifierOptions verifier_options{};
    verifier_options.runtime.check_for_termination = true;
    verifier_options.must_have_exit = true;
    verifier_options.verbosity_opts.print_invariants = (verbosity >= EBPF_VERIFICATION_VERBOSITY_VERBOSE);
    verifier_options.verbosity_opts.print_line_info = true;
    verifier_options.mock_map_fds = true;
    verifier_options.runtime.strict = false;
    verifier_options.runtime.allow_division_by_zero = true;
    verifier_options.runtime.setup_constraints = true;
    verifier_options.runtime.big_endian = false;
    if (verbosity == EBPF_VERIFICATION_VERBOSITY_INFORMATIONAL) {
        verifier_options.verbosity_opts.collect_instruction_deps = true;
        verifier_options.verbosity_opts.simplify = false;
    }
    return verifier_options;
}

_Must_inspect_result_ ebpf_result_t
ebpf_get_map_annotations_from_verifier(
    _Outptr_result_buffer_(*count) const ebpf_verifier_map_info_t** annotations, _Out_ size_t* count) noexcept
{
    *annotations = _map_annotations.empty() ? nullptr : _map_annotations.data();
    *count = _map_annotations.size();
    return EBPF_SUCCESS;
}

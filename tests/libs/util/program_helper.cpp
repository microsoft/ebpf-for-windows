// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "program_helper.h"

_program_load_attach_helper::_program_load_attach_helper(
    _In_z_ const char* file_name,
    ebpf_program_type_t program_type,
    _In_z_ const char* program_name,
    ebpf_execution_type_t execution_type,
    _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
    _In_ size_t attach_parameters_size,
    hook_helper_t& hook)
    : _file_name(file_name), _program_type(program_type), _program_name(program_name), _execution_type(execution_type),
      _link(nullptr), _object(nullptr)
{
    ebpf_result_t result;
    fd_t program_fd;
    const char* log_buffer = nullptr;

    // Load BPF object from ELF file.
    result = ebpf_program_load(
        _file_name.c_str(), &_program_type, nullptr, _execution_type, &_object, &program_fd, &log_buffer);
    if (log_buffer != nullptr) {
        printf("ebpf_program_load: error: %s", log_buffer);
    }
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(program_fd > 0);

    // Load program by name.
    struct bpf_program* program = bpf_object__find_program_by_name(_object, _program_name.c_str());
    REQUIRE(program != nullptr);
    program_fd = bpf_program__fd(program);
    REQUIRE(program_fd > 0);

    // Attach program to link.
    REQUIRE(hook.attach_link(program_fd, attach_parameters, attach_parameters_size, &_link) == EBPF_SUCCESS);

    ebpf_free_string(log_buffer);
}

_program_load_attach_helper::~_program_load_attach_helper()
{
    bpf_link__destroy(_link);
    bpf_object__close(_object);
}

struct bpf_object*
_program_load_attach_helper::get_object()
{
    return _object;
}
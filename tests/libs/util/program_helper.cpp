// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "program_helper.h"

_program_load_attach_helper::_program_load_attach_helper(
    _In_z_ const char* file_name,
    ebpf_program_type_t program_type,
    _In_z_ const char* program_name,
    ebpf_execution_type_t execution_type,
    hook_helper_t& hook,
    bool initiate_api)
    : _file_name(file_name), _program_type(program_type), _program_name(program_name), _execution_type(execution_type),
      _object(nullptr), _api_initialized(false)
{
    ebpf_result_t result;
    fd_t program_fd;
    const char* log_buffer = nullptr;

    if (initiate_api) {
        REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);
        _api_initialized = true;
    }

    // Load BPF object from ELF file.
    result = ebpf_program_load(
        _file_name.c_str(), &_program_type, nullptr, _execution_type, &_object, &program_fd, &log_buffer);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(program_fd > 0);

    // Load program by name.
    struct bpf_program* program = bpf_object__find_program_by_name(_object, _program_name.c_str());
    REQUIRE(program != nullptr);

    // Attach program to link.
    REQUIRE(hook.attach(program) == EBPF_SUCCESS);

    ebpf_free_string(log_buffer);
}

_program_load_attach_helper::~_program_load_attach_helper()
{
    bpf_object__close(_object);

    if (_api_initialized)
        ebpf_api_terminate();
}

struct bpf_object*
_program_load_attach_helper::get_object()
{
    return _object;
}
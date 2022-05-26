// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Utility functions for loading and attaching test eBPF programs.
 */

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "helpers.h"

typedef class _program_load_attach_helper
{
  public:
    _program_load_attach_helper(
        _In_z_ const char* file_name,
        bpf_prog_type program_type,
        _In_z_ const char* program_name,
        ebpf_execution_type_t execution_type,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        _In_ size_t attach_parameters_size,
        hook_helper_t& hook);

    ~_program_load_attach_helper();

    struct bpf_object*
    get_object();

  private:
    std::string _file_name;
    bpf_prog_type _program_type;
    std::string _program_name;
    ebpf_execution_type_t _execution_type;
    bpf_link* _link;
    bpf_object* _object;
} program_load_attach_helper_t;
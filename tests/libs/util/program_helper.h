// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Utility functions for loading and attaching test eBPF programs.
 */

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "hook_helper.h"

typedef class _program_load_attach_helper
{
  public:
    _program_load_attach_helper();
    ~_program_load_attach_helper();

    void
    initialize(
        _In_z_ const char* file_name,
        bpf_prog_type program_type,
        _In_z_ const char* program_name,
        ebpf_execution_type_t execution_type,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        hook_helper_t& hook);

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

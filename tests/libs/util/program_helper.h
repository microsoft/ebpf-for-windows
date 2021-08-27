// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @brief Utility functions for loading and attaching test eBPF programs.
 */

#include "bpf.h"
#include "helpers.h"
#include "libbpf.h"

typedef class _program_load_attach_helper
{
  public:
    _program_load_attach_helper(
        _In_z_ const char* file_name,
        _In_ const ebpf_program_type_t program_type,
        _In_ const char* program_name,
        ebpf_execution_type_t execution_type,
        hook_helper_t& hook,
        bool initiate_api = false);

    ~_program_load_attach_helper();

    struct bpf_object*
    get_object();

  private:
    std::string _file_name;
    ebpf_program_type_t _program_type;
    std::string _program_name;
    ebpf_execution_type_t _execution_type;
    bpf_object* _object;
    bool _api_initialized;
} program_load_attach_helper_t;
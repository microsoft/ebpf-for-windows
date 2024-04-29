// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <time.h>

#pragma comment(lib, "rpcrt4")

#define EBPF_PROGRAM_FILE_EXTENSION_JIT ".o"
#define EBPF_PROGRAM_FILE_EXTENSION_NATIVE ".sys"
#if defined(CONFIG_BPF_JIT_DISABLED)
#define EBPF_PROGRAM_FILE_EXTENSION EBPF_PROGRAM_FILE_EXTENSION_NATIVE
#else
#define EBPF_PROGRAM_FILE_EXTENSION EBPF_PROGRAM_FILE_EXTENSION_JIT
#endif

typedef class _native_module_helper
{
  public:
    void
    initialize(_In_z_ const char* file_name_prefix)
    {
        initialize(file_name_prefix, ebpf_execution_type_t::EBPF_EXECUTION_ANY);
    }
    void
    initialize(_In_z_ const char* file_name_prefix, ebpf_execution_type_t execution_type);
    std::string
    get_file_name() const
    {
        printf("_native_module_helper::get_file_name: %s\n", _file_name.c_str());
        return _file_name;
    }
    ~_native_module_helper();

  private:
    std::string _file_name;
    bool _delete_file_on_destruction = false;
} native_module_helper_t;

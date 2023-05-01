// Copyright (c) Microsoft Corporation
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

typedef class _random_generator
{
  public:
    _random_generator() { srand((uint32_t)time(NULL)); }
    uint32_t
    get_random_number()
    {
        return rand();
    }
} random_generator_t;

static random_generator_t _random_generator;

typedef class _native_module_helper
{
  public:
    _native_module_helper(_In_z_ const char* file_name_prefix)
    {
        initialize(file_name_prefix, ebpf_execution_type_t::EBPF_EXECUTION_ANY);
    }
    _native_module_helper(_In_z_ const char* file_name_prefix, ebpf_execution_type_t execution_type)
    {
        initialize(file_name_prefix, execution_type);
    }
    std::string
    get_file_name() const
    {
        printf("_native_module_helper::get_file_name: %s\n", _file_name.c_str());
        return _file_name;
    }
    ~_native_module_helper();

  private:
    void
    initialize(_In_z_ const char* file_name_prefix, ebpf_execution_type_t execution_type);
    std::string _file_name;
    bool _delete_file_on_destruction = false;
} native_module_helper_t;

_Success_(return == 0) int32_t string_to_wide_string(_In_z_ const char* input, _Outptr_ wchar_t** output);

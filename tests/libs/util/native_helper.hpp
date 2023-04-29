// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <time.h>

#if defined(CONFIG_BPF_JIT_DISABLED)
#define EBPF_PROGRAM_FILE_EXTENSION ".sys"
#else
#define EBPF_PROGRAM_FILE_EXTENSION ".o"
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
    _native_module_helper(_In_z_ const char* file_name);
    std::string
    get_file_name() const
    {
        return _file_name;
    }
    ~_native_module_helper();

  private:
    std::string _file_name;
} native_module_helper_t;

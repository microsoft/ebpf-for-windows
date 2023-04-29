// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "native_helper.hpp"

_native_module_helper::_native_module_helper(_In_z_ const char* file_name_prefix)
{
#if defined(CONFIG_BPF_JIT_DISABLED)
    int32_t random_number;
    std::string file_name_prefix_string(file_name_prefix);

    std::string original_file_name = file_name_prefix_string + std::string(EBPF_PROGRAM_FILE_EXTENSION);

    // Generate a random number to append to the file name.
    random_number = _random_generator.get_random_number();

    std::string random_string = std::to_string(random_number);
    _file_name = file_name_prefix_string + random_string + std::string(EBPF_PROGRAM_FILE_EXTENSION);

    REQUIRE(CopyFileA(original_file_name.c_str(), _file_name.c_str(), TRUE) == TRUE);
#else
    _file_name = std::string(file_name_prefix) + std::string(EBPF_PROGRAM_FILE_EXTENSION);
#endif
}

_native_module_helper::~_native_module_helper()
{
#if defined(CONFIG_BPF_JIT_DISABLED)
    DeleteFileA(_file_name.c_str());

    // Sleep for 2 seconds.
    // Sleep(2000);
#endif
}
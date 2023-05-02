// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "ebpf_execution_type.h"
#include "native_helper.hpp"

#include <rpc.h>

void
_native_module_helper::initialize(_In_z_ const char* file_name_prefix, ebpf_execution_type_t execution_type)
{
    GUID random_guid;
    char* guid_string = nullptr;
#if defined(CONFIG_BPF_JIT_DISABLED)
    ebpf_execution_type_t system_default = ebpf_execution_type_t::EBPF_EXECUTION_NATIVE;
#else
    ebpf_execution_type_t system_default = ebpf_execution_type_t::EBPF_EXECUTION_ANY;
#endif

    if (execution_type == ebpf_execution_type_t::EBPF_EXECUTION_ANY) {
        execution_type = system_default;
    }
    if (execution_type == ebpf_execution_type_t::EBPF_EXECUTION_NATIVE) {
        _delete_file_on_destruction = true;
        std::string file_name_prefix_string(file_name_prefix);
        std::string original_file_name = file_name_prefix_string + std::string(EBPF_PROGRAM_FILE_EXTENSION_NATIVE);

        // Generate a random GUID to append to the file name.
        REQUIRE(UuidCreate(&random_guid) == RPC_S_OK);

        REQUIRE(UuidToStringA(&random_guid, (RPC_CSTR*)&guid_string) == RPC_S_OK);

        _file_name =
            file_name_prefix_string + std::string(guid_string) + std::string(EBPF_PROGRAM_FILE_EXTENSION_NATIVE);
        REQUIRE(CopyFileA(original_file_name.c_str(), _file_name.c_str(), TRUE) == TRUE);
    } else {
        _file_name = std::string(file_name_prefix) + std::string(EBPF_PROGRAM_FILE_EXTENSION_JIT);
    }
}

_native_module_helper::~_native_module_helper()
{
    if (_delete_file_on_destruction) {
        DeleteFileA(_file_name.c_str());
    }
}

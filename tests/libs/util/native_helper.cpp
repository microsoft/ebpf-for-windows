// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "ebpf_execution_type.h"
#include "misc_helper.h"
#include "native_helper.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <io.h>
#include <rpc.h>

// We cannot use REQUIRE from a constructor.  Anything that can fail should be here in initialize().
void
_native_module_helper::initialize(
    _In_z_ const char* file_name_prefix, ebpf_execution_type_t execution_type, bool is_main_thread)
{
    GUID random_guid;
    char* guid_string = nullptr;
#if defined(CONFIG_BPF_JIT_DISABLED)
    ebpf_execution_type_t system_default = ebpf_execution_type_t::EBPF_EXECUTION_NATIVE;
#else
    ebpf_execution_type_t system_default = ebpf_execution_type_t::EBPF_EXECUTION_ANY;
#endif
    // Clean up any previous state.
    // Detach all bpf links
    uint32_t link_id;
    while (bpf_link_get_next_id(0, &link_id) == 0) {
        fd_t link_fd = bpf_link_get_fd_by_id(link_id);
        if (link_fd < 0) {
            break;
        }
        bpf_link_detach(link_fd);
        if (link_fd >= 0) {
            _close(link_fd);
        }
    }

    // Set _is_main_thread before any REQUIRE is invoked.
    _is_main_thread = is_main_thread;

    if (execution_type == ebpf_execution_type_t::EBPF_EXECUTION_ANY) {
        execution_type = system_default;
    }
    if (execution_type == ebpf_execution_type_t::EBPF_EXECUTION_NATIVE) {
        _delete_file_on_destruction = true;
        std::string file_name_prefix_string(file_name_prefix);
        std::string original_file_name = file_name_prefix_string + std::string(EBPF_PROGRAM_FILE_EXTENSION_NATIVE);

        // Generate a random GUID to append to the file name.
        SAFE_REQUIRE(UuidCreate(&random_guid) == RPC_S_OK);

        SAFE_REQUIRE(UuidToStringA(&random_guid, (RPC_CSTR*)&guid_string) == RPC_S_OK);

        _file_name =
            file_name_prefix_string + std::string(guid_string) + std::string(EBPF_PROGRAM_FILE_EXTENSION_NATIVE);
        SAFE_REQUIRE(CopyFileA(original_file_name.c_str(), _file_name.c_str(), TRUE) == TRUE);
        RpcStringFreeA((RPC_CSTR*)&guid_string);
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

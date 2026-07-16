// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "..\..\libs\shared\ebpf_shared_framework.h"
#include "..\..\libs\store_helper\user\ebpf_registry_helper.h"

#include <string>

namespace btf_test
{
inline constexpr GUID guid_null = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};

inline std::wstring
get_store_relative_path()
{
    return std::wstring(ebpf_store_root_sub_key) + L"\\" + EBPF_PROVIDERS_REGISTRY_KEY + L"\\" +
           EBPF_BTF_RESOLVED_FUNCTIONS_REGISTRY_KEY;
}

inline ebpf_result_t
clear_store()
{
    ebpf_result_t result = ebpf_delete_registry_tree(ebpf_store_hkcu_root_key, get_store_relative_path().c_str());
    if (result != EBPF_SUCCESS && result != EBPF_FILE_NOT_FOUND) {
        return result;
    }

    result = ebpf_delete_registry_tree(ebpf_store_hklm_root_key, get_store_relative_path().c_str());
    if (result == EBPF_ACCESS_DENIED || result == EBPF_FILE_NOT_FOUND) {
        result = EBPF_SUCCESS;
    }

    return result;
}
} // namespace btf_test

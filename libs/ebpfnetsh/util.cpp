// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <codecvt>
#include <ws2def.h>
#include <ws2ipdef.h>
// ws2def.h and ws2ipdef.h should be included prior to iphlpapi.h.
#include <iphlpapi.h>
#include "ebpf_result.hpp"
#include "util.h"

std::string
down_cast_from_wstring(const std::wstring& wide_string)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wide_string);
}

ebpf_result_t
parse_ifindex(_In_z_ const wchar_t* arg, _Out_ uint32_t* if_index)
{
    ebpf_result_t result = EBPF_SUCCESS;
    NET_LUID if_luid;
    NET_IFINDEX local_if_index = 0;
    wchar_t* end_ptr;
    uint32_t error = ERROR_SUCCESS;

    *if_index = 0;

    // Check if the input string is an interface index.
    local_if_index = wcstoul(arg, &end_ptr, 10);
    if ((local_if_index >= 0) && (*end_ptr == L'\0')) {
        if (local_if_index != 0) {
            MIB_IPINTERFACE_ROW row = {};
            InitializeIpInterfaceEntry(&row);
            row.InterfaceIndex = local_if_index;
            // Try IPv4 first.
            row.Family = AF_INET;
            error = GetIpInterfaceEntry(&row);
            if (error != ERROR_SUCCESS) {
                // Try again with IPv6.
                row.Family = AF_INET;
                error = GetIpInterfaceEntry(&row);
            }
        }
    } else {
        // Check if the input string is an interface alias.
        error = ConvertInterfaceAliasToLuid(arg, &if_luid);
        if (error == ERROR_SUCCESS)
            error = ConvertInterfaceLuidToIndex((const NET_LUID*)&if_luid, &local_if_index);
    }

    if (error == ERROR_SUCCESS) {
        *if_index = local_if_index;
    } else {
        result = win32_error_code_to_ebpf_result(error);
    }

    return result;
}
// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ebpf_utilities.h"
#include "utilities.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <codecvt>
#include <iphlpapi.h>

std::string
down_cast_from_wstring(const std::wstring& wide_string)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wide_string);
}

_Must_inspect_result_ ebpf_result_t
parse_if_index(_In_z_ const wchar_t* arg, _Out_ uint32_t* if_index)
{
    ebpf_result_t result = EBPF_SUCCESS;
    NET_LUID if_luid;
    NET_IFINDEX local_if_index = 0;
    wchar_t* end_ptr;
    uint32_t error = ERROR_SUCCESS;

    *if_index = 0;

    // Check if the input string is an interface index.
    local_if_index = wcstoul(arg, &end_ptr, 10);
    if ((local_if_index <= 0) || (*end_ptr != L'\0')) {
        // Check if the input string is an interface alias.
        error = ConvertInterfaceAliasToLuid(arg, &if_luid);
        if (error != ERROR_SUCCESS) {
            // Check if the input string is an interface name.
            error = ConvertInterfaceNameToLuidW(arg, &if_luid);
        }
        if (error == ERROR_SUCCESS) {
            error = ConvertInterfaceLuidToIndex((const NET_LUID*)&if_luid, &local_if_index);
        }
    }

    if (error == ERROR_SUCCESS) {
        *if_index = local_if_index;
    } else {
        result = win32_error_code_to_ebpf_result(error);
    }

    return result;
}
// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "framework.h"
#include "utilities.hpp"

std::wstring
guid_to_wide_string(_In_ const GUID* guid)
{
    ebpf_assert(guid);
    wchar_t guid_string[37] = {0};
    swprintf(
        guid_string,
        sizeof(guid_string) / sizeof(guid_string[0]),
        L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        guid->Data1,
        guid->Data2,
        guid->Data3,
        guid->Data4[0],
        guid->Data4[1],
        guid->Data4[2],
        guid->Data4[3],
        guid->Data4[4],
        guid->Data4[5],
        guid->Data4[6],
        guid->Data4[7]);

    return std::wstring(guid_string);
}

std::string
guid_to_string(_In_ const GUID* guid)
{
    ebpf_assert(guid);
    char guid_string[37] = {0};
    sprintf_s(
        guid_string,
        sizeof(guid_string) / sizeof(guid_string[0]),
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        guid->Data1,
        guid->Data2,
        guid->Data3,
        guid->Data4[0],
        guid->Data4[1],
        guid->Data4[2],
        guid->Data4[3],
        guid->Data4[4],
        guid->Data4[5],
        guid->Data4[6],
        guid->Data4[7]);

    return std::string(guid_string);
}

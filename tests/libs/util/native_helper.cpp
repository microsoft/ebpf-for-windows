// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "ebpf_execution_type.h"
#include "native_helper.hpp"

#include <rpc.h>

static std::string
_guid_to_string(_In_ const GUID* guid)
{
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

#pragma warning(push)
#pragma warning(disable : 6101) // Returning uninitialized memory '*unicode_string'
_Success_(return == 0) int32_t string_to_wide_string(_In_z_ const char* input, _Outptr_ wchar_t** output)
{
    wchar_t* unicode_string = NULL;
    int32_t result;
    int32_t size;

    // Compute the size needed to hold the unicode string.
    size = MultiByteToWideChar(CP_UTF8, 0, input, (int32_t)strlen(input), NULL, 0);

    if (size <= 0) {
        result = GetLastError();
        goto Done;
    }

    size++;

    unicode_string = (wchar_t*)malloc(size * sizeof(wchar_t));
    if (unicode_string == NULL) {
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto Done;
    }

    size = MultiByteToWideChar(CP_UTF8, 0, input, (int32_t)strlen(input), unicode_string, size);
    if (size == 0) {
        result = ERROR_INVALID_DATA;
        goto Done;
    }

    *output = unicode_string;
    unicode_string = nullptr;
    result = ERROR_SUCCESS;

Done:
    free(unicode_string);
    return result;
}
#pragma warning(pop)

void
_native_module_helper::initialize(_In_z_ const char* file_name_prefix, ebpf_execution_type_t execution_type)
{
    GUID random_guid;
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
        auto guid_string = _guid_to_string(&random_guid);

        _file_name = file_name_prefix_string + guid_string + std::string(EBPF_PROGRAM_FILE_EXTENSION_NATIVE);
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

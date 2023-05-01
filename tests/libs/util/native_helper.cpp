// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "ebpf_execution_type.h"
#include "native_helper.hpp"

#define EBPF_PROGRAM_FILE_EXTENSION_JIT ".o"
#define EBPF_PROGRAM_FILE_EXTENSION_NATIVE ".sys"

int32_t
string_to_wide_string(_In_z_ const char* input, _Outptr_ wchar_t** output)
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
    unicode_string = NULL;
    result = ERROR_SUCCESS;

Done:
    free(unicode_string);
    return result;
}

void
_native_module_helper::initialize(_In_z_ const char* file_name_prefix, ebpf_execution_type_t execution_type)
{
    // printf("ANUSA: C2 called, execution type = %d\n", execution_type);
#if defined(CONFIG_BPF_JIT_DISABLED)
    ebpf_execution_type_t system_default = ebpf_execution_type_t::EBPF_EXECUTION_NATIVE;
    printf("reached 1, file_name_prefix = %s\n", file_name_prefix);
#else
    ebpf_execution_type_t system_default = ebpf_execution_type_t::EBPF_EXECUTION_ANY;
    printf("reached 2\n");
#endif

    if (execution_type == ebpf_execution_type_t::EBPF_EXECUTION_ANY) {
        execution_type = system_default;
        printf("reached 3\n");
    }
    if (execution_type == ebpf_execution_type_t::EBPF_EXECUTION_NATIVE) {
        printf("reached 4\n");
        _delete_file_on_destruction = true;
        int32_t random_number;
        std::string file_name_prefix_string(file_name_prefix);

        std::string original_file_name = file_name_prefix_string + std::string(EBPF_PROGRAM_FILE_EXTENSION_NATIVE);

        // printf("====> ANUSA: original_file_name: %s\n", original_file_name.c_str());

        // Generate a random number to append to the file name.
        random_number = _random_generator.get_random_number();

        std::string random_string = std::to_string(random_number);
        _file_name = file_name_prefix_string + random_string + std::string(EBPF_PROGRAM_FILE_EXTENSION_NATIVE);

        // printf("====> ANUSA: _file_name: %s\n", _file_name.c_str());

        REQUIRE(CopyFileA(original_file_name.c_str(), _file_name.c_str(), TRUE) == TRUE);

        // printf("====> ANUSA: _file_name2: %s\n", _file_name.c_str());
    } else {
        printf("reached 5\n");
        _file_name = std::string(file_name_prefix) + std::string(EBPF_PROGRAM_FILE_EXTENSION_JIT);
    }
}

_native_module_helper::~_native_module_helper()
{
    if (_delete_file_on_destruction) {
        DeleteFileA(_file_name.c_str());
    }
}
